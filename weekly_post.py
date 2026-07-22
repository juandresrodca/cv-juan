#!/usr/bin/env python3
"""
weekly_post.py — Auto-generate a weekly cybersecurity blog post.

Fetches the latest news from RSS feeds, calls Gemini to draft a post in
Juan's voice, writes the markdown file, and pushes to git.
This is reviewed after gemini create the post 

"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import random
import re
import subprocess
import sys
import textwrap
from datetime import date, datetime
from pathlib import Path

# Note: the heavier third-party imports (google-genai, feedparser) are done
# lazily inside the functions that use them, so cover generation / --backfill
# work even in an environment where those packages aren't installed.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

RSS_FEEDS = [
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
    },
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/cybersecurity-advisories/advisories.xml",
    },
    # Smashing Security — podcast + show notes (verify slug at smashingsecurity.com/rss)
    {
        "name": "Smashing Security",
        "url": "https://feeds.acast.com/public/shows/smashing-security",
    },
]

TOP_N = 6  # number of news items to send to the model (bumped for extra feed)

MODEL = "gemini-2.5-flash"

REPO_ROOT = Path(__file__).parent.resolve()
BLOG_DIR = REPO_ROOT / "src" / "content" / "blog"

SYSTEM_PROMPT = textwrap.dedent("""
    You are Juan Rodriguez, an IT Systems Administrator and Cybersecurity
    specialist with 14+ years of enterprise IT experience. You are currently
    working at Intel Ireland and pursuing your OSCP certification.

    Write a weekly cybersecurity blog post in first person. Be direct and
    technical but accessible. Include a brief personal take on each news item
    from a sysadmin / blue-team perspective. Tone: professional but human,
    not corporate. Language: English.

    Format the output as a valid Markdown file with YAML front matter:

    ---
    title: "<post title>"
    date: <YYYY-MM-DD>
    summary: "<one-sentence summary, max 200 chars>"
    tags: [<comma-separated quoted tags>]
    draft: false
    ---

    <post body in Markdown>

    Rules:
    - The front matter must be the very first thing in the output.
    - Use ## for section headings (one per news item).
    - Keep the post between 600 and 900 words.
    - End with a short sign-off paragraph (no heading).
    - Do not invent CVE numbers or statistics — use only what is provided.
    - Tags should be lowercase, single-word or hyphenated (e.g. "ransomware",
      "patch-tuesday", "identity", "ics-scada", "weekly").
""").strip()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fetch_feed_items(feed_info: dict, max_per_feed: int = 10) -> list[dict]:
    """Parse a single RSS feed and return a list of item dicts."""
    import feedparser

    parsed = feedparser.parse(feed_info["url"])
    items = []
    for entry in parsed.entries[:max_per_feed]:
        published = entry.get("published", entry.get("updated", "unknown date"))
        summary = entry.get("summary", entry.get("content", [{}])[0].get("value", ""))
        # Strip HTML tags from summary (basic)
        import re
        summary = re.sub(r"<[^>]+>", "", summary).strip()
        items.append(
            {
                "source": feed_info["name"],
                "title": entry.get("title", "(no title)"),
                "link": entry.get("link", ""),
                "published": published,
                "summary": summary[:400],  # truncate to keep prompt tight on the last run this fail so we decrease the truncate to 400
            }
        )
    return items


def fetch_top_items(n: int = TOP_N) -> list[dict]:
    """Fetch all feeds and return the n most recent combined items."""
    all_items: list[dict] = []
    for feed in RSS_FEEDS:
        print(f"  Fetching {feed['name']}...")
        try:
            items = fetch_feed_items(feed)
            all_items.extend(items)
        except Exception as exc:
            print(f"  WARNING: could not fetch {feed['name']}: {exc}", file=sys.stderr)

    # Sort by published date (best-effort; fall back to order of insertion)
    def parse_date(item: dict):
        raw = item.get("published", "")
        for fmt in (
            "%a, %d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S %Z",
            "%Y-%m-%dT%H:%M:%S%z",
        ):
            try:
                return datetime.strptime(raw[:31], fmt)
            except ValueError:
                continue
        return datetime.min

    all_items.sort(key=parse_date, reverse=True)
    return all_items[:n]


def build_user_prompt(items: list[dict], today: date) -> str:
    """Construct the user message for the model."""
    lines = [
        f"Today is {today.strftime('%d %B %Y')}.",
        "",
        f"Here are the {len(items)} most recent cybersecurity news items. "
        "Write this week's blog post covering all of them:",
        "",
    ]
    for i, item in enumerate(items, start=1):
        lines.append(f"### Item {i}: {item['title']}")
        lines.append(f"Source: {item['source']}")
        lines.append(f"Published: {item['published']}")
        lines.append(f"URL: {item['link']}")
        if item["summary"]:
            lines.append(f"Summary: {item['summary']}")
        lines.append("")
    return "\n".join(lines)


def call_model(user_prompt: str) -> str:
    """Call the Gemini API and return the raw text response."""
    from google import genai
    from google.genai import types

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "GEMINI_API_KEY is not set. "
            "Copy .env.example to .env and add your key, or set it as a "
            "GitHub Actions secret."
        )

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=MODEL,
        contents=user_prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            max_output_tokens=8192,
            # Disable thinking — this is a structured writing task that doesn't
            # benefit from it, and thinking tokens would otherwise consume the
            # output budget and truncate the post mid-frontmatter.
            thinking_config=types.ThinkingConfig(thinking_budget=0),
        ),
    )
    text = (response.text or "").strip()
    if not text:
        raise RuntimeError(
            f"Gemini returned an empty response (model={MODEL}). "
            "Check the model name is still available and the API key is valid."
        )

    # Gemini sometimes wraps the whole file in a ```markdown ... ``` fence.
    # Strip it so the YAML front matter ends up as the very first line.
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]  # drop opening fence (```markdown / ```md / ```)
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]  # drop closing fence
        text = "\n".join(lines).strip()

    return text


def extract_frontmatter_field(markdown: str, field: str) -> str:
    """Pull a single field value from YAML front matter (simple regex)."""
    import re

    pattern = rf"^{field}:\s*(.+)$"
    match = re.search(pattern, markdown, re.MULTILINE)
    return match.group(1).strip().strip('"') if match else ""


def validate_post(markdown: str) -> None:
    """Validate the generated markdown before it's written or committed.

    A malformed post (e.g. truncated frontmatter) would crash the Astro
    build and take the live site down, so we fail loudly here instead.
    Raises ValueError if the post is not safe to publish.
    """
    if not markdown.startswith("---"):
        raise ValueError("Post does not start with YAML front matter ('---').")

    # The front matter must open AND close with a '---' fence.
    parts = markdown.split("---", 2)
    if len(parts) < 3:
        raise ValueError(
            "Front matter is not closed with a second '---' fence "
            "(likely a truncated response)."
        )

    frontmatter = parts[1]
    body = parts[2].strip()

    required = ["title", "date", "summary", "draft"]
    missing = [f for f in required if not extract_frontmatter_field(markdown, f)]
    if missing:
        raise ValueError(f"Front matter is missing required field(s): {', '.join(missing)}")

    # Quoted string fields must have balanced quotes (catches truncation
    # mid-value, which is exactly what broke the build before).
    import re
    for field in ("title", "summary"):
        match = re.search(rf"^{field}:\s*(.+)$", frontmatter, re.MULTILINE)
        if match:
            value = match.group(1).strip()
            if value.startswith('"') and not value.endswith('"'):
                raise ValueError(f"Front matter field '{field}' has an unterminated quote.")

    if len(body) < 200:
        raise ValueError(
            f"Post body is too short ({len(body)} chars) — likely a truncated response."
        )


def write_post(markdown: str, today: date, dry_run: bool) -> Path:
    """Write the generated post to the blog directory."""
    date_str = today.strftime("%Y-%m-%d")
    filename = f"{date_str}-weekly-cyber-news.md"
    output_path = BLOG_DIR / filename

    if dry_run:
        print("\n" + "=" * 72)
        print(f"DRY RUN — would write to: {output_path}")
        print("=" * 72)
        print(markdown)
        print("=" * 72)
    else:
        BLOG_DIR.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8")
        print(f"  Wrote: {output_path}")

    return output_path


def git_commit_and_push(post_path: Path, today: date, extra_paths: list[Path] | None = None) -> None:
    """Stage, commit, and push the new post (plus any extra files, e.g. its cover)."""
    date_str = today.strftime("%Y-%m-%d")
    paths = [post_path, *(extra_paths or [])]
    rel_paths = [p.relative_to(REPO_ROOT).as_posix() for p in paths]

    def run(cmd: list[str]) -> None:
        print(f"  $ {' '.join(cmd)}")
        result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout.rstrip())
        if result.stderr:
            print(result.stderr.rstrip(), file=sys.stderr)
        if result.returncode != 0:
            raise RuntimeError(f"Command failed: {' '.join(cmd)}")

    run(["git", "add", *rel_paths])
    run(
        [
            "git",
            "commit",
            "-m",
            f"feat(blog): add weekly cyber news post {date_str}",
        ]
    )
    run(["git", "push", "origin", "HEAD"])


# ---------------------------------------------------------------------------
# Cover image generation
#
# Every post gets a themed SVG hero cover so it doesn't ship bare. The design
# stays on-brand (dark gradient, blue accents, a network/constellation motif
# echoing the site's background) and is deterministic per-post: the same slug
# always produces the same cover, so rebuilds are stable, but each post looks
# distinct. The heroImage path is stored base-relative; the blog template
# prefixes import.meta.env.BASE_URL.
# ---------------------------------------------------------------------------

COVER_DIR = REPO_ROOT / "public" / "images" / "blog"
HERO_PATH_TMPL = "images/blog/{slug}.svg"

# Curated, on-brand accent colours. The base design stays blue for cohesion;
# only a couple of highlighted nodes + the eyebrow underline pick up the accent
# so the topic reads without the covers clashing with each other.
_ACCENTS = {
    "post-quantum-cryptography": "#a78bfa",  # violet — crypto / quantum
    "cryptography": "#a78bfa",
    "quantum": "#a78bfa",
    "ai": "#2dd4bf",                          # teal — AI / LLM
    "llm": "#2dd4bf",
    "ransomware": "#fbbf24",                  # amber — active threats
    "breach": "#fbbf24",
    "apt": "#fbbf24",
    "vulnerability": "#fbbf24",
    "exploit": "#fbbf24",
    "supply-chain": "#f472b6",               # pink — supply chain
}
_ACCENT_DEFAULT = "#60a5fa"                   # blue

_MONTHS = ["", "January", "February", "March", "April", "May", "June",
           "July", "August", "September", "October", "November", "December"]

_FONT_FAMILY = "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"


def extract_tags(markdown: str) -> list[str]:
    """Pull the tag list out of the YAML front matter."""
    m = re.search(r"^tags:\s*\[(.*?)\]", markdown, re.MULTILINE | re.DOTALL)
    if not m:
        return []
    return re.findall(r'"([^"]+)"', m.group(1))


def _xml_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _pick_accent(tags: list[str]) -> str:
    for t in tags:
        if t in _ACCENTS:
            return _ACCENTS[t]
    return _ACCENT_DEFAULT


def _wrap_title(title: str, max_chars: int) -> list[str]:
    words, lines, cur = title.split(), [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > max_chars:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


def _title_layout(title: str) -> tuple[list[str], int, int]:
    """Return (lines, font_size, line_height) that fit the cover's text column.

    Progressively shrinks the font (and widens the wrap) so the whole title
    fits. Only a pathologically long title falls through to the last tier, where
    it's capped at 4 lines with an ellipsis rather than silently dropping words.
    """
    for max_chars, font, lh, max_lines in (
        (18, 52, 60, 2),
        (22, 46, 54, 3),
        (27, 40, 48, 3),
        (33, 34, 42, 4),
    ):
        lines = _wrap_title(title, max_chars)
        if len(lines) <= max_lines:
            return lines, font, lh
    lines = _wrap_title(title, 33)
    lines = lines[:4]
    lines[-1] = lines[-1].rstrip(" .,:;") + "…"
    return lines, 34, 42


def _format_date(date_str: str) -> str:
    try:
        d = datetime.strptime(date_str.strip(), "%Y-%m-%d")
        return f"{d.day} {_MONTHS[d.month]} {d.year}"
    except (ValueError, IndexError):
        return date_str.strip()


def _subtitle_from_tags(tags: list[str]) -> str:
    picked = [t for t in tags if t.lower() != "weekly"][:3]
    return " · ".join(t.replace("-", " ").title() for t in picked)


def build_cover_svg(title: str, date_str: str, tags: list[str], seed: str) -> str:
    """Build a themed, deterministic SVG hero cover for a weekly post."""
    accent = _pick_accent(tags)
    lines, font, lh = _title_layout(title)
    subtitle = _subtitle_from_tags(tags)
    date_label = _format_date(date_str)
    rng = random.Random(seed)

    # Constellation motif on the right — a hub with satellite nodes, echoing the
    # site's background network animation.
    hub = (905.0, 250.0)
    sats: list[tuple[float, float]] = []
    for _ in range(7):
        ang = rng.uniform(0, 2 * math.pi)
        rad = rng.uniform(78, 165)
        x = max(745.0, min(1120.0, hub[0] + rad * math.cos(ang)))
        y = max(108.0, min(378.0, hub[1] + rad * math.sin(ang) * 0.72))
        sats.append((x, y))

    edges = [f'<path d="M{hub[0]:.0f} {hub[1]:.0f} L{x:.0f} {y:.0f}"/>' for x, y in sats]
    for a, b in (rng.sample(sats, 2) for _ in range(3)):
        edges.append(f'<path d="M{a[0]:.0f} {a[1]:.0f} L{b[0]:.0f} {b[1]:.0f}"/>')

    highlight = set(rng.sample(range(len(sats)), 2))
    nodes = []
    for i, (x, y) in enumerate(sats):
        if i in highlight:
            nodes.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="6" fill="{accent}"/>')
        else:
            nodes.append(
                f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{rng.choice([3.5, 4, 5])}" '
                f'fill="#93c5fd" opacity="{rng.choice([0.65, 0.8, 1.0])}"/>'
            )

    title_y0 = 200
    title_tspans = "".join(
        f'<tspan x="100" dy="{0 if i == 0 else lh}">{_xml_escape(l)}</tspan>'
        for i, l in enumerate(lines)
    )
    subtitle_y = title_y0 + (len(lines) - 1) * lh + 44

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 480" fill="none" role="img" aria-label="{_xml_escape(title)}">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1200" y2="480" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#111827"/>
      <stop offset="1" stop-color="#1f2937"/>
    </linearGradient>
    <radialGradient id="glow" cx="0.78" cy="0.5" r="0.6">
      <stop offset="0" stop-color="#2563eb" stop-opacity="0.30"/>
      <stop offset="1" stop-color="#2563eb" stop-opacity="0"/>
    </radialGradient>
  </defs>

  <rect width="1200" height="480" fill="url(#bg)"/>
  <rect width="1200" height="480" fill="url(#glow)"/>

  <g stroke="#334155" stroke-width="1" opacity="0.30">
    <path d="M0 120 H1200 M0 240 H1200 M0 360 H1200"/>
    <path d="M200 0 V480 M400 0 V480 M600 0 V480 M800 0 V480 M1000 0 V480"/>
  </g>

  <g stroke="{accent}" stroke-width="1.4" opacity="0.38" fill="none">
    {"".join(edges)}
  </g>
  <g>
    <circle cx="{hub[0]:.0f}" cy="{hub[1]:.0f}" r="30" fill="#0b1220" stroke="#2563eb" stroke-width="2.5"/>
    <g transform="translate({hub[0]:.0f} {hub[1] + 2:.0f})" stroke="#60a5fa" stroke-width="3" fill="none" stroke-linecap="round">
      <rect x="-11" y="-1" width="22" height="16" rx="3" fill="#60a5fa" fill-opacity="0.15"/>
      <path d="M-6 -1 V-8 a6 6 0 0 1 12 0 V-1"/>
    </g>
    {"".join(nodes)}
  </g>

  <g font-family="{_FONT_FAMILY}">
    <text x="100" y="140" fill="#60a5fa" font-size="20" font-weight="600" letter-spacing="3">WEEKLY CYBER NEWS</text>
    <rect x="100" y="154" width="54" height="3" rx="1.5" fill="{accent}"/>
    <text x="100" y="{title_y0}" fill="#ffffff" font-size="{font}" font-weight="800">{title_tspans}</text>
    <text x="100" y="{subtitle_y}" fill="#94a3b8" font-size="19" font-weight="400">{_xml_escape(subtitle)}</text>
    <text x="100" y="432" fill="#64748b" font-size="16" font-weight="500">Juan Rodriguez · {_xml_escape(date_label)}</text>
  </g>
</svg>
'''


def inject_hero_image(markdown: str, hero_path: str) -> str:
    """Add a heroImage field to the front matter if it doesn't already have one."""
    if re.search(r"^heroImage:", markdown, re.MULTILINE):
        return markdown
    new, n = re.subn(
        r"^(draft:.*)$",
        rf'\1\nheroImage: "{hero_path}"',
        markdown,
        count=1,
        flags=re.MULTILINE,
    )
    if n:
        return new
    # Fallback: insert before the closing '---' fence.
    parts = markdown.split("---", 2)
    parts[1] = parts[1].rstrip() + f'\nheroImage: "{hero_path}"\n'
    return "---".join(parts)


def generate_cover_for_post(md_path: Path, dry_run: bool = False, force: bool = False) -> bool:
    """Generate a cover for an existing post and set its heroImage.

    Returns True if anything changed (cover written or front matter updated).
    """
    slug = md_path.stem
    markdown = md_path.read_text(encoding="utf-8")
    if not force and re.search(r"^heroImage:", markdown, re.MULTILINE):
        return False  # already has a cover — leave it alone

    title = extract_frontmatter_field(markdown, "title")
    date_str = extract_frontmatter_field(markdown, "date")
    tags = extract_tags(markdown)
    svg = build_cover_svg(title, date_str, tags, seed=slug)
    hero_path = HERO_PATH_TMPL.format(slug=slug)
    cover_path = COVER_DIR / f"{slug}.svg"
    updated_md = inject_hero_image(markdown, hero_path)

    if dry_run:
        print(f"  [DRY RUN] would write cover {cover_path} and set heroImage on {md_path.name}")
        return True

    COVER_DIR.mkdir(parents=True, exist_ok=True)
    cover_path.write_text(svg, encoding="utf-8")
    if updated_md != markdown:
        md_path.write_text(updated_md, encoding="utf-8")
    print(f"  Cover: {cover_path.name}  ({_pick_accent(tags)})")
    return True


def backfill_covers(dry_run: bool = False, force: bool = False) -> list[Path]:
    """Generate covers for every post that doesn't already have one."""
    changed: list[Path] = []
    for md_path in sorted(BLOG_DIR.glob("*.md")):
        if generate_cover_for_post(md_path, dry_run=dry_run, force=force):
            changed.append(md_path)
    return changed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate and publish a weekly cybersecurity blog post."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview the generated post without writing files or committing.",
    )
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="Generate hero covers for existing posts that lack one, then exit "
             "(no model call, no git ops). Combine with --force to regenerate all.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="With --backfill, regenerate covers even for posts that already have one.",
    )
    args = parser.parse_args()

    today = date.today()
    dry_run: bool = args.dry_run

    # Backfill mode: just (re)generate covers for existing posts and stop. Files
    # are left for the user to review and commit.
    if args.backfill:
        print(f"\n{'[DRY RUN] ' if dry_run else ''}Backfilling hero covers...\n")
        changed = backfill_covers(dry_run=dry_run, force=args.force)
        if changed:
            print(f"\n{len(changed)} post(s) {'would be' if dry_run else ''} updated.")
        else:
            print("\nAll posts already have covers. Nothing to do.")
        return

    print(f"\n{'[DRY RUN] ' if dry_run else ''}Weekly Post Generator — {today}\n")

    # 1. Fetch news
    print("1. Fetching RSS feeds...")
    items = fetch_top_items()
    if not items:
        print("ERROR: No news items fetched. Check your internet connection.", file=sys.stderr)
        sys.exit(1)
    print(f"   Fetched {len(items)} items.")

    # 2. Call the model
    print(f"\n2. Calling Gemini ({MODEL})...")
    user_prompt = build_user_prompt(items, today)
    try:
        markdown = call_model(user_prompt)
    except EnvironmentError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR calling Gemini API: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
    print("   Done.")

    # 3. Validate before touching the filesystem — a malformed post would
    #    crash the Astro build and take the live site down.
    print("\n3. Validating post...")
    try:
        validate_post(markdown)
    except ValueError as exc:
        print(f"ERROR: generated post failed validation: {exc}", file=sys.stderr)
        print("Refusing to publish. No file written, nothing pushed.", file=sys.stderr)
        sys.exit(1)
    print("   Valid.")

    # 4. Generate the hero cover and set heroImage before writing, so the post
    #    ships with an image instead of bare.
    print("\n4. Generating hero cover...")
    slug = f"{today.strftime('%Y-%m-%d')}-weekly-cyber-news"
    hero_path = HERO_PATH_TMPL.format(slug=slug)
    cover_path = COVER_DIR / f"{slug}.svg"
    svg = build_cover_svg(
        title=extract_frontmatter_field(markdown, "title"),
        date_str=extract_frontmatter_field(markdown, "date"),
        tags=extract_tags(markdown),
        seed=slug,
    )
    markdown = inject_hero_image(markdown, hero_path)
    if dry_run:
        print(f"   [DRY RUN] would write cover: {cover_path}")
    else:
        COVER_DIR.mkdir(parents=True, exist_ok=True)
        cover_path.write_text(svg, encoding="utf-8")
        print(f"   Wrote: {cover_path}")

    # 5. Write file
    print("\n5. Writing post...")
    post_path = write_post(markdown, today, dry_run)

    # 6. Git ops
    if not dry_run:
        print("\n6. Committing and pushing...")
        try:
            git_commit_and_push(post_path, today, extra_paths=[cover_path])
            print("   Done. Post is live.")
        except RuntimeError as exc:
            print(f"ERROR during git ops: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        print("\n[DRY RUN] Skipping git add / commit / push.")

    print("\nAll done.\n")


if __name__ == "__main__":
    main()
