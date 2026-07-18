#!/usr/bin/env python3
"""
weekly_post.py — Auto-generate a weekly cybersecurity blog post.

Fetches the latest news from RSS feeds, calls Gemini to draft a post in
Juan's voice, writes the markdown file, and pushes to git.
This is reviewed after gemini create the post 

"""

import argparse
import os
import subprocess
import sys
import textwrap
from datetime import date, datetime
from pathlib import Path

from google import genai
from google.genai import types
import feedparser
from dotenv import load_dotenv

load_dotenv()

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


def git_commit_and_push(post_path: Path, today: date) -> None:
    """Stage, commit, and push the new post."""
    date_str = today.strftime("%Y-%m-%d")
    rel_path = post_path.relative_to(REPO_ROOT).as_posix()

    def run(cmd: list[str]) -> None:
        print(f"  $ {' '.join(cmd)}")
        result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout.rstrip())
        if result.stderr:
            print(result.stderr.rstrip(), file=sys.stderr)
        if result.returncode != 0:
            raise RuntimeError(f"Command failed: {' '.join(cmd)}")

    run(["git", "add", rel_path])
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
    args = parser.parse_args()

    today = date.today()
    dry_run: bool = args.dry_run

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

    # 4. Write file
    print("\n4. Writing post...")
    post_path = write_post(markdown, today, dry_run)

    # 5. Git ops
    if not dry_run:
        print("\n5. Committing and pushing...")
        try:
            git_commit_and_push(post_path, today)
            print("   Done. Post is live.")
        except RuntimeError as exc:
            print(f"ERROR during git ops: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        print("\n[DRY RUN] Skipping git add / commit / push.")

    print("\nAll done.\n")


if __name__ == "__main__":
    main()
