#!/usr/bin/env python3
"""
weekly_post.py — Auto-generate a weekly cybersecurity blog post.

Fetches the latest news from RSS feeds, calls Claude to draft a post in
Juan's voice, writes the markdown file, and pushes to git.

Usage:
    python weekly_post.py          # generate, commit, push
    python weekly_post.py --dry-run  # preview only, no git ops
"""

import argparse
import os
import subprocess
import sys
import textwrap
from datetime import date, datetime
from pathlib import Path

import anthropic
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

TOP_N = 6  # number of news items to send to Claude (bumped for extra feed)

MODEL = "claude-opus-4-8"

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
                "summary": summary[:400],  # truncate to keep prompt tight
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
    """Construct the user message for Claude."""
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


def call_claude(user_prompt: str) -> str:
    """Call the Claude API and return the raw text response."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY is not set. "
            "Copy .env.example to .env and add your key."
        )

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=MODEL,
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return message.content[0].text


def extract_frontmatter_field(markdown: str, field: str) -> str:
    """Pull a single field value from YAML front matter (simple regex)."""
    import re

    pattern = rf"^{field}:\s*(.+)$"
    match = re.search(pattern, markdown, re.MULTILINE)
    return match.group(1).strip().strip('"') if match else ""


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
        if result.returncode != 0:
            print(result.stderr.rstrip(), file=sys.stderr)
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
    run(["git", "push"])


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

    # 2. Call Claude
    print(f"\n2. Calling Claude ({MODEL})...")
    user_prompt = build_user_prompt(items, today)
    try:
        markdown = call_claude(user_prompt)
    except EnvironmentError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    print("   Done.")

    # 3. Write file
    print("\n3. Writing post...")
    post_path = write_post(markdown, today, dry_run)

    # 4. Git ops
    if not dry_run:
        print("\n4. Committing and pushing...")
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
