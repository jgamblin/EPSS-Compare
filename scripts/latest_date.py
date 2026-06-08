#!/usr/bin/env python3
"""
Discover the newest EPSS V5 beta score date that also has a matching V4 file.

Queries the empiricalsec/epss_scores repo, parses the beta_scores directory,
and prints two GitHub Actions outputs:

    latest   the newest date (YYYY-MM-DD) where BOTH the V5 beta file and the
             matching V4 file exist
    dates    space-separated, ascending list of every beta date (for trends)
    changed  "true" if `latest` differs from the score_date already committed
             in docs/data/summary.json, else "false"

Uses only the standard library so it can run before `pip install`.
GITHUB_TOKEN (if present in the environment) is used to lift API rate limits.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

REPO = "empiricalsec/epss_scores"
CONTENTS_API = f"https://api.github.com/repos/{REPO}/contents/beta_scores"
V4_RAW = f"https://raw.githubusercontent.com/{REPO}/main/{{year}}/epss_scores-{{date}}.csv.gz"

BETA_RE = re.compile(r"^epssv5_beta-(\d{4}-\d{2}-\d{2})\.csv\.gz$")


def _request(url: str, method: str = "GET") -> urllib.request.Request:
    req = urllib.request.Request(url, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "EPSS-Compare-build")
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    return req


def list_beta_dates() -> list[str]:
    """Return all beta score dates, ascending."""
    with urllib.request.urlopen(_request(CONTENTS_API), timeout=60) as resp:
        entries = json.load(resp)
    # The contents API caps a directory listing at 1000 entries. We're nowhere
    # near that (one file/day), but warn loudly rather than silently truncate.
    if len(entries) >= 1000:
        print(
            f"WARNING: beta_scores returned {len(entries)} entries — the contents "
            "API caps at 1000, so the newest dates may be missing. Switch to the "
            "Git Trees API if this fires.",
            file=sys.stderr,
        )
    dates = []
    for entry in entries:
        m = BETA_RE.match(entry.get("name", ""))
        if m:
            dates.append(m.group(1))
    return sorted(set(dates))


def v4_exists(date: str) -> bool:
    """True if the matching V4 score file exists for `date`."""
    year = date.split("-")[0]
    url = V4_RAW.format(year=year, date=date)
    for method in ("HEAD", "GET"):
        try:
            with urllib.request.urlopen(_request(url, method=method), timeout=60) as resp:
                return resp.status == 200
        except urllib.error.HTTPError as e:
            if e.code == 405 and method == "HEAD":
                continue  # CDN rejected HEAD; retry with GET
            if e.code in (403, 429):
                # Rate-limited/forbidden — do NOT treat as "file missing", which
                # would silently pick an older date. Fail loudly instead.
                sys.exit(f"Rate-limited or forbidden checking {url} (HTTP {e.code})")
            return False
        except urllib.error.URLError:
            return False
    return False


def current_score_date() -> str | None:
    """The score_date already published in docs/data/summary.json, if any."""
    for path in ("docs/data/summary.json", "docs/data/meta.json"):
        try:
            with open(path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data.get("score_date"):
            return data["score_date"]
    return None


def write_output(**kwargs) -> None:
    # Write the GITHUB_OUTPUT file first (the value that actually drives the
    # workflow), then echo to stdout for the run log.
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            for k, v in kwargs.items():
                f.write(f"{k}={v}\n")
    for k, v in kwargs.items():
        print(f"{k}={v}")


def main() -> int:
    dates = list_beta_dates()
    if not dates:
        print("No beta score files found.", file=sys.stderr)
        return 1

    # Newest date where the matching V4 file is also published.
    latest = None
    for date in reversed(dates):
        if v4_exists(date):
            latest = date
            break

    if latest is None:
        print("No beta date has a matching V4 file yet.", file=sys.stderr)
        return 1

    current = current_score_date()
    changed = "true" if latest != current else "false"

    write_output(latest=latest, dates=" ".join(dates), changed=changed)
    print(f"\nlatest={latest}  current={current}  changed={changed}", file=sys.stderr)
    print(f"beta dates available: {len(dates)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
