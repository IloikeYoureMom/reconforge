"""
Wayback Machine Module
══════════════════════
Queries the Internet Archive's Wayback Machine CDX API to
discover historical snapshots, URLs, and content changes
for a target domain.

Free, no API key required.
CDX API: https://web.archive.org/cdx/search/cdx
"""

import re
import json
from collections import Counter
from datetime import datetime

from ..utils.http import fetch_text


def _fetch_cdx(domain: str, limit: int = 200) -> list:
    """Fetch CDX data from the Wayback Machine."""
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url={domain}/*"
        f"&output=json"
        f"&fl=timestamp,original,statuscode,mimetype,length"
        f"&limit={limit}"
        f"&collapse=timestamp:8"
    )
    data = fetch_text(url, timeout=20)
    if data:
        try:
            rows = json.loads(data)
            if isinstance(rows, list) and len(rows) > 1:
                # Skip header row
                return rows[1:]
        except (json.JSONDecodeError, IndexError):
            pass
    return []


def recon(target: str) -> dict:
    """Query Wayback Machine for historical URL data."""
    target = target.strip().lower()

    # Extract clean domain
    domain = re.sub(r"https?://", "", target)
    domain = domain.split("/")[0]
    domain = re.sub(r"^www\.", "", domain)

    result = {
        "target": target,
        "type": "Wayback History",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    result["findings"].append(f" Target: {domain}")
    result["data"]["domain"] = domain

    # Fetch CDX data
    result["findings"].append("\n Querying Wayback Machine CDX API...")
    rows = _fetch_cdx(domain)

    if not rows:
        result["warnings"].append("  No data from Wayback Machine (API timeout or no snapshots)")
        result["data"]["lookup_links"] = [
            {"title": "Wayback Machine (manual)", "url": f"https://web.archive.org/web/*/{domain}"},
        ]
        return result

    total_snapshots = len(rows)
    result["data"]["total_snapshots"] = total_snapshots
    result["findings"].append(f" Found {total_snapshots} historical snapshot(s)")

    # Parse rows: [timestamp, original, statuscode, mimetype, length]
    urls = set()
    status_codes = Counter()
    mime_types = Counter()
    years = Counter()
    snapshots = []

    for row in rows:
        if len(row) < 5:
            continue
        ts, original, status, mime, length = row[0], row[1], row[2], row[3], row[4]

        urls.add(original)
        status_codes[status] += 1
        mime_types[mime] += 1
        if len(ts) >= 4:
            years[ts[:4]] += 1

        snapshots.append({
            "timestamp": ts,
            "url": original,
            "status": status,
            "type": mime,
            "length": length,
            "wayback_url": f"https://web.archive.org/web/{ts}/{original}",
        })

    # Unique URLs found
    result["data"]["unique_urls_count"] = len(urls)
    result["data"]["unique_urls"] = sorted(urls)
    result["findings"].append(f" {len(urls)} unique URL(s) discovered")

    # Show sample URLs
    if urls:
        result["findings"].append(f"\n Sample URLs ({min(8, len(urls))} of {len(urls)}):")
        for url in sorted(urls)[:8]:
            result["findings"].append(f"    {url}")

    # Status code breakdown
    if status_codes:
        result["data"]["status_codes"] = dict(status_codes)
        result["findings"].append(f"\n Status Code Breakdown:")
        for code, count in status_codes.most_common():
            if code.startswith("2"):
                icon = ""
            elif code.startswith("3"):
                icon = ""
            elif code.startswith("4"):
                icon = ""
            else:
                icon = ""
            result["findings"].append(f"   {icon} HTTP {code}: {count} snapshots")

    # Content type breakdown
    if mime_types:
        result["data"]["content_types"] = dict(mime_types.most_common(10))
        result["findings"].append(f"\n Content Types:")
        for mime, count in mime_types.most_common(5):
            short = mime.split(";")[0] if ";" in mime else mime
            result["findings"].append(f"    {short}: {count}")

    # Yearly breakdown
    if years:
        result["data"]["yearly_snapshots"] = dict(sorted(years.items()))
        result["findings"].append(f"\n Snapshots Per Year:")
        for year in sorted(years.keys()):
            bar = "█" * min(years[year], 40)
            result["findings"].append(f"   {year}: {bar} ({years[year]})")

    # Latest/earliest snapshots
    if snapshots:
        snapshots.sort(key=lambda x: x["timestamp"])
        earliest = snapshots[0]
        latest = snapshots[-1]

        result["data"]["earliest_snapshot"] = earliest["timestamp"]
        result["data"]["latest_snapshot"] = latest["timestamp"]

        try:
            earliest_date = datetime.strptime(earliest["timestamp"][:8], "%Y%m%d").strftime("%Y-%m-%d")
            latest_date = datetime.strptime(latest["timestamp"][:8], "%Y%m%d").strftime("%Y-%m-%d")
            result["findings"].append(f"\n Time Range: {earliest_date} → {latest_date}")
            result["findings"].append(f"    First snapshot: {earliest['url']}")
            result["findings"].append(f"    Latest snapshot:  {latest['url']}")
        except (ValueError, IndexError):
            pass

    # Most interesting findings (based on file extensions)
    interesting_exts = {".sql", ".env", ".bak", ".old", ".cfg", ".conf",
                        ".json", ".xml", ".yml", ".yaml", ".ini", ".log"}
    interesting_urls = []
    for url in urls:
        ext = url[url.rfind("."):] if "." in url else ""
        if ext in interesting_exts:
            interesting_urls.append(url)
        if any(kw in url.lower() for kw in ["admin", "config", "secret", "password", "token", "api", "backup"]):
            if url not in interesting_urls:
                interesting_urls.append(url)

    if interesting_urls:
        result["data"]["interesting_urls"] = sorted(interesting_urls)[:20]
        result["findings"].append(f"\n Potentially Interesting URLs ({len(interesting_urls)}):")
        for url in sorted(interesting_urls)[:10]:
            result["findings"].append(f"    {url}")

    # Lookup links
    result["data"]["lookup_links"] = [
        {"title": "Wayback Machine (full history)", "url": f"https://web.archive.org/web/*/{domain}"},
        {"title": "Wayback Machine (calendar view)", "url": f"https://web.archive.org/web/20240000000000*/{domain}"},
        {"title": "Wayback Machine (changes)", "url": f"https://web.archive.org/web/diff/20230101000000/{domain}"},
    ]

    return result
