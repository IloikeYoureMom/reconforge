"""
urlscan.io Module
══════════════════
Queries urlscan.io for domain screenshots, page history,
and scan results. Shows recent scans, page screenshots,
DOM snapshots, and connected domains.

Free API key (URLSCAN_API_KEY env var) required for live lookups.
Without a key, generates search URLs for manual inspection.
"""

import os
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")


def _search_urlscan(domain: str, max_results: int = 10) -> list:
    """Search urlscan.io for recent scans of a domain."""
    if not URLSCAN_API_KEY:
        return []

    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size={max_results}"
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "User-Agent": "ReconForge/1.0",
    }

    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results = data.get("results", [])
            scans = []
            for item in results[:max_results]:
                scan = item.get("page", {})
                screenshot = item.get("screenshot", "")
                task = item.get("task", {})
                stats = item.get("stats", {})
                scans.append({
                    "url": scan.get("url", ""),
                    "domain": scan.get("domain", ""),
                    "ip": scan.get("ip", ""),
                    "country": scan.get("country", ""),
                    "server": scan.get("server", ""),
                    "status": task.get("status", ""),
                    "time": task.get("time", ""),
                    "uuid": task.get("uuid", ""),
                    "screenshot_url": f"https://urlscan.io{screenshot}" if screenshot else "",
                    "result_url": f"https://urlscan.io/result/{task.get('uuid', '')}/",
                    "page_count": stats.get("resourceStats", 0),
                    "requests": stats.get("requests", 0),
                })
            return scans
    except (HTTPError, URLError, OSError, json.JSONDecodeError):
        return []


def recon(target: str) -> dict:
    """Query urlscan.io for domain screenshots and scan history."""
    target = target.strip().lower()
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    domain = domain.replace("www.", "", 1) if domain.startswith("www.") else domain

    result = {
        "target": target,
        "type": "urlscan.io",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    result["findings"].append(f" Target: {domain}")
    result["data"]["domain"] = domain

    has_key = bool(URLSCAN_API_KEY)
    if has_key:
        result["findings"].append(f" URLSCAN_API_KEY loaded ({URLSCAN_API_KEY[:4]}...)")
        result["data"]["authenticated"] = True
    else:
        result["warnings"].append("  No URLSCAN_API_KEY set — generating search URLs only")
        result["warnings"].append("   Set URLSCAN_API_KEY env var for live scan results")
        result["data"]["authenticated"] = False

    # Search for scans if API key is available
    if has_key:
        result["findings"].append("\n Searching urlscan.io for recent scans...")
        scans = _search_urlscan(domain)

        if scans:
            result["data"]["scans_found"] = scans
            result["data"]["scan_count"] = len(scans)
            result["findings"].append(f" Found {len(scans)} recent scan(s):")

            for i, scan in enumerate(scans[:5], 1):
                url = scan.get("url", "?")
                ip = scan.get("ip", "?")
                server = scan.get("server", "?")
                country = scan.get("country", "?")
                time_str = scan.get("time", "?")[:10] if scan.get("time") else "?"
                result["findings"].append(f"\n    Scan {i}: {url}")
                result["findings"].append(f"       IP: {ip}")
                result["findings"].append(f"       Server: {server}" if server else "")
                result["findings"].append(f"       Country: {country}" if country else "")
                result["findings"].append(f"       Time: {time_str}")
                if scan.get("screenshot_url"):
                    result["findings"].append(f"       Screenshot: {scan['screenshot_url']}")
                if scan.get("result_url"):
                    result["findings"].append(f"       Details: {scan['result_url']}")

            # Unique IPs and countries
            unique_ips = set(s["ip"] for s in scans if s.get("ip"))
            unique_countries = set(s["country"] for s in scans if s.get("country"))
            unique_servers = set(s["server"] for s in scans if s.get("server"))

            if unique_ips:
                result["data"]["unique_ips"] = sorted(unique_ips)
                result["findings"].append(f"\n IPs seen ({len(unique_ips)}): {', '.join(sorted(unique_ips)[:5])}")
            if unique_countries:
                result["data"]["countries"] = sorted(unique_countries)
                result["findings"].append(f" Countries: {', '.join(sorted(unique_countries)[:5])}")
            if unique_servers:
                result["data"]["servers"] = sorted(unique_servers)
                result["findings"].append(f" Servers: {', '.join(sorted(unique_servers)[:5])}")

            # Screenshot URLs
            screenshot_urls = [s["screenshot_url"] for s in scans if s.get("screenshot_url")]
            if screenshot_urls:
                result["data"]["screenshot_urls"] = screenshot_urls
        else:
            result["findings"].append(" No scans found for this domain")

    # Generate search URLs
    result["findings"].append("\n urlscan.io Links:")
    result["data"]["lookup_links"] = [
        {"title": "urlscan.io search", "url": f"https://urlscan.io/search/#domain:{domain}"},
        {"title": "urlscan.io live scan", "url": f"https://urlscan.io/?q={domain}"},
    ]

    for link in result["data"]["lookup_links"]:
        result["findings"].append(f"    {link['title']}: {link['url']}")

    return result
