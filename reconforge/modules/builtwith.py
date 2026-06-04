"""
BuiltWith Technology Profiling Module
══════════════════════════════════════
Queries BuiltWith API to discover the technology stack
used by a domain: frameworks, CMS, analytics, CDN,
web servers, JavaScript libraries, and more.

Free API key (BUILTWITH_API_KEY env var) for live lookups.
Without a key, generates BuiltWith profile URLs for manual inspection.
"""

import os
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

BUILTWITH_API_KEY = os.environ.get("BUILTWITH_API_KEY", "")

# Technology category icons/emojis for display
TECH_CATEGORIES = {
    "Analytics": "",
    "AnalyticsAndTracking": "",
    "Advertising": "",
    "Widgets": "",
    "JavaScriptLibraries": "",
    "JavaScript": "",
    "Fonts": "",
    "Frameworks": "",
    "WebFrameworks": "",
    "CMS": "",
    "ContentManagementSystem": "",
    "CDN": "",
    "ContentDeliveryNetwork": "",
    "WebServers": "",
    "Server": "",
    "Email": "",
    "EmailHosting": "",
    "Hosting": "",
    "Cloud": "",
    "Database": "",
    "SSL": "",
    "Security": "",
    "Payment": "",
    "Ecommerce": "",
    "Mobile": "",
    "Social": "",
    "Widget": "",
    "Maps": "",
    "Video": "",
    "Audio": "",
    "Cache": "",
    "RSS": "",
    "Feed": "",
    "Marketing": "",
    "Optimization": "",
}


def _fetch_builtwith(domain: str) -> dict:
    """Fetch technology profile from BuiltWith free API."""
    if not BUILTWITH_API_KEY:
        return {}

    url = (
        f"https://api.builtwith.com/free1/api.json"
        f"?KEY={BUILTWITH_API_KEY}"
        f"&LOOKUP={domain}"
    )
    try:
        req = Request(url, headers={"User-Agent": "ReconForge/1.0"})
        with urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, json.JSONDecodeError):
        return {}


def recon(target: str) -> dict:
    """Profile the technology stack of a domain."""
    target = target.strip().lower()
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    domain = domain.replace("www.", "", 1) if domain.startswith("www.") else domain

    result = {
        "target": target,
        "type": "BuiltWith Profile",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    result["findings"].append(f" Target: {domain}")
    result["data"]["domain"] = domain

    has_key = bool(BUILTWITH_API_KEY)
    if has_key:
        result["findings"].append(f" BUILTWITH_API_KEY loaded ({BUILTWITH_API_KEY[:4]}...)")
        result["data"]["authenticated"] = True
    else:
        result["warnings"].append("  No BUILTWITH_API_KEY set — generating profile URL only")
        result["warnings"].append("   Set BUILTWITH_API_KEY env var for live tech data")
        result["data"]["authenticated"] = False

    if has_key:
        result["findings"].append("\n Querying BuiltWith for technology profile...")
        data = _fetch_builtwith(domain)

        if data and "Results" in data:
            results = data["Results"]
            if results:
                technologies = results[0].get("Result", {}).get("Paths", {})
                if not technologies:
                    technologies = results[0].get("Result", {})

                total_techs = 0
                category_counts = {}

                for category, techs in technologies.items():
                    if isinstance(techs, list):
                        total_techs += len(techs)
                        category_counts[category] = len(techs)
                    elif isinstance(techs, dict):
                        total_techs += 1
                        category_counts[category] = 1

                result["data"]["total_technologies"] = total_techs
                result["data"]["category_counts"] = category_counts
                result["findings"].append(f" Found {total_techs} technologies in {len(category_counts)} categories")

                # Show each category
                for category, techs in sorted(technologies.items()):
                    if not isinstance(techs, list):
                        techs = [techs]

                    icon = TECH_CATEGORIES.get(category, "")
                    nice_name = category.replace("_", " ").replace("And", " & ").replace("API", "API")

                    # Extract technology names
                    tech_names = []
                    for t in techs[:8]:
                        if isinstance(t, dict):
                            name = t.get("Name", "") or t.get("name", "")
                            desc = t.get("Description", "") or ""
                            if name:
                                tech_names.append(name)
                        elif isinstance(t, str):
                            tech_names.append(t)

                    if tech_names:
                        result["findings"].append(f"\n   {icon} {nice_name} ({len(tech_names)}):")
                        for name in tech_names[:5]:
                            result["findings"].append(f"      • {name}")
                        if len(tech_names) > 5:
                            result["findings"].append(f"      ...and {len(tech_names) - 5} more")

                    # Store full data
                    result["data"][f"tech_{category.lower()}"] = tech_names

    # Generate BuiltWith profile URL
    profile_url = f"https://builtwith.com/{domain}"
    result["findings"].append(f"\n BuiltWith Profile: {profile_url}")
    result["findings"].append(f"   Open this URL in your browser for the full technology breakdown")

    if not has_key:
        result["findings"].append(f"\n To get live data, set BUILTWITH_API_KEY and re-run")
        result["findings"].append(f"   Get a free key at: https://builtwith.com/")

    result["data"]["lookup_links"] = [
        {"title": "BuiltWith Profile", "url": profile_url},
        {"title": "BuiltWith Technology Lookup", "url": f"https://builtwith.com/?lookup={domain}"},
        {"title": "Wappalyzer (alternative)", "url": f"https://www.wappalyzer.com/lookup/{domain}"},
    ]

    return result
