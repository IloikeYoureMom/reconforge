"""
Google Dorking Module
═════════════════════
Generates categorized Google dork queries to discover
sensitive information, vulnerable endpoints, and hidden
content for a target domain.

Since Google blocks automated search queries, this module
generates clickable search URLs for manual investigation.
"""

import re
from urllib.parse import quote_plus


# Google dork queries organized by category
DORK_CATEGORIES = {
    "Admin Panels & Login Pages": [
        ("Admin login", "site:{domain} inurl:admin"),
        ("Admin panel", "site:{domain} inurl:adminlogin OR inurl:admin-login"),
        ("Dashboard", "site:{domain} intitle:dashboard"),
        ("cPanel", "site:{domain} intitle:cpanel"),
        ("phpMyAdmin", "site:{domain} intitle:phpMyAdmin"),
        ("Login page", "site:{domain} inurl:login OR inurl:signin"),
        ("Portal", "site:{domain} inurl:portal"),
        ("wp-admin", "site:{domain} inurl:wp-admin"),
    ],
    "Configuration & Sensitive Files": [
        (".env file", "site:{domain} ext:env"),
        ("SQL dump", "site:{domain} ext:sql"),
        ("Configuration", "site:{domain} ext:cfg OR ext:conf"),
        ("Backup files", "site:{domain} ext:bak OR ext:backup OR ext:old"),
        (".htaccess", "site:{domain} filetype:htaccess"),
        ("Git exposed", "site:{domain} intitle:\"index of\" .git"),
        ("DS_Store", "site:{domain} filetype:DS_Store"),
        ("YAML config", "site:{domain} ext:yml OR ext:yaml"),
    ],
    "Database Files": [
        ("MySQL dump", "site:{domain} ext:sql \"INSERT INTO\""),
        ("CSV data", "site:{domain} ext:csv \"email\" OR \"password\""),
        ("JSON data", "site:{domain} ext:json \"password\" OR \"token\""),
        ("MongoDB backup", "site:{domain} ext:bson"),
        ("SQLite DB", "site:{domain} ext:db OR ext:sqlite OR ext:sqlite3"),
    ],
    "Exposed Documents": [
        ("PDF documents", "site:{domain} ext:pdf"),
        ("Word documents", "site:{domain} ext:doc OR ext:docx"),
        ("Excel spreadsheets", "site:{domain} ext:xls OR ext:xlsx"),
        ("PowerPoint", "site:{domain} ext:ppt OR ext:pptx"),
        ("Text files", "site:{domain} ext:txt \"password\" OR \"confidential\""),
        ("XML sitemap", "site:{domain} filetype:xml inurl:sitemap"),
    ],
    "Error Messages & Debug": [
        ("PHP errors", "site:{domain} \"PHP Fatal error\" OR \"Warning: mysql_connect\""),
        ("Stack traces", "site:{domain} \"at\" \"stack trace\" OR \"Stack Trace\""),
        ("Debug info", "site:{domain} intitle:\"debug\" OR \"debug=true\""),
        ("Directory listing", "site:{domain} intitle:\"index of\" +\"parent directory\""),
        ("Server status", "site:{domain} intitle:\"server status\" OR intitle:\"Apache Status\""),
    ],
    "Security & Vulnerability": [
        ("Open ports/directories", "site:{domain} intitle:\"index of\" -inurl:(htm|html|php|asp)"),
        ("Test environments", "site:{domain} inurl:test OR inurl:staging OR inurl:dev"),
        ("API endpoints", "site:{domain} inurl:api OR inurl:rest OR inurl:graphql"),
        ("Upload endpoints", "site:{domain} inurl:upload OR inurl:file-upload"),
        ("URL parameters", "site:{domain} inurl:\"id=\" OR inurl:\"page=\" OR inurl:\"file=\""),
        ("Webcam streams", "site:{domain} inurl:\"view.shtml\" OR inurl:\"mjpg\""),
        ("phpinfo", "site:{domain} intitle:\"phpinfo\" \"PHP Version\""),
    ],
    "Employee & Email Info": [
        ("Email addresses", "site:{domain} \"@\" \"email\" OR \"mail\""),
        ("Employee directory", "site:{domain} intitle:\"employee directory\""),
        ("Staff pages", "site:{domain} intitle:\"staff\" OR intitle:\"team\" OR intitle:\"about us\""),
        ("Resumes/CVs", "site:{domain} intitle:resume OR intitle:cv filetype:pdf"),
    ],
}


def recon(target: str) -> dict:
    """Generate Google dork queries for a target domain."""
    target = target.strip().lower()

    # Extract clean domain
    domain = re.sub(r"https?://", "", target)
    domain = domain.split("/")[0]
    domain = re.sub(r"^www\.", "", domain)

    result = {
        "target": target,
        "type": "Google Dorking",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    result["findings"].append(f" Target: {domain}")
    result["data"]["domain"] = domain

    # Warning about automated blocking
    result["warnings"].append("  Google blocks automated search queries")
    result["warnings"].append("   Dork URLs are generated for manual browser use")
    result["warnings"].append("   Open them in your browser to check results")

    # Count total dorks
    total_dorks = sum(len(dorks) for dorks in DORK_CATEGORIES.values())
    result["data"]["total_dorks"] = total_dorks
    result["findings"].append(f" Generated {total_dorks} dork queries across {len(DORK_CATEGORIES)} categories")
    result["findings"].append(f"   Open the URLs below in your browser to discover hidden content")

    # Generate dork queries per category
    all_dork_links = []
    for category, dorks in DORK_CATEGORIES.items():
        cat_dorks = []

        result["findings"].append(f"\n {category}:")
        for name, query_template in dorks:
            query = query_template.replace("{domain}", domain)
            encoded_query = quote_plus(query)
            url = f"https://www.google.com/search?q={encoded_query}"
            cat_dorks.append({"name": name, "query": query, "url": url})
            all_dork_links.append({"title": f"[{category}] {name}", "url": url})
            result["findings"].append(f"    {name}: {url}")

        result["data"][f"dorks_{category.lower().replace(' ', '_').replace('&', 'and')}"] = cat_dorks

    result["data"]["all_dork_links"] = all_dork_links
    result["data"]["lookup_links"] = [
        {"title": f"site:{domain} (all indexed pages)", "url": f"https://www.google.com/search?q={quote_plus(f'site:{domain}')}"},
        {"title": f"site:{domain} (filetypes)", "url": f"https://www.google.com/search?q={quote_plus(f'site:{domain}')}+ext:pdf+OR+ext:doc+OR+ext:xls"},
        {"title": f"site:{domain} (admin panels)", "url": f"https://www.google.com/search?q={quote_plus(f'site:{domain} inurl:admin OR inurl:login')}"},
        {"title": f"site:{domain} (sensitive files)", "url": f"https://www.google.com/search?q={quote_plus(f'site:{domain} ext:env OR ext:sql OR ext:bak')}"},
    ]

    # TLD info
    tld = domain.split(".")[-1]
    result["data"]["tld"] = tld
    if tld == "il":
        result["findings"].append("\n .il domain — consider Israeli-specific dorks")

    return result
