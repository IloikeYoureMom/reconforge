"""
GitHub Dorking Module
═════════════════════
Searches GitHub for sensitive data like API keys, tokens,
passwords, and configuration files related to a target.

Uses the free GitHub Search API. A GitHub Personal Access
Token can be provided via the GITHUB_TOKEN env var for
higher rate limits (10 req/min with token).
"""

import os
import json
from urllib.request import Request, urlopen
from urllib.parse import quote_plus, quote
from urllib.error import HTTPError, URLError

from ..utils.http import fetch_json


# Sensitive data dork queries organized by category
DORK_CATEGORIES = {
    "API Keys & Tokens": [
        ("api_key", '"{domain}" api_key'),
        ("api_secret", '"{domain}" api_secret'),
        ("api_token", '"{domain}" api_token'),
        ("access_token", '"{domain}" access_token'),
        ("secret_key", '"{domain}" secret_key'),
        ("private_key", '"{domain}" -----BEGIN'),
        ("auth_token", '"{domain}" auth_token'),
        ("slack_token", '"{domain}" xoxb- OR xoxp-'),
        ("aws_key", '"{domain}" AKIA[0-9A-Z]{16}'),
    ],
    "Passwords & Credentials": [
        ("password", '"{domain}" password='),
        ("passwd", '"{domain}" passwd'),
        ("db_password", '"{domain}" db_password'),
        ("db_pass", '"{domain}" db_pass'),
        ("pwd", '"{domain}" pwd='),
        ("connection_string", '"{domain}" connectionString'),
        ("jdbc_string", '"{domain}" jdbc:'),
    ],
    "Configuration Files": [
        (".env", '"{domain}" .env filename:.env'),
        (".env.example", '"{domain}" filename:.env.example'),
        ("config.json", '"{domain}" filename:config.json'),
        ("database.yml", '"{domain}" filename:database.yml'),
        ("settings.py", '"{domain}" filename:settings.py'),
        ("credentials", '"{domain}" filename:credentials'),
        ("config.php", '"{domain}" filename:config.php'),
        ("wp-config", '"{domain}" filename:wp-config.php'),
        ("htaccess", '"{domain}" filename:.htaccess'),
    ],
    "Sensitive Files": [
        ("dump.sql", '"{domain}" filename:dump.sql'),
        ("backup.sql", '"{domain}" filename:backup.sql'),
        (".bash_history", '"{domain}" filename:.bash_history'),
        (".gitconfig", '"{domain}" filename:.gitconfig'),
        (".npmrc", '"{domain}" filename:.npmrc'),
        ("id_rsa", '"{domain}" filename:id_rsa'),
        ("kubeconfig", '"{domain}" filename:kubeconfig'),
        (".dockercfg", '"{domain}" filename:.dockercfg'),
        ("service_account", '"{domain}" filename:service-account'),
    ],
}

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")


def _search_github(query: str, max_results: int = 5) -> list:
    """Search GitHub code using the REST API."""
    if not GITHUB_TOKEN:
        return []

    url = f"https://api.github.com/search/code?q={quote(query)}&per_page={max_results}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ReconForge/1.0",
        "Authorization": f"token {GITHUB_TOKEN}",
    }

    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            items = data.get("items", [])
            results = []
            for item in items[:max_results]:
                repo = item.get("repository", {}).get("full_name", "unknown")
                path = item.get("path", "unknown")
                html_url = item.get("html_url", "")
                results.append({
                    "repo": repo,
                    "path": path,
                    "url": html_url,
                })
            return results
    except HTTPError as e:
        if e.code == 403:
            return [{"error": "Rate limited", "url": None}]
        return []
    except (URLError, OSError, json.JSONDecodeError):
        return []


def recon(target: str) -> dict:
    """Search GitHub for sensitive data related to the target."""
    target = target.strip().lower()

    # Clean target for search
    search_target = target.replace("http://", "").replace("https://", "").split("/")[0]

    result = {
        "target": target,
        "type": "GitHub Dorking",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    result["findings"].append(f" Target: {search_target}")
    result["data"]["search_target"] = search_target

    has_token = bool(GITHUB_TOKEN)
    if has_token:
        result["findings"].append(f" GitHub API token loaded ({GITHUB_TOKEN[:4]}...)")
        result["data"]["authenticated"] = True
    else:
        result["warnings"].append("  No GITHUB_TOKEN set — generating search URLs only")
        result["warnings"].append("   Set GITHUB_TOKEN env var for live search results")
        result["data"]["authenticated"] = False

    # Run automated dork searches
    total_results = 0
    dork_categories_results = []

    if has_token:
        result["findings"].append("\n Running automated GitHub dork searches...")
        for category, dorks in DORK_CATEGORIES.items():
            cat_results = []
            for name, query_template in dorks:
                query = query_template.replace("{domain}", search_target)
                items = _search_github(query)
                if items and not items[0].get("error"):
                    if items:
                        cat_results.append({
                            "dork": name,
                            "query": query,
                            "results": items,
                        })
                        total_results += len(items)

            if cat_results:
                dork_categories_results.append({
                    "category": category,
                    "dorks": cat_results,
                })

        if total_results > 0:
            result["data"]["dork_results"] = dork_categories_results
            result["data"]["total_findings"] = total_results
            result["findings"].append(f" Found {total_results} potential matches in GitHub code")
        else:
            result["findings"].append(" No sensitive data found in GitHub search results")
    else:
        result["data"]["dork_categories"] = list(DORK_CATEGORIES.keys())

    # Generate search URLs for manual inspection
    result["findings"].append("\n GitHub Dork Queries (click to search):")
    github_search_urls = []
    for category, dorks in DORK_CATEGORIES.items():
        result["findings"].append(f"\n    {category}:")
        for name, query_template in dorks[:5]:
            query = query_template.replace("{domain}", search_target)
            encoded = quote_plus(query)
            url = f"https://github.com/search?q={encoded}&type=code"
            github_search_urls.append({"title": f"[{category}] {name}", "url": url})
            result["findings"].append(f"       {name}: {url}")

    result["data"]["github_search_urls"] = github_search_urls

    # Also add direct org/user search if it looks like a GitHub username
    if not "." in search_target or search_target.endswith(".github.io"):
        result["data"]["lookup_links"] = [
            {"title": f"GitHub: Search repos for '{search_target}'", "url": f"https://github.com/search?q={search_target}&type=repositories"},
            {"title": f"GitHub: Search code for '{search_target}'", "url": f"https://github.com/search?q={search_target}&type=code"},
        ]
    else:
        result["data"]["lookup_links"] = [
            {"title": f"GitHub: Search code for domain", "url": f"https://github.com/search?q=%22{search_target}%22&type=code"},
            {"title": f"GitHub: Search repos for domain", "url": f"https://github.com/search?q=%22{search_target}%22&type=repositories"},
        ]

    # Summary
    if has_token and total_results > 0:
        severity = " Medium" if total_results < 5 else " High"
        result["findings"].append(f"\n Severity: {severity} — {total_results} potential exposures found")
        result["data"]["severity"] = severity

    return result
