"""
Username Reconnaissance Module
══════════════════════════════
Searches for usernames across social media platforms
and analyzes patterns to identify real names.
"""

import re
from ..utils.http import check_url_status


SOCIAL_PLATFORMS = [
    {"name": "Instagram",  "url": "https://www.instagram.com/{u}/"},
    {"name": "Twitter / X", "url": "https://twitter.com/{u}"},
    {"name": "TikTok",     "url": "https://www.tiktok.com/@{u}"},
    {"name": "Facebook",   "url": "https://www.facebook.com/{u}"},
    {"name": "LinkedIn",   "url": "https://www.linkedin.com/in/{u}/"},
    {"name": "GitHub",     "url": "https://github.com/{u}"},
    {"name": "Reddit",     "url": "https://www.reddit.com/user/{u}"},
    {"name": "YouTube",    "url": "https://www.youtube.com/@{u}"},
    {"name": "Snapchat",   "url": "https://www.snapchat.com/add/{u}"},
    {"name": "Telegram",   "url": "https://t.me/{u}"},
    {"name": "Pinterest",  "url": "https://www.pinterest.com/{u}/"},
    {"name": "Twitch",     "url": "https://www.twitch.tv/{u}"},
    {"name": "Medium",     "url": "https://medium.com/@{u}"},
    {"name": "Steam",      "url": "https://steamcommunity.com/id/{u}"},
    {"name": "Behance",    "url": "https://www.behance.net/{u}"},
    {"name": "Dribbble",   "url": "https://dribbble.com/{u}"},
    {"name": "Flickr",     "url": "https://www.flickr.com/people/{u}/"},
    {"name": "Keybase",    "url": "https://keybase.io/{u}"},
    {"name": "Mastodon",   "url": "https://mastodon.social/@{u}"},
    {"name": "Bluesky",    "url": "https://bsky.app/profile/{u}"},
    {"name": "Threads",    "url": "https://www.threads.net/@{u}"},
    {"name": "VK",         "url": "https://vk.com/{u}"},
    {"name": "Patreon",    "url": "https://www.patreon.com/{u}"},
    {"name": "OnlyFans",   "url": "https://onlyfans.com/{u}"},
    {"name": "Fiverr",     "url": "https://www.fiverr.com/{u}"},
    {"name": "Upwork",     "url": "https://www.upwork.com/freelancers/{u}"},
    {"name": "Keybase",    "url": "https://keybase.io/{u}"},
    {"name": "dev.to",     "url": "https://dev.to/{u}"},
    {"name": "AngelList",  "url": "https://angel.co/u/{u}"},
    {"name": "ProductHunt","url": "https://www.producthunt.com/@{u}"},
    {"name": "Hashnode",   "url": "https://hashnode.com/@{u}"},
    {"name": "Codepen",    "url": "https://codepen.io/{u}"},
    {"name": "Replit",     "url": "https://replit.com/@{u}"},
    {"name": "BitBucket",  "url": "https://bitbucket.org/{u}/"},
    {"name": "GitLab",     "url": "https://gitlab.com/{u}"},
    {"name": "HackerOne",  "url": "https://hackerone.com/{u}"},
    {"name": "Bugcrowd",   "url": "https://bugcrowd.com/{u}"},
    {"name": "TryHackMe",  "url": "https://tryhackme.com/p/{u}"},
    {"name": "HackTheBox", "url": "https://app.hackthebox.com/profile/{u}"},
]


NAME_PATTERNS = [
    (r"^[A-Z][a-z]+[\.\_\s\-][A-Z][a-z]+$", "firstname.lastname"),
    (r"^[A-Z][a-z]+[\.\_\s\-][A-Z][a-z]+[\.\_\s\-][A-Z][a-z]+$", "first.middle.last"),
    (r"^[a-z]+\.[a-z]+\d*$", "name+number variant"),
]

BREACH_LOOKUP_LINKS = [
    {"title": "Check on IntelX", "url": "https://intelx.io/?s={u}"},
    {"title": "Check on DeHashed", "url": "https://dehashed.com/search?q={u}"},
    {"title": "Google Search", "url": "https://www.google.com/search?q={u}"},
]


def _analyze_username_pattern(username: str) -> list[dict]:
    """Analyze the username pattern for intelligence."""
    insights = []

    # Length analysis
    length = len(username)
    if length <= 3:
        insights.append({"label": "Length", "value": f"Very short ({length} chars) - likely recycled"})
    elif length <= 6:
        insights.append({"label": "Length", "value": f"Short ({length} chars)"})
    elif length <= 12:
        insights.append({"label": "Length", "value": f"Medium ({length} chars)"})
    else:
        insights.append({"label": "Length", "value": f"Long ({length} chars) - likely unique"})

    # Character composition
    has_lower = bool(re.search(r"[a-z]", username))
    has_upper = bool(re.search(r"[A-Z]", username))
    has_digit = bool(re.search(r"\d", username))
    has_special = bool(re.search(r"[\.\_\-\@\!\#\$\%\^\&\*]", username))

    char_types = []
    if has_lower: char_types.append("lowercase")
    if has_upper: char_types.append("UPPERCASE")
    if has_digit: char_types.append("digits")
    if has_special: char_types.append("special")
    insights.append({"label": "Characters", "value": ", ".join(char_types)})

    # Name pattern detection
    for pattern, desc in NAME_PATTERNS:
        if re.match(pattern, username):
            insights.append({"label": "  Name Pattern", "value": f"Looks like: {desc}"})

    return insights


def recon(username: str) -> dict:
    """Run full username reconnaissance."""
    username = username.strip()

    result = {
        "target": username,
        "type": "Username",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    # 1. Basic analysis
    result["data"]["username"] = username
    result["findings"].append(f" Target: @{username}")

    patterns = _analyze_username_pattern(username)
    result["data"]["patterns"] = patterns
    for p in patterns:
        result["findings"].append(f" {p['label']}: {p['value']}")

    # 2. Platform check (threaded)
    from concurrent.futures import ThreadPoolExecutor, as_completed
    result["findings"].append(f"\n Checking {len(SOCIAL_PLATFORMS)} platforms...")
    found_platforms = []

    def _check_platform(platform):
        url = platform["url"].replace("{u}", username)
        status = check_url_status(url, timeout=3)
        if status and status != 404:
            return {"name": platform["name"], "url": url, "status": status}
        return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(_check_platform, p): p for p in SOCIAL_PLATFORMS}
        for future in as_completed(futures, timeout=60):
            try:
                result_p = future.result()
                if result_p:
                    found_platforms.append(result_p)
            except Exception:
                pass

    if found_platforms:
        result["data"]["platforms_found"] = found_platforms
        result["findings"].append(f"\n Found on {len(found_platforms)} platform(s):")
        for p in found_platforms[:10]:
            result["findings"].append(f"    {p['name']}: {p['url']}")
        if len(found_platforms) > 10:
            result["findings"].append(f"   ...and {len(found_platforms) - 10} more")
    else:
        result["findings"].append("\n Not found on checked platforms")
        result["warnings"].append("  Could not verify against all platforms")

    # 3. OSINT lookup links
    result["data"]["lookup_links"] = []
    for link in BREACH_LOOKUP_LINKS:
        url = link["url"].replace("{u}", username)
        result["data"]["lookup_links"].append({"title": link["title"], "url": url})

    return result
