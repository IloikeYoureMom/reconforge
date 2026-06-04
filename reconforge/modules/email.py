"""
Email Reconnaissance Module
═══════════════════════════
Analyzes email addresses: format validation, provider detection,
breach checking, and pattern analysis.
"""

import re
import hashlib

from ..utils.http import fetch_text
from ..utils.dns import resolve_hostname, check_mx_records


COMMON_PROVIDERS = {
    "gmail.com": "Google Gmail",
    "yahoo.com": "Yahoo Mail",
    "yahoo.co.il": "Yahoo Mail Israel",
    "hotmail.com": "Microsoft Hotmail",
    "outlook.com": "Microsoft Outlook",
    "live.com": "Microsoft Live",
    "protonmail.com": "ProtonMail",
    "proton.me": "ProtonMail",
    "pm.me": "ProtonMail",
    "icloud.com": "Apple iCloud",
    "aol.com": "AOL Mail",
    "zoho.com": "Zoho Mail",
    "mail.com": "Mail.com",
    "gmx.com": "GMX Mail",
    "yandex.com": "Yandex Mail",
    "fastmail.com": "Fastmail",
    "tutanota.com": "Tutanota",
    "tuta.io": "Tutanota",
    "disroot.org": "Disroot",
    "riseup.net": "Riseup",
    "cock.li": "Cock.li",
    "walla.co.il": "Walla! Mail",
    "013.net": "013 Netvision",
    "netvision.net.il": "Netvision",
    "bezeqint.net": "Bezeq International",
    "smile.net.il": "012 Smile",
    "zahav.net.il": "Zahav",
    "actcom.net.il": "Actcom",
    "barak.net.il": "Barak",
    "edu.il": "Israeli Academic (.edu.il)",
}


def _sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest().upper()


def _check_hibp(email: str) -> dict:
    """Check HaveIBeenPwned API for breach status."""
    sha1 = _sha1_hex(email)
    prefix = sha1[:5]
    suffix = sha1[5:]

    resp = fetch_text(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
    if resp:
        lines = resp.splitlines()
        for line in lines:
            line_suffix, count = line.split(":")
            if line_suffix.strip().upper() == suffix:
                return {
                    "breached": True,
                    "count": int(count.strip()),
                }
        return {"breached": False, "count": 0}
    return {"breached": None, "count": 0}


def _detect_pattern(email: str) -> str:
    """Detect email naming pattern."""
    local = email.split("@")[0]
    patterns = [
        (r"^[a-z]+\.[a-z]+$", "firstname.lastname"),
        (r"^[a-z]+\.[a-z]+\.[a-z]+$", "first.middle.last"),
        (r"^[a-z]+\_[a-z]+$", "first_last"),
        (r"^[a-z]+\-[a-z]+$", "first-last"),
        (r"^[a-z]+\d+$", "name+number"),
        (r"^\d+[a-z]+$", "number+name"),
        (r"^[a-z]{1}\.[a-z]+$", "initial.lastname"),
        (r"^[a-z]+[\.\_\-]?\d{4,}$", "name+year"),
        (r"^info$", "generic (info)"),
        (r"^admin$", "generic (admin)"),
        (r"^contact$", "generic (contact)"),
        (r"^support$", "generic (support)"),
        (r"^sales$", "generic (sales)"),
        (r"^noreply$", "generic (no-reply)"),
    ]
    for pattern, desc in patterns:
        if re.match(pattern, local, re.IGNORECASE):
            return desc

    if len(local) <= 3:
        return "short/abbreviated"
    return "custom"


def recon(email: str) -> dict:
    """Run full email reconnaissance."""
    email = email.strip().lower()

    result = {
        "target": email,
        "type": "Email",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    # 1. Format validation
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        result["warnings"].append(" Invalid email format")
        return result

    result["findings"].append(" Valid email format")
    result["data"]["format_valid"] = True

    # 2. Extract components
    local, domain = email.split("@")
    result["data"]["local_part"] = local
    result["data"]["domain"] = domain
    result["findings"].append(f" Local part: {local}")
    result["findings"].append(f" Domain: {domain}")

    # 3. Provider detection
    provider = COMMON_PROVIDERS.get(domain)
    if provider:
        result["data"]["provider"] = provider
        result["findings"].append(f" Provider: {provider}")
    else:
        # Check for subdomain providers
        base_domain = ".".join(domain.split(".")[-2:])
        provider = COMMON_PROVIDERS.get(base_domain)
        if provider:
            result["data"]["provider"] = provider
            result["findings"].append(f" Provider: {provider} ({domain})")
        else:
            result["data"]["provider"] = "Custom domain"
            result["findings"].append(f" Provider: Custom / Self-hosted")

    # 4. Country TLD detection
    if domain.endswith(".il"):
        result["findings"].append(" Israeli domain (.il)")
        result["data"]["country"] = "Israel"

    # 5. Pattern analysis
    pattern_desc = _detect_pattern(email)
    result["data"]["pattern"] = pattern_desc
    result["findings"].append(f" Pattern: {pattern_desc}")

    # 6. MX record check
    mx = check_mx_records(domain)
    if mx:
        result["data"]["mx_records"] = mx
        result["findings"].append(f" MX Records found ({len(mx)}):")
        for m in mx[:2]:
            result["findings"].append(f"   → {m['exchange']} (priority {m['priority']})")
    else:
        result["warnings"].append("  No MX records - domain may not receive email")

    # 7. HaveIBeenPwned check
    breach = _check_hibp(email)
    if breach["breached"]:
        result["data"]["breached"] = True
        result["data"]["breach_count"] = breach["count"]
        result["findings"].append(f" Breached! Found in {breach['count']} data breach(es)")
    elif breach["breached"] is False:
        result["findings"].append(" Not found in known data breaches")
    else:
        result["warnings"].append("  Could not check HaveIBeenPwned")

    # 8. OSINT Lookup Links
    result["data"]["lookup_links"] = [
        {"title": "Google Search", "url": f"https://www.google.com/search?q={email}"},
        {"title": "HaveIBeenPwned", "url": f"https://haveibeenpwned.com/account/{email}"},
        {"title": "EmailRep.io", "url": f"https://emailrep.io/{email}"},
        {"title": "Hunter.io", "url": f"https://hunter.io/email-verifier/{email}"},
    ]

    return result
