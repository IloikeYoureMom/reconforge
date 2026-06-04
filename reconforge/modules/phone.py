"""
Phone Number Reconnaissance Module
═══════════════════════════════════
Analyzes phone numbers: carrier detection, country identification,
format validation, and OSINT lookup links.
"""

import re


MOBILE_PREFIXES = {
    "IL": {
        "050": "Pelephone",
        "052": "Cellcom",
        "053": "HOT Mobile",
        "054": "Partner (Orange)",
        "055": "MVNO/MIRS",
        "056": "Wataniya/Golan",
        "058": "Golan Telecom",
        "059": "MIRS",
    },
    "US": {
        "201": "Verizon",
        "202": "Verizon",
        "212": "Verizon",
    },
}

LANDLINE_PREFIXES = {
    "IL": {
        "02": "Jerusalem",
        "03": "Tel Aviv",
        "04": "Haifa",
        "08": "Southern",
        "09": "Sharon",
    },
    "UK": {
        "020": "London",
        "0121": "Birmingham",
        "0161": "Manchester",
    },
}


def _clean_phone(phone: str) -> str:
    """Strip everything except digits and leading +."""
    return re.sub(r"[^\d+]", "", phone)


def _format_phone(cleaned: str) -> str:
    """Format phone number for display."""
    if cleaned.startswith("+972") and len(cleaned) == 13:
        return f"{cleaned[:4]}-{cleaned[4:7]}-{cleaned[7:]}"
    if cleaned.startswith("0") and len(cleaned) == 10:
        return f"{cleaned[:3]}-{cleaned[3:6]}-{cleaned[6:]}"
    if cleaned.startswith("0") and len(cleaned) == 9:
        return f"{cleaned[:2]}-{cleaned[2:5]}-{cleaned[5:]}"
    return cleaned


def recon(phone: str) -> dict:
    """Run full phone number reconnaissance."""
    phone = phone.strip()

    result = {
        "target": phone,
        "type": "Phone Number",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    result["findings"].append(f" Target: {phone}")

    # 1. Clean and format
    cleaned = _clean_phone(phone)
    if not cleaned:
        result["warnings"].append(" Invalid phone number")
        return result

    formatted = _format_phone(cleaned)
    result["data"]["formatted"] = formatted
    result["findings"].append(f" Formatted: {formatted}")

    # 2. Country detection
    country = None
    if cleaned.startswith("+972") or (cleaned.startswith("0") and len(cleaned) in (9, 10)):
        country = "IL"
        result["data"]["country"] = "Israel"
        result["findings"].append(" Country: Israel")
    elif cleaned.startswith("+1") or cleaned.startswith("1"):
        country = "US"
        result["data"]["country"] = "USA/Canada"
        result["findings"].append(" Country: USA/Canada")
    elif cleaned.startswith("+44") or cleaned.startswith("44"):
        country = "UK"
        result["data"]["country"] = "United Kingdom"
        result["findings"].append(" Country: United Kingdom")
    elif cleaned.startswith("+7"):
        country = "RU"
        result["data"]["country"] = "Russia"
        result["findings"].append(" Country: Russia")
    else:
        result["data"]["country"] = "Unknown"
        result["findings"].append(" Country: Unknown")

    # 3. Carrier detection (Israel)
    if country == "IL":
        prefix = cleaned[-9:-6] if cleaned.startswith("+972") else cleaned[1:4]
        if len(cleaned) == 9:  # 0XX-XXXXXX format
            prefix = cleaned[1:3]
            mobile = MOBILE_PREFIXES.get("IL", {}).get(prefix)
            landline = LANDLINE_PREFIXES.get("IL", {}).get(prefix)
            if mobile:
                result["data"]["type"] = "Mobile"
                result["data"]["carrier"] = mobile
                result["findings"].append(f" Type: Mobile ({mobile})")
            elif landline:
                result["data"]["type"] = "Landline"
                result["data"]["area"] = landline
                result["findings"].append(f" Type: Landline ({landline})")
            else:
                result["data"]["type"] = "Mobile"
                result["findings"].append(" Type: Mobile (unknown carrier)")
        elif len(cleaned) == 10:
            prefix = cleaned[1:4]
            mobile = MOBILE_PREFIXES.get("IL", {}).get(prefix)
            landline = LANDLINE_PREFIXES.get("IL", {}).get(prefix)
            if mobile:
                result["data"]["type"] = "Mobile"
                result["data"]["carrier"] = mobile
                result["findings"].append(f" Type: Mobile ({mobile})")
            elif landline:
                result["data"]["type"] = "Landline"
                result["data"]["area"] = landline
                result["findings"].append(f" Type: Landline ({landline})")
            else:
                result["data"]["type"] = "Unknown"
                result["findings"].append(" Type: Unknown prefix")

    # 4. OSINT lookup links
    result["data"]["lookup_links"] = [
        {"title": "Google Search", "url": f"https://www.google.com/search?q={cleaned}"},
        {"title": "TrueCaller (web)", "url": f"https://www.truecaller.com/search/il/{cleaned}"},
        {"title": "Numlookup", "url": f"https://www.numlookup.com/{cleaned}"},
        {"title": "SpyDialer", "url": f"https://spydialer.com/default.aspx?search={cleaned}"},
    ]

    return result
