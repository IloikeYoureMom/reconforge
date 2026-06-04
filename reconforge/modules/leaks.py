"""
Pastebin / Leak Search Module
══════════════════════════════
Searches for leaked data, pastes, and breach information
across multiple free sources:
  - psbdmp.ws (Pastebin dump search)
  - HaveIBeenPwned (breach check for emails)
  - OSINT lookup links for various leak databases
"""

import re
import hashlib
from typing import Optional

from ..utils.http import fetch_json, fetch_text


def _detect_target_type(target: str) -> str:
    """Detect whether target is an email, username, domain, or IP."""
    target = target.strip()
    if re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", target):
        return "email"
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        return "ip"
    if re.match(r"^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}$", target):
        return "domain"
    return "username"


def _search_psbdmp(query: str) -> list:
    """Search psbdmp.ws for pastes containing the query."""
    try:
        data = fetch_json(
            f"https://psbdmp.ws/api/v2/search/{query}",
            timeout=8
        )
        if data and isinstance(data, dict):
            entries = data.get("data", [])
            if isinstance(entries, list):
                results = []
                for entry in entries[:20]:
                    if isinstance(entry, dict):
                        results.append({
                            "id": entry.get("id", "?"),
                            "title": entry.get("title", entry.get("id", "Untitled")),
                            "date": entry.get("date", entry.get("time", "Unknown")),
                            "source": "Pastebin (psbdmp)",
                            "url": f"https://psbdmp.ws/dump/{entry.get('id', '')}",
                        })
                    elif isinstance(entry, str):
                        results.append({
                            "id": entry,
                            "title": f"Dump {entry[:20]}",
                            "date": "Unknown",
                            "source": "Pastebin (psbdmp)",
                            "url": f"https://psbdmp.ws/dump/{entry}",
                        })
                return results
    except Exception:
        pass
    return []


def _check_hibp(email: str) -> Optional[dict]:
    """Check HaveIBeenPwned for breach status."""
    try:
        sha1 = hashlib.sha1(email.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        resp = fetch_text(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5
        )

        if resp:
            for line in resp.splitlines():
                line_suffix, line_count = line.split(":")
                if line_suffix.strip().upper() == suffix:
                    return {"breached": True, "count": int(line_count.strip())}
            return {"breached": False, "count": 0}
    except Exception:
        pass
    return None


def recon(target: str) -> dict:
    """Search for leaks, pastes, and breach data related to the target."""
    target = target.strip()
    target_type = _detect_target_type(target)

    result = {
        "target": target,
        "type": "Leak Intelligence",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    result["findings"].append(f" Target: {target}")
    result["findings"].append(f" Detected type: {target_type}")
    result["data"]["target_type"] = target_type

    # ─── psbdmp.ws Search (Pastebin Dumps) ──────────────────────
    result["findings"].append("\n Searching paste dump databases...")
    pastes = _search_psbdmp(target)

    if pastes:
        result["data"]["pastes_found"] = pastes
        result["data"]["paste_count"] = len(pastes)
        result["findings"].append(f" Found {len(pastes)} paste(s) containing this target:")
        for paste in pastes[:8]:
            date = paste.get("date", "?")
            title = paste.get("title", "?")[:60]
            url = paste.get("url", "")
            result["findings"].append(f"    [{date}] {title}")
            result["findings"].append(f"       {url}")
        if len(pastes) > 8:
            result["findings"].append(f"   ...and {len(pastes) - 8} more pastes")
    else:
        result["findings"].append(" No pastes found in public dump databases")
        result["data"]["paste_count"] = 0

    # ─── HIBP Breach Check (for emails) ─────────────────────────
    if target_type == "email":
        result["findings"].append("\n Checking data breach databases...")
        hibp = _check_hibp(target)

        if hibp:
            if hibp["breached"]:
                result["data"]["hibp_breached"] = True
                result["data"]["hibp_breach_count"] = hibp["count"]
                count = hibp["count"]
                result["findings"].append(f" Found in {count} data breach(es)!")
                if count <= 3:
                    result["findings"].append("    Severity: Low (few exposures)")
                elif count <= 10:
                    result["findings"].append("    Severity:  Medium")
                else:
                    result["findings"].append("    Severity:  High (widely exposed!)")
            else:
                result["data"]["hibp_breached"] = False
                result["findings"].append(" Not found in known data breaches")
        else:
            result["warnings"].append("  Could not check HaveIBeenPwned (API unavailable)")

    # ─── OSINT Leak Database Links ──────────────────────────────
    result["findings"].append("\n OSINT Leak Database Links:")
    lookup_links = []

    if target_type == "email":
        lookup_links.extend([
            {"title": "HaveIBeenPwned", "url": f"https://haveibeenpwned.com/account/{target}"},
            {"title": "Firefox Monitor", "url": f"https://monitor.firefox.com/scan?email={target}"},
            {"title": "EmailRep.io", "url": f"https://emailrep.io/{target}"},
        ])
    elif target_type == "username":
        lookup_links.extend([
            {"title": "IntelX", "url": f"https://intelx.io/?s={target}"},
            {"title": "WhatsMyName", "url": f"https://whatsmyname.app/?q={target}"},
            {"title": "DeHashed", "url": f"https://dehashed.com/search?q={target}"},
        ])
    elif target_type == "domain":
        lookup_links.extend([
            {"title": "IntelX", "url": f"https://intelx.io/?s={target}"},
            {"title": "DeHashed", "url": f"https://dehashed.com/search?q={target}"},
        ])
    elif target_type == "ip":
        lookup_links.extend([
            {"title": "AbuseIPDB", "url": f"https://www.abuseipdb.com/check/{target}"},
            {"title": "IntelX", "url": f"https://intelx.io/?s={target}"},
        ])

    # Universal lookup links
    lookup_links.extend([
        {"title": "psbdmp.ws Search", "url": f"https://psbdmp.ws/search/{target}"},
        {"title": "Google Search (quoted)", "url": f"https://www.google.com/search?q=%22{target}%22"},
        {"title": "Pastebin Search", "url": f"https://pastebin.com/search?q={target}"},
        {"title": "Leaked.site", "url": f"https://leaked.site/?s={target}"},
    ])

    result["data"]["lookup_links"] = lookup_links
    for link in lookup_links:
        result["findings"].append(f"    {link['title']}: {link['url']}")

    # Summary
    total_leaks = result["data"].get("paste_count", 0)
    hibp_breached = result["data"].get("hibp_breached", False)
    result["data"]["compromised"] = total_leaks > 0 or hibp_breached

    return result
