"""
AlienVault OTX Threat Intelligence Module
══════════════════════════════════════════
Queries AlienVault Open Threat Exchange (OTX) for threat
intelligence about domains and IPs. Discovers associated
malware, pulses, passive DNS, and URL indicators.

Free API key (OTX_API_KEY env var) recommended for higher rate limits.
Without a key, generates OTX search URLs for manual inspection.
"""

import os
import json
import re
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

OTX_BASE = "https://otx.alienvault.com"


def _otx_get(path: str, timeout: int = 15) -> dict:
    """Make an authenticated request to the OTX API."""
    if not OTX_API_KEY:
        return {}

    url = f"{OTX_BASE}{path}"
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY,
        "User-Agent": "ReconForge/1.0",
        "Accept": "application/json",
    }

    try:
        req = Request(url, headers=headers)
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, OSError, json.JSONDecodeError):
        return {}


def _get_domain_info(domain: str) -> dict:
    """Get general domain intelligence from OTX."""
    return _otx_get(f"/api/v1/indicators/domain/{domain}/general")


def _get_domain_passive_dns(domain: str) -> list:
    """Get passive DNS records for a domain."""
    data = _otx_get(f"/api/v1/indicators/domain/{domain}/passive_dns?limit=50")
    return data.get("passive_dns", []) if data else []


def _get_domain_urls(domain: str) -> list:
    """Get URL list for a domain."""
    data = _otx_get(f"/api/v1/indicators/domain/{domain}/url_list?limit=50")
    return data.get("url_list", []) if data else []


def _get_domain_malware(domain: str) -> list:
    """Get malware samples associated with a domain."""
    data = _otx_get(f"/api/v1/indicators/domain/{domain}/malware?limit=20")
    return data.get("data", []) if data else []


def _get_ip_info(ip: str) -> dict:
    """Get IP reputation from OTX."""
    return _otx_get(f"/api/v1/indicators/IPv4/{ip}/general")


def recon(target: str) -> dict:
    """Query AlienVault OTX for threat intelligence."""
    target = target.strip().lower()
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]
    clean = clean.replace("www.", "", 1) if clean.startswith("www.") else clean

    # Detect type
    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean))

    result = {
        "target": target,
        "type": "OTX Threat Intel",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    result["findings"].append(f" Target: {clean}")
    result["data"]["target"] = clean
    result["data"]["type"] = "IP" if is_ip else "Domain"

    has_key = bool(OTX_API_KEY)
    if has_key:
        result["findings"].append(f" OTX_API_KEY loaded ({OTX_API_KEY[:4]}...)")
        result["data"]["authenticated"] = True
    else:
        result["warnings"].append("  No OTX_API_KEY set — generating search URLs only")
        result["warnings"].append("   Set OTX_API_KEY env var for live threat data")
        result["data"]["authenticated"] = False

    if has_key:
        result["findings"].append("\n Querying AlienVault OTX...")

        if not is_ip:
            # Domain intelligence
            info = _get_domain_info(clean)
            if info:
                # Reputation
                pulses = info.get("pulse_info", {})
                pulse_count = pulses.get("count", 0)
                related_pulses = pulses.get("pulses", [])

                result["data"]["pulse_count"] = pulse_count
                if pulse_count > 0:
                    result["findings"].append(f" Found in {pulse_count} threat pulse(s)!")
                    result["data"]["related_pulses"] = []
                    for pulse in related_pulses[:5]:
                        name = pulse.get("name", "Unnamed")
                        description = pulse.get("description", "")[:100]
                        created = pulse.get("created", "")[:10]
                        tags = pulse.get("tags", [])
                        result["findings"].append(f"\n     Pulse: {name}")
                        result["findings"].append(f"       {created}")
                        if tags:
                            result["findings"].append(f"       Tags: {', '.join(tags[:5])}")
                        result["data"]["related_pulses"].append({
                            "name": name,
                            "description": description,
                            "created": created,
                            "tags": tags,
                        })
                else:
                    result["findings"].append(" Not found in any threat pulses")

                # Country & ASN
                country = info.get("country", "")
                asn = info.get("asn", "")
                if country:
                    result["data"]["country"] = country
                    result["findings"].append(f" Country: {country}")
                if asn:
                    result["data"]["asn"] = asn
                    result["findings"].append(f" ASN: {asn}")

            # Passive DNS
            passive_dns = _get_domain_passive_dns(clean)
            if passive_dns:
                unique_ips = set()
                unique_ases = set()
                for record in passive_dns[:30]:
                    ip = record.get("address", "")
                    asn = record.get("asn", "")
                    if ip:
                        unique_ips.add(ip)
                    if asn:
                        unique_ases.add(asn)

                result["data"]["passive_dns_count"] = len(passive_dns)
                result["data"]["passive_dns_ips"] = sorted(unique_ips)
                result["findings"].append(f"\n Passive DNS: {len(passive_dns)} records, {len(unique_ips)} unique IPs")
                for ip in sorted(unique_ips)[:8]:
                    result["findings"].append(f"    {ip}")
                if len(unique_ips) > 8:
                    result["findings"].append(f"   ...and {len(unique_ips) - 8} more")

            # Associated URLs
            urls = _get_domain_urls(clean)
            if urls:
                result["data"]["url_count"] = len(urls)
                result["findings"].append(f"\n Associated URLs ({len(urls)}):")
                for entry in urls[:8]:
                    url = entry.get("url", "")
                    date = entry.get("date", "")[:10]
                    if url:
                        result["findings"].append(f"    {url} ({date})")

            # Malware samples
            malware = _get_domain_malware(clean)
            if malware:
                result["data"]["malware_count"] = len(malware)
                result["findings"].append(f"\n Malware samples ({len(malware)}):")
                for sample in malware[:5]:
                    hash_val = sample.get("hash", "")[:16]
                    date = sample.get("date", "")[:10]
                    title = sample.get("title", "Unknown")
                    result["findings"].append(f"    {title} — {hash_val}... ({date})")

        else:
            # IP intelligence
            info = _get_ip_info(clean)
            if info:
                pulses = info.get("pulse_info", {})
                pulse_count = pulses.get("count", 0)
                related_pulses = pulses.get("pulses", [])

                result["data"]["pulse_count"] = pulse_count
                if pulse_count > 0:
                    result["findings"].append(f" IP found in {pulse_count} threat pulse(s)!")
                    for pulse in related_pulses[:5]:
                        name = pulse.get("name", "Unnamed")
                        tags = pulse.get("tags", [])
                        result["findings"].append(f"     Pulse: {name}")
                        if tags:
                            result["findings"].append(f"       Tags: {', '.join(tags[:5])}")
                else:
                    result["findings"].append(" IP not found in any threat pulses")

                country = info.get("country", "")
                asn = info.get("asn", "")
                if country:
                    result["data"]["country"] = country
                    result["findings"].append(f" Country: {country}")
                if asn:
                    result["data"]["asn"] = asn
                    result["findings"].append(f" ASN: {asn}")

    # Generate OTX search URLs
    if is_ip:
        search_url = f"https://otx.alienvault.com/indicator/ip/{clean}"
    else:
        search_url = f"https://otx.alienvault.com/indicator/domain/{clean}"

    result["findings"].append("\n OTX Links:")
    result["data"]["lookup_links"] = [
        {"title": "OTX Indicator Page", "url": search_url},
        {"title": "OTX Search", "url": f"https://otx.alienvault.com/browse/pulses?q={clean}"},
    ]
    for link in result["data"]["lookup_links"]:
        result["findings"].append(f"    {link['title']}: {link['url']}")

    return result
