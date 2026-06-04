"""
IP Address Reconnaissance Module
═════════════════════════════════
IP intelligence: geolocation, ISP, threat checks, open ports, and more.
"""

import re
import json

from ..utils.http import fetch_text, fetch_json
from ..utils.dns import resolve_rdns
from ..utils import cache
from ..utils.ports import scan_ports


PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
    ("169.254.0.0", "169.254.255.255"),
]


def _ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    return (
        (int(parts[0]) << 24)
        | (int(parts[1]) << 16)
        | (int(parts[2]) << 8)
        | int(parts[3])
    )


def _is_private(ip: str) -> bool:
    ip_int = _ip_to_int(ip)
    for start, end in PRIVATE_RANGES:
        if _ip_to_int(start) <= ip_int <= _ip_to_int(end):
            return True
    return False


def _get_geolocation(ip: str) -> dict:
    """Get IP geolocation from ip-api.com."""
    cache_key = f"geo_{ip}"
    cached = cache.get(cache_key, max_age_hours=168)  # 7 day cache
    if cached:
        return cached

    data = fetch_json(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,proxy,hosting,query", timeout=4)
    if data and data.get("status") == "success":
        cache.set(cache_key, data)
        return data
    return {"status": "fail"}





def recon(ip: str) -> dict:
    """Run full IP reconnaissance."""
    ip = ip.strip()

    result = {
        "target": ip,
        "type": "IP Address",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    # 1. Validation
    ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(ipv4_pattern, ip):
        result["warnings"].append(" Invalid IP address format")
        return result

    octets = ip.split(".")
    if any(int(o) > 255 for o in octets):
        result["warnings"].append(" Invalid IP (octet > 255)")
        return result

    result["findings"].append(f" Target: {ip}")

    # 2. Public/Private check
    if _is_private(ip):
        result["data"]["visibility"] = "private"
        result["findings"].append(" Private IP (LAN / internal)")
        return result

    result["data"]["visibility"] = "public"
    result["findings"].append(" Public IP (internet)")

    # 3. Reverse DNS
    rdns = resolve_rdns(ip)
    if rdns:
        result["data"]["reverse_dns"] = rdns
        result["findings"].append(f" Hostname: {rdns}")

    # 4. Geolocation
    geo = _get_geolocation(ip)
    if geo.get("status") == "success":
        result["data"]["geolocation"] = {
            "country": geo.get("country"),
            "country_code": geo.get("countryCode"),
            "region": geo.get("regionName"),
            "city": geo.get("city"),
            "zip": geo.get("zip"),
            "coordinates": {"lat": geo.get("lat"), "lon": geo.get("lon")},
            "isp": geo.get("isp"),
            "org": geo.get("org"),
            "asn": geo.get("as"),
        }

        result["findings"].append(f" Location: {geo.get('city', '?')}, {geo.get('regionName', '?')}, {geo.get('country', '?')}")
        result["findings"].append(f" ISP: {geo.get('isp', 'Unknown')}")
        result["findings"].append(f" Organization: {geo.get('org', 'Unknown')}")
        if geo.get("as"):
            result["findings"].append(f" ASN: {geo['as']}")

        if geo.get("lat") and geo.get("lon"):
            result["data"]["coordinates"] = f"{geo['lat']}, {geo['lon']}"
            result["findings"].append(f" Coordinates: {geo['lat']}, {geo['lon']}")

        if geo.get("proxy"):
            result["findings"].append("  Proxy/VPN detected!")
            result["data"]["proxy"] = True
        if geo.get("hosting"):
            result["findings"].append(" Hosted (datacenter IP)")
            result["data"]["hosting"] = True
    else:
        result["warnings"].append("  Could not geolocate IP")

    # 5. Port scan (threaded)
    open_ports = scan_ports(ip, timeout=1.5)

    if open_ports:
        result["data"]["open_ports"] = open_ports
        result["findings"].append(f"\n Open Ports ({len(open_ports)}):")
        for port in open_ports[:8]:
            result["findings"].append(f"    {port}")
        if len(open_ports) > 8:
            result["findings"].append(f"   ...and {len(open_ports) - 8} more")
    else:
        result["findings"].append("\n No common ports detected (firewall or filtered)")

    # 6. OSINT lookup links
    result["data"]["lookup_links"] = [
        {"title": "Shodan", "url": f"https://www.shodan.io/host/{ip}"},
        {"title": "VirusTotal", "url": f"https://www.virustotal.com/gui/ip-address/{ip}"},
        {"title": "AbuseIPDB", "url": f"https://www.abuseipdb.com/check/{ip}"},
        {"title": "IPinfo.io", "url": f"https://ipinfo.io/{ip}"},
        {"title": "Censys", "url": f"https://search.censys.io/search?resource=hosts&q={ip}"},
        {"title": "Google Maps", "url": f"https://www.google.com/maps?q={geo.get('lat', '')},{geo.get('lon', '')}" if geo.get('lat') else None},
    ]
    result["data"]["lookup_links"] = [l for l in result["data"]["lookup_links"] if l["url"]]

    return result
