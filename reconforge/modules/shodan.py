"""
Shodan InternetDB Module
═════════════════════════
Uses the free Shodan InternetDB API (no key required) to get
port, service, CVE, and hostname intelligence for IP addresses.

Shodan InternetDB: https://internetdb.shodan.io/
Completely free, no API key needed for basic lookups.
"""

import re
import socket

from ..utils.http import fetch_json


# Common port to service name mapping
PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 5986: "WinRM HTTPS",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 5060: "SIP", 161: "SNMP",
}

DANGEROUS_PORTS = [21, 23, 445, 3389, 5900, 6379, 27017, 11211, 9200]

TAG_DESCRIPTIONS = {
    "cloud": " Cloud-hosted",
    "database": " Database server",
    "iot": " IoT device",
    "webcam": " Webcam",
    "router": " Router/Network device",
    "camera": " Camera/Surveillance",
    "printer": " Printer",
    "vpn": " VPN",
    "proxy": " Proxy",
    "honeypot": " Honeypot",
    "malware": " Malware-related",
    "c2": " Command & Control",
}

def _is_private(ip: str) -> bool:
    """Check if an IP is in a private range."""
    if ip.startswith(("10.", "127.", "169.254.", "192.168.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            pass
    return False


def _extract_ip(target: str) -> str:
    """Extract clean IP from potential hostname or URL."""
    target = target.strip()
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, target):
        return target
    # Try to resolve domain to IP
    try:
        ips = socket.getaddrinfo(target, None)
        for info in ips:
            ip = info[4][0]
            if ip.count(".") == 3:
                return ip
    except Exception:
        pass
    return target  # Return as-is if resolution fails


def recon(target: str) -> dict:
    """Query Shodan InternetDB for information about an IP or host."""
    ip = _extract_ip(target)

    result = {
        "target": target,
        "type": "Shodan Intel",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    result["findings"].append(f" Target: {target}")
    if ip != target:
        result["findings"].append(f" Resolved to IP: {ip}")
        result["data"]["resolved_ip"] = ip

    # Validate IP format
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(ip_pattern, ip):
        result["warnings"].append(" Invalid IP address")
        return result

    octets = ip.split(".")
    if any(int(o) > 255 for o in octets):
        result["warnings"].append(" Invalid IP (octet > 255)")
        return result

    # Skip private IPs
    if _is_private(ip):
        result["findings"].append(" Private IP — Shodan has no data (internal/LAN)")
        result["data"]["private_ip"] = True
        result["data"]["lookup_links"] = [
            {"title": "Shodan Search", "url": f"https://www.shodan.io/search?query={ip}"},
        ]
        return result

    # Query Shodan InternetDB (free, no key)
    data = fetch_json(f"https://internetdb.shodan.io/{ip}", timeout=10)

    if data is None:
        result["warnings"].append("  Shodan InternetDB query failed (timeout or unavailable)")
        result["data"]["lookup_links"] = [
            {"title": "Shodan (manual search)", "url": f"https://www.shodan.io/search?query={ip}"},
        ]
        return result

    # Parse response
    hostnames = data.get("hostnames", [])
    ports = data.get("ports", [])
    tags = data.get("tags", [])
    vulns = data.get("vulns", [])
    cpes = data.get("cpes", [])

    if not ports and not vulns:
        result["findings"].append(" No data in Shodan InternetDB for this IP")
    else:
        result["findings"].append(f" Data found in Shodan InternetDB")

    # Hostnames
    if hostnames:
        result["data"]["hostnames"] = hostnames
        result["findings"].append(f"\n Hostnames ({len(hostnames)}):")
        for h in hostnames[:8]:
            result["findings"].append(f"    {h}")
        if len(hostnames) > 8:
            result["findings"].append(f"   ...and {len(hostnames) - 8} more")

    # Ports & Services
    if ports:
        result["data"]["open_ports"] = sorted(ports)
        result["data"]["port_count"] = len(ports)
        result["findings"].append(f"\n Open Ports ({len(ports)}):")
        for port in sorted(ports)[:20]:
            service = PORT_SERVICE_MAP.get(port, "unknown")
            result["findings"].append(f"    Port {port}/{service}")
        if len(ports) > 20:
            result["findings"].append(f"   ...and {len(ports) - 20} more")

        # Dangerous ports
        dangerous_found = [p for p in ports if p in DANGEROUS_PORTS]
        if dangerous_found:
            services = [PORT_SERVICE_MAP.get(p, str(p)) for p in dangerous_found]
            result["findings"].append(f"\n  Potentially dangerous services exposed:")
            for s in services:
                result["findings"].append(f"    {s}")
            result["data"]["dangerous_ports"] = dangerous_found

    # Tags
    if tags:
        result["data"]["tags"] = tags
        result["findings"].append(f"\n Tags ({len(tags)}):")
        for tag in tags[:10]:
            desc = TAG_DESCRIPTIONS.get(tag, tag)
            result["findings"].append(f"    {desc}")
        if len(tags) > 10:
            result["findings"].append(f"   ...and {len(tags) - 10} more")

    # CVEs / Vulnerabilities
    if vulns:
        result["data"]["vulnerabilities"] = sorted(vulns)
        result["data"]["vuln_count"] = len(vulns)
        result["findings"].append(f"\n Vulnerabilities ({len(vulns)}):")
        for cve in sorted(vulns)[:10]:
            result["findings"].append(f"     {cve}")
        if len(vulns) > 10:
            result["findings"].append(f"   ...and {len(vulns) - 10} more CVEs")
    else:
        result["findings"].append("\n No known CVEs detected by Shodan")

    # CPEs
    if cpes:
        result["data"]["cpes"] = cpes[:10]
        result["data"]["cpe_count"] = len(cpes)
        result["findings"].append(f"\n Software/CPEs ({len(cpes)}):")
        for cpe in cpes[:8]:
            result["findings"].append(f"    {cpe}")

    # Security summary
    risk_factors = []
    if ports:
        if len(ports) > 15:
            risk_factors.append("many open ports")
        if any(p in [21, 23] for p in ports):
            risk_factors.append("FTP/Telnet exposed")
        if 3389 in ports:
            risk_factors.append("RDP exposed")
        if 6379 in ports or 27017 in ports:
            risk_factors.append("unsecured database")
        if 445 in ports:
            risk_factors.append("SMB exposed")
    if vulns:
        risk_factors.append(f"{len(vulns)} CVEs")

    if risk_factors:
        risk_level = " High" if (len(vulns or []) > 3 or len(ports or []) > 20 or any(p in [21, 23, 3389] for p in (ports or []))) else " Medium"
        result["findings"].append(f"\n Risk Level: {risk_level}")
        result["findings"].append(f"     Factors: {', '.join(risk_factors)}")
        result["data"]["risk_level"] = risk_level
        result["data"]["risk_factors"] = risk_factors

    # OSINT Lookup Links
    result["data"]["lookup_links"] = [
        {"title": "Shodan (full details)", "url": f"https://www.shodan.io/host/{ip}"},
        {"title": "Shodan InternetDB", "url": f"https://internetdb.shodan.io/{ip}"},
        {"title": "VirusTotal", "url": f"https://www.virustotal.com/gui/ip-address/{ip}"},
        {"title": "AbuseIPDB", "url": f"https://www.abuseipdb.com/check/{ip}"},
        {"title": "Censys", "url": f"https://search.censys.io/search?resource=hosts&q={ip}"},
    ]

    return result
