"""
DNS Utility Module
══════════════════
DNS resolution, MX record lookup, NS lookup, and more.
"""

import socket
from typing import Optional


def resolve_hostname(hostname: str) -> list[str]:
    """Resolve a hostname to IP addresses."""
    try:
        results = socket.getaddrinfo(hostname, None)
        ips = set()
        for r in results:
            ip = r[4][0]
            if ip.count(".") == 3:  # IPv4 only for simplicity
                ips.add(ip)
        return sorted(ips)
    except socket.gaierror:
        return []


def resolve_rdns(ip: str) -> Optional[str]:
    """Reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def check_mx_records(domain: str) -> list[dict]:
    """Check MX records for a domain."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX")
        records = []
        for r in answers:
            exchange = str(r.exchange).rstrip(".")
            priority = r.preference
            records.append({"exchange": exchange, "priority": priority})
        return sorted(records, key=lambda x: x["priority"])
    except ImportError:
        return [{"exchange": "dnspython not installed", "priority": 0}]
    except Exception:
        return []


def check_ns_records(domain: str) -> list[str]:
    """Check NS records for a domain."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "NS")
        return sorted([str(r.target).rstrip(".") for r in answers])
    except ImportError:
        return ["dnspython not installed"]
    except Exception:
        return []


def check_txt_records(domain: str) -> list[str]:
    """Check TXT records for a domain."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "TXT")
        records = []
        for r in answers:
            txt = "".join([s.decode() if isinstance(s, bytes) else s for s in r.strings])
            records.append(txt)
        return records
    except ImportError:
        return ["dnspython not installed"]
    except Exception:
        return []


def check_spf_record(domain: str) -> Optional[str]:
    """Extract SPF record from TXT records."""
    txts = check_txt_records(domain)
    for txt in txts:
        if txt.startswith("v=spf1"):
            return txt
    return None


def check_dmarc_record(domain: str) -> Optional[str]:
    """Check DMARC record (_dmarc.domain)."""
    try:
        import dns.resolver
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for r in answers:
                txt = "".join([s.decode() if isinstance(s, bytes) else s for s in r.strings])
                if txt.startswith("v=DMARC1"):
                    return txt
        except Exception:
            pass
    except ImportError:
        pass
    return None
