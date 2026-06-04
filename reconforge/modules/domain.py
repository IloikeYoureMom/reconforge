"""
Domain Reconnaissance Module
════════════════════════════
Analyzes domains: DNS records, WHOIS, SSL, security headers,
technology detection, subdomain discovery, and more.
"""

import re
from urllib.parse import urlparse

from ..utils.dns import (
    resolve_hostname,
    resolve_rdns,
    check_mx_records,
    check_ns_records,
    check_txt_records,
    check_spf_record,
    check_dmarc_record,
)
from ..utils.http import fetch_text, check_url_status
from ..utils import cache
from ..utils.ports import scan_ports


SUBDOMAIN_WORDLIST = [
    "www", "mail", "admin", "api", "dev", "staging", "test", "blog",
    "cdn", "static", "files", "images", "media", "img", "css", "js",
    "docs", "help", "support", "status", "statuspage", "webmail",
    "vpn", "remote", "portal", "app", "m", "mobile", "shop",
    "store", "billing", "pay", "payment", "secure", "login",
    "signup", "register", "forum", "community", "chat", "wiki",
    "git", "svn", "jira", "confluence", "jenkins", "ci", "build",
    "monitor", "monitoring", "analytics", "tracking", "metrics",
    "grafana", "prometheus", "kibana", "elastic", "logs", "log",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "smtp", "pop3", "imap", "dns", "ns1", "ns2", "mx",
    "ftp", "sftp", "ssh", "rdp", "telnet", "proxy", "torrent",
    "calendar", "mail2", "owa", "exchange", "autodiscover",
    "lyncdiscover", "sip", "meet", "webex", "zoom",
    "recruiting", "careers", "jobs", "hr", "employee",
    "partner", "partners", "vendors", "suppliers",
    "research", "lab", "labs", "sandbox", "demo",
    "newsletter", "news", "press", "info",
    "direct", "direct-connect", "cloud", "cloudapp",
    "backup", "download", "upload", "transfer",
    "intranet", "extranet", "ldap", "radius", "ntp",
]


def _extract_domain(target: str) -> str:
    """Extract clean domain from a URL or hostname."""
    target = target.strip().lower()
    if target.startswith("http"):
        parsed = urlparse(target)
        domain = parsed.netloc
    else:
        domain = target

    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]

    # Remove leading www.
    return re.sub(r"^www\.", "", domain)


def _detect_tech(url: str) -> list[str]:
    """Basic technology detection from HTTP response headers/content."""
    techs = []
    html = fetch_text(url, timeout=8)
    if not html:
        return []

    # Server header / generator tags
    match = re.search(r'<meta[^>]*name="generator"[^>]*content="([^"]+)"', html, re.IGNORECASE)
    if match:
        techs.append(f"Generator: {match.group(1)}")

    if "wp-content" in html or "wp-includes" in html:
        techs.append("WordPress")
    if "react-root" in html or "react" in html.lower()[:5000]:
        techs.append("React")
    if "next" in html.lower()[:2000] and "js" in html.lower()[:2000]:
        techs.append("Next.js")
    if "vue" in html.lower()[:3000]:
        techs.append("Vue.js")
    if "angular" in html.lower()[:3000]:
        techs.append("Angular")
    if "jquery" in html.lower():
        techs.append("jQuery")
    if "bootstrap" in html.lower():
        techs.append("Bootstrap")
    if "tailwind" in html.lower():
        techs.append("Tailwind CSS")
    if "shopify" in html.lower() or "myshopify" in html.lower():
        techs.append("Shopify")
    if "cloudflare" in html.lower():
        techs.append("Cloudflare")

    return techs


def _check_http_security(url: str) -> dict:
    """Check HTTP security headers."""
    result = {
        "strict_transport_security": False,
        "x_frame_options": False,
        "x_content_type_options": False,
        "x_xss_protection": False,
        "content_security_policy": False,
        "referrer_policy": False,
        "permissions_policy": False,
    }

    try:
        import urllib.request
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            headers = dict(resp.headers)
            result["strict_transport_security"] = "strict-transport-security" in headers
            result["x_frame_options"] = "x-frame-options" in headers
            result["x_content_type_options"] = "x-content-type-options" in headers
            result["x_xss_protection"] = "x-xss-protection" in headers
            result["content_security_policy"] = "content-security-policy" in headers
            result["referrer_policy"] = "referrer-policy" in headers
            result["permissions_policy"] = "permissions-policy" in headers or "feature-policy" in headers
            result["server"] = headers.get("server", "Unknown")
            result["powered_by"] = headers.get("x-powered-by", "")
            return result
    except Exception:
        return result


def recon(domain: str) -> dict:
    """Run full domain reconnaissance."""
    domain = _extract_domain(domain)

    result = {
        "target": domain,
        "type": "Domain",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    # 1. DNS Resolution
    ips = resolve_hostname(domain)
    if ips:
        result["data"]["ip_addresses"] = ips
        result["findings"].append(f" Resolved to {len(ips)} IP address(es): {', '.join(ips[:5])}")
        if len(ips) > 5:
            result["findings"].append(f"   ...and {len(ips) - 5} more")

        # Reverse DNS for first IP
        rdns = resolve_rdns(ips[0])
        if rdns and rdns != domain:
            result["data"]["reverse_dns"] = rdns
            result["findings"].append(f" Reverse DNS: {rdns}")

        # Check common ports on first IP (threaded)
        open_ports = scan_ports(ips[0], timeout=1.5)
        if open_ports:
            result["data"]["open_ports"] = open_ports
            result["findings"].append(f" Open ports ({len(open_ports)}): {', '.join(open_ports[:8])}")
            if len(open_ports) > 8:
                result["findings"].append(f"   ...and {len(open_ports) - 8} more")
        else:
            result["findings"].append(" No common ports detected (or filtered)")
    else:
        result["warnings"].append("  Domain does not resolve")

    # 2. MX Records
    mx_records = check_mx_records(domain)
    if mx_records:
        result["data"]["mx_records"] = mx_records
        result["findings"].append(f" MX Records ({len(mx_records)}):")
        for mx in mx_records[:3]:
            result["findings"].append(f"   Priority {mx['priority']}: {mx['exchange']}")
        mail_providers = _detect_mail_provider(mx_records)
        if mail_providers:
            result["data"]["mail_provider"] = mail_providers
            result["findings"].append(f" Mail Provider: {mail_providers}")

    # 3. NS Records
    ns_records = check_ns_records(domain)
    if ns_records:
        result["data"]["ns_records"] = ns_records
        result["findings"].append(f" Nameservers ({len(ns_records)}): {', '.join(ns_records[:4])}")

    # 4. TXT/SPF/DMARC
    txt_records = check_txt_records(domain)
    if txt_records:
        result["data"]["txt_records"] = txt_records

    spf = check_spf_record(domain)
    if spf:
        result["data"]["spf_record"] = spf
        result["findings"].append(f" SPF Record: {spf[:60]}...")

    dmarc = check_dmarc_record(domain)
    if dmarc:
        result["data"]["dmarc_record"] = dmarc
        result["findings"].append(f" DMARC: {dmarc[:60]}...")
    else:
        result["warnings"].append("  No DMARC record - email spoofing protection missing")

    # 5. HTTP/S Security
    for protocol in ["https://", "http://"]:
        url = f"{protocol}{domain}"
        status = check_url_status(url)
        if status:
            result["data"]["website"] = url
            result["data"]["http_status"] = status
            result["findings"].append(f" Website: {url} (HTTP {status})")

            # Security headers
            sec = _check_http_security(url)
            if sec:
                result["data"]["security_headers"] = sec
                result["findings"].append(" Security Headers:")
                for header, present in sec.items():
                    if isinstance(present, bool):
                        result["findings"].append(f"   {'' if present else ''} {header.replace('_', ' ').title()}")

            # Technology detection
            techs = _detect_tech(url)
            if techs:
                result["data"]["technologies"] = techs
                result["findings"].append(f" Technologies: {', '.join(techs)}")
            break

    # 6. Subdomain discovery (threaded)
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _check_sub(sub):
        subdomain = f"{sub}.{domain}"
        sub_ips = resolve_hostname(subdomain)
        return (subdomain, sub_ips)

    subdomains = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(_check_sub, sub): sub for sub in SUBDOMAIN_WORDLIST}
        for future in as_completed(futures, timeout=30):
            try:
                subdomain, sub_ips = future.result()
                if sub_ips:
                    subdomains.append({"subdomain": subdomain, "ips": sub_ips})
            except Exception:
                pass

    if subdomains:
        result["data"]["subdomains"] = subdomains
        result["findings"].append(f" Discovered {len(subdomains)} subdomain(s):")
        for sd in subdomains[:6]:
            result["findings"].append(f"    {sd['subdomain']} → {', '.join(sd['ips'])}")
        if len(subdomains) > 6:
            result["findings"].append(f"   ...and {len(subdomains) - 6} more")
    else:
        result["findings"].append(" No common subdomains discovered")

    # 7. WHOIS info hint
    tld = domain.split(".")[-1]
    if tld == "il":
        result["findings"].append(" .il domain (Israel)")
    elif tld == "ru":
        result["findings"].append(" .ru domain (Russia)")

    return result


def _detect_mail_provider(mx_records: list) -> str:
    """Detect email provider from MX records."""
    mx_str = " ".join([m["exchange"].lower() for m in mx_records])
    providers = {
        "google": "Google Workspace (Gmail)",
        "googlemail": "Google Workspace (Gmail)",
        "outlook": "Microsoft 365 (Outlook)",
        "protection.outlook": "Microsoft 365 (Outlook)",
        "mail.protection": "Microsoft 365 (Outlook)",
        "protonmail": "ProtonMail",
        "proton": "ProtonMail",
        "zoho": "Zoho Mail",
        "mxrecord": "MXRecord",
        "cloudflare": "Cloudflare Email",
        "migadu": "Migadu",
        "fastmail": "Fastmail",
        "titan": "Titan Email",
        "yandex": "Yandex Mail",
    }
    for key, name in providers.items():
        if key in mx_str:
            return name
    return "Custom mail server"
