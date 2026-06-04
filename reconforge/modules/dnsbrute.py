"""
DNS Brute-force Module
══════════════════════
Brute-forces subdomains using DNS resolution and a built-in
wordlist of common subdomain names. Uses threading for speed.

This module resolves potential subdomains via DNS to discover
hidden services, internal tools, and forgotten endpoints.
"""

import re
import secrets
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..utils.dns import resolve_hostname


# Core wordlist: 150 common subdomains discovered in real-world pentests
SUBDOMAIN_WORDLIST = [
    # Web & Infrastructure
    "www", "wwww", "web", "www2", "www3", "www4", "www5",
    "home", "main", "index", "default", "new", "old", "live",
    "app", "app1", "app2", "api", "api2", "api3", "api-v2", "v2", "v3",
    "dev", "dev1", "development", "developer", "developers",
    "staging", "stage", "test", "testing", "tests", "qa", "uat",
    "demo", "sandbox", "lab", "labs", "beta", "alpha", "preview",
    "admin", "adm", "admin1", "administrator", "root", "sysadmin",
    "manage", "manager", "management", "dashboard", "control",
    "portal", "gateway", "hub", "console", "panel", "cpanel", "whm",
    "status", "uptime", "health", "monitor", "monitoring", "stats",
    "analytics", "metrics", "report", "reports",
    "blog", "news", "press", "media", "info", "about",
    "docs", "documentation", "wiki", "knowledgebase", "kb", "faq",
    "help", "support", "service", "services", "ticket", "tickets",
    "mail", "mail2", "mail3", "smtp", "pop3", "imap", "webmail",
    "email", "newsletter", "lists",
    "cdn", "cdn1", "cdn2", "static", "static1", "static2",
    "assets", "files", "images", "img", "img1", "img2", "css", "js",
    "upload", "uploads", "download", "downloads",
    "media", "video", "videos", "stream", "tv",
    "shop", "store", "shopify", "cart", "checkout", "billing",
    "pay", "payment", "payments", "invoice", "invoices",
    # Security & Access
    "vpn", "vpn1", "vpn2", "remote", "remote1", "access",
    "ssh", "rdp", "sftp", "ftp", "ftps", "ftp2", "sftp",
    "proxy", "proxies", "proxy1", "socks",
    "secure", "security", "auth", "authentication", "login",
    "sso", "oauth", "oauth2", "identity", "saml", "okta",
    "firewall", "fw", "ids", "ips", "waf",
    "sentry", "siem", "soc",
    # Database & Storage
    "db", "db1", "db2", "database", "mysql", "postgres", "postgresql",
    "mongo", "mongodb", "redis", "elastic", "elasticsearch",
    "sql", "mssql", "oracle", "couchdb", "cassandra",
    "backup", "backups", "storage", "data", "datasync",
    # Internal & Corporate
    "intranet", "extranet", "hr", "employees", "employee",
    "corp", "corporate", "internal", "internal1", "internal2",
    "office", "office365", "sharepoint", "teams", "365",
    "jira", "confluence", "jenkins", "gitlab", "github", "bitbucket",
    "git", "svn", "repo", "repos", "code", "source",
    "ci", "cd", "build", "builds", "deploy", "deployment",
    "docker", "k8s", "kubernetes", "registry",
    "logging", "logs", "log", "logstash", "kibana", "grafana",
    "puppet", "chef", "ansible", "nagios", "zabbix",
    # Communications
    "chat", "discuss", "forum", "forums", "community",
    "talk", "voice", "phone", "call", "meet", "meeting",
    "calendar", "cal", "schedule", "book",
    "mailing", "list", "listserv", "mailman",
    # Third-party & Cloud
    "cloud", "aws", "azure", "gcp", "gce", "ec2", "s3",
    "heroku", "netlify", "vercel", "pages", "gh-pages",
    "firebase", "firestore", "functions",
    "worker", "workers", "edge", "lambda",
    # Misc
    "m", "mobile", "mobi", "touch",
    "sitemap", "robots", "crossdomain", "xmlrpc",
    "direct", "direct-connect", "p2p", "peer",
    "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "ntp", "time", "clock",
    "ldap", "ldaps", "radius", "dhcp",
]


def _check_wildcard(domain: str) -> tuple:
    """Check if a domain has a wildcard DNS record.
    Returns (has_wildcard, wildcard_ips).
    """
    random_sub = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(10))
    test_domain = f"{random_sub}.{domain}"
    ips = resolve_hostname(test_domain)
    if ips:
        return (True, set(ips))
    return (False, set())


def recon(domain: str) -> dict:
    """Brute-force subdomains via DNS resolution."""
    domain = domain.strip().lower()

    # Clean domain
    domain = re.sub(r"https?://", "", domain)
    domain = domain.split("/")[0]
    domain = re.sub(r"^www\.", "", domain)

    result = {
        "target": domain,
        "type": "DNS Brute-force",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    result["findings"].append(f" Target: {domain}")
    result["data"]["domain"] = domain

    # Resolve main domain first
    main_ips = resolve_hostname(domain)
    if not main_ips:
        result["warnings"].append("  Main domain does not resolve — subdomain brute-force may not work")
        return result

    result["data"]["main_domain_ips"] = main_ips
    result["findings"].append(f" Main domain resolves to: {', '.join(main_ips)}")

    # Check for wildcard DNS
    wildcard, wildcard_ips = _check_wildcard(domain)
    result["data"]["wildcard_dns"] = wildcard
    if wildcard:
        result["warnings"].append("  Wildcard DNS detected — results may include false positives")
        result["findings"].append("   Will filter out wildcard responses...")
    else:
        result["findings"].append(" No wildcard DNS detected")

    # Brute-force subdomains with threading
    total_checks = len(SUBDOMAIN_WORDLIST)
    result["findings"].append(f"\n Brute-forcing {total_checks} subdomains...")

    found_subdomains = []

    def _check_sub(sub: str):
        subdomain = f"{sub}.{domain}"
        ips = resolve_hostname(subdomain)
        if ips:
            ips_set = set(ips)
            # Filter out wildcard IPs
            if not wildcard or ips_set != wildcard_ips:
                return {"subdomain": subdomain, "ips": sorted(ips)}
            elif wildcard and ips_set == wildcard_ips:
                return {"subdomain": subdomain, "ips": sorted(ips), "wildcard": True}
        return None

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(_check_sub, sub): sub for sub in SUBDOMAIN_WORDLIST}
        for future in as_completed(futures, timeout=45):
            try:
                result_item = future.result()
                if result_item:
                    found_subdomains.append(result_item)
            except Exception:
                pass

    # Sort for consistent output
    found_subdomains.sort(key=lambda x: x["subdomain"])

    # Filter out wildcard matches
    real_subdomains = [s for s in found_subdomains if not s.get("wildcard")]
    wildcard_matches = [s for s in found_subdomains if s.get("wildcard")]

    if real_subdomains:
        result["data"]["subdomains_found"] = real_subdomains
        result["data"]["subdomain_count"] = len(real_subdomains)
        result["findings"].append(f"\n Found {len(real_subdomains)} real subdomain(s):")

        for s in real_subdomains[:15]:
            result["findings"].append(f"    {s['subdomain']} → {', '.join(s['ips'])}")
        if len(real_subdomains) > 15:
            result["findings"].append(f"   ...and {len(real_subdomains) - 15} more")

        # Group by IP
        ip_groups = {}
        for s in real_subdomains:
            for ip in s["ips"]:
                if ip not in ip_groups:
                    ip_groups[ip] = []
                ip_groups[ip].append(s["subdomain"])
        result["data"]["ip_grouping"] = {ip: subs for ip, subs in ip_groups.items() if len(subs) > 1}

        # Highlight interesting subdomains
        interesting_keywords = ["admin", "dev", "test", "api", "vpn", "jenkins",
                                "jira", "git", "db", "internal", "secret", "monitor",
                                "portal", "backup", "login", "dashboard", "console"]
        interesting = [s for s in real_subdomains
                       if any(kw in s["subdomain"] for kw in interesting_keywords)]

        if interesting:
            result["data"]["interesting_subdomains"] = [s["subdomain"] for s in interesting]
            result["findings"].append(f"\n Potentially interesting ({len(interesting)}):")
            for s in interesting[:8]:
                result["findings"].append(f"    {s['subdomain']} → {', '.join(s['ips'])}")
    else:
        result["findings"].append("\n No subdomains discovered via DNS brute-force")

    if wildcard_matches:
        result["data"]["wildcard_matches"] = len(wildcard_matches)
        result["findings"].append(f"\n  {len(wildcard_matches)} wildcard match(es) filtered out")

    # Summary stats
    result["data"]["checked_count"] = total_checks
    result["data"]["wildcard_detected"] = wildcard

    # Lookup links
    result["data"]["lookup_links"] = [
        {"title": "crt.sh (cross-reference subdomains)", "url": f"https://crt.sh/?q=%25.{domain}"},
        {"title": "SecurityTrails (DNS history)", "url": f"https://securitytrails.com/domain/{domain}"},
        {"title": "VirusTotal (passive DNS)", "url": f"https://www.virustotal.com/gui/domain/{domain}"},
    ]

    return result
