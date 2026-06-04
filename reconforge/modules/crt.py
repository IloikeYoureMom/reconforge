"""
Certificate Transparency Module (crt.sh)
═════════════════════════════════════════
Queries crt.sh Certificate Transparency logs to discover
SSL certificates and subdomains for a target domain.
Free, no API key required.
"""

from urllib.parse import urlparse

from ..utils.http import fetch_json


def recon(domain: str) -> dict:
    """Query crt.sh for certificates related to a domain."""
    domain = domain.strip().lower()
    # Remove protocol and paths if it's a URL
    if domain.startswith("http"):
        domain = urlparse(domain).netloc
    # Remove www. prefix
    if domain.startswith("www."):
        domain = domain[4:]

    result = {
        "target": domain,
        "type": "Certificate Transparency",
        "findings": [],
        "warnings": [],
        "data": {},
    }

    result["findings"].append(f" Querying crt.sh for: {domain}")

    # Query crt.sh API - use wildcard to catch all subdomains
    # Note: crt.sh can be slow (10-20s for large domains), use a generous timeout
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    data = fetch_json(url, timeout=60)

    if data is None:
        result["warnings"].append("  crt.sh did not respond (may be rate-limited or unavailable)")
        result["data"]["lookup_links"] = [
            {"title": "crt.sh (browser search)", "url": f"https://crt.sh/?q=%25.{domain}"},
        ]
        return result

    if not isinstance(data, list) or len(data) == 0:
        result["findings"].append(" No certificates found")
        return result

    result["findings"].append(f" Retrieved {len(data)} certificate records")

    # Extract unique subdomains from certificate name_value fields
    all_subdomains = set()
    unique_issuers = set()
    unique_cas = set()
    earliest = None
    latest = None

    for cert in data:
        name_value = cert.get("name_value", "")
        issuer = cert.get("issuer_name", "")

        if issuer:
            unique_issuers.add(issuer)
            # Extract CA name
            if "CN=" in issuer:
                cn_parts = [p.split("=")[1] for p in issuer.split(",") if "CN=" in p]
                if cn_parts:
                    unique_cas.add(cn_parts[0])

        # Parse dates
        not_before = cert.get("not_before", "")
        not_after = cert.get("not_after", "")
        if not_before and (earliest is None or not_before < earliest):
            earliest = not_before
        if not_after and (latest is None or not_after > latest):
            latest = not_after

        # Split by newlines (crt.sh joins multiple domains with newlines)
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and domain in name:
                # Remove wildcard prefix
                clean_name = name.replace("*.", "")
                all_subdomains.add(clean_name)

    # Filter out the main domain itself
    subdomains_only = {s for s in all_subdomains if s != domain}
    subdomains_only.discard(f"www.{domain}")

    result["data"]["certificates_count"] = len(data)
    result["data"]["unique_subdomains_count"] = len(subdomains_only)
    result["data"]["unique_issuers_count"] = len(unique_issuers)
    result["data"]["certificate_authorities"] = sorted(unique_cas)

    result["findings"].append(f" Found {len(all_subdomains)} unique domain(s) in certificates")
    result["findings"].append(f" Issued by {len(unique_cas)} CA(s): {', '.join(sorted(unique_cas)[:5])}")
    if len(unique_cas) > 5:
        result["findings"].append(f"   ...and {len(unique_cas) - 5} more")

    # Show all discovered domains
    if all_subdomains:
        sorted_domains = sorted(all_subdomains)
        result["data"]["domains_found"] = sorted_domains
        result["findings"].append(f"\n All discovered domains ({len(all_subdomains)}):")
        for d in sorted_domains[:15]:
            result["findings"].append(f"    {d}")
        if len(sorted_domains) > 15:
            result["findings"].append(f"   ...and {len(sorted_domains) - 15} more")

    # Show subdomains separately (without the main domain)
    if subdomains_only:
        sorted_subs = sorted(subdomains_only)
        result["data"]["subdomains"] = sorted_subs
        result["findings"].append(f"\n Subdomains ({len(sorted_subs)}):")
        for s in sorted_subs[:10]:
            result["findings"].append(f"    {s}")
        if len(sorted_subs) > 10:
            result["findings"].append(f"   ...and {len(sorted_subs) - 10} more")

    # Date range
    if earliest and latest:
        result["data"]["certificate_period"] = f"{earliest[:10]} to {latest[:10]}"
        result["findings"].append(f" Certificate period: {earliest[:10]} to {latest[:10]}")

    # Issuers breakdown
    if unique_issuers:
        result["data"]["issuers"] = sorted(unique_issuers)
        result["findings"].append(f"\n Certificate Authorities ({len(unique_cas)}):")
        for ca in sorted(unique_cas)[:8]:
            result["findings"].append(f"    {ca}")

    # OSINT Lookup Links
    result["data"]["lookup_links"] = [
        {"title": "crt.sh Search", "url": f"https://crt.sh/?q=%25.{domain}"},
        {"title": "crt.sh (exact match)", "url": f"https://crt.sh/?q={domain}"},
        {"title": "SSL Mate CertSpotter", "url": f"https://sslmate.com/certspotter/search?q={domain}"},
    ]

    return result
