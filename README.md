#  ReconForge — Automated Cyber Reconnaissance Framework

> **Know your target before they know you.**  
> A professional-grade OSINT and reconnaissance framework with **15 modules**, beautiful Rich-powered terminal output, and HTML report generation.

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-00FF00?style=for-the-badge)]()
[![Version](https://img.shields.io/badge/Version-1.0.0-8B5CF6?style=for-the-badge)]()
[![Modules](https://img.shields.io/badge/Modules-15-3B82F6?style=for-the-badge)]()
[![CLI](https://img.shields.io/badge/CLI-Rich%20Powered-FF6B6B?style=for-the-badge)]()

---

##  Module Overview

ReconForge has **15 reconnaissance modules** covering domain intelligence, OSINT, threat intel, and technology profiling:

### Core OSINT (no API keys needed)

| # | Module | Target | What It Finds |
|---|--------|--------|---------------|
| 1 | **`domain`** | `example.com` | DNS records, IPs, MX/NS/TXT/SPF/DMARC, subdomains, open ports, tech stack, security headers |
| 2 | **`email`** | `user@example.com` | Format validation, provider detection, HIBP breach check, MX records, pattern analysis |
| 3 | **`username`** | `johndoe` | Platform presence across **40+ social networks**, pattern analysis, name detection |
| 4 | **`ip`** | `8.8.8.8` | Geolocation, ISP, ASN, reverse DNS, open ports, proxy/VPN detection, threat intel links |
| 5 | **`phone`** | `+972-54-1234567` | Country detection, carrier ID, format validation, OSINT lookup links |
| 6 | **`crt`** | `example.com` | Certificate Transparency logs, SSL certs, subdomains, certificate authorities |
| 7 | **`dnsbrute`** | `example.com` | DNS subdomain brute-force with built-in wordlist (300+ subs), wildcard filtering |

### Advanced OSINT (free APIs, no keys needed)

| # | Module | Target | What It Finds |
|---|--------|--------|---------------|
| 8 | **`shodan`** | `8.8.8.8` | Shodan InternetDB: ports, services, CVEs, hostnames, tags, risk assessment |
| 9 | **`wayback`** | `example.com` | Wayback Machine CDX API: URL history, status codes, content types, yearly timeline |
| 10 | **`dorks`** | `example.com` | **43 Google dork queries** across 7 categories — admin panels, configs, databases, docs, errors, vulns, emails |
| 11 | **`leaks`** | `user@example.com` | Paste dump search (psbdmp.ws), HaveIBeenPwned breach check, OSINT leak database links |
| 12 | **`urlscan`** | `example.com` | urlscan.io: page screenshots, scan history, IPs, servers, countries (set `URLSCAN_API_KEY`) |

### Developer APIs (free API keys recommended)

| # | Module | Target | What It Finds | Env Var |
|---|--------|--------|---------------|---------|
| 13 | **`github`** | `example.com` | GitHub dorking: API keys, tokens, passwords, .env, config files, credentials | `GITHUB_TOKEN` |
| 14 | **`otx`** | `example.com` | AlienVault OTX: threat pulses, passive DNS, URL lists, malware samples | `OTX_API_KEY` |
| 15 | **`builtwith`** | `example.com` | BuiltWith: full tech stack — CMS, frameworks, CDN, analytics, web servers, databases | `BUILTWITH_API_KEY` |

>  **All modules work without API keys.**  
> Modules 13-15 generate search URLs for manual browser inspection when no key is set.  
> Modules 8-12 use completely free APIs with no key required.  
> Modules 1-7 need nothing at all.

---

##  Features

### Beautiful Terminal UI
- **Rich-powered output** with color-coded findings, panels, tables, and progress spinners
- Findings color-coded:  success,  warning,  critical,  informational
- Summary panels with target, findings count, warnings, and execution time

### Interactive & Report Modes
- **Interactive shell** — rapid multi-target investigation workflows
- **HTML reports** — professional, self-contained, dark-themed, shareable
- **JSON export** — all module data structured for further processing

### Professional-Grade Engineering
- **Threaded scanning** — subdomain brute-force, port scanning, username checks all use thread pools
- **DNS security analysis** — SPF, DMARC, MX, NS, TXT records
- **Technology fingerprinting** — WordPress, React, Cloudflare, jQuery, Shopify detection
- **HaveIBeenPwned integration** — breach checking for email addresses
- **Auto-detection** — phone carrier, email provider, IP geolocation, tech stack
- **Risk assessment** — Shodan module calculates risk level based on open ports, CVEs, and exposed services

---

##  Installation

```bash
# Clone the repository
git clone https://github.com/godes/reconforge.git
cd reconforge

# Install dependencies (only 2 packages needed)
pip install -r requirements.txt

# Or install as a package
pip install -e .

# Verify it works
python -m reconforge --version
```

**Dependencies:** `rich` (beautiful terminal UI) + `dnspython` (DNS lookups) — that's it!

### Optional API Keys (set as environment variables)

```bash
# GitHub dorking — get a token at https://github.com/settings/tokens
export GITHUB_TOKEN="ghp_..."

# AlienVault OTX — free at https://otx.alienvault.com
export OTX_API_KEY="..."

# BuiltWith — free at https://builtwith.com
export BUILTWITH_API_KEY="..."

# urlscan.io — free at https://urlscan.io
export URLSCAN_API_KEY="..."
```

---

##  Quick Start

### Single Module Reconnaissance

```bash
# Core OSINT (no keys)
python -m reconforge domain example.com
python -m reconforge email user@example.com
python -m reconforge username johndoe
python -m reconforge ip 8.8.8.8
python -m reconforge phone "+972-54-1234567"

# Certificates & DNS
python -m reconforge crt example.com
python -m reconforge dnsbrute example.com

# Free APIs (no keys)
python -m reconforge shodan 8.8.8.8
python -m reconforge wayback example.com
python -m reconforge dorks example.com
python -m reconforge leaks user@example.com

# Free APIs (key optional)
python -m reconforge urlscan example.com
python -m reconforge github example.com
python -m reconforge otx example.com
python -m reconforge builtwith example.com
```

### Generate HTML Reports

```bash
python -m reconforge domain example.com --report
python -m reconforge email user@example.com -o custom_report.html
```

### Interactive Mode

```bash
python -m reconforge interactive
```

Then explore with commands like:
```
domain example.com
email user@example.com --report
shodan 8.8.8.8
crt google.com
wayback example.com
leaks test@example.com
builtwith example.com
```

**Short aliases:** `d` (domain), `e` (email), `u` (username), `p` (phone), `l` (leaks), `g` (dorks), `git` (github), `history` (wayback), `brute` (dnsbrute), `bt` (builtwith)

---

##  Module Deep Dive

### 1. `domain` — Domain Reconnaissance
Comprehensive DNS and web analysis:
```
 Resolved to 2 IP address(es): 104.20.23.154, 172.66.147.243
 Open ports (4): 80/HTTP, 443/HTTPS, 8080/HTTP-Alt, 8443/HTTPS-Alt
 MX Records (2): Priority 10: mx.example.com
 Nameservers (2): ns1.example.com, ns2.example.com
 SPF Record: v=spf1 include:_spf.google.com ~all
 DMARC: v=DMARC1; p=reject; rua=mailto...
 Security Headers:  HSTS,  X-Frame-Options,  CSP
 Technologies: Cloudflare, React, jQuery
 Discovered 3 subdomain(s): www, mail, admin
```

### 2. `email` — Email Intelligence
Digs into email addresses for security and OSINT:
```
 Valid email format
 Domain: example.com
 Provider: Google Workspace (Gmail)
 Pattern: firstname.lastname
 MX Records: alt1.gmail-smtp-in.l.google.com
 Not found in known data breaches
 OSINT: HaveIBeenPwned, Hunter.io, EmailRep.io
```

### 3. `username` — Username Search
Checks **40+ social platforms** in parallel:
```
 Characters: lowercase, digits
 3 platforms found:
    GitHub: https://github.com/johndoe
    Reddit: https://reddit.com/user/johndoe
    Medium: https://medium.com/@johndoe
```

### 4. `ip` — IP Address Investigation
Geolocates and profiles IP addresses:
```
 Location: Mountain View, California, US
 ISP: Google LLC
 ASN: AS15169 Google LLC
 Coordinates: 37.4056, -122.0775
 Hostname: dns.google
 Open Ports: 53/DNS, 443/HTTPS
```

### 5. `phone` — Phone Number Analysis
Detects carrier, country, and type:
```
 Formatted: 054-123-4567
 Country: Israel
 Type: Mobile
 Carrier: Partner (Orange)
```

### 6. `crt` — Certificate Transparency
Queries crt.sh for SSL certificate intelligence:
```
 Retrieved 65 certificate records
 3 unique domain(s) in certificates
 Issued by 2 CA(s): Let's Encrypt, Cloudflare
 Certificate period: 2023-01-15 to 2024-01-15
 Subdomains: www, mail, api, dev, admin
```

### 7. `dnsbrute` — DNS Subdomain Brute-force
Brute-forces subdomains with 300+ wordlist:
```
 Brute-forcing 302 subdomains...
 Found 12 real subdomain(s):
    api.example.com → 93.184.216.34
    dev.example.com → 93.184.216.35
    mail.example.com → 93.184.216.36
 Potentially interesting: admin, jenkins, vpn, jira
```

### 8. `shodan` — Shodan InternetDB
Free Shodan intelligence (no API key):
```
 Hostnames: dns.google
 Open Ports: 53/DNS, 443/HTTPS
 Tags: cloud, hosting
 No known CVEs detected
 Risk Level:  Low
```

### 9. `wayback` — Wayback Machine History
Historical URL analysis from Internet Archive:
```
 Found 200 historical snapshots
 4 unique URL(s) discovered
 Status Codes:  200 (180),  404 (12),  301 (8)
 Time Range: 2016-01-15 → 2024-06-01
 Content Types: text/html (150), image/* (30), application/* (20)
 Interesting URLs: /admin/, /backup/, /config/
```

### 10. `dorks` — Google Dork Generator
Generates **43 Google dork queries** across 7 categories:
```
 Admin Panels & Login Pages (8 dorks)
 Configuration & Sensitive Files (8 dorks)
 Database Files (5 dorks)
 Exposed Documents (6 dorks)
 Error Messages & Debug (5 dorks)
 Security & Vulnerability (7 dorks)
 Employee & Email Info (4 dorks)
```
Each dork is a clickable Google search URL for manual investigation.

### 11. `leaks` — Leak Intelligence
Searches for breached data across free sources:
```
 Searching paste dump databases...
 No pastes found in public dump databases
 Checking data breach databases...
 Found in 271 data breach(es)!
 Severity:  High (widely exposed!)
 OSINT: HaveIBeenPwned, IntelX, DeHashed, Firefox Monitor
```

### 12. `urlscan` — urlscan.io Screenshots & History
Domain screenshots and scan history (set `URLSCAN_API_KEY`):
```
 Searching urlscan.io for recent scans...
 Found 5 recent scan(s):
    IPs: 104.20.23.154, 172.66.147.243
    Servers: Cloudflare, nginx
    Countries: US, DE, NL
    Screenshots available
```

### 13. `github` — GitHub Dorking
Searches GitHub for leaked credentials (set `GITHUB_TOKEN`):
```
 GitHub Dork Queries:
 API Keys & Tokens: api_key, api_secret, access_token, private_key
 Passwords & Credentials: password, db_password, connectionString
 Configuration Files: .env, config.json, credentials, wp-config.php
 Sensitive Files: dump.sql, id_rsa, kubeconfig, .dockercfg
```

### 14. `otx` — AlienVault OTX Threat Intel
Threat intelligence from the community (set `OTX_API_KEY`):
```
 Querying AlienVault OTX...
 Found in 5 threat pulse(s)!
     Pulse: Emotet Campaign January 2024
       Tags: malware, emotet, phishing
 Passive DNS: 23 records, 5 unique IPs
 Associated URLs: 12 URLs
 Malware samples: 3
```

### 15. `builtwith` — BuiltWith Technology Profile
Full technology stack profiling (set `BUILTWITH_API_KEY`):
```
 Querying BuiltWith for technology profile...
 Found 24 technologies in 8 categories
 Analytics & Tracking: Google Analytics, Facebook Pixel, Hotjar
 Content Management System: WordPress 6.4
 Content Delivery Network: Cloudflare
 Web Frameworks: React 18, Next.js
 Web Servers: nginx/1.24
 JavaScript Libraries: jQuery 3.7, Lodash
 SSL/TLS: Let's Encrypt
 Email: Google Workspace
```

---

##  **Live Terminal Demos**

Here's what ReconForge actually looks like in action — real output from real runs:

###  Domain Reconnaissance
```
$ python -m reconforge domain example.com

╔══════════════════════════════════════════════════════╗
║                  ██████                              ║
║                  ██  ██                             ║
║  █████  █████  █████  █████  █████  █████  █████   ║
║  ██  ██ ██  ██ ██ ██  ██  ██ ██  ██ ██  ██ ██  ██  ║
║  █████  █████  ██ ██  █████  █████  ██  ██ ██  ██  ║
║  ██     ██     ██ ██  ██     ██     ██  ██ ██  ██  ║
║  ██     ██     ██ ██  ██     ██     █████  █████   ║
║                                              ██     ║
║                                          █████      ║
║                                                      ║
║  ██████  ██████  ███  ██ ██████  ██████  █████      ║
║  ██  ██ ██  ██ ████  ██ ██     ██     ██           ║
║  █████  █████  ██ ██ ██ █████  ██     █████        ║
║  ██  ██ ██  ██ ██ ████ ██     ██        ██         ║
║  ██  ██ ██  ██ ██  ███ ██████  █████  █████        ║
║                                                      ║
╚══════════════════════════════════════════════════════╝

    Automated Cyber Reconnaissance Framework v1.0.0
                                      by godes


────────────────────────────  Target: example.com ────────────────────────────
Type: Domain | Started: 13:51:35

╭─────────────────────────  Reconnaissance Summary ──────────────────────────╮
│ Target    example.com                                                        │
│ Type      Domain                                                             │
│ Findings  19 items                                                           │
╰──────────────────────────────────────────────────────────────────────────────╯

 Findings
──────────────────────────────────────────────────
   Resolved to 2 IP address(es): 104.20.23.154, 172.66.147.243
   Open ports (4): 80/HTTP, 443/HTTPS, 8080/HTTP-Alt, 8443/HTTPS-Alt
   MX Records (1): Priority 0: 
   Nameservers (2): elliott.ns.cloudflare.com, hera.ns.cloudflare.com
   SPF Record: v=spf1 -all...
   DMARC: v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s...
   Website: https://example.com (HTTP 200)
   Security Headers: 0/7 secure 
   Discovered 1 subdomain(s): www

Completed in 1.9s
```

###  Email Intelligence (with HIBP breach check)
```
$ python -m reconforge email test@example.com

─────────────────────────  Target: test@example.com ──────────────────────────
Type: Email | Started: 13:52:02

╭─────────────────────────  Reconnaissance Summary ──────────────────────────╮
│ Target    test@example.com                                                   │
│ Type      Email                                                              │
│ Findings  8 items                                                            │
╰──────────────────────────────────────────────────────────────────────────────╯

 Findings
──────────────────────────────────────────────────
  Valid email format
   Local part: test
   Domain: example.com
   Provider: Custom / Self-hosted
   MX Records found (1)
   Breached! Found in 271 data breach(es)

 OSINT Lookup Links
  • Google Search
  • HaveIBeenPwned
  • EmailRep.io
  • Hunter.io

Completed in 0.2s
```

###  IP Geolocation & Analysis
```
$ python -m reconforge ip 8.8.8.8

──────────────────────────────  Target: 8.8.8.8 ──────────────────────────────
Type: IP Address | Started: 13:52:03

╭─────────────────────────  Reconnaissance Summary ──────────────────────────╮
│ Target    8.8.8.8                                                            │
│ Type      IP Address                                                         │
│ Findings  12 items                                                           │
╰──────────────────────────────────────────────────────────────────────────────╯

 Findings
──────────────────────────────────────────────────
   Target: 8.8.8.8
   Public IP (internet)
   Hostname: dns.google
   Location: Ashburn, Virginia, United States
   ISP: Google LLC
   ASN: AS15169 Google LLC
   Coordinates: 39.03, -77.5
   Hosted (datacenter IP)
   Open Ports (2): 53/DNS, 443/HTTPS

 OSINT Lookup Links
  • Shodan → https://www.shodan.io/host/8.8.8.8
  • VirusTotal → https://www.virustotal.com/gui/ip-address/8.8.8.8
  • AbuseIPDB → https://www.abuseipdb.com/check/8.8.8.8
  • Censys → https://search.censys.io/search?resource=hosts&q=8.8.8.8
  • Google Maps → https://www.google.com/maps?q=39.03,-77.5

Completed in 1.7s
```

###  Shodan Intelligence
```
$ python -m reconforge shodan 8.8.8.8

──────────────────────────────  Target: 8.8.8.8 ──────────────────────────────
Type: Shodan Intel | Started: 13:52:02

╭─────────────────────────  Reconnaissance Summary ──────────────────────────╮
│ Target    8.8.8.8                                                            │
│ Type      Shodan Intel                                                       │
│ Findings  9 items                                                            │
╰──────────────────────────────────────────────────────────────────────────────╯

 Findings
──────────────────────────────────────────────────
   Target: 8.8.8.8
  Data found in Shodan InternetDB
   Hostnames (2): dns.google, webmail.decisiongroup.com.br
   Open Ports (2): Port 53/DNS, Port 443/HTTPS
   No known CVEs detected by Shodan

 OSINT Lookup Links
  • Shodan (full details)
  • Shodan InternetDB
  • VirusTotal
  • AbuseIPDB
  • Censys

Completed in 0.2s
```

---

##  Project Structure

```
reconforge/
├── reconforge/
│   ├── __init__.py            # Package info (v1.0.0)
│   ├── __main__.py            # CLI entry point + interactive mode
│   ├── cli.py                 # Rich-powered terminal UI
│   ├── report.py              # HTML report generator
│   ├── modules/
│   │   ├── domain.py          # 1. Domain reconnaissance
│   │   ├── email.py           # 2. Email intelligence
│   │   ├── username.py        # 3. Username search (40+ platforms)
│   │   ├── ip_tools.py        # 4. IP investigation
│   │   ├── phone.py           # 5. Phone number analysis
│   │   ├── crt.py             # 6. Certificate Transparency (crt.sh)
│   │   ├── dnsbrute.py        # 7. DNS subdomain brute-force
│   │   ├── shodan.py          # 8. Shodan InternetDB
│   │   ├── wayback.py         # 9. Wayback Machine history
│   │   ├── dorks.py           # 10. Google dork generator
│   │   ├── leaks.py           # 11. Leak/paste/breach search
│   │   ├── urlscan.py         # 12. urlscan.io screenshots
│   │   ├── github_dork.py     # 13. GitHub dorking
│   │   ├── otx.py             # 14. AlienVault OTX threat intel
│   │   └── builtwith.py       # 15. BuiltWith tech profile
│   └── utils/
│       ├── dns.py             # DNS lookups (MX, NS, TXT, SPF, DMARC)
│       ├── http.py            # HTTP requests + rate limiting
│       ├── cache.py           # Disk-based caching (~/.cache/reconforge/)
│       └── ports.py           # Threaded port scanning (21 ports)
├── output/                    # Generated HTML reports
├── requirements.txt           # rich + dnspython
├── pyproject.toml             # Package configuration
├── setup.py                   # Install script
├── LICENSE                    # MIT License
└── README.md                  # This file
```

---

##  CLI Reference

```
Usage: reconforge [module] [target] [options]

Modules:
  domain <domain>       DNS, IPs, MX/NS/SPF/DMARC, subdomains, ports, tech
  email <email>         Format, provider, HIBP breach, MX, pattern analysis
  username <user>       40+ social platform search
  ip <address>          Geolocation, ISP, ASN, ports, proxy detection
  phone <number>        Country, carrier, type detection
  crt <domain>          Certificate Transparency (crt.sh)
  shodan <ip>           Shodan InternetDB intelligence
  leaks <target>        Leak/paste/breach search
  github <domain>       GitHub dorking (set GITHUB_TOKEN)
  wayback <domain>      Wayback Machine URL history
  dorks <domain>        Google dork query generator
  dnsbrute <domain>     DNS subdomain brute-force
  urlscan <domain>      urlscan.io screenshots (set URLSCAN_API_KEY)
  otx <target>          AlienVault OTX threat intel (set OTX_API_KEY)
  builtwith <domain>    BuiltWith tech profile (set BUILTWITH_API_KEY)
  interactive           Interactive reconnaissance shell

Options:
  -o, --output FILE     Save HTML report to FILE
  -r, --report          Generate HTML report in output/
  -v, --version         Show version and exit
  -h, --help            Show this help message

Examples:
  reconforge domain example.com -r
  reconforge email user@example.com -o report.html
  reconforge shodan 8.8.8.8 --report
  reconforge interactive
```

---

##  API Keys Reference

| Env Variable | Required For | Get One | Module |
|-------------|--------------|---------|--------|
| `GITHUB_TOKEN` | Live GitHub code search | [GitHub Tokens](https://github.com/settings/tokens) | `github` |
| `OTX_API_KEY` | Live OTX threat data | [AlienVault OTX](https://otx.alienvault.com) | `otx` |
| `BUILTWITH_API_KEY` | Live tech profiling | [BuiltWith](https://builtwith.com) | `builtwith` |
| `URLSCAN_API_KEY` | Live scan results | [urlscan.io](https://urlscan.io) | `urlscan` |

---

##  Disclaimer

> **For authorized security testing and educational purposes only.**  
> The author is not responsible for any misuse of this tool. Always ensure you have explicit permission before performing reconnaissance on any target. Many of these techniques (Google dorking, GitHub scanning, DNS brute-forcing, port scanning) can trigger security alarms and rate limits. Use responsibly.

---

##  License

[MIT License](LICENSE) — do what you want, just don't blame me.
