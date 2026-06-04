"""
ReconForge — HTML Report Generator
═══════════════════════════════════
Generates professional HTML intelligence reports with
styling, charts, and interactive elements.
"""

import json
import os
import html
from datetime import datetime


REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconForge Report — {target}</title>
    <style>
        :root {{
            --bg: #0a0e17;
            --bg-card: #111827;
            --bg-tertiary: #1a2332;
            --border: #1e3a5f;
            --text: #e2e8f0;
            --text-muted: #64748b;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --accent-glow: rgba(59, 130, 246, 0.15);
            --green: #22c55e;
            --yellow: #f59e0b;
            --red: #ef4444;
            --radius: 8px;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; padding: 40px 20px; }}

        /* Header */
        .header {{
            text-align: center;
            padding: 40px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 40px;
        }}
        .header h1 {{
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 8px;
            background: linear-gradient(135deg, var(--accent), #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header .meta {{
            color: var(--text-muted);
            font-size: 14px;
        }}
        .header .badge {{
            display: inline-block;
            padding: 4px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 12px;
        }}
        .badge-domain {{ background: #1e3a5f; color: #93c5fd; }}
        .badge-email {{ background: #065f46; color: #6ee7b7; }}
        .badge-username {{ background: #5c3d0e; color: #fcd34d; }}
        .badge-ip {{ background: #5c0e0e; color: #fca5a5; }}
        .badge-phone {{ background: #5c280e; color: #fdba74; }}

        /* Summary Card */
        .summary {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 24px;
            margin-bottom: 32px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-top: 16px;
        }}
        .summary-item {{
            text-align: center;
            padding: 16px;
            background: var(--bg-tertiary);
            border-radius: var(--radius);
        }}
        .summary-item .value {{
            font-size: 28px;
            font-weight: 700;
        }}
        .summary-item .label {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        /* Sections */
        .section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 24px;
            margin-bottom: 24px;
        }}
        .section h2 {{
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .finding-item {{
            padding: 8px 12px;
            margin-bottom: 4px;
            border-radius: 4px;
            font-size: 14px;
            display: flex;
            align-items: flex-start;
            gap: 8px;
        }}
        .finding-item .icon {{
            flex-shrink: 0;
        }}
        .finding-green {{ color: var(--green); }}
        .finding-yellow {{ color: var(--yellow); }}
        .finding-red {{ color: var(--red); }}
        .finding-cyan {{ color: var(--accent); }}

        /* Key-Value Table */
        .kv-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }}
        .kv-table td {{
            padding: 6px 12px;
            border-bottom: 1px solid var(--border);
        }}
        .kv-table td:first-child {{
            color: var(--text-muted);
            font-weight: 500;
            white-space: nowrap;
            width: 160px;
        }}

        /* Platform list */
        .platform-list {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 8px;
        }}
        .platform-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 12px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            text-decoration: none;
            color: var(--text);
            font-size: 13px;
            transition: all 0.2s;
        }}
        .platform-item:hover {{
            border-color: var(--accent);
            background: var(--accent-glow);
        }}
        .platform-status {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            flex-shrink: 0;
        }}
        .status-found {{ background: var(--green); }}
        .status-unknown {{ background: var(--text-muted); }}

        /* Links */
        .link-list {{
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .link-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            text-decoration: none;
            color: var(--accent);
            font-size: 13px;
            transition: all 0.2s;
        }}
        .link-item:hover {{
            border-color: var(--accent);
            background: var(--accent-glow);
        }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 20px;
            color: var(--text-muted);
            font-size: 13px;
            border-top: 1px solid var(--border);
            margin-top: 40px;
        }}

        /* Responsive */
        @media (max-width: 600px) {{
            .container {{ padding: 20px 12px; }}
            .summary-grid {{ grid-template-columns: 1fr 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        {content}
        <div class="footer">
            <p>Generated by <strong>ReconForge</strong> — Automated Cyber Reconnaissance Framework</p>
            <p style="font-size: 12px; margin-top: 4px;">{generated_at}</p>
            <p style="font-size: 12px; margin-top: 6px; color: var(--text-muted);">Built with  by <a href="https://github.com/godes" style="color: var(--accent); text-decoration: none;">godes</a></p>
        </div>
    </div>
</body>
</html>"""


def _css_class_for_type(type_str: str) -> str:
    """Get CSS class for entity type badge."""
    mapping = {
        "Domain": "badge-domain",
        "Email": "badge-email",
        "Username": "badge-username",
        "IP Address": "badge-ip",
        "Phone Number": "badge-phone",
        "Certificate Transparency": "badge-domain",
        "Shodan Intel": "badge-ip",
        "Leak Intelligence": "badge-email",
        "GitHub Dorking": "badge-username",
        "Wayback History": "badge-domain",
        "Google Dorking": "badge-domain",
        "DNS Brute-force": "badge-domain",
        "urlscan.io": "badge-domain",
        "OTX Threat Intel": "badge-ip",
        "BuiltWith Profile": "badge-domain",
        "Technology Profile": "badge-domain",
    }
    return mapping.get(type_str, "badge-domain")


def _finding_class(finding: str) -> str:
    """Get CSS class for a finding line."""
    if finding.startswith("") or finding.startswith(""):
        return "finding-red"
    if finding.startswith(""):
        return "finding-yellow"
    if finding.startswith("") or finding.startswith(""):
        return "finding-green"
    if finding.startswith("") or finding.startswith("") or finding.startswith(""):
        return "finding-cyan"
    return ""


def _build_findings_html(findings: list) -> str:
    """Build findings section HTML."""
    if not findings:
        return ""

    result_html = '<div class="section"><h2> Findings</h2>'
    for finding in findings:
        if not finding.strip():
            continue

        icon = "•"
        finding_text = finding
        if finding[0] in ["", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""]:
            icon = finding[0]
            finding_text = finding[1:].strip()

        cls = _finding_class(finding)
        result_html += f'<div class="finding-item {cls}"><span class="icon">{icon}</span><span>{html.escape(finding_text)}</span></div>'

    result_html += "</div>"
    return result_html


def _build_data_html(data: dict) -> str:
    """Build data table section HTML."""
    if not data:
        return ""

    sections = []
    lookup_links = data.get("lookup_links", [])

    if data:
        section_html = '<div class="section"><h2> Detailed Data</h2><table class="kv-table">'
        for key, value in data.items():
            if key == "lookup_links":
                continue
            if isinstance(value, (str, int, float, bool)):
                section_html += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{value}</td></tr>"
            elif isinstance(value, list):
                items = ", ".join(str(v) for v in value[:6])
                if len(value) > 6:
                    items += f" ... ({len(value)} total)"
                section_html += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{items}</td></tr>"
        section_html += "</table></div>"
        sections.append(section_html)

    # Platforms found (username module)
    platforms = data.get("platforms_found", [])
    if platforms:
        section_html = '<div class="section"><h2> Found On Platforms</h2><div class="platform-list">'
        for p in platforms:
            section_html += f'<a href="{p["url"]}" target="_blank" rel="noopener" class="platform-item">'
            section_html += f'<span class="platform-status status-found"></span>'
            section_html += f'<span>{p["name"]}</span>'
            section_html += f'<span style="color:var(--text-muted);margin-left:auto;font-size:11px;">HTTP {p.get("status", "?")}</span>'
            section_html += "</a>"
        section_html += "</div></div>"
        sections.append(section_html)

    # Lookup links
    if lookup_links:
        section_html = '<div class="section"><h2> OSINT Lookup Links</h2><div class="link-list">'
        for link in lookup_links:
            if link and link.get("url"):
                section_html += f'<a href="{link["url"]}" target="_blank" rel="noopener" class="link-item">'
                section_html += f'<span>{link["title"]}</span>'
                section_html += f'<span style="color:var(--text-muted);margin-left:auto;font-size:11px;"></span>'
                section_html += "</a>"
        section_html += "</div></div>"
        sections.append(section_html)

    return "\n".join(sections)


def _build_warnings_html(warnings: list) -> str:
    """Build warnings section HTML."""
    if not warnings:
        return ""

    html = '<div class="section" style="border-color:var(--yellow);">'
    html += "<h2> Warnings</h2>"
    for w in warnings:
        html += f'<div class="finding-item finding-yellow"><span></span><span>{w}</span></div>'
    html += "</div>"
    return html


def generate_report(result: dict, output_path: str = "output/report.html"):
    """Generate an HTML report file from reconnaissance results."""
    target = result.get("target", "unknown")
    target_type = result.get("type", "Unknown")
    findings = result.get("findings", [])
    warnings = result.get("warnings", [])
    data = result.get("data", {}).copy() if result.get("data") else {}
    data["lookup_links"] = data.get("lookup_links", [])

    findings_count = len(findings)
    warnings_count = len(warnings)

    # Build content
    content_parts = []

    # Header section inline
    header_html = f"""
    <div class="header">
        <h1>Reconnaissance Report</h1>
        <div class="meta">
            Target: <strong>{target}</strong> &middot; Type: {target_type}
            &middot; {datetime.now().strftime('%Y-%m-%d %H:%M')}
        </div>
        <span class="badge {_css_class_for_type(target_type)}">{target_type}</span>
    </div>
    """

    # Summary card
    header_html += f"""
    <div class="summary">
        <h2 style="font-size:14px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin:0;border:none;">Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="value" style="color:var(--accent);">{target}</div>
                <div class="label">Target</div>
            </div>
            <div class="summary-item">
                <div class="value" style="color:var(--green);">{findings_count}</div>
                <div class="label">Findings</div>
            </div>
            <div class="summary-item">
                <div class="value" style="color:var(--yellow);">{warnings_count}</div>
                <div class="label">Warnings</div>
            </div>
            <div class="summary-item">
                <div class="value" style="color:var(--accent);">{target_type}</div>
                <div class="label">Type</div>
            </div>
        </div>
    </div>
    """
    content_parts.append(header_html)

    # Findings
    content_parts.append(_build_findings_html(findings))

    # Warnings
    content_parts.append(_build_warnings_html(warnings))

    # Data
    content_parts.append(_build_data_html(data))

    content = "\n".join(content_parts)

    # Render template
    output_html = REPORT_TEMPLATE.format(
        target=html.escape(target),
        content=content,
        generated_at=f"Generated on {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}",
    )

    # Write output
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(output_html)

    return os.path.abspath(output_path)
