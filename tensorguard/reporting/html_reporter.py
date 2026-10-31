import html
from typing import Dict, Any


def generate_html_report(scan_data: Dict[str, Any], output_path: str = "tensorguard_report.html"):
    """Generate a sleek, standalone HTML security report with dark mode theme."""
    status = scan_data["status"]
    status_color = "#10b981" if status == "PASSED" else "#ef4444"
    status_bg = "rgba(16, 185, 129, 0.12)" if status == "PASSED" else "rgba(239, 68, 68, 0.12)"

    rows_html = ""
    if not scan_data["findings"]:
        rows_html = """
        <tr>
            <td colspan="4" style="text-align: center; padding: 32px; color: #94a3b8; font-size: 0.95rem;">
                No vulnerabilities detected. All serialization artifacts and code paths passed verification.
            </td>
        </tr>
        """
    else:
        for f in scan_data["findings"]:
            sev = f["severity"].upper()
            sev_colors = {
                "CRITICAL": ("#dc2626", "rgba(220, 38, 38, 0.15)"),
                "HIGH": ("#f97316", "rgba(249, 115, 22, 0.15)"),
                "MEDIUM": ("#eab308", "rgba(234, 179, 8, 0.15)"),
                "LOW": ("#38bdf8", "rgba(56, 189, 248, 0.15)"),
            }
            c_text, c_bg = sev_colors.get(sev, ("#94a3b8", "rgba(148, 163, 184, 0.15)"))
            evidence_block = (
                f'<pre style="margin-top: 6px; padding: 8px; background: #090d16; border-radius: 6px; color: #cbd5e1; font-size: 0.8rem; overflow-x: auto;"><code>{html.escape(f["evidence"])}</code></pre>'
                if f.get("evidence")
                else ""
            )

            rows_html += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
                <td style="padding: 14px 16px;">
                    <span style="background: {c_bg}; color: {c_text}; padding: 4px 10px; border-radius: 9999px; font-weight: 700; font-size: 0.75rem; letter-spacing: 0.05em; border: 1px solid {c_text}40;">
                        {sev}
                    </span>
                </td>
                <td style="padding: 14px 16px; font-family: monospace; color: #38bdf8; font-size: 0.85rem;">{html.escape(f["rule_id"])}</td>
                <td style="padding: 14px 16px; font-family: monospace; color: #e2e8f0; font-size: 0.85rem;">{html.escape(f["file_path"])}</td>
                <td style="padding: 14px 16px; color: #cbd5e1; font-size: 0.9rem;">
                    <div>{html.escape(f["message"])}</div>
                    {evidence_block}
                </td>
            </tr>
            """

    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TensorGuard Security Audit - {scan_data['scan_id'][:8]}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: #0b0f19;
            color: #f8fafc;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.5;
            padding: 40px 20px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #1e293b;
            padding-bottom: 24px;
            margin-bottom: 32px;
        }}
        .brand {{
            font-size: 1.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.02em;
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 6px 16px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 0.875rem;
            letter-spacing: 0.05em;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .card {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 12px;
            padding: 20px;
        }}
        .card-label {{
            color: #94a3b8;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 6px;
        }}
        .card-value {{
            font-size: 1.6rem;
            font-weight: 700;
            color: #f8fafc;
        }}
        .table-wrap {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 32px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        th {{
            background: #1e293b;
            color: #94a3b8;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 12px 16px;
        }}
        .meta-box {{
            background: #0f172a;
            border-left: 4px solid #38bdf8;
            padding: 16px 20px;
            border-radius: 0 8px 8px 0;
            margin-bottom: 24px;
            font-size: 0.875rem;
            color: #94a3b8;
        }}
        .meta-box strong {{ color: #f8fafc; }}
        .footer {{
            text-align: center;
            color: #64748b;
            font-size: 0.8rem;
            margin-top: 48px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="brand">TensorGuard Security Report</div>
                <div style="color: #64748b; font-size: 0.85rem; margin-top: 4px;">Supply Chain & Serialization Integrity Audit</div>
            </div>
            <div class="badge" style="background: {status_bg}; color: {status_color}; border: 1px solid {status_color}40;">
                {status}
            </div>
        </div>

        <div class="meta-box">
            <strong>Target:</strong> {html.escape(scan_data['target_path'])} &nbsp;|&nbsp; 
            <strong>Scan ID:</strong> {html.escape(scan_data['scan_id'])} &nbsp;|&nbsp; 
            <strong>Audited At:</strong> {scan_data['timestamp']} &nbsp;|&nbsp; 
            <strong>Standard:</strong> OWASP Top 10 for LLMs (LLM05: Supply Chain)
        </div>

        <div class="stats-grid">
            <div class="card">
                <div class="card-label">Critical Findings</div>
                <div class="card-value" style="color: #ef4444;">{scan_data['critical_count']}</div>
            </div>
            <div class="card">
                <div class="card-label">High Findings</div>
                <div class="card-value" style="color: #f97316;">{scan_data['high_count']}</div>
            </div>
            <div class="card">
                <div class="card-label">Medium Findings</div>
                <div class="card-value" style="color: #eab308;">{scan_data['medium_count']}</div>
            </div>
            <div class="card">
                <div class="card-label">Low Findings</div>
                <div class="card-value" style="color: #38bdf8;">{scan_data['low_count']}</div>
            </div>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th style="width: 120px;">Severity</th>
                        <th style="width: 180px;">Rule ID</th>
                        <th style="width: 260px;">Target File</th>
                        <th>Details & Code Evidence</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Generated automatically by TensorGuard &bull; AI Model Serialization Scanner
        </div>
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)