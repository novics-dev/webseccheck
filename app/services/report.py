"""
Report generation service — PDF and HTML.
"""

from __future__ import annotations

import io
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Severity weights for risk score calculation
SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

SEVERITY_COLORS = {
    "critical": (0.8, 0.1, 0.1),
    "high": (0.9, 0.4, 0.0),
    "medium": (0.9, 0.7, 0.0),
    "low": (0.2, 0.5, 0.8),
    "info": (0.5, 0.5, 0.5),
}

OWASP_NAMES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
    "GDPR": "GDPR Technical Measures",
}


def calculate_risk_score(scan) -> float:
    """Calculate 0-100 risk score based on severity of failed/warning checks."""
    checks = scan.checks.all() if hasattr(scan.checks, 'all') else scan.checks
    total_weight = 0
    for check in checks:
        if check.status in ("fail", "warning"):
            total_weight += SEVERITY_WEIGHTS.get(check.severity, 0)
    return min(float(total_weight), 100.0)


def generate_html_summary(scan_id: int) -> str:
    """Generate an HTML email summary for the given scan."""
    from app.models import Scan, ScanCheck

    scan = Scan.query.get(scan_id)
    if not scan:
        return "<p>Scan not found.</p>"

    checks = ScanCheck.query.filter_by(scan_id=scan_id).order_by(
        ScanCheck.owasp_category, ScanCheck.severity
    ).all()

    failed = [c for c in checks if c.status == "fail"]
    warnings = [c for c in checks if c.status == "warning"]
    passed = [c for c in checks if c.status == "pass"]

    risk = scan.risk_score
    if risk >= 70:
        risk_color = "#dc3545"
        risk_label = "HIGH RISK"
    elif risk >= 40:
        risk_color = "#fd7e14"
        risk_label = "MEDIUM RISK"
    else:
        risk_color = "#28a745"
        risk_label = "LOW RISK"

    rows = ""
    for check in failed + warnings:
        sev_colors = {
            "critical": "#721c24",
            "high": "#856404",
            "medium": "#004085",
            "low": "#155724",
            "info": "#6c757d",
        }
        color = sev_colors.get(check.severity, "#6c757d")
        rows += f"""
        <tr>
            <td style="padding:8px;border:1px solid #dee2e6">{check.owasp_category}</td>
            <td style="padding:8px;border:1px solid #dee2e6">{check.check_name}</td>
            <td style="padding:8px;border:1px solid #dee2e6;color:{color};font-weight:bold">{check.severity.upper()}</td>
            <td style="padding:8px;border:1px solid #dee2e6">{check.description[:100]}</td>
        </tr>"""

    target = scan.permission.target_url if scan.permission else "Unknown"
    completed = scan.completed_at.strftime("%Y-%m-%d %H:%M UTC") if scan.completed_at else "N/A"

    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>WebSecCheck Report</title></head>
<body style="font-family:Arial,sans-serif;max-width:800px;margin:0 auto;padding:20px">
    <div style="background:#1a1a2e;color:white;padding:20px;border-radius:8px;margin-bottom:20px">
        <h1 style="margin:0">WebSecCheck Security Report</h1>
        <p style="margin:5px 0 0">OWASP Top 10 + GDPR Technical Measures Security Scan</p>
    </div>

    <div style="background:#f8f9fa;padding:15px;border-radius:8px;margin-bottom:20px">
        <table style="width:100%">
            <tr>
                <td><strong>Target:</strong> {target}</td>
                <td><strong>Completed:</strong> {completed}</td>
            </tr>
            <tr>
                <td><strong>Risk Score:</strong> <span style="color:{risk_color};font-size:1.5em;font-weight:bold">{risk:.0f}/100 ({risk_label})</span></td>
                <td><strong>Total Checks:</strong> {scan.total_checks}</td>
            </tr>
        </table>
    </div>

    <div style="margin-bottom:20px">
        <span style="background:#dc3545;color:white;padding:5px 10px;border-radius:4px;margin-right:8px">
            {len(failed)} Failed
        </span>
        <span style="background:#fd7e14;color:white;padding:5px 10px;border-radius:4px;margin-right:8px">
            {len(warnings)} Warnings
        </span>
        <span style="background:#28a745;color:white;padding:5px 10px;border-radius:4px">
            {len(passed)} Passed
        </span>
    </div>

    <h2>Findings</h2>
    <table style="width:100%;border-collapse:collapse">
        <thead>
            <tr style="background:#343a40;color:white">
                <th style="padding:10px;text-align:left">Category</th>
                <th style="padding:10px;text-align:left">Check</th>
                <th style="padding:10px;text-align:left">Severity</th>
                <th style="padding:10px;text-align:left">Description</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>

    <p style="margin-top:30px;color:#6c757d;font-size:0.9em">
        This report was generated automatically by WebSecCheck.
        Results are indicative and should be verified by a security professional.
    </p>
</body>
</html>"""


def generate_pdf_report(scan_id: int) -> bytes:
    """Generate a professional PDF report using ReportLab."""
    from app.models import Scan, ScanCheck

    scan = Scan.query.get(scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    checks = ScanCheck.query.filter_by(scan_id=scan_id).order_by(
        ScanCheck.owasp_category, ScanCheck.severity
    ).all()

    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"WebSecCheck Report — Scan #{scan_id}",
    )

    styles = getSampleStyleSheet()
    style_title = ParagraphStyle("title", parent=styles["Title"], fontSize=24, spaceAfter=12)
    style_h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=16, spaceAfter=8)
    style_h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, spaceAfter=6)
    style_normal = styles["Normal"]
    style_small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8)

    story = []
    target = scan.permission.target_url if scan.permission else "Unknown"
    completed = scan.completed_at.strftime("%Y-%m-%d %H:%M UTC") if scan.completed_at else "N/A"
    risk = scan.risk_score

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("WebSecCheck", style_title))
    story.append(Paragraph("OWASP Top 10 + GDPR Technical Measures Security Assessment Report", styles["Heading2"]))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.darkblue))
    story.append(Spacer(1, 1 * cm))

    cover_data = [
        ["Target URL:", target],
        ["Scan ID:", str(scan_id)],
        ["Completed:", completed],
        ["Risk Score:", f"{risk:.0f} / 100"],
        ["Total Checks:", str(scan.total_checks)],
        ["Failed:", str(scan.failed_checks)],
        ["Warnings:", str(scan.warning_checks)],
        ["Passed:", str(scan.passed_checks)],
    ]
    cover_table = Table(cover_data, colWidths=[4 * cm, 12 * cm])
    cover_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
    ]))
    story.append(cover_table)
    story.append(PageBreak())

    # ------------------------------------------------------------------
    # Executive Summary
    # ------------------------------------------------------------------
    story.append(Paragraph("Executive Summary", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 0.3 * cm))

    failed_checks = [c for c in checks if c.status == "fail"]
    warning_checks = [c for c in checks if c.status == "warning"]

    if risk >= 70:
        risk_summary = "HIGH RISK — Immediate action required."
        risk_color = colors.red
    elif risk >= 40:
        risk_summary = "MEDIUM RISK — Security improvements recommended."
        risk_color = colors.orange
    else:
        risk_summary = "LOW RISK — Minor improvements suggested."
        risk_color = colors.green

    story.append(Paragraph(f"Risk Score: {risk:.0f}/100 — {risk_summary}", style_normal))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        f"This automated security assessment scanned {target} across all OWASP Top 10 (2021) "
        f"categories and GDPR Technical Measures. "
        f"{len(failed_checks)} checks failed and {len(warning_checks)} warnings were identified.",
        style_normal
    ))
    story.append(Spacer(1, 1 * cm))

    # Summary table
    summary_data = [
        ["Severity", "Failed", "Warning"],
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        f_count = sum(1 for c in failed_checks if c.severity == sev)
        w_count = sum(1 for c in warning_checks if c.severity == sev)
        if f_count or w_count:
            summary_data.append([sev.capitalize(), str(f_count), str(w_count)])

    if len(summary_data) > 1:
        sum_table = Table(summary_data, colWidths=[5 * cm, 3 * cm, 3 * cm])
        sum_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ]))
        story.append(sum_table)

    story.append(PageBreak())

    # ------------------------------------------------------------------
    # Findings per OWASP category
    # ------------------------------------------------------------------
    story.append(Paragraph("Detailed Findings", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 0.5 * cm))

    categories = {}
    for check in checks:
        categories.setdefault(check.owasp_category, []).append(check)

    for cat_id in sorted(categories.keys()):
        cat_checks = categories[cat_id]
        cat_name = OWASP_NAMES.get(cat_id, cat_id)
        story.append(Paragraph(f"{cat_id} — {cat_name}", style_h2))

        for check in cat_checks:
            sev_color_rgb = SEVERITY_COLORS.get(check.severity, (0.5, 0.5, 0.5))
            sev_color = colors.Color(*sev_color_rgb)

            check_data = [
                [Paragraph(f"<b>{check.check_name}</b>", style_normal),
                 Paragraph(f"<font color='{'red' if check.status == 'fail' else 'orange' if check.status == 'warning' else 'green'}'><b>{check.status.upper()}</b></font>  [{check.severity.upper()}]", style_normal)],
                [Paragraph(check.description or "", style_small), ""],
            ]
            if check.remediation:
                check_data.append([Paragraph(f"<i>Remediation: {check.remediation[:200]}</i>", style_small), ""])

            check_table = Table(check_data, colWidths=[11 * cm, 5 * cm])
            check_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightblue),
                ("SPAN", (0, 1), (-1, 1)),
                ("SPAN", (0, 2), (-1, 2)),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(KeepTogether([check_table, Spacer(1, 0.2 * cm)]))

        story.append(Spacer(1, 0.5 * cm))

    # ------------------------------------------------------------------
    # Remediation table
    # ------------------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("Remediation Recommendations", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 0.5 * cm))

    rem_data = [["Category", "Check", "Severity", "Recommendation"]]
    for check in sorted(failed_checks + warning_checks, key=lambda c: (
        ["critical", "high", "medium", "low", "info"].index(c.severity)
    )):
        if check.remediation:
            rem_data.append([
                check.owasp_category,
                check.check_name[:30],
                check.severity.capitalize(),
                Paragraph(check.remediation[:150], style_small),
            ])

    if len(rem_data) > 1:
        rem_table = Table(rem_data, colWidths=[1.5 * cm, 4 * cm, 2 * cm, 9 * cm])
        rem_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(rem_table)

    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(
        "This report was generated automatically by WebSecCheck. "
        "Results are indicative and should be validated by a qualified security professional.",
        style_small,
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
