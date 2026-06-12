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


def _management_samenvatting(
    target: str,
    risk: float,
    failed_checks: list,
    warning_checks: list,
    all_checks: list,
    scan,
) -> list:
    """
    Bouw de Nederlandstalige managementsamenvatting als een lijst van ReportLab-elementen.
    Analyseert bevindingen dynamisch en schrijft in begrijpelijke taal voor management.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_LEFT

    styles = getSampleStyleSheet()
    style_h1 = ParagraphStyle("mh1", parent=styles["Heading1"], fontSize=16, spaceAfter=8)
    style_h2 = ParagraphStyle("mh2", parent=styles["Heading2"], fontSize=12, spaceAfter=6, spaceBefore=12)
    style_normal = ParagraphStyle("mn", parent=styles["Normal"], fontSize=10, spaceAfter=6, leading=15)
    style_bullet = ParagraphStyle("mbullet", parent=styles["Normal"], fontSize=10, spaceAfter=4,
                                  leading=14, leftIndent=15, bulletIndent=5)
    style_small = ParagraphStyle("msmall", parent=styles["Normal"], fontSize=8)
    style_bold = ParagraphStyle("mbold", parent=styles["Normal"], fontSize=10, fontName="Helvetica-Bold")

    story = []

    # Titel
    story.append(Paragraph("Managementsamenvatting", style_h1))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2c3e6b")))
    story.append(Spacer(1, 0.4 * cm))

    # ---- Risicooordeel ------------------------------------------------
    scan_date = scan.completed_at.strftime("%-d %B %Y") if scan.completed_at else "onbekend"
    if risk >= 70:
        oordeel = "HOOG RISICO"
        oordeel_kleur = colors.HexColor("#dc3545")
        oordeel_tekst = (
            "De beveiligingssituatie van deze website is op dit moment zorgwekkend. "
            "Er zijn ernstige kwetsbaarheden gevonden die direct aangepakt moeten worden. "
            "Wacht hier niet mee: kwaadwillenden kunnen deze zwakke plekken misbruiken "
            "om gegevens te stelen, klanten te misleiden of de dienstverlening te verstoren."
        )
    elif risk >= 40:
        oordeel = "GEMIDDELD RISICO"
        oordeel_kleur = colors.HexColor("#fd7e14")
        oordeel_tekst = (
            "De website heeft een aantal beveiligingsproblemen die serieuze aandacht verdienen. "
            "Er is geen directe ramp op komst, maar als deze punten niet worden opgepakt "
            "groeit het risico op een beveiligingsincident. Aanpak binnen de komende weken "
            "is sterk aanbevolen."
        )
    else:
        oordeel = "LAAG RISICO"
        oordeel_kleur = colors.HexColor("#198754")
        oordeel_tekst = (
            "De basisbeveiliging van deze website is redelijk op orde. "
            "Er zijn enkele verbeterpunten gevonden, maar er zijn geen kritieke of hoge "
            "risico's vastgesteld. De aanbevelingen in dit rapport helpen de website "
            "verder te versterken."
        )

    oordeel_data = [[
        Paragraph(f"<b>Risico-oordeel: {oordeel}</b>", ParagraphStyle(
            "oo", parent=styles["Normal"], fontSize=14, textColor=colors.white, fontName="Helvetica-Bold"
        )),
        Paragraph(f"<b>Risicoscore: {risk:.0f} / 100</b>", ParagraphStyle(
            "os", parent=styles["Normal"], fontSize=14, textColor=colors.white, fontName="Helvetica-Bold",
            alignment=2,
        )),
    ]]
    oordeel_table = Table(oordeel_data, colWidths=[10 * cm, 6 * cm])
    oordeel_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), oordeel_kleur),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(oordeel_table)
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(oordeel_tekst, style_normal))

    # ---- Wat is er onderzocht? -----------------------------------------
    story.append(Paragraph("Wat is er onderzocht?", style_h2))
    story.append(Paragraph(
        f"Op <b>{scan_date}</b> is een geautomatiseerde beveiligingsscan uitgevoerd op "
        f"<b>{target}</b>. Daarbij zijn in totaal <b>{len(all_checks)} beveiligingscontroles</b> "
        f"uitgevoerd, verdeeld over de tien meest voorkomende categorieën van internetbeveiligingsrisico's "
        f"(de internationale OWASP Top 10) én een reeks specifieke privacycontroles op grond van de AVG/GDPR. "
        f"Denk hierbij aan zaken als: hoe goed de website beschermd is tegen hackers die proberen in te breken, "
        f"hoe veilig de verbinding met de website is, of persoonsgegevens goed worden beschermd, "
        f"en of de website voldoet aan privacywetgeving.",
        style_normal
    ))

    # ---- Uitkomsten in één oogopslag -----------------------------------
    story.append(Paragraph("Uitkomsten in één oogopslag", style_h2))

    n_critical = sum(1 for c in failed_checks if c.severity == "critical")
    n_high = sum(1 for c in failed_checks if c.severity == "high")
    n_medium = sum(1 for c in failed_checks + warning_checks if c.severity == "medium")
    n_low = sum(1 for c in failed_checks + warning_checks if c.severity == "low")
    n_pass = sum(1 for c in all_checks if c.status == "pass")

    overzicht_data = [
        ["Resultaat", "Aantal", "Wat betekent dit?"],
        ["🔴  Kritiek / Hoog", f"{n_critical + n_high}",
         "Direct gevaar. Aanpak zo snel mogelijk vereist."],
        ["🟠  Gemiddeld", f"{n_medium}",
         "Verhoogd risico. Aanpak binnen enkele weken gewenst."],
        ["🟡  Laag", f"{n_low}",
         "Beperkt risico. Opnemen in de normale verbeteragenda."],
        ["🟢  Geslaagd", f"{n_pass}",
         "Geen problemen gevonden op dit onderdeel."],
    ]
    overzicht_table = Table(overzicht_data, colWidths=[4 * cm, 2 * cm, 10 * cm])
    overzicht_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e6b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fff5f5"), colors.white,
                                               colors.HexColor("#fffbf0"), colors.HexColor("#f0fff4")]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(overzicht_table)
    story.append(Spacer(1, 0.4 * cm))

    # ---- Belangrijkste bevindingen (dynamisch) -------------------------
    story.append(Paragraph("Belangrijkste bevindingen", style_h2))

    # Groepeer kritieke en hoge bevindingen per categorie
    kritieke = [c for c in failed_checks if c.severity in ("critical", "high")]
    if kritieke:
        story.append(Paragraph(
            "De onderstaande beveiligingsproblemen zijn als <b>kritiek of hoog</b> beoordeeld "
            "en vragen om de snelste opvolging:",
            style_normal
        ))
        for check in kritieke[:8]:  # max 8 bullets om het leesbaar te houden
            cat_naam = OWASP_NAMES.get(check.owasp_category, check.owasp_category)
            ernst = "Kritiek" if check.severity == "critical" else "Hoog"
            story.append(Paragraph(
                f"• <b>{check.check_name}</b> [{ernst}] — {check.description}",
                style_bullet
            ))
        if len(kritieke) > 8:
            story.append(Paragraph(
                f"  … en nog {len(kritieke) - 8} andere kritieke/hoge bevindingen. "
                f"Zie de gedetailleerde bevindingen verderop in dit rapport.",
                style_bullet
            ))
    else:
        story.append(Paragraph(
            "Er zijn geen kritieke of hoge beveiligingsproblemen vastgesteld. "
            "Dit is een positief teken — de basisbeveiliging is op orde.",
            style_normal
        ))
    story.append(Spacer(1, 0.3 * cm))

    # Categorieën met de meeste problemen
    cat_fails: dict[str, int] = {}
    for c in failed_checks + warning_checks:
        cat_fails[c.owasp_category] = cat_fails.get(c.owasp_category, 0) + 1
    top_cats = sorted(cat_fails.items(), key=lambda x: x[1], reverse=True)[:4]

    if top_cats:
        story.append(Paragraph("Aandachtsgebieden", style_h2))
        story.append(Paragraph(
            "De volgende gebieden scoren het minst goed en verdienen extra aandacht:",
            style_normal
        ))
        for cat_id, count in top_cats:
            cat_naam = OWASP_NAMES.get(cat_id, cat_id)
            uitleg = _cat_uitleg_nl(cat_id)
            story.append(Paragraph(
                f"• <b>{cat_naam}</b> ({count} bevinding{'en' if count != 1 else ''}) — {uitleg}",
                style_bullet
            ))
        story.append(Spacer(1, 0.3 * cm))

    # ---- GDPR/AVG-paragraaf --------------------------------------------
    gdpr_fails = [c for c in failed_checks + warning_checks if c.owasp_category == "GDPR"]
    gdpr_pass = [c for c in all_checks if c.owasp_category == "GDPR" and c.status == "pass"]
    if gdpr_fails or gdpr_pass:
        story.append(Paragraph("Privacy en AVG/GDPR", style_h2))
        if gdpr_fails:
            story.append(Paragraph(
                f"Er zijn <b>{len(gdpr_fails)} privacygerelateerde aandachtspunten</b> gevonden. "
                f"De AVG (Algemene Verordening Gegevensbescherming) verplicht organisaties om "
                f"persoonsgegevens zorgvuldig te beschermen. Overtredingen kunnen leiden tot "
                f"hoge boetes (tot 4% van de wereldwijde jaaromzet) en reputatieschade. "
                f"Bekende knelpunten uit deze scan zijn onder andere:",
                style_normal
            ))
            for check in gdpr_fails[:5]:
                story.append(Paragraph(f"• {check.check_name}: {check.description}", style_bullet))
        else:
            story.append(Paragraph(
                "Op het gebied van privacy en AVG/GDPR zijn geen directe problemen vastgesteld. "
                "Dit is een positief signaal richting toezichthouders en bezoekers van de website.",
                style_normal
            ))

    # ---- Advies aan het management -------------------------------------
    story.append(Paragraph("Advies aan het management", style_h2))
    adviezen = []
    if n_critical + n_high > 0:
        adviezen.append(
            f"Los de <b>{n_critical + n_high} kritieke en hoge bevindingen</b> zo snel mogelijk op. "
            f"Wijs een verantwoordelijke aan en stel een deadline van maximaal twee weken."
        )
    if n_medium > 0:
        adviezen.append(
            f"Plan de <b>{n_medium} gemiddelde bevindingen</b> in binnen de komende maand. "
            f"Neem ze op in de backlog van het ontwikkelteam of de leverancier."
        )
    if gdpr_fails:
        adviezen.append(
            "Bespreek de privacybevindingen met de Functionaris Gegevensbescherming (FG) of "
            "een privacyjurist om te beoordelen of er meldplicht of andere verplichtingen gelden."
        )
    adviezen.append(
        "Voer periodiek (minimaal elk kwartaal) een herhaalscan uit om te controleren of "
        "verbeteringen effect hebben gehad en om nieuwe kwetsbaarheden tijdig te signaleren."
    )
    adviezen.append(
        "Laat kritieke bevindingen valideren door een gecertificeerde beveiligingsspecialist "
        "voordat definitieve conclusies worden getrokken."
    )
    for advies in adviezen:
        story.append(Paragraph(f"• {advies}", style_bullet))

    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        "<i>Dit rapport is automatisch gegenereerd door Fortrisk CyberScan. "
        "De resultaten zijn indicatief en dienen te worden beoordeeld door een gekwalificeerde beveiligingsprofessional. "
        "Fortrisk aanvaardt geen aansprakelijkheid voor beslissingen die uitsluitend op basis van dit rapport worden genomen.</i>",
        style_small
    ))
    return story


def _cat_uitleg_nl(cat_id: str) -> str:
    """Eenvoudige managementuitleg per OWASP-categorie in het Nederlands."""
    uitleg = {
        "A01": "Niet alle pagina's en functies zijn goed afgeschermd. Onbevoegden kunnen mogelijk bij informatie die niet voor hen bedoeld is.",
        "A02": "Gegevens worden niet overal even veilig versleuteld verstuurd of opgeslagen. Dit maakt onderschepping makkelijker.",
        "A03": "De website accepteert mogelijk schadelijke invoer van gebruikers, waarmee aanvallers de website kunnen manipuleren.",
        "A04": "De opzet van bepaalde functies bevat beveiligingsgaten die bij het ontwerp hadden moeten worden voorkomen.",
        "A05": "De technische instellingen van de website staan niet optimaal afgesteld, waardoor onnodige risico's ontstaan.",
        "A06": "De website maakt gebruik van software-onderdelen met bekende beveiligingsproblemen die nog niet zijn bijgewerkt.",
        "A07": "Het inlogsysteem heeft zwakke plekken waardoor aanvallers accounts kunnen overnemen of omzeilen.",
        "A08": "Er is onvoldoende controle of de software en data die de website gebruikt wel authentiek en ongewijzigd zijn.",
        "A09": "Verdachte gebeurtenissen worden onvoldoende bijgehouden, waardoor aanvallen moeilijk te detecteren zijn.",
        "A10": "De website kan worden misbruikt om namens zichzelf verzoeken te sturen naar interne systemen.",
        "GDPR": "Er zijn privacygerelateerde tekortkomingen gevonden die mogelijk in strijd zijn met de AVG-wetgeving.",
    }
    return uitleg.get(cat_id, "Zie de gedetailleerde bevindingen voor meer informatie.")


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
        title=f"Fortrisk CyberScan Rapport — Scan #{scan_id}",
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

    failed_checks = [c for c in checks if c.status == "fail"]
    warning_checks = [c for c in checks if c.status == "warning"]

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("Fortrisk CyberScan", style_title))
    story.append(Paragraph("Beveiligingsrapport — OWASP Top 10 &amp; AVG/GDPR", styles["Heading2"]))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2c3e6b")))
    story.append(Spacer(1, 1 * cm))

    cover_data = [
        ["Doelwebsite:", target],
        ["Scan ID:", str(scan_id)],
        ["Voltooid op:", completed],
        ["Risicoscore:", f"{risk:.0f} / 100"],
        ["Totaal controles:", str(scan.total_checks)],
        ["Mislukt:", str(scan.failed_checks)],
        ["Waarschuwingen:", str(scan.warning_checks)],
        ["Geslaagd:", str(scan.passed_checks)],
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
    # Managementsamenvatting (uitgebreid, Nederlandstalig)
    # ------------------------------------------------------------------
    story.extend(_management_samenvatting(target, risk, failed_checks, warning_checks, checks, scan))
    story.append(PageBreak())

    # ------------------------------------------------------------------
    # Gedetailleerde bevindingen per categorie
    # ------------------------------------------------------------------
    story.append(Paragraph("Gedetailleerde bevindingen", style_h1))
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
            check_data = [
                [Paragraph(f"<b>{check.check_name}</b>", style_normal),
                 Paragraph(
                     f"<font color='{'red' if check.status == 'fail' else 'orange' if check.status == 'warning' else 'green'}'>"
                     f"<b>{check.status.upper()}</b></font>  [{check.severity.upper()}]",
                     style_normal
                 )],
                [Paragraph(check.description or "", style_small), ""],
            ]
            if check.remediation:
                check_data.append([Paragraph(f"<i>Aanbeveling: {check.remediation[:200]}</i>", style_small), ""])

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
    # Actielijst (voorheen: Remediation Recommendations)
    # ------------------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("Actielijst", style_h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 0.5 * cm))

    rem_data = [["Categorie", "Bevinding", "Ernst", "Aanbevolen actie"]]
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
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e6b")),
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
        "Dit rapport is automatisch gegenereerd door Fortrisk CyberScan. "
        "De resultaten zijn indicatief en dienen te worden beoordeeld door een gekwalificeerde beveiligingsprofessional.",
        style_small,
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()
