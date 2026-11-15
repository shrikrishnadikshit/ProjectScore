"""One-page-plus PDF rating report for a company (BRS reporting: board-ready output)."""

from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

FACTOR_LABELS = {
    "compromise": "Compromise & malicious activity",
    "vulnerability": "Vulnerabilities & patching",
    "network_exposure": "Network service exposure",
    "identity": "Identity & credential exposure",
    "email_security": "Email security",
    "tls": "TLS / encryption",
    "web_security": "Web application security",
    "dns_health": "DNS health",
    "breach_history": "Breach & ransomware history",
    "brand": "Brand & impersonation",
}
GRADE_COLORS = {"A": "#1f8a4c", "B": "#5c9e2e", "C": "#c58a06", "D": "#d4631c", "F": "#c62f3a"}
GRADE_TEXT = {
    "A": "Advanced: strong external hygiene, low observed risk",
    "B": "Good: minor weaknesses",
    "C": "Intermediate: material weaknesses requiring attention",
    "D": "Basic: significant weaknesses; elevated likelihood of incident",
    "F": "Critical: severe exposures or evidence of compromise",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {"critical": "#a3142a", "high": "#c62f3a", "medium": "#c58a06", "low": "#4a7fb5", "info": "#8a97a5"}
INK, MUTED, RULE, BAND = colors.HexColor("#15202b"), colors.HexColor("#5b6b7b"), colors.HexColor("#dde3ea"), colors.HexColor("#f0f3f6")
PRIMARY = colors.HexColor("#0f6e6e")


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontName="Helvetica-Bold", fontSize=20, leading=24,
                                textColor=INK, alignment=0, spaceAfter=2),
        "sub": ParagraphStyle("s", parent=base["Normal"], fontSize=9.5, textColor=MUTED, leading=13),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12.5,
                             textColor=INK, spaceBefore=12, spaceAfter=6),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=9.5, leading=13, textColor=INK),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontSize=8, leading=10.5, textColor=MUTED),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontSize=8.5, leading=11, textColor=INK),
        "score": ParagraphStyle("sc", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=34, leading=38,
                                textColor=INK, alignment=TA_CENTER),
        "grade": ParagraphStyle("g", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=30, leading=34,
                                textColor=colors.white, alignment=TA_CENTER),
    }


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(PRIMARY)
    canvas.rect(0, A4[1] - 6 * mm, A4[0], 6 * mm, stroke=0, fill=1)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "ProjectScore security rating report · Confidential")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(entity: dict, history: list[dict], organization: str, now: datetime | None = None) -> bytes:
    now = now or datetime.now(timezone.utc)
    st = _styles()
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=18 * mm, title=f"{entity['name']} security rating",
                            author="ProjectScore")
    story = []

    story.append(Paragraph(entity["name"], st["title"]))
    meta = [entity["primary_domain"]]
    if entity.get("industry"):
        meta.append(entity["industry"])
    meta.append(f"Tier {entity['tier']}")
    story.append(Paragraph(" · ".join(meta), st["sub"]))
    story.append(Paragraph(f"Prepared for {organization} on {now.strftime('%d %B %Y')}", st["sub"]))
    story.append(Spacer(1, 8 * mm))

    grade = entity.get("grade")
    if entity.get("score") is None:
        story.append(Paragraph("This company has not been scanned yet.", st["body"]))
    else:
        latest = history[-1] if history else {}
        coverage = (latest.get("trace") or {}).get("coverage")
        gates = (latest.get("trace") or {}).get("gates") or []
        summary = [Paragraph(f"<b>{GRADE_TEXT.get(grade, '')}</b>", st["body"]), Spacer(1, 2 * mm)]
        if latest.get("created_at"):
            summary.append(Paragraph(f"Last scanned {latest['created_at'][:10]} · rating model {latest.get('model_version', '')}",
                                     st["small"]))
        if coverage is not None and coverage < 1:
            summary.append(Paragraph(f"Based on {round(coverage * 100)}% of rating factors by weight; the rest are not yet "
                                     "assessed.", st["small"]))
        for g in gates:
            summary.append(Paragraph(f"<font color='#c62f3a'>Score capped at {g['cap']} because of a severe issue.</font>",
                                     st["small"]))
        if len(history) >= 2:
            first, last = history[0]["overall"], history[-1]["overall"]
            change = last - first
            summary.append(Paragraph(f"Change since {history[0]['created_at'][:10]}: "
                                     f"{'+' if change >= 0 else ''}{change} points", st["small"]))
        top = Table([[Paragraph(str(entity["score"]), st["score"]), Paragraph(grade or "–", st["grade"]), summary]],
                    colWidths=[38 * mm, 24 * mm, None], rowHeights=[26 * mm])
        top.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (1, 0), (1, 0), colors.HexColor(GRADE_COLORS.get(grade, "#8a97a5"))),
            ("BOX", (0, 0), (-1, -1), 0.6, RULE),
            ("LEFTPADDING", (2, 0), (2, 0), 10),
        ]))
        story.append(top)
        story.append(Paragraph("Scale: 300 to 900. A 800+, B 700–799, C 600–699, D 500–599, F below 500.", st["small"]))

        factors = sorted(entity.get("factors", {}).items(), key=lambda kv: -kv[1]["weight"])
        if factors:
            story.append(Paragraph("Risk factors", st["h2"]))
            rows = [["Factor", "Grade", "Score", "Weight", "Assets"]]
            for key, f in factors:
                rows.append([FACTOR_LABELS.get(key, key), f["grade"], f"{round(f['score'])}/100",
                             f"{round(f['weight'] * 100)}%", str(f["assets"])])
            t = Table(rows, colWidths=[None, 18 * mm, 22 * mm, 20 * mm, 20 * mm])
            style = [("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5), ("FONT", (0, 1), (-1, -1), "Helvetica", 9),
                     ("TEXTCOLOR", (0, 0), (-1, 0), MUTED), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
                     ("ALIGN", (1, 0), (-1, -1), "CENTER"), ("TOPPADDING", (0, 0), (-1, -1), 5),
                     ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]
            for i, (_, f) in enumerate(factors, start=1):
                style += [("TEXTCOLOR", (1, i), (1, i), colors.HexColor(GRADE_COLORS.get(f["grade"], "#8a97a5"))),
                          ("FONT", (1, i), (1, i), "Helvetica-Bold", 10)]
            t.setStyle(TableStyle(style))
            story.append(t)

    findings = sorted(entity.get("findings", []), key=lambda f: (SEVERITY_ORDER.index(f["severity"])
                                                                  if f["severity"] in SEVERITY_ORDER else 9, f["asset"]))
    story.append(Paragraph(f"Open findings ({len(findings)})", st["h2"]))
    if not findings:
        story.append(Paragraph("No open findings.", st["body"]))
    else:
        counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITY_ORDER}
        story.append(Paragraph(" · ".join(f"<font color='{SEVERITY_COLORS[s]}'><b>{n} {s}</b></font>"
                                          for s, n in counts.items() if n), st["body"]))
        story.append(Spacer(1, 3 * mm))
        rows = [["Severity", "Finding", "Asset"]]
        for f in findings:
            rows.append([f["severity"].capitalize(), Paragraph(f["title"], st["cell"]), Paragraph(f["asset"], st["cell"])])
        t = Table(rows, colWidths=[20 * mm, None, 58 * mm], repeatRows=1)
        style = [("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5), ("FONT", (0, 1), (0, -1), "Helvetica-Bold", 8.5),
                 ("TEXTCOLOR", (0, 0), (-1, 0), MUTED), ("BACKGROUND", (0, 0), (-1, 0), BAND),
                 ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
        for i, f in enumerate(findings, start=1):
            style.append(("TEXTCOLOR", (0, i), (0, i), colors.HexColor(SEVERITY_COLORS.get(f["severity"], "#8a97a5"))))
        t.setStyle(TableStyle(style))
        story.append(t)

    story.append(KeepTogether([
        Paragraph("How this rating works", st["h2"]),
        Paragraph("The rating is built only from publicly observable information about the company's internet-facing "
                  "systems, collected without intrusive testing. Each finding contributes severity × confidence × "
                  "time decay to its risk factor; factor penalties are normalised by the number of assets so that "
                  "large and small organisations are compared fairly, then combined using the factor weights into a "
                  "300–900 score. Severe issues can cap the score. Rated companies can dispute findings.", st["body"]),
    ]))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()
