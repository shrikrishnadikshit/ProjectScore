"""One-page-plus PDF rating report for a company (BRS reporting: board-ready output)."""

from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.graphics.shapes import Circle, Drawing, Line, PolyLine, Rect, String
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


BANDS = [(300, 499, "F", "Critical"), (500, 599, "D", "Basic"), (600, 699, "C", "Intermediate"),
         (700, 799, "B", "Good"), (800, 900, "A", "Advanced")]
WIDTH = A4[0] - 36 * mm
RISK_COLORS = {"low": "#1f8a4c", "Low": "#1f8a4c", "medium": "#c58a06", "Moderate": "#c58a06",
               "high": "#d4631c", "Elevated": "#d4631c", "critical": "#c62f3a", "High": "#c62f3a"}


def _x(score: float, x0: float, w: float) -> float:
    return x0 + (max(300, min(900, score)) - 300) / 600 * w


def band_bar(score: int | None, average: int | None = None) -> Drawing:
    """The 300 to 900 scale in coloured bands, with markers for the company and the peer average."""
    w, h = WIDTH, 22 * mm
    d = Drawing(w, h)
    y, bh = 7 * mm, 4 * mm
    for lo, hi, g, name in BANDS:
        x1, x2 = _x(lo, 0, w), _x(hi + (1 if hi < 900 else 0), 0, w)
        d.add(Rect(x1, y, x2 - x1 - 1, bh, fillColor=colors.HexColor(GRADE_COLORS[g]), strokeColor=None))
        d.add(String((x1 + x2) / 2, y - 3.6 * mm, f"{g} · {name}", fontName="Helvetica", fontSize=7,
                     fillColor=MUTED, textAnchor="middle"))
        d.add(String((x1 + x2) / 2, y - 6.6 * mm, f"{lo}–{hi}", fontName="Helvetica", fontSize=6.5,
                     fillColor=MUTED, textAnchor="middle"))
    if average is not None:
        xa = _x(average, 0, w)
        d.add(Line(xa, y - 0.5 * mm, xa, y + bh + 0.5 * mm, strokeColor=INK, strokeWidth=1, strokeDashArray=[2, 1.5]))
        d.add(String(xa, y + bh + 1.5 * mm, f"Peer average {average}", fontName="Helvetica", fontSize=7,
                     fillColor=MUTED, textAnchor="middle"))
    if score is not None:
        xs = _x(score, 0, w)
        d.add(Circle(xs, y + bh / 2, 2.6 * mm, fillColor=colors.white, strokeColor=INK, strokeWidth=1.4))
        label_y = y + bh + 5 * mm if average is not None and abs(_x(average, 0, w) - xs) < 30 * mm else y + bh + 1.5 * mm
        d.add(String(xs, label_y, f"This company {score}", fontName="Helvetica-Bold", fontSize=7.5,
                     fillColor=INK, textAnchor="middle"))
    return d


def distribution_chart(dist: list[dict], score: int) -> Drawing:
    w, h = WIDTH, 34 * mm
    d = Drawing(w, h)
    base, top = 7 * mm, h - 4 * mm
    peak = max(1.0, max(b["share"] for b in dist))
    bw = w / len(dist)
    for i, b in enumerate(dist):
        bh = (top - base) * b["share"] / peak
        mine = b["from"] <= score <= b["to"]
        if bh > 0:
            d.add(Rect(i * bw + 2, base, bw - 4, bh, strokeColor=None,
                       fillColor=PRIMARY if mine else colors.HexColor("#b8c4cf")))
            d.add(String(i * bw + bw / 2, base + bh + 1.2 * mm, f"{b['share']:.0f}%", fontName="Helvetica",
                         fontSize=6.5, fillColor=MUTED, textAnchor="middle"))
        d.add(String(i * bw + bw / 2, 2 * mm, str(b["from"]), fontName="Helvetica", fontSize=6.5,
                     fillColor=INK if mine else MUTED, textAnchor="middle"))
    d.add(Line(0, base, w, base, strokeColor=RULE, strokeWidth=0.6))
    return d


def trend_chart(t: dict) -> Drawing:
    w, h = WIDTH, 44 * mm
    d = Drawing(w, h)
    left, right, bottom, top = 10 * mm, w - 2 * mm, 7 * mm, h - 3 * mm
    lo_s, hi_s = 300, 900
    ys = lambda v: bottom + (v - lo_s) / (hi_s - lo_s) * (top - bottom)  # noqa: E731
    span = (t["end"] - t["start"]).total_seconds() or 1
    xs = lambda at: left + (at - t["start"]).total_seconds() / span * (right - left)  # noqa: E731
    for lo, hi, g, _ in BANDS:  # faint band backgrounds
        d.add(Rect(left, ys(lo), right - left, ys(min(hi + 1, 900)) - ys(lo), strokeColor=None,
                   fillColor=colors.HexColor(GRADE_COLORS[g]), fillOpacity=0.07))
    for v in (300, 500, 700, 900):
        d.add(Line(left, ys(v), right, ys(v), strokeColor=RULE, strokeWidth=0.4))
        d.add(String(left - 1.5 * mm, ys(v) - 2, str(v), fontName="Helvetica", fontSize=6.5, fillColor=MUTED,
                     textAnchor="end"))
    # month labels
    m = t["start"].replace(day=1)
    while m <= t["end"]:
        if m >= t["start"]:
            d.add(String(xs(m), 2 * mm, m.strftime("%b %y") if m.month == 1 else m.strftime("%b"), fontName="Helvetica",
                         fontSize=6.5, fillColor=MUTED, textAnchor="middle"))
        m = m.replace(year=m.year + 1, month=1) if m.month == 12 else m.replace(month=m.month + 1)
    pts = t["points"]
    if len(pts) == 1:
        p = pts[0]
        d.add(Circle(xs(p["at"]), ys(p["score"]), 1.6 * mm, fillColor=PRIMARY, strokeColor=None))
    elif pts:
        coords = []
        for i, p in enumerate(pts):  # step line: a score holds until the next scan
            if i:
                coords += [xs(p["at"]), ys(pts[i - 1]["score"])]
            coords += [xs(p["at"]), ys(p["score"])]
        coords += [right, ys(pts[-1]["score"])]
        d.add(PolyLine(coords, strokeColor=PRIMARY, strokeWidth=1.6))
    return d


def timeline_chart(inc: dict) -> Drawing:
    w, h = WIDTH, 16 * mm
    d = Drawing(w, h)
    y = 9 * mm
    start = datetime(inc["start"].year, inc["start"].month, inc["start"].day, tzinfo=timezone.utc)
    end = datetime(inc["end"].year, inc["end"].month, inc["end"].day, tzinfo=timezone.utc)
    span = (end - start).total_seconds() or 1
    xs = lambda dt: (dt - start).total_seconds() / span * w  # noqa: E731
    d.add(Line(0, y, w, y, strokeColor=RULE, strokeWidth=1.2))
    m = start.replace(day=1)
    while m <= end:
        if m >= start:
            d.add(Line(xs(m), y - 1 * mm, xs(m), y + 1 * mm, strokeColor=RULE, strokeWidth=0.6))
            if m.month in (1, 4, 7, 10):
                d.add(String(xs(m), 2 * mm, m.strftime("%b %Y"), fontName="Helvetica", fontSize=6.5,
                             fillColor=MUTED, textAnchor="middle"))
        m = m.replace(year=m.year + 1, month=1) if m.month == 12 else m.replace(month=m.month + 1)
    for e in inc["events"]:
        dt = datetime(e["date"].year, e["date"].month, e["date"].day, tzinfo=timezone.utc)
        d.add(Circle(xs(dt), y, 1.8 * mm, fillColor=colors.HexColor("#c62f3a"), strokeColor=colors.white))
    return d


def _executive_sections(entity: dict, extras: dict, st: dict) -> list:
    out = []
    score = entity["score"]

    # Industry comparison
    peer = extras.get("peers")
    if peer is not None:
        block = [Paragraph("Comparison with peers", st["h2"])]
        if peer.get("group") is None:
            block.append(Paragraph(f"Peer comparison appears once at least {peer['min_group']} companies are rated "
                                   f"{'in ' + peer['industry'] if peer.get('industry') else 'on the platform'}.", st["body"]))
        else:
            diff = score - peer["average"]
            where = "above" if diff > 0 else "below" if diff < 0 else "level with"
            grp = peer["group"]
            block.append(Paragraph(
                f"<b>{score}</b> for this company against an average of <b>{peer['average']}</b> for {grp} "
                f"({peer['count']} companies): {abs(diff) if diff else ''} {'points ' if diff else ''}{where} the average. "
                f"It scores higher than {peer['percentile']}% of the group.", st["body"]))
            if peer.get("fallback"):
                block.append(Paragraph(f"Fewer than {peer['min_group']} companies are rated in {peer['industry']} so far, "
                                       "so all rated companies are used.", st["small"]))
            block.append(Spacer(1, 2 * mm))
            block.append(Paragraph("Share of the group in each score range", st["small"]))
            block.append(distribution_chart(peer["distribution"], score))
        out.append(KeepTogether(block))

    # 12-month trend
    t = extras.get("trend")
    if t is not None:
        block = [Paragraph("Score over the last 12 months", st["h2"])]
        if t.get("points"):
            hi, lo = t["highest"], t["lowest"]
            block.append(Paragraph(
                f"Highest <b>{hi['score']}</b> on {hi['at']:%d %b %Y} · lowest <b>{lo['score']}</b> on {lo['at']:%d %b %Y} · "
                f"change over the period {'+' if t['change'] >= 0 else ''}{t['change']} points. "
                "Includes every rescan, accepted dispute and change in findings.", st["body"]))
            block.append(trend_chart(t))
            if len(t["points"]) < 3:
                block.append(Paragraph("Monitoring started recently, so the history is short.", st["small"]))
        else:
            block.append(Paragraph("No scans in the last 12 months.", st["body"]))
        out.append(KeepTogether(block))

    # Ransomware and incident risk
    rw, ir = extras.get("ransomware"), extras.get("incident_risk")
    if rw or ir:
        cells = []
        if rw:
            reasons = [s["label"] for s in rw["signals"]][:3]
            cells.append([Paragraph("<b>Ransomware risk</b>", st["body"]),
                          Paragraph(f"<font color='{RISK_COLORS[rw['level']]}'><b>{rw['level'].capitalize()}</b></font> "
                                    f"(index {rw['index']:.2f} of 1)", st["body"]),
                          Paragraph(("Main reasons: " + "; ".join(reasons) + ".") if reasons else
                                    "No outside signs of the usual ransomware entry points.", st["cell"])])
        if ir:
            cells.append([Paragraph("<b>Security incident risk</b>", st["body"]),
                          Paragraph(f"<font color='{RISK_COLORS[ir['level']]}'><b>{ir['level']}</b></font>", st["body"]),
                          Paragraph(ir["text"], st["cell"])])
        tbl = Table(cells, colWidths=[42 * mm, 34 * mm, None])
        tbl.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
                                 ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        out.append(KeepTogether([Paragraph("Risk outlook", st["h2"]), tbl, Spacer(1, 1.5 * mm),
                                 Paragraph("Indicative. Ransomware risk comes from the outside signs ransomware gangs "
                                           "use to get in, weighted and combined. Incident risk follows the rating band; "
                                           "we check it against real incidents as our records grow.", st["small"])]))

    # Publicly disclosed incidents
    inc = extras.get("incidents")
    if inc is not None:
        block = [Paragraph("Publicly disclosed incidents in the last 18 months", st["h2"]), timeline_chart(inc)]
        if inc["events"]:
            rows = [["Date", "Type", "What happened"]]
            for e in inc["events"]:
                rows.append([e["date"].strftime("%d %b %Y"), e["kind"], Paragraph(e["text"], st["cell"])])
            tbl = Table(rows, colWidths=[24 * mm, 36 * mm, None], repeatRows=1)
            tbl.setStyle(TableStyle([("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5), ("FONT", (0, 1), (1, -1), "Helvetica", 8.5),
                                     ("TEXTCOLOR", (0, 0), (-1, 0), MUTED), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
                                     ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            block.append(tbl)
        else:
            block.append(Paragraph("No publicly disclosed incidents found in the last 18 months.", st["body"]))
        block.append(Spacer(1, 1.5 * mm))
        block.append(Paragraph("Covers data breaches published by Have I Been Pwned, listings on ransomware leak sites, "
                               "and incidents reported in the news or by regulators that we have recorded.", st["small"]))
        out.append(KeepTogether(block))
    return out


def build_pdf(entity: dict, history: list[dict], organization: str, now: datetime | None = None,
              extras: dict | None = None) -> bytes:
    extras = extras or {}
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
        peer = extras.get("peers") or {}
        story.append(Spacer(1, 3 * mm))
        story.append(band_bar(entity["score"], peer.get("average")))
        story.extend(_executive_sections(entity, extras, st))

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
                  "300–900 score. Severe issues can cap the score.", st["body"]),
    ]))
    story.append(KeepTogether([
        Paragraph("Changes, disputes and data sources", st["h2"]),
        Paragraph(f"<b>Rating model.</b> This report uses rating model {(history[-1].get('model_version') if history else '') or 'n/a'}. "
                  "When we change how ratings are calculated, the new model version is recorded with every score, the "
                  "change is described on our methodology page before it takes effect, and score history is not rewritten.",
                  st["body"]),
        Spacer(1, 2 * mm),
        Paragraph("<b>Disputes.</b> A rated company can challenge any finding, free of charge, through our public "
                  "dispute form or its own account. Each dispute is reviewed by a person; accepted disputes remove "
                  "the finding and the score is recalculated.", st["body"]),
        Spacer(1, 2 * mm),
        Paragraph("<b>Sources.</b> DNS and certificate transparency logs, the company's public websites and mail "
                  "servers, CISA KEV and FIRST EPSS, NVD, Have I Been Pwned, abuse.ch, Spamhaus, Shodan InternetDB, and "
                  "public incident reports. Peer figures use only aggregates of at least five companies.", st["body"]),
    ]))
    story.append(KeepTogether([
        Paragraph("Disclaimer", st["h2"]),
        Paragraph("This report is provided for the recipient's internal risk management only. It is based on information "
                  "observable from the internet at the time of scanning and may be incomplete or out of date; it is not an "
                  "audit, a penetration test or a certification, and it is not investment, legal or insurance advice. "
                  "ProjectScore gives no warranty that the information is accurate or complete, and accepts no "
                  "liability for decisions made using it, to the extent the law allows. Please do not share this "
                  "report outside your organisation without the rated company's consent.", st["small"]),
    ]))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()
