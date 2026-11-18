"""Exports and the board report (BRS RPT-002, RPT-004).

CSV and Excel exports of the portfolio and of every open finding, and a short board report as PowerPoint
or Word: the portfolio score, grade spread, the riskiest vendors, the biggest drops in 30 days, and how fast
issues get fixed. Cells that start with = + - @ are prefixed with ' so a spreadsheet never runs them as
formulas.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Finding, PortfolioItem, Score, User, VendorProfile

router = APIRouter(prefix="/api")
SEV = ("critical", "high", "medium", "low")
PORTFOLIO_COLS = ["Company", "Domain", "Tier", "Industry", "Score", "Grade", "Change (30 days)", "Critical", "High",
                  "Medium", "Low", "Last scanned", "Business owner", "Contract ends"]
FINDING_COLS = ["Company", "Domain", "Severity", "Finding", "Risk factor", "Asset", "First seen", "Last seen", "Code"]
MIME = {"csv": "text/csv; charset=utf-8",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}


def _safe(v):
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def portfolio(session: Session, org_id: int) -> list[dict]:
    items = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == org_id)).all()
    ids = [i.entity_id for i in items]
    if not ids:
        return []
    counts: dict[int, dict[str, int]] = {}
    for f in session.scalars(select(Finding).where(Finding.entity_id.in_(ids), Finding.status == "open")):
        if f.severity in SEV:
            counts.setdefault(f.entity_id, dict.fromkeys(SEV, 0))[f.severity] += 1
    profiles = {p.entity_id: p for p in session.scalars(select(VendorProfile).where(VendorProfile.org_id == org_id))}
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    rows = []
    for i in items:
        scores = session.scalars(select(Score).where(Score.entity_id == i.entity_id).order_by(Score.created_at, Score.id)).all()
        latest = scores[-1] if scores else None
        before = [s for s in scores if _aware(s.created_at) <= cutoff]
        base = before[-1] if before else (scores[0] if scores else None)
        p = profiles.get(i.entity_id)
        d = (p.details if p else None) or {}
        rows.append({"id": i.entity_id, "name": i.entity.name, "domain": i.entity.primary_domain, "tier": i.tier,
                     "industry": i.entity.industry, "score": latest.overall if latest else None,
                     "grade": latest.grade if latest else None,
                     "change": (latest.overall - base.overall) if latest and base and base is not latest else 0,
                     **counts.get(i.entity_id, dict.fromkeys(SEV, 0)),
                     "scanned": _aware(latest.created_at).date().isoformat() if latest else None,
                     "owner": d.get("business_owner"), "contract_end": d.get("contract_end")})
    return sorted(rows, key=lambda r: r["name"].lower())


def _portfolio_table(rows: list[dict]) -> list[list]:
    return [[r["name"], r["domain"], r["tier"], r["industry"], r["score"], r["grade"], r["change"], r["critical"],
             r["high"], r["medium"], r["low"], r["scanned"], r["owner"], r["contract_end"]] for r in rows]


def _findings_table(session: Session, org_id: int) -> list[list]:
    items = {i.entity_id: i.entity for i in session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == org_id))}
    if not items:
        return []
    order = {s: n for n, s in enumerate(SEV + ("info",))}
    fs = session.scalars(select(Finding).where(Finding.entity_id.in_(list(items)), Finding.status == "open")).all()
    fs = sorted(fs, key=lambda f: (items[f.entity_id].name.lower(), order.get(f.severity, 9), f.title))
    return [[items[f.entity_id].name, items[f.entity_id].primary_domain, f.severity, f.title, f.risk_factor, f.asset_value,
             _aware(f.first_seen).date().isoformat(), _aware(f.last_seen).date().isoformat(), f.code] for f in fs]


def to_csv(header: list[str], rows: list[list]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow([_safe(v) if v is not None else "" for v in r])
    return ("﻿" + buf.getvalue()).encode()  # BOM so Excel reads UTF-8


def to_xlsx(sheets: list[tuple[str, list[str], list[list]]]) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font

    wb = Workbook()
    wb.remove(wb.active)
    for title, header, rows in sheets:
        ws = wb.create_sheet(title[:31])
        ws.append(header)
        for c in ws[1]:
            c.font = Font(bold=True)
        for r in rows:
            ws.append([_safe(v) for v in r])
        ws.freeze_panes = "A2"
        for col in ws.columns:
            width = max(len(str(c.value or "")) for c in col)
            ws.column_dimensions[col[0].column_letter].width = min(60, max(10, width + 2))
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


def _file(data: bytes, kind: str, name: str) -> Response:
    stamp = date.today().isoformat()
    return Response(data, media_type=MIME[kind], headers={"Content-Disposition": f'attachment; filename="{name}-{stamp}.{kind}"'})


@router.get("/exports/portfolio.{kind}")
def export_portfolio(kind: str, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> Response:
    rows = _portfolio_table(portfolio(session, user.org_id))
    if kind == "csv":
        return _file(to_csv(PORTFOLIO_COLS, rows), kind, "portfolio")
    if kind == "xlsx":
        findings = _findings_table(session, user.org_id)
        return _file(to_xlsx([("Portfolio", PORTFOLIO_COLS, rows), ("Open findings", FINDING_COLS, findings)]), kind, "portfolio")
    raise HTTPException(404, "use csv or xlsx")


@router.get("/exports/findings.{kind}")
def export_findings(kind: str, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> Response:
    rows = _findings_table(session, user.org_id)
    if kind == "csv":
        return _file(to_csv(FINDING_COLS, rows), kind, "findings")
    if kind == "xlsx":
        return _file(to_xlsx([("Open findings", FINDING_COLS, rows)]), kind, "findings")
    raise HTTPException(404, "use csv or xlsx")


# ---------- board report ----------

def board_data(session: Session, user: User) -> dict:
    from .workflow import stats

    rows = portfolio(session, user.org_id)
    scored = [r for r in rows if r["score"] is not None]
    avg = round(sum(r["score"] for r in scored) / len(scored)) if scored else None
    grades = {g: sum(r["grade"] == g for r in scored) for g in "ABCDF"}
    riskiest = sorted(scored, key=lambda r: (r["score"], -r["critical"]))[:5]
    drops = sorted([r for r in scored if r["change"] < 0], key=lambda r: r["change"])[:5]
    crit = sum(r["critical"] for r in rows)
    high = sum(r["high"] for r in rows)
    fixes = stats(session, user.org_id)
    actions = []
    for r in riskiest[:3]:
        if r["critical"] or r["high"]:
            actions.append(f"{r['name']}: {r['critical']} critical and {r['high']} high issues open; ask the vendor to fix them.")
    for r in drops[:2]:
        actions.append(f"{r['name']}: score fell {-r['change']} points in 30 days; find out what changed.")
    if fixes.get("overdue"):
        actions.append(f"{fixes['overdue']} tracked fixes are past their due date; follow up with the owners.")
    ending = [r for r in rows if r["contract_end"] and r["contract_end"] <= (date.today() + timedelta(days=90)).isoformat()]
    for r in ending[:3]:
        actions.append(f"{r['name']}: contract ends {r['contract_end']}; decide whether to renew or offboard.")
    return {"org": user.org.name, "date": date.today().strftime("%d %B %Y"), "vendors": len(rows), "scored": len(scored),
            "average": avg, "grade_of_average": _grade(avg), "grades": grades, "critical": crit, "high": high,
            "riskiest": riskiest, "drops": drops, "fixes": fixes, "actions": actions or ["No urgent actions this period."]}


def _grade(score: int | None) -> str | None:
    if score is None:
        return None
    return "A" if score >= 800 else "B" if score >= 700 else "C" if score >= 600 else "D" if score >= 500 else "F"


def _headline(d: dict) -> list[tuple[str, str]]:
    f = d["fixes"]
    return [("Vendors monitored", str(d["vendors"])),
            ("Average score", f"{d['average']} ({d['grade_of_average']})" if d["average"] else "No scans yet"),
            ("Open critical / high issues", f"{d['critical']} / {d['high']}"),
            ("Fixes overdue", str(f.get("overdue", 0))),
            ("Mean time to fix", f"{f['mttr_days']} days" if f.get("mttr_days") is not None else "Not enough data yet"),
            ("Fixed on time", f"{f['on_time_pct']}%" if f.get("on_time_pct") is not None else "Not enough data yet")]


def _vendor_rows(rs: list[dict], change: bool = False) -> list[list[str]]:
    return [[r["name"], str(r["score"]), r["grade"], (f"{r['change']:+d}" if change else f"{r['critical']} / {r['high']}")] for r in rs]


def build_pptx(d: dict) -> bytes:
    from pptx import Presentation
    from pptx.dml.color import RGBColor
    from pptx.util import Inches, Pt

    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
    dark = RGBColor(0x1F, 0x29, 0x37)

    def slide(title: str):
        s = prs.slides.add_slide(prs.slide_layouts[5])
        s.shapes.title.text = title
        tf = s.shapes.title.text_frame
        tf.paragraphs[0].font.size, tf.paragraphs[0].font.bold, tf.paragraphs[0].font.color.rgb = Pt(30), True, dark
        s.shapes.title.left, s.shapes.title.top, s.shapes.title.width, s.shapes.title.height = Inches(0.6), Inches(0.4), Inches(12), Inches(0.9)
        return s

    def table(s, header, rows, top=1.6):
        if not rows:
            box = s.shapes.add_textbox(Inches(0.6), Inches(top), Inches(12), Inches(0.6))
            box.text_frame.text = "Nothing to show."
            return
        t = s.shapes.add_table(len(rows) + 1, len(header), Inches(0.6), Inches(top), Inches(12), Inches(0.45 * (len(rows) + 1))).table
        for c, h in enumerate(header):
            t.cell(0, c).text = h
        for r, row in enumerate(rows, 1):
            for c, v in enumerate(row):
                t.cell(r, c).text = str(v)
        for row in t.rows:
            for cell in row.cells:
                for p in cell.text_frame.paragraphs:
                    p.font.size = Pt(16)

    s = prs.slides.add_slide(prs.slide_layouts[0])
    s.shapes.title.text = "Third-party cyber risk"
    s.placeholders[1].text = f"{d['org']} · board summary · {d['date']}"

    s = slide("Headline")
    table(s, ["Measure", "Now"], [list(x) for x in _headline(d)])

    s = slide("Grade spread")
    table(s, ["Grade", "Vendors"], [[g, str(n)] for g, n in d["grades"].items()])
    note = s.shapes.add_textbox(Inches(0.6), Inches(5.0), Inches(12), Inches(1))
    note.text_frame.text = "Scores run from 300 to 900. A is 800 and above, F is below 500."

    s = slide("Highest-risk vendors")
    table(s, ["Vendor", "Score", "Grade", "Critical / high issues"], _vendor_rows(d["riskiest"]))

    s = slide("Biggest drops in the last 30 days")
    table(s, ["Vendor", "Score", "Grade", "Change"], _vendor_rows(d["drops"], change=True))

    s = slide("Recommended actions")
    box = s.shapes.add_textbox(Inches(0.6), Inches(1.6), Inches(12), Inches(5))
    tf = box.text_frame
    tf.word_wrap = True
    for n, a in enumerate(d["actions"]):
        p = tf.paragraphs[0] if n == 0 else tf.add_paragraph()
        p.text, p.font.size = f"• {a}", Pt(20)
    out = io.BytesIO()
    prs.save(out)
    return out.getvalue()


def build_docx(d: dict) -> bytes:
    from docx import Document

    doc = Document()
    doc.add_heading("Third-party cyber risk: board summary", 0)
    doc.add_paragraph(f"{d['org']} · {d['date']}")

    def table(header, rows):
        if not rows:
            doc.add_paragraph("Nothing to show.")
            return
        t = doc.add_table(rows=1, cols=len(header))
        t.style = "Light Grid Accent 1"
        for c, h in enumerate(header):
            t.rows[0].cells[c].text = h
        for row in rows:
            cells = t.add_row().cells
            for c, v in enumerate(row):
                cells[c].text = str(v)

    doc.add_heading("Headline", 1)
    table(["Measure", "Now"], [list(x) for x in _headline(d)])
    doc.add_heading("Grade spread", 1)
    doc.add_paragraph("Scores run from 300 to 900. A is 800 and above, F is below 500.")
    table(["Grade", "Vendors"], [[g, str(n)] for g, n in d["grades"].items()])
    doc.add_heading("Highest-risk vendors", 1)
    table(["Vendor", "Score", "Grade", "Critical / high issues"], _vendor_rows(d["riskiest"]))
    doc.add_heading("Biggest drops in the last 30 days", 1)
    table(["Vendor", "Score", "Grade", "Change"], _vendor_rows(d["drops"], change=True))
    doc.add_heading("Recommended actions", 1)
    for a in d["actions"]:
        doc.add_paragraph(a, style="List Bullet")
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()


@router.get("/reports/board.{kind}")
def board_report(kind: str, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> Response:
    if kind not in ("pptx", "docx"):
        raise HTTPException(404, "use pptx or docx")
    d = board_data(session, user)
    data = build_pptx(d) if kind == "pptx" else build_docx(d)
    slug = re.sub(r"[^a-z0-9]+", "-", (user.org.name or "board").lower()).strip("-") or "board"
    return _file(data, kind, f"{slug}-board-report")
