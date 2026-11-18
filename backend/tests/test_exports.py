import csv
import io

from docx import Document
from fastapi.testclient import TestClient
from openpyxl import load_workbook
from pptx import Presentation

from app import auth, db, main
from app.auth import create_user
from app.collectors import RawFinding
from app.models import Entity
from app.scan import scan_entity

PASSWORD = "correct-horse-battery"
EVIL = RawFinding("tls", "tls_expired", "=HYPERLINK(\"http://x\")", "critical", "vendor.example")


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    create_user(s, "Other", "admin@o.example", PASSWORD, role="admin")
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def test_exports_and_board_report():
    admin, other = login("admin@c.example"), login("admin@o.example")
    eid = admin.post("/api/entities", json={"name": "Vendor", "primary_domain": "vendor.example"}).json()["id"]
    s = db.SessionLocal()
    scan_entity(s, s.get(Entity, eid), lambda e: ([EVIL], {"tls": 40}))
    s.close()

    r = admin.get("/api/exports/portfolio.csv")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows[0][0] == "Company" and rows[1][0] == "Vendor" and rows[1][7] == "1"

    f = admin.get("/api/exports/findings.csv").content.decode("utf-8-sig")
    assert "'=HYPERLINK" in f  # formula neutralised

    wb = load_workbook(io.BytesIO(admin.get("/api/exports/portfolio.xlsx").content))
    assert wb.sheetnames == ["Portfolio", "Open findings"] and wb["Portfolio"]["A2"].value == "Vendor"
    assert str(wb["Open findings"]["D2"].value).startswith("'=")

    assert other.get("/api/exports/portfolio.csv").content.decode("utf-8-sig").count("\n") == 1  # header only
    assert admin.get("/api/exports/portfolio.pdf").status_code == 404

    prs = Presentation(io.BytesIO(admin.get("/api/reports/board.pptx").content))
    text = " ".join(sh.text_frame.text for sl in prs.slides for sh in sl.shapes if sh.has_text_frame)
    assert len(prs.slides) == 6 and "Recommended actions" in text
    doc = Document(io.BytesIO(admin.get("/api/reports/board.docx").content))
    body = " ".join(p.text for p in doc.paragraphs) + " ".join(c.text for t in doc.tables for row in t.rows for c in row.cells)
    assert "Highest-risk vendors" in body and "Vendor" in body and "critical" in body
