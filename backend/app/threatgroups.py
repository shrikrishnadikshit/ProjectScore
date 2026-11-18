"""Ransomware group profiles from MITRE ATT&CK, matched to what our scans see at each vendor.

ATT&CK records which techniques each threat group and ransomware family uses. Our findings are already mapped
to ATT&CK techniques (attack.py), so a vendor is exposed to a group when the group is known to break in using a
technique the vendor has evidence for, for example "Exploit Public-Facing Application" on a vendor with an
exploitable, internet-facing system. The data is a trimmed copy of ATT&CK Enterprise built by
scripts/build_attack_groups.py; it changes about twice a year.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Finding, PortfolioItem, User

router = APIRouter(prefix="/api")
DATA = Path(__file__).resolve().parent / "data" / "ransomware_groups.json"
ENTRY_TACTICS = {"initial-access"}


@lru_cache(maxsize=1)
def data() -> dict:
    return json.loads(DATA.read_text())


def _parent(t: str) -> str:
    return t.split(".")[0]


def tech_url(t: str) -> str:
    return f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"


def evidence_techniques(findings: list[Finding]) -> dict[str, list[str]]:
    """Technique id -> titles of the open findings that give an attacker that technique."""
    from .attack import techniques
    from .attackpaths import paths

    out: dict[str, list[str]] = {}
    for f in findings:
        if f.status != "open":
            continue
        for t in techniques(f.code):
            out.setdefault(t["id"], [])
            if f.title not in out[t["id"]]:
                out[t["id"]].append(f.title)
    for p in paths(findings):
        for s in p["steps"]:
            if s["state"] == "evidence":
                titles = out.setdefault(s["technique"]["id"], [])
                for e in s["evidence"]:
                    if e["title"] not in titles:
                        titles.append(e["title"])
    return out


# Ways in that nearly every group uses (phishing, drive-by). On their own they say nothing about which group
# a vendor should worry about, so a group must also match a more specific way in.
COMMON = {"T1566", "T1189", "T1598", "T1204"}


def match(profile: dict, evidence: dict[str, list[str]]) -> list[dict]:
    """The group's techniques the vendor has evidence for, one row per technique family.

    A group's sub-technique (T1078.004 Cloud Accounts) matches evidence for its parent (T1078 Valid Accounts),
    but is reported once, under the parent, so a broad finding is not counted several times."""
    techs = data()["techniques"]
    have = {_parent(t): t for t in evidence}
    hits: dict[str, dict] = {}
    for t in profile["techniques"]:
        p = _parent(t)
        ev = evidence.get(t) or (evidence.get(have[p]) if p in have else None)
        if not ev or p in hits:
            continue
        key = t if t in evidence else have.get(p, t)
        info = techs.get(key) or techs.get(t, {})
        name = info.get("name") or techs.get(t, {}).get("name")
        tactics = set(techs.get(t, {}).get("tactics", [])) | set(info.get("tactics", []))
        hits[p] = {"id": key, "name": name, "url": tech_url(key), "entry": bool(tactics & ENTRY_TACTICS),
                   "common": p in COMMON, "evidence": ev[:3]}
    return list(hits.values())


def exposure(findings: list[Finding], limit: int = 10) -> list[dict]:
    evidence = evidence_techniques(findings)
    if not evidence:
        return []
    out = []
    for p in data()["profiles"]:
        hits = match(p, evidence)
        entry = [h for h in hits if h["entry"]]
        if not any(not h["common"] for h in entry):
            continue  # only groups that could get in through something specific we saw
        entry.sort(key=lambda h: h["common"])
        out.append({"id": p["id"], "name": p["name"], "kind": p["kind"], "url": p["url"], "aliases": p["aliases"][:4],
                    "ransomware": p["ransomware"][:5], "modified": p["modified"], "entry": entry, "other": [h for h in hits if not h["entry"]][:8]})
    # most specific ways in first, then the groups whose ATT&CK record was updated most recently (still active)
    out.sort(key=lambda g: g["modified"], reverse=True)
    out.sort(key=lambda g: (-sum(not h["common"] for h in g["entry"]), -len(g["other"])))
    return out[:limit]


def _summary(p: dict) -> dict:
    techs = data()["techniques"]
    return {"id": p["id"], "name": p["name"], "kind": p["kind"], "aliases": p["aliases"], "url": p["url"],
            "description": p["description"], "ransomware": p["ransomware"], "first_seen": p["first_seen"],
            "technique_count": len(p["techniques"]),
            "entry_techniques": [{"id": t, "name": techs.get(t, {}).get("name"), "url": tech_url(t)} for t in p["techniques"]
                                 if set(techs.get(t, {}).get("tactics", [])) & ENTRY_TACTICS]}


@router.get("/threat-groups")
def list_groups(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    """Every ransomware group and family, with how many of your vendors it could reach."""
    items = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id)).all()
    names = {i.entity_id: i.entity.name for i in items}
    findings: dict[int, list[Finding]] = {}
    if names:
        for f in session.scalars(select(Finding).where(Finding.entity_id.in_(list(names)), Finding.status == "open")).all():
            findings.setdefault(f.entity_id, []).append(f)
    exposed: dict[str, list[dict]] = {}
    for eid, fs in findings.items():
        for g in exposure(fs, limit=1000):
            exposed.setdefault(g["id"], []).append({"entity_id": eid, "name": names[eid],
                                                    "via": [h["name"] for h in g["entry"] if not h["common"]][:3]})
    d = data()
    profiles = [{**_summary(p), "vendors": exposed.get(p["id"], [])} for p in d["profiles"]]
    profiles.sort(key=lambda p: (-len(p["vendors"]), p["kind"] != "group", p["name"].lower()))
    return {"profiles": profiles, "source": d["source"], "version": d["version"], "notice": d["notice"],
            "groups": sum(p["kind"] == "group" for p in profiles), "families": sum(p["kind"] == "software" for p in profiles)}


@router.get("/threat-groups/{gid}")
def get_group(gid: str, user: User = Depends(auth.current_user)) -> dict:
    p = next((p for p in data()["profiles"] if p["id"] == gid.upper()), None)
    if p is None:
        raise HTTPException(404, "group not found")
    techs = data()["techniques"]
    return {**_summary(p), "software": [{"id": i, "name": n} for i, n in p["software"]],
            "techniques": [{"id": t, "name": techs.get(t, {}).get("name"), "tactics": techs.get(t, {}).get("tactics", []),
                            "url": tech_url(t)} for t in p["techniques"]], "notice": data()["notice"]}


@router.get("/entities/{entity_id}/threat-groups")
def entity_groups(entity_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    fs = session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open")).all()
    every = exposure(fs, limit=1000)
    return {"groups": every[:10], "total": len(every), "notice": data()["notice"], "version": data()["version"]}
