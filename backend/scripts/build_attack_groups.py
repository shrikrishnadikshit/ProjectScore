"""Build app/data/ransomware_groups.json from MITRE ATT&CK Enterprise STIX data.

Usage: python scripts/build_attack_groups.py enterprise-attack.json
Source: https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json).
Keeps only groups and software linked to ransomware, with the techniques they use. The full file is ~55 MB,
too large to load on a small server, so the trimmed file is committed instead and rebuilt when ATT&CK updates.
"""

import json
import re
import sys
from pathlib import Path

CITE = re.compile(r"\s*\(Citation:[^)]*\)")
LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
RANSOM = re.compile(r"ransomware", re.I)


def ext(o, source="mitre-attack"):
    return next((r for r in o.get("external_references", []) if r.get("source_name") == source), {})


def clean(text, limit=600):
    t = LINK.sub(r"\1", CITE.sub("", text or "")).strip()
    if len(t) <= limit:
        return t
    cut = t[:limit]
    return cut[: cut.rfind(". ") + 1] if ". " in cut else cut + "…"


def main(path):
    bundle = json.load(open(path))
    objs = {o["id"]: o for o in bundle["objects"]}
    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
    version = next((o.get("x_mitre_version") for o in bundle["objects"] if o["type"] == "x-mitre-collection"), None)
    uses: dict[str, list[str]] = {}
    for o in bundle["objects"]:
        if o["type"] == "relationship" and o.get("relationship_type") == "uses" and live(o):
            uses.setdefault(o["source_ref"], []).append(o["target_ref"])

    def techniques(sid):
        out = set()
        for t in uses.get(sid, []):
            o = objs.get(t)
            if o and o["type"] == "attack-pattern" and live(o):
                out.add(ext(o).get("external_id"))
        return sorted(x for x in out if x)

    tech_names = {ext(o).get("external_id"): o["name"] for o in bundle["objects"]
                  if o["type"] == "attack-pattern" and live(o)}
    tactics = {ext(o).get("external_id"): [p["phase_name"] for p in o.get("kill_chain_phases", [])]
               for o in bundle["objects"] if o["type"] == "attack-pattern" and live(o)}

    software = {}
    for o in bundle["objects"]:
        if o["type"] in ("malware", "tool") and live(o):
            software[o["id"]] = {"id": ext(o).get("external_id"), "name": o["name"], "type": o["type"],
                                 "ransomware": bool(RANSOM.search(o.get("description", ""))),
                                 "url": ext(o).get("url")}

    groups = []
    for o in bundle["objects"]:
        if o["type"] != "intrusion-set" or not live(o):
            continue
        sw = [software[t] for t in uses.get(o["id"], []) if t in software]
        techs = techniques(o["id"])
        related = (RANSOM.search(o.get("description", "")) or any(s["ransomware"] for s in sw) or "T1486" in techs)
        if not related:
            continue
        # techniques of the group's software count too: that is how it operates
        all_t = set(techs)
        for t in uses.get(o["id"], []):
            if t in software:
                all_t.update(techniques(t))
        groups.append({"id": ext(o).get("external_id"), "kind": "group", "name": o["name"],
                       "aliases": [a for a in o.get("aliases", []) if a != o["name"]][:10],
                       "description": clean(o.get("description")), "url": ext(o).get("url"),
                       "first_seen": (o.get("first_seen") or o.get("created") or "")[:10] or None,
                       "modified": (o.get("modified") or "")[:10],
                       "software": sorted({(s["id"], s["name"]) for s in sw})[:30],
                       "ransomware": sorted({s["name"] for s in sw if s["ransomware"]}),
                       "techniques": sorted(all_t)})
    families = []
    for sid, s in software.items():
        if not s["ransomware"] or s["type"] != "malware":
            continue
        o = objs[sid]
        families.append({"id": s["id"], "kind": "software", "name": s["name"],
                         "aliases": [a for a in o.get("x_mitre_aliases", []) if a != s["name"]][:10],
                         "description": clean(o.get("description")), "url": s["url"],
                         "first_seen": (o.get("created") or "")[:10] or None, "modified": (o.get("modified") or "")[:10],
                         "software": [], "ransomware": [s["name"]], "techniques": techniques(sid)})
    used = {t for g in groups + families for t in g["techniques"]}
    out = {"source": "MITRE ATT&CK Enterprise", "version": version,
           "notice": "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.",
           "techniques": {t: {"name": tech_names.get(t), "tactics": tactics.get(t, [])} for t in sorted(used)},
           "profiles": sorted(groups, key=lambda g: g["name"].lower()) + sorted(families, key=lambda g: g["name"].lower())}
    dest = Path(__file__).resolve().parent.parent / "app" / "data" / "ransomware_groups.json"
    dest.write_text(json.dumps(out, separators=(",", ":"), ensure_ascii=False))
    print(f"{len(groups)} groups, {len(families)} ransomware families, {len(used)} techniques, version {version} -> {dest}")


if __name__ == "__main__":
    main(sys.argv[1])
