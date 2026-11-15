"""Automatic vendor detection (a company's own suppliers, i.e. your fourth parties).

Companies reveal many of the services they rely on in public DNS: who handles their email (MX), who may
send mail as them (SPF includes), which SaaS tools they have verified their domain with (TXT), who runs
their DNS (NS), and where their websites are hosted (CNAMEs of their subdomains). We read only these
public records; nothing is sent to the company's systems. Each vendor comes with its own domain, so it
can be added to the portfolio and rated like any other company.
"""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .collectors.dns_util import LookupFailed, resolve, txt_records
from .models import Entity, PortfolioItem, Score, User, VendorDetection

router = APIRouter(prefix="/api")
MAX_AGE = timedelta(days=7)

# (pattern matched against the record, vendor name, vendor domain, category)
MX = [
    (r"(^|\.)(google|googlemail)\.com$", "Google Workspace", "google.com", "Email"),
    (r"\.(mail\.)?protection\.outlook\.com$", "Microsoft 365", "microsoft.com", "Email"),
    (r"\.pphosted\.com$", "Proofpoint", "proofpoint.com", "Email security"),
    (r"\.mimecast\.com$", "Mimecast", "mimecast.com", "Email security"),
    (r"\.iphmx\.com$", "Cisco Secure Email", "cisco.com", "Email security"),
    (r"\.barracudanetworks\.com$", "Barracuda", "barracuda.com", "Email security"),
    (r"\.messagelabs\.com$", "Broadcom (Symantec) Email Security", "broadcom.com", "Email security"),
    (r"\.zoho\.(com|in|eu)$", "Zoho Mail", "zoho.com", "Email"),
    (r"\.secureserver\.net$", "GoDaddy", "godaddy.com", "Email"),
    (r"\.rediffmailpro\.com$", "Rediff", "rediff.com", "Email"),
    (r"\.amazonaws\.com$", "Amazon Web Services", "amazon.com", "Email"),
]
SPF = [
    (r"_spf\.google\.com$", "Google Workspace", "google.com", "Email"),
    (r"spf\.protection\.outlook\.com$", "Microsoft 365", "microsoft.com", "Email"),
    (r"sendgrid\.net$", "SendGrid (Twilio)", "twilio.com", "Email sending"),
    (r"mailgun\.org$", "Mailgun", "mailgun.com", "Email sending"),
    (r"amazonses\.com$", "Amazon SES", "amazon.com", "Email sending"),
    (r"servers\.mcsv\.net$", "Mailchimp", "mailchimp.com", "Marketing"),
    (r"mandrillapp\.com$", "Mailchimp Transactional", "mailchimp.com", "Email sending"),
    (r"_spf\.salesforce\.com$", "Salesforce", "salesforce.com", "CRM"),
    (r"mail\.zendesk\.com$", "Zendesk", "zendesk.com", "Customer support"),
    (r"(freshdesk|freshemail|freshworks)\.", "Freshworks", "freshworks.com", "Customer support"),
    (r"hubspotemail\.net$", "HubSpot", "hubspot.com", "Marketing"),
    (r"mktomail\.com$", "Adobe Marketo", "adobe.com", "Marketing"),
    (r"sparkpostmail\.com$", "SparkPost (Bird)", "sparkpost.com", "Email sending"),
    (r"zoho\.(com|in|eu)$", "Zoho", "zoho.com", "Email"),
    (r"pphosted\.com$", "Proofpoint", "proofpoint.com", "Email security"),
    (r"mimecast\.com$", "Mimecast", "mimecast.com", "Email security"),
    (r"secureserver\.net$", "GoDaddy", "godaddy.com", "Email"),
    (r"zcsend\.net$", "Zoho Campaigns", "zoho.com", "Marketing"),
    (r"netcorecloud\.net$|pepipost\.net$", "Netcore Cloud", "netcorecloud.com", "Email sending"),
]
TXT = [
    (r"^google-site-verification=", "Google", "google.com", "Cloud and productivity"),
    (r"^MS=ms\d+", "Microsoft 365", "microsoft.com", "Email"),
    (r"^atlassian-domain-verification=", "Atlassian", "atlassian.com", "Collaboration"),
    (r"^docusign=", "DocuSign", "docusign.com", "E-signature"),
    (r"^facebook-domain-verification=", "Meta", "meta.com", "Marketing"),
    (r"^apple-domain-verification=", "Apple", "apple.com", "Device management"),
    (r"^adobe-idp-site-verification=", "Adobe", "adobe.com", "Software"),
    (r"^stripe-verification=", "Stripe", "stripe.com", "Payments"),
    (r"^ZOOM_verify_", "Zoom", "zoom.us", "Collaboration"),
    (r"^slack-domain-verification=", "Slack", "slack.com", "Collaboration"),
    (r"^onetrust-domain-verification=", "OneTrust", "onetrust.com", "Privacy"),
    (r"^cisco-ci-domain-verification=", "Cisco Webex", "cisco.com", "Collaboration"),
    (r"^dropbox-domain-verification=", "Dropbox", "dropbox.com", "File sharing"),
    (r"^box-domain-verification=", "Box", "box.com", "File sharing"),
    (r"^zoho-verification=", "Zoho", "zoho.com", "Software"),
    (r"^knowbe4-site-verification=", "KnowBe4", "knowbe4.com", "Security training"),
    (r"^globalsign-domain-verification=", "GlobalSign", "globalsign.com", "Certificates"),
    (r"^miro-verification=", "Miro", "miro.com", "Collaboration"),
    (r"^mongodb-site-verification=", "MongoDB", "mongodb.com", "Database"),
    (r"^openai-domain-verification=", "OpenAI", "openai.com", "AI"),
    (r"^hubspot-developer-verification=", "HubSpot", "hubspot.com", "Marketing"),
    (r"^workplace-domain-verification=", "Meta Workplace", "meta.com", "Collaboration"),
    (r"^citrix-verification-code=", "Citrix", "citrix.com", "Remote access"),
    (r"^teamviewer-sso-verification=", "TeamViewer", "teamviewer.com", "Remote access"),
    (r"^wiz-domain-verification=", "Wiz", "wiz.io", "Cloud security"),
    (r"^yandex-verification:", "Yandex", "yandex.com", "Marketing"),
]
NS = [
    (r"\.ns\.cloudflare\.com$", "Cloudflare", "cloudflare.com", "DNS"),
    (r"\.awsdns-", "Amazon Web Services", "amazon.com", "DNS"),
    (r"\.azure-dns\.", "Microsoft Azure", "microsoft.com", "DNS"),
    (r"\.domaincontrol\.com$", "GoDaddy", "godaddy.com", "DNS"),
    (r"\.nsone\.net$", "IBM NS1", "ibm.com", "DNS"),
    (r"\.ultradns\.", "Vercara UltraDNS", "vercara.com", "DNS"),
    (r"\.akam\.net$|\.akamaiedge\.net$", "Akamai", "akamai.com", "DNS"),
    (r"\.googledomains\.com$|ns-cloud-.*\.googledomains\.com$", "Google Cloud", "google.com", "DNS"),
    (r"\.registrar-servers\.com$", "Namecheap", "namecheap.com", "DNS"),
    (r"\.dnsmadeeasy\.com$", "DNS Made Easy", "dnsmadeeasy.com", "DNS"),
    (r"\.digitalocean\.com$", "DigitalOcean", "digitalocean.com", "DNS"),
    (r"\.hostgator\.|\.bluehost\.com$", "Newfold Digital (Bluehost, HostGator)", "newfold.com", "DNS"),
]
CNAME = [
    (r"\.cloudfront\.net$|\.elb\.amazonaws\.com$|\.s3[.-].*amazonaws\.com$|\.amazonaws\.com$", "Amazon Web Services", "amazon.com", "Hosting and CDN"),
    (r"\.(azurewebsites|azureedge|trafficmanager|cloudapp\.azure|azurefd|blob\.core\.windows)\.", "Microsoft Azure", "microsoft.com", "Hosting and CDN"),
    (r"\.cdn\.cloudflare\.net$|\.cloudflare\.net$", "Cloudflare", "cloudflare.com", "Hosting and CDN"),
    (r"\.(akamaiedge|edgekey|edgesuite|akamaized)\.net$", "Akamai", "akamai.com", "Hosting and CDN"),
    (r"\.fastly\.net$|\.fastlylb\.net$", "Fastly", "fastly.com", "Hosting and CDN"),
    (r"\.ghs\.googlehosted\.com$|\.googlehosted\.com$|\.appspot\.com$|\.run\.app$", "Google Cloud", "google.com", "Hosting and CDN"),
    (r"\.herokudns\.com$|\.herokuapp\.com$", "Heroku (Salesforce)", "heroku.com", "Hosting and CDN"),
    (r"\.github\.io$", "GitHub", "github.com", "Hosting and CDN"),
    (r"\.netlify\.(app|com)$", "Netlify", "netlify.com", "Hosting and CDN"),
    (r"\.vercel-dns\.com$|\.vercel\.app$", "Vercel", "vercel.com", "Hosting and CDN"),
    (r"\.myshopify\.com$|shops\.myshopify\.com$", "Shopify", "shopify.com", "E-commerce"),
    (r"\.zendesk\.com$", "Zendesk", "zendesk.com", "Customer support"),
    (r"\.freshdesk\.com$|\.freshservice\.com$", "Freshworks", "freshworks.com", "Customer support"),
    (r"\.hubspot\.net$|\.hs-sites\.com$|\.hubspot\.com$", "HubSpot", "hubspot.com", "Marketing"),
    (r"\.wpengine\.com$|\.wpenginepowered\.com$", "WP Engine", "wpengine.com", "Hosting and CDN"),
    (r"\.force\.com$|\.salesforce\.com$|\.salesforce-sites\.com$", "Salesforce", "salesforce.com", "CRM"),
    (r"\.squarespace\.com$", "Squarespace", "squarespace.com", "Website builder"),
    (r"\.wixdns\.net$", "Wix", "wix.com", "Website builder"),
    (r"\.atlassian\.net$|\.statuspage\.io$", "Atlassian", "atlassian.com", "Collaboration"),
    (r"\.incapdns\.net$", "Imperva", "imperva.com", "Web security"),
    (r"\.sucuri\.net$", "Sucuri", "sucuri.net", "Web security"),
    (r"\.zohosites\.(com|in)$|\.zoho\.(com|in)$", "Zoho", "zoho.com", "Software"),
    (r"\.okta\.com$|\.oktapreview\.com$", "Okta", "okta.com", "Identity"),
    (r"\.mktoweb\.com$|\.mktossl\.com$", "Adobe Marketo", "adobe.com", "Marketing"),
    (r"\.pantheonsite\.io$", "Pantheon", "pantheon.io", "Hosting and CDN"),
    (r"\.webflow\.io$|proxy-ssl\.webflow\.com$", "Webflow", "webflow.com", "Website builder"),
]
SOURCE_LABEL = {"mx": "Handles the company's email", "spf": "Allowed to send email as the company",
                "txt": "Domain verified with this service", "ns": "Runs the company's DNS",
                "cname": "Hosts one of the company's websites"}


def _match(value: str, rules) -> tuple | None:
    value = value.lower().rstrip(".")
    for pattern, name, domain, category in rules:
        if re.search(pattern, value, re.IGNORECASE):
            return name, domain, category
    return None


def classify(records: dict[str, list[tuple[str, str]]], own_domain: str) -> list[dict]:
    """records: source -> [(record value, where it was seen)]. Returns one row per vendor."""
    rules = {"mx": MX, "spf": SPF, "txt": TXT, "ns": NS, "cname": CNAME}
    vendors: dict[str, dict] = {}
    for source, values in records.items():
        for value, seen_on in values:
            hit = _match(value, rules[source])
            if not hit:
                continue
            name, domain, category = hit
            if domain == own_domain:
                continue  # a company is not its own vendor
            v = vendors.setdefault(name, {"name": name, "domain": domain, "category": category, "evidence": []})
            ev = {"source": source, "what": SOURCE_LABEL[source], "record": value[:200], "seen_on": seen_on}
            if ev not in v["evidence"] and len(v["evidence"]) < 5:
                v["evidence"].append(ev)
    return sorted(vendors.values(), key=lambda v: (v["category"], v["name"]))


def _safe(fn, *args) -> list:
    try:
        return fn(*args)
    except LookupFailed:
        return []


def gather(domain: str, hosts: list[str]) -> dict[str, list[tuple[str, str]]]:
    """Reads the public DNS records that reveal vendors."""
    mx = [(str(r.exchange), domain) for r in _safe(resolve, domain, "MX")]
    ns = [(str(r.target), domain) for r in _safe(resolve, domain, "NS")]
    txt = _safe(txt_records, domain)
    spf = []
    for record in txt:
        if record.lower().startswith("v=spf1"):
            spf += [(m, domain) for m in re.findall(r"include:([^\s]+)", record, re.IGNORECASE)]
    txt_vals = [(t, domain) for t in txt if not t.lower().startswith("v=spf1")]

    def cname(host):
        return [(str(r.target), host) for r in _safe(resolve, host, "CNAME")]

    with ThreadPoolExecutor(max_workers=16) as pool:
        cnames = [c for chunk in pool.map(cname, hosts) for c in chunk]
    return {"mx": mx, "spf": spf, "txt": txt_vals, "ns": ns, "cname": cnames}


def detect(entity: Entity, gather_fn=None) -> list[dict]:
    from .scan import hosts_for

    gather_fn = gather_fn or gather
    return classify(gather_fn(entity.primary_domain, hosts_for(entity)), entity.primary_domain)


def refresh(session: Session, entity: Entity, gather_fn=None) -> VendorDetection:
    row = session.scalars(select(VendorDetection).where(VendorDetection.entity_id == entity.id)).first()
    if row is None:
        row = VendorDetection(entity_id=entity.id)
        session.add(row)
    row.vendors = detect(entity, gather_fn)
    row.detected_at = datetime.now(timezone.utc)
    session.commit()
    return row


def refresh_after_scan(session: Session, entity: Entity) -> None:
    if os.environ.get("VENDOR_DETECTION", "on") == "off":
        return
    try:
        refresh(session, entity)
    except Exception:  # vendor detection must never lose a completed scan
        session.rollback()


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _with_portfolio(session: Session, user: User, vendors: list[dict]) -> list[dict]:
    domains = [v["domain"] for v in vendors]
    rated = {e.primary_domain: e for e in session.scalars(select(Entity).where(Entity.primary_domain.in_(domains)))}
    mine = set(session.scalars(select(PortfolioItem.entity_id).where(PortfolioItem.org_id == user.org_id)))
    out = []
    for v in vendors:
        e = rated.get(v["domain"])
        row = {**v, "in_portfolio": bool(e and e.id in mine), "entity_id": e.id if e and e.id in mine else None,
               "grade": None, "score": None}
        if row["in_portfolio"]:
            s = session.scalars(select(Score).where(Score.entity_id == e.id)
                                .order_by(Score.created_at.desc(), Score.id.desc())).first()
            row["grade"], row["score"] = (s.grade, s.overall) if s else (None, None)
        out.append(row)
    return out


@router.get("/entities/{entity_id}/vendors")
def entity_vendors(entity_id: int, refresh_now: bool = False, user: User = Depends(auth.current_user),
                   session: Session = Depends(db.get_session)) -> dict:
    item = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id,
                                                       PortfolioItem.entity_id == entity_id)).first()
    if item is None:
        raise HTTPException(404, "entity not found")
    row = session.scalars(select(VendorDetection).where(VendorDetection.entity_id == entity_id)).first()
    stale = row is None or datetime.now(timezone.utc) - _aware(row.detected_at) > MAX_AGE
    if (stale or refresh_now) and os.environ.get("VENDOR_DETECTION", "on") != "off":
        row = refresh(session, item.entity)
    vendors = row.vendors if row else []
    return {"detected_at": _aware(row.detected_at).isoformat() if row else None,
            "vendors": _with_portfolio(session, user, vendors)}


@router.get("/fourth-parties")
def fourth_parties(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    """Which services your vendors depend on, and how many of them share each one (concentration risk)."""
    items = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id)).all()
    by_entity = {i.entity_id: i.entity for i in items}
    rows = session.scalars(select(VendorDetection).where(VendorDetection.entity_id.in_(list(by_entity)))).all()
    agg: dict[str, dict] = {}
    for r in rows:
        for v in r.vendors or []:
            a = agg.setdefault(v["name"], {"name": v["name"], "domain": v["domain"], "category": v["category"], "used_by": []})
            e = by_entity[r.entity_id]
            if all(u["id"] != e.id for u in a["used_by"]):
                a["used_by"].append({"id": e.id, "name": e.name})
    vendors = _with_portfolio(session, user, sorted(agg.values(), key=lambda a: (-len(a["used_by"]), a["name"])))
    return {"companies_checked": len(rows), "companies_total": len(by_entity), "vendors": vendors}
