"""Remediation guidance and prioritised fix plans.

Every finding type has plain-language guidance: why it matters, how to fix it, how much effort it takes
and who usually owns the fix. The fix plan groups a company's open findings by type and ranks them by
how many rating points fixing them would recover, computed with the same scoring engine as the rating.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Finding, Score, User
from .scoring import ScoringFinding, compute_score

router = APIRouter(prefix="/api")

EFFORT_ORDER = {"quick": 0, "moderate": 1, "project": 2}

# code (or code prefix ending in "*") -> guidance
GUIDE: dict[str, dict] = {
    "spf_missing": {"why": "Without SPF, anyone can send email that appears to come from your domain.",
                    "fix": ["List every service that sends mail for you (mail host, CRM, marketing, billing).",
                            "Publish one TXT record at the domain root, e.g. v=spf1 include:_spf.google.com include:sendgrid.net -all.",
                            "Use ~all for a few days while you check reports, then -all."],
                    "effort": "quick", "owner": "Email or DNS administrator"},
    "spf_multiple": {"why": "Two SPF records make SPF invalid, so receivers ignore it.",
                     "fix": ["Merge all include: and ip4: entries into a single v=spf1 TXT record.", "Delete the extra record."],
                     "effort": "quick", "owner": "Email or DNS administrator"},
    "spf_pass_all": {"why": "+all tells receivers that any server in the world may send as you.",
                     "fix": ["Replace +all with -all (or ~all while testing).", "Make sure every legitimate sender is listed first."],
                     "effort": "quick", "owner": "Email or DNS administrator"},
    "spf_weak": {"why": "?all or a missing all mechanism gives no protection against spoofing.",
                 "fix": ["End the SPF record with ~all, then -all once mail flow is confirmed."],
                 "effort": "quick", "owner": "Email or DNS administrator"},
    "dmarc_missing": {"why": "Without DMARC, spoofed mail using your exact domain reaches inboxes; it is the main defence against CEO-fraud and invoice-fraud emails.",
                      "fix": ["Publish _dmarc.<domain> TXT: v=DMARC1; p=none; rua=mailto:dmarc@<domain>.",
                              "Review the aggregate reports for 2 to 4 weeks and fix any legitimate senders failing SPF or DKIM.",
                              "Move to p=quarantine, then p=reject."],
                      "effort": "moderate", "owner": "Email administrator"},
    "dmarc_monitor_only": {"why": "p=none only reports; spoofed mail is still delivered.",
                           "fix": ["Check DMARC reports that all real senders pass.", "Change the policy to p=quarantine, then p=reject."],
                           "effort": "moderate", "owner": "Email administrator"},
    "dmarc_partial": {"why": "pct below 100 leaves part of spoofed mail unprotected.",
                      "fix": ["Raise pct to 100 (or remove the pct tag)."], "effort": "quick", "owner": "Email administrator"},
    "mta_sts_missing": {"why": "Without MTA-STS, mail sent to you can be downgraded to unencrypted delivery by an attacker in the path.",
                        "fix": ["Host a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt listing your MX hosts (mode: testing).",
                                "Publish _mta-sts.<domain> TXT: v=STSv1; id=<date>.", "Switch to mode: enforce after a few weeks of TLS reports."],
                        "effort": "moderate", "owner": "Email administrator"},
    "dkim_not_found": {"why": "DKIM signs your outgoing mail so receivers can tell it is genuine; DMARC relies on it.",
                       "fix": ["Turn on DKIM signing in each mail service (Google Workspace, Microsoft 365, your email marketing tool).",
                               "Publish the DKIM public keys they give you in DNS.",
                               "If you already sign with a custom selector, this finding can be disputed."],
                       "effort": "quick", "owner": "Email administrator"},
    "dkim_weak_key": {"why": "DKIM keys under 1024 bits can be cracked, letting attackers sign mail as you.",
                      "fix": ["Generate a new 2048-bit DKIM key in your mail service.", "Publish it under a new selector, switch signing, then remove the old key."],
                      "effort": "quick", "owner": "Email administrator"},
    "dkim_1024": {"why": "1024-bit DKIM keys are below current recommendations.",
                  "fix": ["Rotate to a 2048-bit key under a new selector."], "effort": "quick", "owner": "Email administrator"},
    "dnssec_missing": {"why": "DNSSEC stops attackers forging DNS answers for your domain.",
                       "fix": ["Enable DNSSEC signing at your DNS provider (usually one switch).", "Add the DS record at your registrar."],
                       "effort": "moderate", "owner": "DNS administrator"},
    "dangling_cname": {"why": "A DNS name pointing to a deleted cloud resource can be claimed by an attacker (subdomain takeover) and used for phishing on your own domain.",
                       "fix": ["Delete the CNAME record if the service is no longer used.", "Otherwise recreate the target resource you own."],
                       "effort": "quick", "owner": "DNS administrator"},
    "cert_expired": {"why": "Browsers block the site and users learn to click through warnings.",
                     "fix": ["Renew the certificate and install it on every server and load balancer for this host.",
                             "Automate renewal (ACME / Let's Encrypt or your CA's tooling) and alert 30 days before expiry."],
                     "effort": "quick", "owner": "Infrastructure team"},
    "cert_expiring": {"why": "The certificate will soon expire and break the site.",
                      "fix": ["Renew now and automate renewal."], "effort": "quick", "owner": "Infrastructure team"},
    "cert_untrusted": {"why": "An untrusted or mismatched certificate means visitors cannot verify they reached you.",
                       "fix": ["Install a certificate from a public CA that covers this exact hostname.",
                               "Include the full intermediate chain.", "If the host is not meant to be public, remove it from DNS."],
                       "effort": "quick", "owner": "Infrastructure team"},
    "tls_old_protocol": {"why": "TLS 1.0 and 1.1 have known weaknesses and are banned by PCI DSS and most regulators.",
                         "fix": ["Disable TLS 1.0 and 1.1 on the server or load balancer; allow TLS 1.2 and 1.3 only."],
                         "effort": "quick", "owner": "Infrastructure team"},
    "hsts_missing": {"why": "Without HSTS, a visitor's first request can be intercepted and downgraded to HTTP.",
                     "fix": ["Send Strict-Transport-Security: max-age=31536000; includeSubDomains on HTTPS responses."],
                     "effort": "quick", "owner": "Web team"},
    "csp_missing": {"why": "A Content-Security-Policy limits the damage of cross-site scripting.",
                    "fix": ["Start with Content-Security-Policy-Report-Only and a policy listing your script and style sources.",
                            "Fix violations, then enforce."], "effort": "moderate", "owner": "Web team"},
    "xfo_missing": {"why": "Pages can be framed by other sites to trick users into clicking (clickjacking).",
                    "fix": ["Send X-Frame-Options: DENY or a CSP frame-ancestors directive."], "effort": "quick", "owner": "Web team"},
    "xcto_missing": {"why": "Stops browsers guessing file types, which can turn uploads into scripts.",
                     "fix": ["Send X-Content-Type-Options: nosniff."], "effort": "quick", "owner": "Web team"},
    "security_txt_missing": {"why": "Security researchers who find a problem have no clear way to tell you, so reports get lost or go public.",
                             "fix": ["Publish /.well-known/security.txt with a Contact: email and an Expires: date (see securitytxt.org)."],
                             "effort": "quick", "owner": "Web team"},
    "privacy_policy_missing": {"why": "India's DPDP Act 2023 and most other privacy laws expect a clear privacy notice for anyone whose data you collect.",
                               "fix": ["Link a privacy policy from the footer of every page.", "Explain what personal data you collect, why, and how people can contact you about it."],
                               "effort": "moderate", "owner": "Legal and web team"},
    "cookie_not_secure": {"why": "Cookies without Secure can leak over unencrypted connections.",
                          "fix": ["Set the Secure attribute on all cookies served over HTTPS."], "effort": "quick", "owner": "Web team"},
    "session_cookie_not_httponly": {"why": "Scripts injected into the page could steal the session cookie and take over accounts.",
                                    "fix": ["Set HttpOnly on session and authentication cookies."], "effort": "quick", "owner": "Web team"},
    "*_eol": {"why": "Software that no longer receives security updates stays vulnerable to every new flaw.",
              "fix": ["Upgrade to a supported release.", "If an upgrade is not possible soon, isolate the system and restrict who can reach it.",
                      "Stop the server advertising its version in headers."], "effort": "project", "owner": "Infrastructure team"},
    "*_eol_old": {"why": "Very old software with many public exploits.",
                  "fix": ["Upgrade to a supported release as a priority.", "Restrict access until it is upgraded."],
                  "effort": "project", "owner": "Infrastructure team"},
    "*_outdated": {"why": "This version has published vulnerabilities fixed in later releases.",
                   "fix": ["Apply the latest patch release.", "Hide the version number in server headers."],
                   "effort": "moderate", "owner": "Infrastructure team"},
    "*_vulnerable": {"why": "This JavaScript library version has known vulnerabilities that can be exploited in visitors' browsers.",
                     "fix": ["Upgrade the library to the latest version and retest the pages that use it.",
                             "Remove it if it is no longer needed."], "effort": "moderate", "owner": "Web team"},
    "*_vulnerable_old": {"why": "Very old JavaScript library with known vulnerabilities.",
                         "fix": ["Upgrade or remove the library."], "effort": "moderate", "owner": "Web team"},
    "apache_path_traversal_kev": {"why": "This Apache version is being actively exploited to read files and run code.",
                                  "fix": ["Upgrade Apache to the latest 2.4 release immediately.", "Check logs for exploitation and treat the server as possibly compromised."],
                                  "effort": "quick", "owner": "Infrastructure team"},
    "openssl_heartbleed_risk": {"why": "Heartbleed lets attackers read server memory, including private keys and passwords.",
                                "fix": ["Upgrade OpenSSL.", "Replace the TLS certificate and private key, and reset credentials that may have been exposed."],
                                "effort": "moderate", "owner": "Infrastructure team"},
    "kev_exposed": {"why": "Software on this IP has vulnerabilities that CISA has confirmed are being exploited by attackers right now.",
                    "fix": ["Patch or upgrade the affected software now, starting with CVEs that have the highest CVSS and EPSS.",
                            "If it cannot be patched within days, take it off the internet or put it behind a VPN.",
                            "Check for signs of compromise on the system."], "effort": "moderate", "owner": "Infrastructure team"},
    "known_cves": {"why": "Software on this IP has published vulnerabilities.",
                   "fix": ["Patch to the latest version; prioritise CVEs with CVSS 9+ or high EPSS.",
                           "Remove the service from the internet if it does not need to be public."],
                   "effort": "moderate", "owner": "Infrastructure team"},
    "slow_patch_*": {"why": "A serious vulnerability has stayed open for over two months, which signals a slow patching process.",
                     "fix": ["Patch the underlying finding.", "Set a patching target (critical within 14 days, high within 30) and track it."],
                     "effort": "moderate", "owner": "Infrastructure team"},
    "rdp_exposed_*": {"why": "Internet-facing Remote Desktop is one of the most common ransomware entry points.",
                      "fix": ["Close port 3389 to the internet.", "Give remote staff access through a VPN or zero-trust gateway with MFA."],
                      "effort": "quick", "owner": "Network team"},
    "vnc_exposed_*": {"why": "VNC is often weakly protected and gives full remote control.",
                      "fix": ["Block VNC from the internet; use a VPN with MFA."], "effort": "quick", "owner": "Network team"},
    "telnet_exposed_*": {"why": "Telnet sends passwords in clear text and is routinely brute-forced.",
                         "fix": ["Disable Telnet; use SSH with keys if remote management is needed."], "effort": "quick", "owner": "Network team"},
    "ftp_exposed_*": {"why": "FTP sends credentials and files unencrypted.",
                      "fix": ["Replace with SFTP or HTTPS uploads, or restrict FTP to known IP addresses."], "effort": "moderate", "owner": "Network team"},
    "smb_exposed_*": {"why": "SMB on the internet has been the route for worms such as WannaCry.",
                      "fix": ["Block ports 445 and 139 at the firewall immediately."], "effort": "quick", "owner": "Network team"},
    "netbios_exposed_*": {"why": "NetBIOS leaks internal information and is exploitable.",
                          "fix": ["Block port 139 at the firewall."], "effort": "quick", "owner": "Network team"},
    "db_exposed_*": {"why": "Databases reachable from the internet are a leading cause of large data leaks.",
                     "fix": ["Remove the database from the internet; allow only application servers on a private network.",
                             "Require authentication and rotate credentials.", "Check whether data was accessed."],
                     "effort": "quick", "owner": "Infrastructure team"},
    "ai_service_exposed_*": {"why": "AI model servers, notebooks and vector databases usually have no password by default. "
                                    "Attackers use them to steal models, prompts and data, run code, or mine cryptocurrency on your GPUs.",
                             "fix": ["Confirm what is running on this port; if it is an AI service, take it off the internet.",
                                     "Put it behind a VPN or an authenticating proxy and turn on its own authentication.",
                                     "Update it to the latest version and check logs for unknown use."],
                             "effort": "quick", "owner": "AI / data platform team"},
    "snmp_exposed_*": {"why": "SNMP can leak device configuration and is used in amplification attacks.",
                       "fix": ["Block UDP 161 from the internet; use SNMPv3 internally."], "effort": "quick", "owner": "Network team"},
    "ics_exposed_*": {"why": "Industrial and building control systems on the internet can be manipulated physically.",
                      "fix": ["Disconnect from the internet now; access only through a secured remote-access gateway.",
                              "Follow CERT-In and IEC 62443 guidance for OT networks."], "effort": "moderate", "owner": "OT / engineering team"},
    "docker_api_exposed_*": {"why": "An open Docker API gives attackers full control of the host.",
                             "fix": ["Close port 2375 immediately; use TLS-authenticated access on a private network.", "Check the host for unknown containers."],
                             "effort": "quick", "owner": "Infrastructure team"},
    "botnet_c2": {"why": "This IP is listed as controlling a botnet, so a system you operate is very likely compromised.",
                  "fix": ["Isolate the system and start incident response.", "Report to CERT-In within 6 hours if it qualifies as a reportable incident.",
                          "Rebuild from clean images and rotate credentials."], "effort": "project", "owner": "Security / incident response"},
    "malware_hosting": {"why": "Your website is serving malware right now, which harms visitors and gets the domain blocklisted.",
                        "fix": ["Take the affected files offline.", "Find how they were uploaded (often an outdated CMS or plugin) and patch it.",
                                "Request delisting from URLhaus once clean."], "effort": "moderate", "owner": "Web team"},
    "malware_user_content": {"why": "Users of your service are hosting malware on it.",
                             "fix": ["Scan uploads for malware and act on abuse reports quickly."], "effort": "moderate", "owner": "Trust and safety team"},
    "spamhaus_drop": {"why": "The IP sits in a netblock Spamhaus lists as hijacked or used by criminals.",
                      "fix": ["Confirm who owns the netblock.", "If it is yours, contact Spamhaus and your registry to resolve the listing."],
                      "effort": "moderate", "owner": "Network team"},
    "attack_source": {"why": "This IP was recently seen attacking other systems, which usually means a compromised machine.",
                      "fix": ["Find the system using this IP and check it for malware or misuse.", "Patch and rebuild if compromised."],
                      "effort": "moderate", "owner": "Security team"},
    "impersonation_*": {"why": "A website on a look-alike domain is imitating the company, usually to steal passwords or "
                               "payments from its customers, staff or suppliers.",
                        "fix": ["Confirm the site is not yours (or a partner's) and take screenshots as evidence.",
                                "Report it to Google Safe Browsing and Netcraft so browsers start warning visitors.",
                                "Send a takedown request to the domain's registrar and hosting provider (abuse contacts via ICANN Lookup).",
                                "Warn customers and staff, and consider a UDRP complaint to recover the domain."],
                        "effort": "moderate", "owner": "Security and legal teams"},
    "lookalike_domain_*": {"why": "Domains that look like yours are used to phish your staff, customers and suppliers.",
                           "fix": ["Check whether you own it. If so, dispute this finding.",
                                   "If not, monitor it, warn staff, and consider a takedown or UDRP complaint if it is used for phishing.",
                                   "Enforce DMARC so the real domain cannot be spoofed."], "effort": "moderate", "owner": "Brand / security team"},
    "ransomware_leak_*": {"why": "A ransomware group says it has breached this company and may publish or sell its data. "
                                 "Vendors in this state can lose your data and be unable to deliver services.",
                          "fix": ["Ask the company to confirm the incident and whether your data was affected.",
                                  "Request their incident report, containment status and notification timeline.",
                                  "Review and limit their access to your systems until they confirm recovery."],
                          "effort": "major", "owner": "Incident response team"},
    "infostealer_employees": {"why": "Malware on staff computers stole saved passwords and session cookies, which are sold to "
                                     "ransomware gangs as ready-made ways in (no phishing needed).",
                              "fix": ["Reset passwords and revoke sessions for affected staff accounts.",
                                      "Require phishing-resistant multi-factor authentication for all remote and SaaS access.",
                                      "Stop staff saving work passwords in browsers on personal devices; use managed devices with EDR."],
                              "effort": "moderate", "owner": "Identity and endpoint team"},
    "infostealer_customers": {"why": "Customers' own infected computers leaked their logins to this company's sites, "
                                     "which enables account takeover.",
                              "fix": ["Offer or require multi-factor authentication for customer accounts.",
                                      "Detect logins from leaked credentials and force a password reset."],
                              "effort": "moderate", "owner": "Product security team"},
    "breach_*": {"why": "A past breach exposed account data; reused passwords from it are used in credential-stuffing attacks.",
                 "fix": ["Force password resets for affected accounts if not done.", "Require MFA for staff and customers.",
                         "Confirm the root cause was fixed."], "effort": "moderate", "owner": "Security team"},
}
DEFAULT = {"why": "This weakens your external security posture.", "fix": ["Review the finding details and fix the underlying issue."],
           "effort": "moderate", "owner": "IT team"}


def guidance(code: str) -> dict:
    if code in GUIDE:
        return GUIDE[code]
    best = None
    for key, g in GUIDE.items():
        if "*" not in key:
            continue
        prefix, suffix = key.split("*", 1)
        if code.startswith(prefix) and code.endswith(suffix) and len(code) > len(prefix) + len(suffix) - 1:
            if best is None or len(key) > len(best[0]):
                best = (key, g)
    return best[1] if best else DEFAULT


def _scoring(f) -> ScoringFinding:
    return ScoringFinding(risk_factor=f.risk_factor, severity=f.severity, asset_value=f.asset_value, code=f.code,
                          detection_confidence=f.detection_confidence, status=f.status, last_seen=f.last_seen,
                          evidence=f.evidence or {})


def plan(findings: list, coverage: dict[str, int]) -> dict:
    """Group open findings by type and rank by rating points recovered if that type is fixed everywhere."""
    base = compute_score([_scoring(f) for f in findings], coverage)["overall"]
    groups: dict[str, list] = {}
    for f in findings:
        if f.status == "open":
            groups.setdefault(f.code, []).append(f)
    items = []
    for code, fs in groups.items():
        ids = {f.id for f in fs}
        after = compute_score([_scoring(f) for f in findings if f.id not in ids], coverage)["overall"]
        g = guidance(code)
        items.append({"code": code, "title": fs[0].title, "severity": fs[0].severity, "risk_factor": fs[0].risk_factor,
                      "assets": sorted({f.asset_value for f in fs}), "finding_ids": sorted(ids),
                      "points": after - base, "why": g["why"], "fix": g["fix"], "effort": g["effort"], "owner": g["owner"]})
    items.sort(key=lambda i: (-i["points"], EFFORT_ORDER[i["effort"]], i["code"]))
    open_ids = {f.id for f in findings if f.status == "open"}
    quick = {i for it in items if it["effort"] == "quick" for i in it["finding_ids"]}
    score_quick = compute_score([_scoring(f) for f in findings if f.id not in quick], coverage)["overall"]
    score_all = compute_score([_scoring(f) for f in findings if f.id not in open_ids], coverage)["overall"]
    return {"current": base, "after_quick_fixes": score_quick, "after_all_fixes": score_all, "items": items}


@router.get("/entities/{entity_id}/remediation")
def remediation_plan(entity_id: int, user: User = Depends(auth.current_user),
                     session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    latest = session.scalars(select(Score).where(Score.entity_id == entity_id)
                             .order_by(Score.created_at.desc(), Score.id.desc())).first()
    if latest is None:
        return {"current": None, "items": []}
    coverage = {k: v["assets"] for k, v in (latest.factors or {}).items()}
    findings = session.scalars(select(Finding).where(Finding.entity_id == entity_id)).all()
    return plan(findings, coverage)
