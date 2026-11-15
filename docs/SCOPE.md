# ProjectScore v1: scope for the 25 December 2026 launch

Source: `BRS_Security_Ratings_Platform_v1.2.docx`. The BRS plans roughly 9 to 12 months, with the MVP at
month 4. This release is a narrower first version that can be live by 25 December 2026. Everything not
listed here stays in the BRS backlog for later releases.

## What v1 does

1. **Entities and assets.** A user adds an organisation by its primary domain. The platform records the
   domain and discovers subdomains passively from Certificate Transparency logs (crt.sh).
2. **Non-intrusive checks** (outside-in, publicly observable only, BRS 4.1 and 7.1):
   - Email security: SPF, DMARC policy strength, MTA-STS (risk factor 5).
   - TLS / encryption: certificate validity and expiry, protocol version, HSTS (risk factor 6).
   - Web application security: security headers and cookie flags (risk factor 7).
   - DNS health: DNSSEC, dangling CNAMEs (risk factor 8).
   - Vulnerability intelligence: CISA KEV and FIRST EPSS lookups for software versions seen in banners
     (risk factor 2), added in week 3.
3. **Rating engine v1** following BRS Section 7.4: severity x confidence x time decay, size
   normalisation with alpha 0.5, per-factor 0 to 100 scores and A to F grades, overall 300 to 900 score,
   severity gates, and a full calculation trace so every deducted point links to a finding.
4. **Vendor portfolio** with tiering and weekly automatic re-scans, plus alerts when a score drops.
5. **Web dashboard and PDF report** per entity.
6. **Login** for a small number of pilot tenants.
7. **Responsible scanning:** identifiable user agent, rate limiting, and a public opt-out page (BRS 4.4).

## Not in v1 (deferred)

Professional Services workspace, full CTI (OpenCTI/MISP), identity and breach intelligence, compliance
mapping library, board packs, Trust Hub disputes beyond a simple form, cyber insurance and other v1.1
modules, active testing of any kind, port scanning of third parties.

## Architecture

- **Backend:** Python 3.12+, FastAPI, SQLAlchemy. PostgreSQL in production, SQLite for local and tests.
- **Workers:** scans run as background jobs (in-process for v1, a queue later).
- **Frontend:** React, served separately and talking to the REST API.
- **Hosting:** one region, one cloud provider (to be chosen with the owner's budget).

## Weekly plan

| Week (starting) | Outcome |
|---|---|
| 16 Nov | Scope, skeleton, data model, first collectors, rating engine (this commit) |
| 23 Nov | Subdomain discovery, KEV/EPSS, score history, background scans |
| 30 Nov | React dashboard, vendor portfolio, login |
| 7 Dec | PDF report, alerts, opt-out page, staging deploy |
| 14 Dec | Hardening, security review, pilot data |
| 21 Dec | Production launch by 25 Dec |

## Owner actions

- Create the GitHub repository.
- Choose hosting and budget, and a domain name.
- Get legal sign-off on passive scanning and the BRS Section 24 privacy items before production data
  collection.
