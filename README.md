# ProjectScore

Security ratings and cyber risk intelligence platform. The requirements live in the BRS
(`BRS_Security_Ratings_Platform_v1.2.docx`); the scope of the first release, due 25 December 2026, is in
[docs/SCOPE.md](docs/SCOPE.md).

## What works today

- REST API to add organisations by domain, start a scan, and read the score, findings and score history.
- Passive collectors: email security (SPF, DMARC, MTA-STS), DNS health (DNSSEC, dangling CNAMEs),
  TLS (certificate trust and expiry, protocol, HSTS) and web headers and cookies.
- Rating engine v1 from BRS Section 7: severity x confidence x time decay, size normalisation, factor
  grades, 300 to 900 overall score, severity gates, and a trace for every deducted point.
- If DNS cannot be queried reliably, the affected factors are marked as not assessed rather than
  reported as missing records.

- Web app (React): vendor portfolio with search, sorting and summary tiles; company page with score
  gauge, grade, trend, factor grades, open findings and the full calculation trace; add a company and
  scan it.

## Run it locally

```bash
# 1. Build the web app
cd frontend && npm install && npm run build && cd ..

# 2. Start the server (serves the API at /api and the web app at /)
cd backend
pip install -r requirements.txt
python -m app.seed          # optional: fictional demo companies and a demo login
COOKIE_SECURE=false uvicorn app.main:app --reload
# open http://127.0.0.1:8000  (API docs at /docs)
```

For frontend development with live reload, run `npm run dev` in `frontend` alongside uvicorn and open
http://localhost:5173.

Uses SQLite by default; set `DATABASE_URL` (for example `postgresql+psycopg://...`) for PostgreSQL.

## Tests

```bash
cd backend && python -m pytest -q
```

## Deploy to Render

The repository includes `render.yaml` and a `Dockerfile`. In Render, choose **New > Blueprint**, select this
repository, and Render creates the web service and a PostgreSQL database and wires `DATABASE_URL`
between them. Every push to `main` redeploys. Health check: `/api/health`.

When Render asks for `ADMIN_EMAIL` and `ADMIN_PASSWORD` (12+ characters), enter the first
administrator's login. That account is created on first start.

## Accounts

- Access is by invitation only. Each client organisation has its own private portfolio; scan results for
  a company are shared, so a vendor is scanned once however many clients monitor it.
- Roles: **owner** (the platform operator: manages users and organisations for every client, from the
  Team page), **admin** (manages users in their own organisation), **member** (uses the portfolio).
  The `ADMIN_EMAIL` account is the owner.
- New users and password resets get a one-time temporary password on the Team page; users change it on
  their account page.
- Every monitored company is rescanned automatically every 7 days (`RESCAN_DAYS`). The scheduler runs
  inside the web server, so keep a single instance or move it to a worker before scaling out.
- Each company page has a PDF report download.
- IP addresses and registered IP ranges are found passively (DNS plus RDAP registry records; only blocks
  registered to the company itself count, not cloud or hosting ranges). Open services and vulnerable
  software come from existing internet-wide scan data, never from scanning the IPs directly:
  `EXPOSURE_SOURCE=internetdb` (default, free; its terms are non-commercial, so confirm licensing before
  commercial launch), `SHODAN_API_KEY=...` to use the paid Shodan API instead, or `EXPOSURE_SOURCE=off`.
  Exposed CVEs are matched against the CISA KEV catalogue; KEV matches cap the score at 700.
- **In-depth scans** (admins, opt-in): active testing of the organisation's own websites with Nuclei
  (free, MIT licence; installed in the Docker image with a pinned, checksum-verified release and the free
  community templates). Requires DNS TXT proof of control (valid 90 days) and a named, written
  authorisation stored with each scan; scope is limited to the verified domain and its subdomains; DoS,
  brute-force and fuzzing templates are excluded; rate-limited; one scan per domain per 24 hours. Results
  are private to the organisation and never change ratings. Needs the 2 GB Render plan.
- Public scanner page at `/scanner` explains the scanner and takes opt-out requests; the owner reviews
  them on the Opt-outs page, and approved domains (and their subdomains) are never scanned. The scanner's
  user agent links to this page; set `SCANNER_INFO_URL` if the site moves to its own domain.
- Compromise signals: hostnames and IPs are matched against free public threat feeds (abuse.ch Feodo
  Tracker and URLhaus, Spamhaus DROP, blocklist.de), cached for 6 hours. A botnet or malware hit caps the
  score at 640. Set `COMPROMISE_FEEDS=off` to disable.
- Free rating report at `/free-report` for prospects: work email must be at the domain; shows score, grade,
  factor grades and issue counts but no hostnames or IPs; reuses a rating under 7 days old; 3 requests per IP
  per day. Requests appear as leads on the owner's Leads page.
- Framework mapping on each company page: findings mapped to NIST CSF 2.0, ISO/IEC 27001:2022 Annex A,
  CERT-In Directions (2022), RBI Cyber Security Framework (2016) and SEBI CSCRF (2024). Indicative only,
  not a compliance assessment (`backend/app/frameworks.py`).
- Alerts: when a company drops a grade, falls 20+ points (`ALERT_SCORE_DROP`) or gets new critical/high
  issues, every organisation watching it sees an alert (nav badge and Alerts page). Email goes out through
  Resend when `RESEND_API_KEY` and `ALERT_EMAIL_FROM` are set; links use `APP_URL`.
- Email checks include DKIM (27 common selectors; weak keys flagged). Look-alike domains (typos,
  homoglyphs, other TLDs) are checked in DNS for the brand factor, ignoring ones on the company's own
  nameservers. Breach history comes from the public Have I Been Pwned catalogue (CC BY 4.0), decaying
  with a one-year half-life from the breach date (`BREACH_FEED=off` disables).
- Patching speed: median days to fix vulnerabilities from scan history; serious ones open over 60 days add
  a finding. Benchmarking against industry and all rated companies (groups of 5 or more only).
- Up to 100 hostnames (`MAX_HOSTS_PER_ENTITY`) and 256 IPs (`MAX_IPS_PER_ENTITY`) per company.
- Disputes: any user can dispute a finding on a company in their portfolio, and rated companies can use the
  public form on `/scanner`. The owner decides on the Disputes page. Accepting marks the finding as a false
  positive, keeps it from returning on later scans and recalculates the score at once.
- Users can also be added from a shell on the server:
  `python -m app.admin create-user --org "Client Ltd" --email person@client.com [--admin]`
- Admins can also add users to their own organisation with `POST /api/users`.
- Local demo login after `python -m app.seed`: `demo@example.com` / `demo-password-123`. For local HTTP,
  run uvicorn with `COOKIE_SECURE=false`.

## Security and operations

- The app sends a strict Content-Security-Policy, HSTS (in production), X-Frame-Options DENY, nosniff and
  no-store on API responses. Cross-site POSTs to `/api/` are refused by an Origin check.
- The scanner never contacts private or internal addresses: every host and every redirect target must
  resolve only to public IPs (`backend/app/collectors/netsafe.py`). This matters because anyone can request
  a free report on any domain.
- Public forms have per-IP limits plus overall daily caps (200 form posts, `FREE_REPORT_DAILY_SCANS`
  new free-report scans, default 40).
- Error tracking: set `SENTRY_DSN` (and optionally `SENTRY_ENVIRONMENT`) on Render. No personal data is sent.
- Backups: Render continuously backs up paid Postgres databases with point-in-time recovery (3 days on a
  Hobby workspace, 7 days on Pro). For longer retention, use **Create export** on the database's Recovery
  page (kept 7 days) and download it, for example monthly. Deleting the database deletes its backups.
