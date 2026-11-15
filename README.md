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
- Public scanner page at `/scanner` explains the scanner and takes opt-out requests; the owner reviews
  them on the Opt-outs page, and approved domains (and their subdomains) are never scanned. The scanner's
  user agent links to this page; set `SCANNER_INFO_URL` if the site moves to its own domain.
- Users can also be added from a shell on the server:
  `python -m app.admin create-user --org "Client Ltd" --email person@client.com [--admin]`
- Admins can also add users to their own organisation with `POST /api/users`.
- Local demo login after `python -m app.seed`: `demo@example.com` / `demo-password-123`. For local HTTP,
  run uvicorn with `COOKIE_SECURE=false`.
