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
python -m app.seed          # optional: fictional demo companies
uvicorn app.main:app --reload
# open http://127.0.0.1:8000  (API docs at /docs)
```

For frontend development with live reload, run `npm run dev` in `frontend` alongside uvicorn and open
http://localhost:5173.

Uses SQLite by default; set `DATABASE_URL` (for example `postgresql+psycopg://...`) for PostgreSQL.

## Tests

```bash
cd backend && python -m pytest -q
```
