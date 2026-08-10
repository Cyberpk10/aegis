# Aegis

Aegis is a **defensive** email-security analysis tool. It ingests a single `.eml` file, runs a
deterministic, rule-based phishing indicator engine over it, fuses the findings into a 0-100 risk
score, and maps the findings to compliance/control frameworks (MITRE ATT&CK, NIST CSF, ISO 27001,
SOC 2).

Aegis performs **analysis only**: it does not send email, does not exploit anything, and does not
make outbound network/DNS calls. SPF/DKIM/DMARC results are parsed from the email's existing
`Authentication-Results` header rather than independently re-verified.

See [DEPLOYMENT.md](DEPLOYMENT.md) for deploying to production (Render backend + Vercel frontend).

## Milestone 1 scope

- Parse `.eml` headers, including SPF/DKIM/DMARC authentication results.
- Deterministic indicator engine: sender/reply-to mismatch, look-alike/homoglyph domains, urgency
  language, credential/payment requests, link analysis (display-vs-href mismatch, shorteners,
  suspicious TLDs), attachment risk.
- Risk fusion into a 0-100 score with verdict bands: Safe (<25), Suspicious (25-54),
  Malicious (>=55).
- Framework mapping loaded from versioned YAML (`backend/app/mapping/frameworks/*.yaml`).
- `POST /api/analyze` returns verdict, score, indicators, and framework mappings.
- pytest suite with labeled phishing/benign sample `.eml` files.

## Milestone 2 scope (in progress)

- Optional LLM analyst narrative: a short (2-4 sentence) explanation of the already-computed
  rule-based verdict, generated server-side by a Haiku-class Claude model. The LLM only explains
  the existing score/verdict — it never recomputes or overrides them. Off by default.

### Enabling the analyst narrative

```sh
cd backend
cp .env.example .env   # then edit .env and paste in a real ANTHROPIC_API_KEY
```

`backend/app/core/config.py` loads `.env` automatically (via `python-dotenv`) at startup — no
manual `export`/`source` needed. `.env` is gitignored; `.env.example` documents the variables and
is committed. Real environment variables (shell, CI) always take precedence over `.env`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `ENABLE_LLM_REASONING` | `false` | Set to `true` to turn on the LLM analyst narrative. |
| `ANTHROPIC_API_KEY` | (unset) | Required when the feature is enabled. Never hardcode this. |
| `ANTHROPIC_MODEL` | `claude-haiku-4-5` | Overrides the model used for the narrative. |

If the flag is on but the key is missing, or the API call fails/times out, `analyst_narrative` is
returned as `null` and the full rule-based result is still returned — the feature degrades
gracefully and never blocks analysis. The pytest suite pins `enable_llm_reasoning` to `false` for
every test regardless of your local `.env`, so it stays offline and deterministic no matter what
you have configured for manual testing.

## Stage 2 scope — persistence & case management

Every `POST /api/analyze` now persists its result as a **case** so past analyses can be browsed
later. Two design choices worth calling out:

- **Data minimization**: the `cases` table stores the analysis result (verdict, score,
  indicators, framework mappings, analyst narrative) but never the raw email body/headers. The
  uploaded `.eml` is written to disk (`RAW_EMAIL_STORAGE_DIR`, default `backend/data/raw_emails/`)
  under its case UUID, and only that path is stored in the DB. Files older than
  `RAW_EMAIL_RETENTION_DAYS` (default 30) are purged best-effort at backend startup.
- **SQLite by default, Postgres for real deployments**: `DATABASE_URL` defaults to a local SQLite
  file so `uvicorn` and `pytest` both run with zero setup. Point it at Postgres (e.g. the
  docker-compose service below) for a real deployment.

### Endpoints

| Method & path | Purpose |
| --- | --- |
| `POST /api/analyze` | Analyzes a `.eml` and now also persists + returns a case `id`. |
| `GET /api/cases` | Paginated case list. Filters: `verdict`, `date_from`, `date_to`. |
| `GET /api/cases/{id}` | Full persisted case detail. |
| `DELETE /api/cases/{id}` | Deletes the case row and its stored raw `.eml`. |

### Postgres via Docker

```sh
docker compose up -d                 # starts Postgres on localhost:5432
cd backend
# in .env: DATABASE_URL=postgresql+psycopg://aegis:aegis@localhost:5432/aegis
alembic upgrade head
```

Without Docker, the backend falls back to a local `aegis.db` SQLite file and creates the schema
automatically at startup (no `alembic upgrade` needed for that path).

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./aegis.db` | SQLAlchemy DB URL. |
| `RAW_EMAIL_STORAGE_DIR` | `./data/raw_emails` | Where raw `.eml` uploads are stored. |
| `RAW_EMAIL_RETENTION_DAYS` | `30` | Days a raw `.eml` is kept before purge. |

## Backend

Requires Python 3.11+.

```sh
cd backend
python3.11 -m venv .venv && source .venv/bin/activate   # use whichever 3.11+ interpreter you have
pip install -e ".[dev]"
pytest -v
uvicorn app.main:app --reload
```

`POST http://localhost:8000/api/analyze` with a multipart `file` field containing a `.eml`.

The test suite pins each test to a fresh in-memory SQLite database (see
`backend/tests/conftest.py`) — it never touches Postgres or your local `aegis.db`.

## Frontend

```sh
cd frontend
npm install
npm run dev
```

The dev server proxies `/api` to `http://localhost:8000` (see `vite.config.ts`). The **Cases** tab
lists past analyses (verdict, score, sender, date), with filtering, pagination, and a click-through
detail view.
