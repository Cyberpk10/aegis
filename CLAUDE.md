# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Aegis is a **defensive** email/identity-security platform. It started as a single-shot `.eml`
analyzer (Milestone 1) and has grown milestone-by-milestone (see `README.md` and the dated
comments throughout `backend/app/core/config.py`, which doubles as a changelog) into:

- A deterministic, rule-based phishing indicator engine that fuses findings into a 0-100 risk
  score and maps them to compliance frameworks (MITRE ATT&CK, NIST CSF, ISO 27001, SOC 2).
- An optional ML classifier signal and an optional LLM analyst narrative, both bounded add-ons
  that can only nudge — never override — the rule-based verdict.
- Multi-channel (email + Slack/Teams chat) detection, cross-signal intrusion/UEBA detection over
  ingested activity events, case/incident management, audit evidence packs, and continuous
  control monitoring.
- Closed-loop autonomous response (quarantine, block domain, disable session, flag for review)
  gated by a policy engine, executed for real only via a Microsoft Graph connector — otherwise a
  mock connector, so nothing fires unconfigured.

Aegis performs analysis and (opt-in, policy-gated) containment only: no exploitation, no
destructive actions are defined anywhere in the action catalog.

Three independent components, each with its own dependency/test setup:

| Dir | What | Consumed by |
| --- | --- | --- |
| `backend/` | FastAPI app — the actual runtime | Render (prod), `uvicorn` (dev) |
| `frontend/` | React + Vite + TS SPA | Vercel (prod), `vite` (dev) |
| `ml/` | Offline corpus-assembly + training pipeline for the phishing classifier | Not imported by the runtime backend; publishes artifacts *into* `backend/app/ml/artifacts/` |

## Commands

### Backend (`cd backend`)

```sh
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -v                          # full suite
pytest tests/unit/test_risk_engine.py -v          # single file
pytest tests/unit/test_risk_engine.py::test_name  # single test
uvicorn app.main:app --reload      # dev server on :8000
```

Tests are fully offline/deterministic regardless of local `.env`: `tests/conftest.py` forces a
fresh in-memory SQLite DB per test, pins `enable_llm_reasoning`/`enable_ml_classifier` to
`False`, clears the ML model's `lru_cache`, and resets the shared rate limiter — all
`autouse=True` fixtures, so no per-test opt-in is needed.

Postgres (optional, for parity with prod):

```sh
docker compose up -d               # Postgres on localhost:5432
# backend/.env: DATABASE_URL=postgresql+psycopg://aegis:aegis@localhost:5432/aegis
alembic upgrade head
```

Without Docker/Postgres, `app.main`'s lifespan hook auto-creates tables on a local
`aegis.db` SQLite file — no Alembic step needed for that path. Real deployments (Postgres) are
expected to run `alembic upgrade head` instead of relying on that fallback.

### Frontend (`cd frontend`)

```sh
npm install
npm run dev       # Vite dev server; proxies /api -> http://localhost:8000
npm run build     # tsc -b && vite build
npm run lint      # eslint .
```

### ML pipeline (`cd ml`)

```sh
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
python -m aegis_ml.cli build --skip-download   # normalize -> dedupe -> split -> report
python -m aegis_ml.train                        # train, calibrate, evaluate, publish artifacts
```

`aegis_ml.train` writes documentation to `ml/models/{metrics.json,CARD.md}` (committed) and the
actual binary artifacts the backend loads to `backend/app/ml/artifacts/` (Docker's build context
is `backend/` only, hence the split location). `ml/aegis_ml/features.py` imports the real
backend parser/indicator code by path for train/serve feature parity — the two are pinned to
never drift.

No CI workflow or linter config (ruff/black/mypy) is currently checked in for the Python
packages; `frontend`'s `eslint` is the only configured linter in the repo.

## Backend architecture

**Request flow for the core analyzer** (`app/analysis/email_pipeline.py::run_email_pipeline`,
shared by the direct-upload, paste-text, and inbound-webhook entry points):

```
raw bytes -> parse_eml() -> run_indicators() -> [optional ML predict()] -> fuse() -> score/verdict
                                                                          -> map_indicators() -> framework mappings
                                                                          -> [optional LLM narrative]
```

- `app/parsing/eml_parser.py` + `app/parsing/auth_results.py` — parses `.eml` bytes, including
  `Authentication-Results` (SPF/DKIM/DMARC are read from this header, never independently
  re-verified — no outbound network/DNS calls anywhere in analysis).
- `app/indicators/` — one module per deterministic rule (sender/reply-to mismatch, look-alike
  domains, urgency language, credential/payment requests, link analysis, attachment risk, auth
  failures, AI-authored-text heuristics, chat context). `engine.py` is a flat registry +
  runner — adding a rule means adding a module and one line in `_RULES`.
- `app/scoring/risk_engine.py` — fuses indicator scores (+ optional bounded ML probability) into
  the 0-100 score and Safe/Suspicious/Malicious verdict. The ML signal is structurally bounded so
  it alone can never flip a verdict band.
- `app/mapping/framework_mapper.py` + `app/mapping/frameworks/*.yaml` — versioned YAML mapping
  indicator IDs to MITRE ATT&CK / NIST CSF / ISO 27001 / SOC 2 controls.
- `app/ml/classifier.py` — loads the joblib artifacts (see `ml/models/CARD.md`) and predicts;
  degrades to `(None, None)` if artifacts are missing or the feature is off.
- `app/reasoning/llm_analyst.py` — calls Anthropic (Haiku-class model) to narrate the
  already-computed verdict; never recomputes it. Fails soft (`null` narrative) on any error.

**Detections (intrusion/UEBA) mirror the indicators pattern exactly**, one level up from a
single email — over ingested activity `Event`s instead of a parsed email:

- `app/detections/` — one module per rule (brute force, impossible travel, anomalous location,
  off-hours access, mass file access, data exfiltration, privilege escalation).
  `engine.py::run_detections` is the same flat registry pattern as indicators.
- `app/baselines/aggregation.py` — per-actor behavioral baselines (UEBA) with cold-start gates
  (a baseline isn't trusted over static thresholds until it has enough history — see the
  `baseline_*` settings in `app/core/config.py`).
- `app/channels/` — Slack/Teams message adapters normalize chat messages into the same shape the
  indicator engine consumes (`chat_context` indicator); live ingestion is flagged off
  (`enable_live_slack_ingestion`/`enable_live_teams_ingestion`) pending real webhook wiring.

**Autonomy (closed-loop response)** — `app/autonomy/`:

- `actions.py` — the fixed, small action catalog (`QUARANTINE_EMAIL`, `DISABLE_SESSION`,
  `BLOCK_SENDER_DOMAIN`, `FLAG_ACCOUNT_FOR_REVIEW`). No destructive action exists anywhere in
  this module — that's a structural property, not a configurable policy.
  Reversible-by-default; `DISABLE_SESSION` is the one exception (no Graph API to un-revoke),
  which is why any irreversible action always requires human approval.
- `policy.py` — pure decision function (`AUTO_EXECUTE` / `REQUIRE_APPROVAL` / `SKIP`), no I/O.
- `executor.py` — the *only* place that calls a connector: enforces the policy decision, a
  blast-radius rate limit (reads the audit log, hence not in `policy.py`), and records the
  action.
- `connector_factory.py` — per-account seam choosing `MockConnector` (default, fully offline) vs
  `GraphConnector` (real Microsoft Graph). Falls back to mock unless the shared Graph app
  registration credentials *and* a per-account `GraphIntegration` row both exist and are enabled
  — nothing real ever fires for an unconfigured account.
- `graph_connector.py` — real MSAL/Graph calls; failure contract is strict (success dict or
  raise — no silent "soft failure" state), since the executor infers success purely from
  exceptions.

**Multi-tenancy & auth** (`app/db/models.py`, `app/auth/`): every `Account` (org/tenant) owns
many `User`s; virtually every other table (`Case`, `Incident`, `Event`, `Label`,
`AutonomyPolicy`/`AutonomyAction`, ...) is scoped to one `Account` via FK. JWT access + refresh
tokens; `app/auth/dependencies.py::get_current_user` reloads the `User` row from the DB on every
request (not just trusting token claims) so a deactivation or role change takes effect
immediately, not after TTL expiry. `require_admin` layers a role check on top.

**Config** (`app/core/config.py`): a single `Settings` dataclass, env-var-driven, loaded once at
import time as the module-level `settings` singleton. Every feature added since M2 is off by
default and documented inline with *why* — read the comment above a field before changing its
default. `.env` (gitignored) is auto-loaded via `python-dotenv`; real environment variables
always take precedence. `backend/.env.example` documents the full variable set.

**Persistence**: SQLite by default (zero-setup dev/test), Postgres via `DATABASE_URL` for real
deployments (`postgres://`/`postgresql://` URLs are rewritten to `postgresql+psycopg://` since
the app depends on psycopg v3, not the legacy psycopg2 default). Raw `.eml` uploads are stored on
disk keyed by case UUID (never in the DB — data minimization), purged after
`RAW_EMAIL_RETENTION_DAYS`.

**Routing**: every router lives in `app/api/routes/` and is included in `app/main.py`; there's no
router auto-discovery. `app/main.py`'s `lifespan` also runs the raw-email purge on startup and
(SQLite only) creates tables if missing.

## Frontend architecture

React + TS + Vite SPA, Tailwind for styling, Recharts for charts. `src/api/client.ts` is the
shared `apiFetch` wrapper every API module routes through: attaches the bearer token, and on a
401 transparently refreshes once and retries before falling back to logged-out state
(`onAuthExpired` callback, wired by `AuthContext`) — callers never handle token expiry
themselves. `src/components/` is organized by feature area (dashboard, autonomy, audit, copilot,
detections, monitoring, settings), mirroring the backend's route/domain split.

## Cross-cutting conventions worth knowing before editing

- **Registry pattern repeats deliberately**: indicators, detections, and (to a lesser extent)
  framework mappings are all "list of pure functions in a `_RULES`/`_RULES` list, run in a flat
  loop" — `app/detections/engine.py`'s docstring literally says it mirrors
  `app/indicators/engine.py`. Follow the existing pattern rather than introducing a new
  dispatch mechanism when adding a rule.
- **Feature flags default off and fail soft**: `enable_llm_reasoning`, `enable_ml_classifier`,
  `enable_copilot`, `enable_live_{slack,teams}_ingestion` all default `False`, and every one of
  them is designed so that missing config/artifacts/credentials degrades to "feature returns
  null/mock" rather than erroring. Preserve that contract for any new optional feature.
  `tests/conftest.py` pins the LLM and ML flags off for every test regardless of local `.env`.
- **Pure aggregation vs. I/O split**: modules like `app/dashboard/aggregation.py`,
  `app/baselines/aggregation.py`, and `app/autonomy/policy.py` are deliberately pure
  (no DB/network) with a thin caller elsewhere doing the I/O — makes them directly unit-testable
  without DB fixtures. Keep new aggregation/decision logic pure and push I/O to the route or a
  dedicated `store.py`.
- **One shared pipeline, not copies**: `app/analysis/email_pipeline.py` exists specifically so
  the direct-upload and inbound-webhook routes don't duplicate the parse -> indicators -> score
  -> mapping -> narrative sequence. `app/api/routes/messages.py` intentionally has its own
  smaller, separate pipeline (no `.eml`/raw-storage/LLM involved) — don't try to unify those two.
