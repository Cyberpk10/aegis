# Aegis

Aegis is a **defensive** email-security analysis tool. It ingests a single `.eml` file, runs a
deterministic, rule-based phishing indicator engine over it, fuses the findings into a 0-100 risk
score, and maps the findings to compliance/control frameworks (MITRE ATT&CK, NIST CSF, ISO 27001,
SOC 2).

Aegis performs **analysis only**: it does not send email, does not exploit anything, and does not
make outbound network/DNS calls. SPF/DKIM/DMARC results are parsed from the email's existing
`Authentication-Results` header rather than independently re-verified.

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

## Frontend

```sh
cd frontend
npm install
npm run dev
```

The dev server proxies `/api` to `http://localhost:8000` (see `vite.config.ts`).
