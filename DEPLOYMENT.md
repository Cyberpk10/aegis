# Deploying Aegis to production

Backend → **Render** (Docker web service + managed Postgres). Frontend → **Vercel** (static Vite
build). This gets you a live HTTPS URL end to end. Follow the steps in order — the backend and
frontend each need the other's URL, so there's a short back-and-forth at steps 5 and 6.

## Before you start

- **Accounts**: GitHub (free), Render (free to create; the resources below cost money — see
  below), Vercel (you may already have one). Optionally an Anthropic API key if you want the LLM
  analyst narrative / copilot on in production — off by default, same as local dev.
- **Cost**: this guide uses Render's **Starter** web service (~$7/mo, always-on) and **Basic-256mb**
  Postgres (~$6–7/mo, persistent) — roughly **$13–14/mo total**. Render also has free tiers for
  both (web service sleeps after 15 min idle; Postgres auto-deletes 30 days after creation) if
  you want to evaluate before paying — swap `plan: starter`/`plan: basic-256mb` in `render.yaml`
  for `plan: free` if so, and skip that database expiring being a problem for you. Confirm
  current prices at [render.com/pricing](https://render.com/pricing) before entering a card —
  they change over time. Vercel's Hobby plan (used below) is free.
- **No custom domain needed** — Render and Vercel both give you free HTTPS on their own
  subdomains (`*.onrender.com` / `*.vercel.app`).

## 1. Push this repo to GitHub

Render builds from a connected GitHub repo. If this repo isn't on GitHub yet:

```bash
gh repo create aegis --private --source=. --remote=origin
git push -u origin main
```

(Or create the repo in the GitHub UI first, then `git remote add origin <url> && git push -u origin main`.)

## 2. (Optional) Test the Docker image locally first

Proves the container + migrations actually work before you pay for anything:

```bash
docker compose up -d db          # local Postgres, from the repo-root docker-compose.yml
docker build -t aegis-backend backend/
docker run --rm -p 8000:8000 \
  -e DATABASE_URL="postgresql+psycopg://aegis:aegis@host.docker.internal:5432/aegis" \
  aegis-backend
```

Watch the logs for `alembic upgrade head` completing, then `curl http://localhost:8000/health` —
should return `{"status":"ok"}`.

## 3. Create the Render resources

**Recommended — Blueprint (one step, auto-wires the database URL):**

1. In the Render dashboard: **New +** → **Blueprint**.
2. Connect your GitHub account if you haven't, select the `aegis` repo.
3. Render reads `render.yaml` from the repo root and shows you the two resources it'll create
   (`aegis-db` Postgres, `aegis-backend` web service) — confirm the plans match what you want
   (Starter/Basic-256mb per above, or swap to `free` first if you changed the file).
4. It'll prompt you for the `sync: false` env vars (`CORS_ALLOWED_ORIGINS`, `ANTHROPIC_API_KEY`)
   — leave `CORS_ALLOWED_ORIGINS` as a placeholder like `https://placeholder.vercel.app` for now,
   you'll fix it in step 6. Leave `ANTHROPIC_API_KEY` blank unless you're enabling LLM features.
5. Click through to create both resources.

**If the Blueprint import fails to parse** (Render's blueprint schema has changed over time —
`render.yaml` here matches the current documented format, but confirm against your dashboard if
it errors): create them manually instead —
1. **New +** → **PostgreSQL** → name it `aegis-db`, plan Basic-256mb, create it. Copy its
   **Internal Connection String** once it's provisioned.
2. **New +** → **Web Service** → connect the `aegis` repo → Runtime: **Docker** → Dockerfile
   path `backend/Dockerfile`, Docker context `backend` → plan Starter.
3. Under **Environment**, add: `DATABASE_URL` (the connection string you copied),
   `ENVIRONMENT=production`, `LOG_LEVEL=INFO`, `CORS_ALLOWED_ORIGINS=https://placeholder.vercel.app`
   (temporary), and optionally `ANTHROPIC_API_KEY`/`ENABLE_LLM_REASONING=true`/`ENABLE_COPILOT=true`.
4. Set **Health Check Path** to `/health`. Create the service.

## 4. Confirm the backend is live

Once the first deploy finishes, open the build/deploy logs and confirm you see `alembic upgrade
head` run without errors. Then:

```bash
curl https://<your-service-name>.onrender.com/health
```

should return `{"status":"ok"}` over HTTPS. Note this URL — you need it in the next step.

## 5. Deploy the frontend to Vercel

A **new, separate** Vercel project (don't reuse an existing one you may have for another site):

```bash
cd frontend
npx vercel link          # creates a new project, follow the prompts
npx vercel env add VITE_API_BASE_URL production
# paste https://<your-service-name>.onrender.com when prompted (no trailing slash)
npx vercel --prod
```

Or via the dashboard: **Add New** → **Project** → import the repo, set **Root Directory** to
`frontend` (Vercel auto-detects Vite, no other config needed), add the `VITE_API_BASE_URL` env
var under Project Settings → Environment Variables, then deploy.

Note the resulting URL (`https://<project>.vercel.app`).

## 6. Lock CORS down to the real frontend URL

Back in Render, edit the `aegis-backend` web service's `CORS_ALLOWED_ORIGINS` env var to the real
Vercel URL from step 5 (e.g. `https://aegis-frontend.vercel.app` — no trailing slash). Saving it
triggers an automatic redeploy.

## 7. Verify end to end

Open the Vercel URL in a browser:
- Confirm it loads over HTTPS.
- Open the Cases view — it should successfully load data from the Render backend with no CORS
  errors in the browser console (DevTools → Console/Network).
- `curl -I https://<your-service-name>.onrender.com/api/cases` from outside the browser should
  also succeed (confirms the backend itself, independent of CORS, is healthy).

That's a live, HTTPS, production Aegis deployment.

## Notes for later

- `ENABLE_LLM_REASONING`/`ENABLE_COPILOT` are both off by default in `render.yaml`, matching
  local dev — turn them on (and set `ANTHROPIC_API_KEY`) once you've confirmed the base deploy
  works, not as part of the first deploy.
- Every subsequent push to the connected branch triggers a new Render build, which re-runs
  `alembic upgrade head` before starting — new migrations ship automatically on deploy.
- Logs: Render's dashboard log viewer captures stdout/stderr automatically, including uvicorn's
  per-request access log and anything from `logging` (level controlled by `LOG_LEVEL`).
