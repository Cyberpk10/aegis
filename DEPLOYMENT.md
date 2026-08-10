# Deploying Aegis to production

Backend → **Render** (Docker web service + managed Postgres). Frontend → **Vercel** (static Vite
build). This gets you a live HTTPS URL end to end. Follow the steps in order — the backend and
frontend each need the other's URL, so there's a short back-and-forth at steps 5 and 6.

## Before you start

- **Accounts**: GitHub (free), Render (free to create; the resources below cost money — see
  below), Vercel (you may already have one). Optionally an Anthropic API key if you want the LLM
  analyst narrative / copilot on in production — off by default, same as local dev. If you want
  email forwarding intake (M8 Stage 3), also a free Mailgun account — see step 8.
- **Cost**: this guide uses Render's **Starter** web service (~$7/mo, always-on) and **Basic-256mb**
  Postgres (~$6–7/mo, persistent) — roughly **$13–14/mo total**. Render also has free tiers for
  both (web service sleeps after 15 min idle; Postgres auto-deletes 30 days after creation) if
  you want to evaluate before paying — swap `plan: starter`/`plan: basic-256mb` in `render.yaml`
  for `plan: free` if so, and skip that database expiring being a problem for you. Confirm
  current prices at [render.com/pricing](https://render.com/pricing) before entering a card —
  they change over time. Vercel's Hobby plan (used below) is free.
- **No custom domain needed for the app itself** — Render and Vercel both give you free HTTPS on
  their own subdomains (`*.onrender.com` / `*.vercel.app`). Email forwarding intake (step 8) is
  the one exception: receiving mail requires MX records, which only work on a domain you actually
  control DNS for — not possible on a Render/Vercel-managed subdomain. Skip step 8 entirely if you
  don't need that feature yet; everything else works without it.

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
4. It'll prompt you for the `sync: false` env vars (`CORS_ALLOWED_ORIGINS`, `ANTHROPIC_API_KEY`,
   `JWT_SECRET_KEY`) — leave `CORS_ALLOWED_ORIGINS` as a placeholder like
   `https://placeholder.vercel.app` for now, you'll fix it in step 6. Leave `ANTHROPIC_API_KEY`
   blank unless you're enabling LLM features. For `JWT_SECRET_KEY`, generate a real random value
   — `python3 -c "import secrets; print(secrets.token_urlsafe(64))"` — and paste it in; this one
   isn't optional, since it's what signs every session token (see the auth note below).
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
   (temporary), `JWT_SECRET_KEY` (a real random value — see step 4 above, this one's required),
   and optionally `ANTHROPIC_API_KEY`/`ENABLE_LLM_REASONING=true`/`ENABLE_COPILOT=true`.
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
- Confirm it loads over HTTPS and shows the Aegis login screen.
- Create an account through the onboarding screen (or sign in with one you already created via
  the API) — it should land on the dashboard with no CORS errors in the browser console
  (DevTools → Console/Network).
- `curl -I https://<your-service-name>.onrender.com/api/cases` from outside the browser should
  return `401` (confirms the backend itself, independent of CORS, is healthy and actually
  enforcing auth — a `200` here would mean routes aren't protected).

That's a live, HTTPS, production Aegis deployment.

## 8. (Optional) Email forwarding intake (M8 Stage 3) — Mailgun setup

Lets users forward suspicious emails to a per-account address (shown on the app's Settings tab)
instead of only uploading `.eml` files. Requires a domain you control DNS for.

1. Create a free [Mailgun](https://www.mailgun.com) account (100 emails/day, 1 inbound route,
   no time limit — no credit card needed for the free tier at signup).
2. **Sending → Domains** → add a receiving subdomain, e.g. `in.<yourdomain>.com` (a subdomain,
   not your apex domain — keeps this fully isolated from any existing mail/DNS on the root
   domain). Mailgun shows you MX records to add; add them at your DNS provider and wait for
   verification (usually minutes, can take longer).
3. **Receiving → Routes** → create a route:
   - **Filter**: `match_recipient("^pilot-[a-z0-9]+@in\.<yourdomain>\.com$")` (swap in your real
     subdomain; this one regex matches every account's address, so you never touch this again as
     new accounts sign up).
   - **Action**: `forward("https://<your-backend>.onrender.com/api/inbound/email/mime")` — the
     `/mime` suffix is what makes Mailgun include the full raw original email (`body-mime`)
     instead of its own parsed-apart fields; without it the webhook still works but falls back to
     a lower-fidelity reconstruction (see `app.inbound.mailgun.extract_raw_email`).
4. **Sending → Webhooks** → copy the **HTTP webhook signing key** (this is *not* your API key —
   it's a separate value used only to verify inbound webhook authenticity).
5. On the Render service, set `MAILGUN_WEBHOOK_SIGNING_KEY` (the value from step 4) and
   `INBOUND_EMAIL_DOMAIN` (the subdomain from step 2, e.g. `in.yourdomain.com`) — same
   `sync: false` prompt-for-value pattern as `JWT_SECRET_KEY`. Redeploy.
6. Verify: sign in to Aegis, open the **Settings** tab, copy the forwarding address shown there
   (`pilot-<token>@in.yourdomain.com`), and forward yourself a real (or sample) phishing email to
   it. A new Case should appear in the Cases tab within a few seconds. `curl -I
   https://<your-backend>.onrender.com/api/inbound/email/mime` (a bare GET, no valid payload)
   should return `405` (route exists, wrong method) rather than `404` — confirms the route is
   live even before you have a real forwarded email to test with.

## Notes for later

- `ENABLE_LLM_REASONING`/`ENABLE_COPILOT` are both off by default in `render.yaml`, matching
  local dev — turn them on (and set `ANTHROPIC_API_KEY`) once you've confirmed the base deploy
  works, not as part of the first deploy.
- Every subsequent push to the connected branch triggers a new Render build, which re-runs
  `alembic upgrade head` before starting — new migrations ship automatically on deploy.
- Logs: Render's dashboard log viewer captures stdout/stderr automatically, including uvicorn's
  per-request access log and anything from `logging` (level controlled by `LOG_LEVEL`).
- **Auth (M8 Stage 2)**: `JWT_SECRET_KEY` must stay the same value across restarts/redeploys —
  changing it (or leaving it unset, which falls back to a random per-process value) instantly
  invalidates every logged-in session. Password-reset and teammate-invite links are generated by
  the backend and returned directly in the API response rather than emailed (no email provider is
  wired up yet) — an admin can find/relay them via `GET /api/auth/users` and the invite/reset
  endpoints, or by looking at the `invite_link`/`reset_link` field in the API response.
- **Email forwarding intake (M8 Stage 3)**: forwarded-email analysis is best-effort for anything
  other than a `message/rfc822` attachment forward — a plain "hit Forward" in Gmail/Outlook/Apple
  Mail is text-marker-parsed, which recovers the original sender/subject/body but *not* the
  original `Authentication-Results` header (SPF/DKIM/DMARC-based indicators on those cases reflect
  the forwarder's mail server, not the original attacker's — see `app.inbound.unwrap`). A Case is
  deduplicated per-account by content hash, so retries or an accidental double-forward of the
  exact same email don't create duplicate Cases.
