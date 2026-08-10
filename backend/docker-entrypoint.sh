#!/bin/sh
set -e

if [ -z "$DATABASE_URL" ]; then
  echo "FATAL: DATABASE_URL is not set." >&2
  echo "This container requires a real database connection string in production — it will" >&2
  echo "not silently fall back to a local SQLite file (which would be wiped on every" >&2
  echo "redeploy and isn't writable by the container's non-root user anyway)." >&2
  echo "On Render: if you used the render.yaml Blueprint this should be wired automatically" >&2
  echo "from the aegis-db resource; if you created the web service manually, set" >&2
  echo "DATABASE_URL under its Environment tab to the Postgres instance's connection string." >&2
  exit 1
fi

alembic upgrade head
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --proxy-headers
