# Aegis backend — production image (M8 Stage 1).
#
# psycopg[binary] ships compiled wheels, so no Postgres dev headers/gcc are needed here.
# Migrations run at container start (see docker-entrypoint.sh), not at build time — build
# time has no DATABASE_URL to migrate against.

FROM python:3.12-slim

WORKDIR /app

# Only copy dependency metadata first so dependency install is cached across rebuilds that
# only change application code.
COPY pyproject.toml ./
COPY app ./app

RUN pip install --no-cache-dir .

COPY alembic.ini ./
COPY alembic ./alembic
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

RUN useradd --create-home --shell /usr/sbin/nologin appuser
USER appuser

EXPOSE 8000

ENTRYPOINT ["./docker-entrypoint.sh"]
