FROM python:3.12-slim

# tzdata for zoneinfo (Europe/Berlin blackout-window check); no compiler
# needed since psycopg2-binary ships its own libpq.
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV TZ=Europe/Berlin \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY normalizer.py db.py pipeline.py backfill.py follow.py migrate.py cli.py ./

ENTRYPOINT ["python3", "cli.py"]
# Default mode when the compose service starts normally. Override for a
# one-off run, e.g.:
#   docker compose run --rm fingerprint-normalizer backfill --since-days 90
#   docker compose run --rm fingerprint-normalizer migrate --dry-run
CMD ["follow"]
