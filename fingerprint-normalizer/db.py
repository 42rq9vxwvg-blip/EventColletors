"""
Database access and the backup-window guard.

Schema and table names confirmed against the live DB on 2026-08-21 (via
\\d in psql, DB "n8n", schema "monitoring") -- these are no longer
assumptions. monitoring_mcp has SELECT/INSERT/UPDATE on fingerprints and
event_fingerprints, and SELECT on events; confirmed the same day. DELETE
(needed only by migrate.py, only at a future version bump) still pending
confirmation as of this writing.

ASCII-only per project rule 5.
"""

import os
import time
from datetime import datetime, time as dtime
from zoneinfo import ZoneInfo

import psycopg2
import psycopg2.extras

# --- connection -------------------------------------------------------

PG_HOST = os.environ.get("PG_HOST", "postgres")
PG_PORT = os.environ.get("PG_PORT", "5432")
PG_DB = os.environ.get("PG_DB", "n8n")
# monitoring_mcp already has the privileges this container needs
# (confirmed via has_table_privilege, 2026-08-21) -- no dedicated
# fingerprint_svc user required. Not the n8n admin user, which is a
# separate login with full rights on everything.
PG_USER = os.environ.get("PG_USER", "monitoring_mcp")
PG_PASSWORD = os.environ.get("PG_PASSWORD", "")
PG_PASSWORD_FILE = os.environ.get("PG_PASSWORD_FILE")
if PG_PASSWORD_FILE and os.path.exists(PG_PASSWORD_FILE):
    with open(PG_PASSWORD_FILE) as f:
        PG_PASSWORD = f.read().strip()

# All three tables live in this schema, not "public". Everything below is
# schema-qualified explicitly rather than relying on a user's default
# search_path -- that happened to work by accident once already (the
# tables ended up in "monitoring" only because the n8n admin user's
# search_path defaulted there), and monitoring_mcp's search_path is not
# guaranteed to match.
DB_SCHEMA = os.environ.get("DB_SCHEMA", "monitoring")

# --- source event table: names confirmed via \d monitoring.events -----
EVENTS_TABLE = f"{DB_SCHEMA}.{os.environ.get('EVENTS_TABLE', 'events')}"
EVENTS_ID_COL = os.environ.get("EVENTS_ID_COL", "id")
EVENTS_TS_COL = os.environ.get("EVENTS_TS_COL", "timestamp")
EVENTS_HOST_COL = os.environ.get("EVENTS_HOST_COL", "host")
EVENTS_PROGRAM_COL = os.environ.get("EVENTS_PROGRAM_COL", "program")
EVENTS_MESSAGE_COL = os.environ.get("EVENTS_MESSAGE_COL", "message")

# fingerprints / event_fingerprints: confirmed existing with the exact
# structure from 001_create_fingerprints.sql / 002_event_fingerprints.sql,
# owned by n8n, schema "monitoring".
FINGERPRINTS_TABLE = f"{DB_SCHEMA}.fingerprints"
EVENT_FINGERPRINTS_TABLE = f"{DB_SCHEMA}.event_fingerprints"

# Single-row liveness marker, written every tick (004_normalizer_heartbeat.sql).
# Separate from event_fingerprints.computed_at on purpose: that only advances
# when work happens, so it cannot distinguish "idle" from "dead".
HEARTBEAT_TABLE = f"{DB_SCHEMA}.normalizer_heartbeat"

# --- operational knobs --------------------------------------------------
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "2000"))
FOLLOW_BATCH_SIZE = int(os.environ.get("FOLLOW_BATCH_SIZE", "500"))
FOLLOW_INTERVAL_SECONDS = int(os.environ.get("FOLLOW_INTERVAL_SECONDS", "300"))

# Applies to any pass (backfill OR a follow tick that fell behind) that
# would touch more than this many pending events at once -- that is the
# "voller Scan" I/O load Axel wants kept out of the nightly backup window.
# Small routine follow ticks stay under this and are never blocked.
LARGE_BATCH_THRESHOLD = int(os.environ.get("LARGE_BATCH_THRESHOLD", "2000"))

TZ = ZoneInfo(os.environ.get("TZ", "Europe/Berlin"))
BLACKOUT_START = dtime(23, 45)
BLACKOUT_END = dtime(4, 0)


def get_connection():
    return psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASSWORD
    )


def in_blackout_window(now: datetime | None = None) -> bool:
    """True during the nightly backup window (23:45-04:00 Europe/Berlin),
    derived from observed backup start times: Paperless ab 23:55, C2 ab
    01:00, USB ab 02:00, Integritaetspruefung ab 03:00. A full scan in this
    window is the I/O contention that has already taken Postgres down
    twice (I-07/I-08 in the incident typology)."""
    now = now or datetime.now(TZ)
    t = now.timetz().replace(tzinfo=None)
    if BLACKOUT_START <= BLACKOUT_END:
        return BLACKOUT_START <= t < BLACKOUT_END
    # wraps around midnight
    return t >= BLACKOUT_START or t < BLACKOUT_END


def wait_until_outside_blackout(poll_seconds: int = 60) -> None:
    while in_blackout_window():
        time.sleep(poll_seconds)
