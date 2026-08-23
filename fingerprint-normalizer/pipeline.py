"""
Shared batch-processing core for backfill and follow.

Both modes call process_next_batch() in a loop -- backfill until it
returns 0 (caught up), follow forever with a sleep between ticks. This is
the single place that turns raw events into fingerprint upserts, so
backfill and the ongoing follow loop can never drift into two different
notions of what a fingerprint is (Axels Kernpunkt: geteilter Code, sonst
zwei Fingerprints fuer dieselbe Form).

Per-event processing is exactly-once by construction: the watermark is
MAX(event_id) in event_fingerprints, read and advanced within the same
transaction as the fingerprint upserts, so a crash mid-batch rolls
everything in that batch back together. vorkommen is therefore a plain
additive counter here -- correct BECAUSE the watermark guarantees an
event is never processed twice, not despite it.

ASCII-only per project rule 5.
"""

from collections import defaultdict

import psycopg2.extras

from normalizer import fingerprint as compute_fingerprint, CLEANER_VERSION, NORMALIZER_VERSION
import db


def get_watermark(cur) -> int:
    cur.execute(f"SELECT COALESCE(MAX(event_id), 0) FROM {db.EVENT_FINGERPRINTS_TABLE}")
    return cur.fetchone()[0]


def count_pending(cur, after_id: int) -> int:
    cur.execute(
        f"SELECT COUNT(*) FROM {db.EVENTS_TABLE} WHERE {db.EVENTS_ID_COL} > %s",
        (after_id,),
    )
    return cur.fetchone()[0]


def fetch_batch(cur, after_id: int, limit: int, min_timestamp=None):
    """Fetch the next batch of events strictly after after_id, ordered by
    id so the watermark advances monotonically. min_timestamp optionally
    bounds the initial backfill to the last N days."""
    query = (
        f"SELECT {db.EVENTS_ID_COL}, {db.EVENTS_TS_COL}, {db.EVENTS_HOST_COL}, "
        f"{db.EVENTS_PROGRAM_COL}, {db.EVENTS_MESSAGE_COL} "
        f"FROM {db.EVENTS_TABLE} WHERE {db.EVENTS_ID_COL} > %s"
    )
    params = [after_id]
    if min_timestamp is not None:
        query += f" AND {db.EVENTS_TS_COL} >= %s"
        params.append(min_timestamp)
    query += f" ORDER BY {db.EVENTS_ID_COL} LIMIT %s"
    params.append(limit)
    cur.execute(query, params)
    return cur.fetchall()


def process_and_write_batch(conn, events) -> int:
    """Compute fingerprints for a batch of event rows and write them
    (event_fingerprints bridge rows + fingerprints upsert) in one
    transaction. Returns the number of events actually processed (i.e.
    newly recorded -- see note below).

    events: sequence of (id, timestamp, host, program, message) rows.

    Write order matters here and is deliberately event_fingerprints FIRST:
    that INSERT ... ON CONFLICT (event_id) DO NOTHING RETURNING tells us
    exactly which events in this batch were NOT already recorded. Only
    those contribute to the fingerprints aggregates below. This makes
    reprocessing-safety a property of the SQL itself, not just of the
    watermark that normally prevents reprocessing in the first place --
    a manual mis-invocation replaying an old batch can no longer inflate
    vorkommen, it just becomes a no-op for anything already seen.
    event_fingerprints.fingerprint has a DEFERRABLE FK to fingerprints, so
    inserting it before the referenced fingerprints row exists is fine as
    long as that row exists by commit time (it does, see below).
    """
    if not events:
        # The caller (process_next_batch) already ran get_watermark() and
        # fetch_batch() on this connection, which opened a transaction that
        # is still open at this point. Every other exit from this function
        # commits; this early return did not, so an empty batch left the
        # connection "idle in transaction" holding ACCESS SHARE on
        # monitoring.events -- the same leak that was fixed in follow.py's
        # main loop on 2026-08-24, just on a second, rarer path (reachable
        # when count_pending() sees rows that fetch_batch() then filters out
        # via min_timestamp, and from any direct caller of this function).
        conn.rollback()
        return 0

    fp_by_event = {}
    for event_id, ts, host, program, message in events:
        fp_by_event[event_id] = (ts, host, program, message, compute_fingerprint(host, program, message))

    with conn.cursor() as cur:
        ef_candidates = [
            (
                event_id, r.fingerprint, CLEANER_VERSION, NORMALIZER_VERSION,
                r.bom_missing,               # host-aware, derived in normalizer
                r.bom_missing_unverified,    # strict subset of bom_missing
            )
            for event_id, (ts, host, program, message, r) in fp_by_event.items()
        ]
        newly_inserted = psycopg2.extras.execute_values(
            cur,
            f"""
            INSERT INTO {db.EVENT_FINGERPRINTS_TABLE}
                (event_id, fingerprint, cleaner_ver, normalizer_ver,
                 bom_missing, bom_missing_unverified)
            VALUES %s
            ON CONFLICT (event_id) DO NOTHING
            RETURNING event_id
            """,
            ef_candidates,
            fetch=True,
        )
        new_event_ids = {row[0] for row in newly_inserted}

        if not new_event_ids:
            conn.commit()  # nothing new; still commit to release the transaction cleanly
            return 0

        per_fp = {}
        bom_missing = 0
        bom_missing_unverified = defaultdict(int)
        for event_id in new_event_ids:
            ts, host, program, message, r = fp_by_event[event_id]

            if r.bom_missing:
                bom_missing += 1
                if r.bom_missing_unverified:
                    bom_missing_unverified[(host, program)] += 1

            agg = per_fp.get(r.fingerprint)
            if agg is None:
                per_fp[r.fingerprint] = {
                    "host": host, "program": program, "beispiel_roh": r.beispiel_roh,
                    "erstmals": ts, "zuletzt": ts, "count": 1,
                }
            else:
                agg["count"] += 1
                if ts < agg["erstmals"]:
                    agg["erstmals"] = ts
                if ts > agg["zuletzt"]:
                    agg["zuletzt"] = ts

        psycopg2.extras.execute_batch(
            cur,
            f"""
            INSERT INTO {db.FINGERPRINTS_TABLE} AS f
                (fingerprint, host, program, beispiel_roh, erstmals, zuletzt,
                 vorkommen, cleaner_ver, normalizer_ver)
            VALUES (%(fp)s, %(host)s, %(program)s, %(beispiel_roh)s,
                    %(erstmals)s, %(zuletzt)s, %(count)s, %(cleaner_ver)s,
                    %(normalizer_ver)s)
            ON CONFLICT (fingerprint) DO UPDATE SET
                vorkommen = f.vorkommen + EXCLUDED.vorkommen,
                erstmals = LEAST(f.erstmals, EXCLUDED.erstmals),
                zuletzt = GREATEST(f.zuletzt, EXCLUDED.zuletzt),
                cleaner_ver = EXCLUDED.cleaner_ver,
                normalizer_ver = EXCLUDED.normalizer_ver
            """,
            [
                {
                    "fp": fp, "host": a["host"], "program": a["program"],
                    "beispiel_roh": a["beispiel_roh"], "erstmals": a["erstmals"],
                    "zuletzt": a["zuletzt"], "count": a["count"],
                    "cleaner_ver": CLEANER_VERSION, "normalizer_ver": NORMALIZER_VERSION,
                }
                for fp, a in per_fp.items()
            ],
        )

    conn.commit()

    if bom_missing:
        print(f"[warn] {bom_missing} DiskStation225-Zeilen ohne BOM in diesem Batch", flush=True)
        for (host, program), n in bom_missing_unverified.items():
            print(
                f"[warn]   davon {n}x unverifizierte Quelle {host}/{program} "
                "-- Vorreinigungsregel pruefen",
                flush=True,
            )

    return len(new_event_ids)


def write_heartbeat(conn, mode: str, pending: int, processed: int) -> None:
    """Record that a tick just happened, whether or not it did any work.

    Committed immediately and on its own: the heartbeat must survive even
    if the following batch fails, and it must never be the reason a
    transaction stays open (see the 2026-08-24 idle-in-transaction fix).

    last_work_at is only advanced when processed > 0 -- COALESCE keeps the
    previous value on idle ticks rather than nulling it. That is what makes
    "running but nothing to do" distinguishable from "hung": last_tick_at
    stays fresh while last_work_at legitimately ages.
    """
    with conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO {db.HEARTBEAT_TABLE} AS h
                (id, mode, last_tick_at, last_work_at, last_pending,
                 last_batch_size, cleaner_ver, normalizer_ver)
            VALUES (1, %(mode)s, now(),
                    CASE WHEN %(processed)s > 0 THEN now() ELSE NULL END,
                    %(pending)s, %(processed)s, %(cleaner_ver)s, %(normalizer_ver)s)
            ON CONFLICT (id) DO UPDATE SET
                mode = EXCLUDED.mode,
                last_tick_at = EXCLUDED.last_tick_at,
                last_work_at = COALESCE(EXCLUDED.last_work_at, h.last_work_at),
                last_pending = EXCLUDED.last_pending,
                last_batch_size = EXCLUDED.last_batch_size,
                cleaner_ver = EXCLUDED.cleaner_ver,
                normalizer_ver = EXCLUDED.normalizer_ver
            """,
            {
                "mode": mode, "pending": pending, "processed": processed,
                "cleaner_ver": CLEANER_VERSION, "normalizer_ver": NORMALIZER_VERSION,
            },
        )
    conn.commit()


def process_next_batch(conn, limit: int, min_timestamp=None) -> int:
    """One unit of work: read watermark, fetch next batch, write it.
    Returns events processed (0 means caught up)."""
    with conn.cursor() as cur:
        watermark = get_watermark(cur)
        batch = fetch_batch(cur, watermark, limit, min_timestamp)
    return process_and_write_batch(conn, batch)