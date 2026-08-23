"""
Follow mode: infinite loop, small batches, sleeps between ticks.
restart: unless-stopped in compose replaces cron here.

If the container was down long enough that a backlog larger than
LARGE_BATCH_THRESHOLD has built up, a single tick would turn into exactly
the kind of full-scan I/O load the backup window needs protecting from --
so a large backlog is deferred (not processed) while inside that window,
and processed in small batches once outside it, same as backfill.

Reconnect on DB errors instead of dying (found 2026-08-22, via a
pg_terminate_backend that killed a held-open connection mid-cycle):
any psycopg2.Error during a tick closes the stale connection, reconnects
with backoff, logs, and continues -- a killed backend, a Postgres
restart, or a network hiccup on the Docker network becomes a logged
reconnect instead of a container crash. Previously this relied entirely
on the restart: unless-stopped policy outside the container, which works
but is slower and noisier than recovering in-process. This is exactly the
I-08 failure mode (DB unreachable) occurring in the component that feeds
the I-08 detection itself -- worth being robust about here specifically.

Roll back the read-only watermark/pending check every tick (found
2026-08-24, via a second pg_terminate_backend incident -- this time
another service's startup ALTER TABLE hanging waiting for an ACCESS
EXCLUSIVE lock): autocommit is intentionally off on this connection
(process_and_write_batch needs several statements to commit atomically),
so the implicit transaction opened by get_watermark()/count_pending()
never closes on its own. When neither branch below reaches
process_next_batch() (pending == 0, or a large backlog deferred during
the blackout window), nothing ever commits or rolls it back, and the
connection sits "idle in transaction" holding a snapshot on
monitoring.events for the rest of the sleep interval -- long enough to
block unrelated DDL elsewhere. This is a distinct failure mode from the
dead-connection case above: the connection is alive and answers fine,
so psycopg2.Error is never raised and the reconnect logic above does not
see it. Fixed by an unconditional rollback() right after the read,
before branching -- cheap (nothing was written) and closes the
transaction every tick regardless of which branch runs next.

ASCII-only per project rule 5.
"""

import signal
import sys
import time

import psycopg2

import db
import pipeline

_stop = False


def _handle_stop(signum, frame):
    global _stop
    _stop = True


def _connect_with_backoff(max_backoff_seconds: int = 60):
    """Keep trying db.get_connection() until it succeeds or a stop signal
    arrives. Backoff doubles each attempt, capped at max_backoff_seconds,
    so a fully-down Postgres doesn't turn into a tight retry loop."""
    delay = 1
    while not _stop:
        try:
            return db.get_connection()
        except psycopg2.Error as e:
            print(f"[follow] Verbindungsaufbau fehlgeschlagen: {e}. Erneut in {delay}s.", flush=True)
            for _ in range(delay):
                if _stop:
                    return None
                time.sleep(1)
            delay = min(delay * 2, max_backoff_seconds)
    return None


def main(argv):
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    conn = _connect_with_backoff()
    if conn is None:
        print("[follow] Beendet vor dem ersten Verbindungsaufbau (Stop-Signal).", flush=True)
        return 0

    print(
        f"[follow] Start. Batch={db.FOLLOW_BATCH_SIZE} "
        f"Intervall={db.FOLLOW_INTERVAL_SECONDS}s",
        flush=True,
    )
    try:
        while not _stop:
            try:
                with conn.cursor() as cur:
                    watermark = pipeline.get_watermark(cur)
                    pending = pipeline.count_pending(cur, watermark)
                conn.rollback()  # close the read-only transaction now, no
                                  # matter which branch below runs next --
                                  # see module docstring, 2026-08-24 fix

                if pending > db.LARGE_BATCH_THRESHOLD and db.in_blackout_window():
                    print(
                        f"[follow] {pending} Ereignisse Rueckstand waehrend der Nachtruhe -- "
                        "warte, statt in einem Rutsch nachzuziehen.",
                        flush=True,
                    )
                    processed = 0
                elif pending > 0:
                    processed = pipeline.process_next_batch(conn, db.FOLLOW_BATCH_SIZE)
                    print(f"[follow] {processed} Ereignisse verarbeitet ({pending} standen an)", flush=True)
                else:
                    # Previously this branch printed nothing at all, so a
                    # quiet stretch left no trace in the log and looked
                    # identical to a hung container. It is not: "nothing to
                    # do" is the normal state most of the time.
                    print(f"[follow] Leerlauf, nichts anstehend (Watermark={watermark})", flush=True)
                    processed = 0

                # Written on EVERY path, including idle and blackout -- this
                # is the liveness signal the API and the app read. Must stay
                # outside the branches above; if it only ran when work
                # happened it would be no better than MAX(computed_at).
                pipeline.write_heartbeat(conn, "follow", pending, processed)

                if processed > 0:
                    continue  # immediately check for more instead of sleeping

            except psycopg2.Error as e:
                print(f"[follow] DB-Fehler in diesem Zyklus: {e}. Baue Verbindung neu auf.", flush=True)
                try:
                    conn.close()
                except psycopg2.Error:
                    pass  # connection is already dead, nothing to clean up
                conn = _connect_with_backoff()
                if conn is None:
                    break  # stop signal arrived while reconnecting
                continue  # retry immediately with the fresh connection

            for _ in range(db.FOLLOW_INTERVAL_SECONDS):
                if _stop:
                    break
                time.sleep(1)
    finally:
        if conn is not None:
            try:
                conn.close()
            except psycopg2.Error:
                pass
        print("[follow] beendet.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))