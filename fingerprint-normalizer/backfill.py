"""
Backfill mode: catch up from the current watermark to "now" in batches,
then exit. Intended for the initial 90-day pass and for catching up after
extended downtime.

Guarded against the nightly backup window: if the pending amount of work
looks like a full scan (more than LARGE_BATCH_THRESHOLD events outstanding)
and we are inside 23:45-04:00 Europe/Berlin, refuse to start rather than
compete with Hyper Backup / integrity check for disk I/O -- that
combination has taken Postgres down twice already (I-07/I-08).

Usage:
    python3 cli.py backfill [--since-days N] [--force] [--batch-size N]

ASCII-only per project rule 5.
"""

import argparse
import sys
from datetime import datetime, timedelta

import db
import pipeline


def main(argv):
    ap = argparse.ArgumentParser(prog="backfill")
    ap.add_argument(
        "--since-days",
        type=int,
        default=int(__import__("os").environ.get("BACKFILL_SINCE_DAYS", "90")),
        help="Nur Ereignisse der letzten N Tage beruecksichtigen (nur beim allerersten Lauf relevant; danach bestimmt der Watermark den Startpunkt ohnehin).",
    )
    ap.add_argument(
        "--batch-size", type=int, default=db.BATCH_SIZE, help="Events pro Transaktion."
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Nachtruhe-Guard (23:45-04:00) ignorieren. Nur fuer bewusste manuelle Laeufe.",
    )
    args = ap.parse_args(argv)

    min_ts = datetime.now(db.TZ) - timedelta(days=args.since_days)

    conn = db.get_connection()
    try:
        with conn.cursor() as cur:
            watermark = pipeline.get_watermark(cur)
            pending = pipeline.count_pending(cur, watermark)

        print(f"[backfill] Watermark event_id={watermark}, {pending} Ereignisse ausstehend", flush=True)

        if pending > db.LARGE_BATCH_THRESHOLD and db.in_blackout_window() and not args.force:
            print(
                "[backfill] Innerhalb der Nachtruhe (23:45-04:00) und "
                f"{pending} Ereignisse ausstehend (> {db.LARGE_BATCH_THRESHOLD}). "
                "Breche ab, um nicht mit Hyper Backup / Integritaetspruefung um Disk-I/O "
                "zu konkurrieren. Spaeter erneut starten oder --force verwenden.",
                flush=True,
            )
            return 1

        total = 0
        while True:
            # re-check the guard every iteration in case a long backfill
            # runs across midnight into the window
            if total > 0 and db.in_blackout_window() and not args.force:
                print(
                    "[backfill] Nachtruhe hat waehrend des Laufs begonnen, pausiere hier "
                    f"(bisher {total} verarbeitet). Erneut starten, um fortzusetzen.",
                    flush=True,
                )
                return 1

            n = pipeline.process_next_batch(conn, args.batch_size, min_timestamp=min_ts)
            if n == 0:
                break
            total += n
            print(f"[backfill] {total}/{pending} verarbeitet", flush=True)

        print(f"[backfill] fertig, {total} Ereignisse verarbeitet.", flush=True)
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
