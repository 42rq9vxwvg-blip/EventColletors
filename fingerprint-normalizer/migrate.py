"""
Migration step for a normalizer/cleaner version bump.

The problem: bumping CLEANER_VERSION or NORMALIZER_VERSION changes the
fingerprint STRING for some forms. Without this step, every hand-reviewed
klasse/incident_typ would orphan on the old string and the review queue
would silently refill with hundreds of already-known forms.

The bridge is event_fingerprints: for every event still tagged with an old
(cleaner_ver, normalizer_ver), re-read the raw event and recompute its
fingerprint under the CURRENT normalizer code. Group by old fingerprint:

  - All its events land on exactly one new fingerprint (merge or a
    cosmetic rename): carry the old classification over automatically.
    If two different old fingerprints merge into the same new one and
    disagree on classification, that is a genuine conflict -- do not
    guess, clear the classification and flag it for manual review.
  - Its events land on more than one new fingerprint (the new normalizer
    split what used to be one form): none of the resulting new
    fingerprints inherit a classification. They enter the review queue
    like any new form.

Old fingerprint rows are deleted once every event that produced them has
been migrated -- their contribution is now fully represented by the new
fingerprint row(s).

Usage:
    python3 cli.py migrate [--from-cleaner-ver N --from-normalizer-ver N] [--dry-run]

With no --from-* args, the old version is auto-detected: it must be the
single distinct (cleaner_ver, normalizer_ver) pair present in
event_fingerprints other than the current code's version. Ambiguous
history (more than one old version present) requires explicit args.

ASCII-only per project rule 5.
"""

import argparse
import sys

import psycopg2.extras

import db
from normalizer import fingerprint as compute_fingerprint, CLEANER_VERSION, NORMALIZER_VERSION


def detect_old_version(cur):
    cur.execute(
        "SELECT DISTINCT cleaner_ver, normalizer_ver FROM " + db.EVENT_FINGERPRINTS_TABLE + " "
        "WHERE (cleaner_ver, normalizer_ver) <> (%s, %s)",
        (CLEANER_VERSION, NORMALIZER_VERSION),
    )
    rows = cur.fetchall()
    if not rows:
        return None
    if len(rows) > 1:
        raise SystemExit(
            "Mehr als eine alte Version im Register gefunden "
            f"({rows}) -- bitte --from-cleaner-ver/--from-normalizer-ver explizit angeben."
        )
    return rows[0]


def migrate_one(conn, old_fp, old_c, old_n, dry_run):
    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT ef.event_id, e.{db.EVENTS_TS_COL}, e.{db.EVENTS_HOST_COL},
                   e.{db.EVENTS_PROGRAM_COL}, e.{db.EVENTS_MESSAGE_COL}
            FROM {db.EVENT_FINGERPRINTS_TABLE} ef
            JOIN {db.EVENTS_TABLE} e ON e.{db.EVENTS_ID_COL} = ef.event_id
            WHERE ef.fingerprint = %s AND ef.cleaner_ver = %s AND ef.normalizer_ver = %s
            """,
            (old_fp, old_c, old_n),
        )
        rows = cur.fetchall()

        cur.execute(
            f"SELECT klasse, incident_typ, bewertet_am, bewertet_von "
            f"FROM {db.FINGERPRINTS_TABLE} WHERE fingerprint = %s",
            (old_fp,),
        )
        old_class = cur.fetchone()

    new_agg = {}
    event_updates = []
    for event_id, ts, host, program, message in rows:
        r = compute_fingerprint(host, program, message)
        event_updates.append((event_id, r.fingerprint))
        a = new_agg.setdefault(
            r.fingerprint,
            {
                "host": host,
                "program": program,
                "beispiel_roh": r.beispiel_roh,
                "erstmals": ts,
                "zuletzt": ts,
                "count": 0,
            },
        )
        a["count"] += 1
        a["erstmals"] = min(a["erstmals"], ts)
        a["zuletzt"] = max(a["zuletzt"], ts)

    targets = list(new_agg.keys())
    classified = bool(old_class) and old_class[2] is not None  # bewertet_am set
    result = {"old_fp": old_fp, "targets": targets, "events": len(rows), "outcome": None}

    if dry_run:
        result["outcome"] = "dry-run"
        return result

    with conn.cursor() as cur:
        for new_fp, a in new_agg.items():
            cur.execute(
                f"""
                INSERT INTO {db.FINGERPRINTS_TABLE} AS f
                    (fingerprint, host, program, beispiel_roh, erstmals, zuletzt,
                     vorkommen, cleaner_ver, normalizer_ver)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (fingerprint) DO UPDATE SET
                    vorkommen = f.vorkommen + EXCLUDED.vorkommen,
                    erstmals = LEAST(f.erstmals, EXCLUDED.erstmals),
                    zuletzt = GREATEST(f.zuletzt, EXCLUDED.zuletzt),
                    cleaner_ver = EXCLUDED.cleaner_ver,
                    normalizer_ver = EXCLUDED.normalizer_ver
                """,
                (
                    new_fp, a["host"], a["program"], a["beispiel_roh"],
                    a["erstmals"], a["zuletzt"], a["count"],
                    CLEANER_VERSION, NORMALIZER_VERSION,
                ),
            )

        if len(targets) == 1 and classified:
            new_fp = targets[0]
            cur.execute(
                f"SELECT klasse, incident_typ, bewertet_am, bewertet_von "
                f"FROM {db.FINGERPRINTS_TABLE} WHERE fingerprint = %s",
                (new_fp,),
            )
            existing = cur.fetchone()
            existing_classified = bool(existing) and existing[2] is not None

            if not existing_classified:
                cur.execute(
                    f"UPDATE {db.FINGERPRINTS_TABLE} SET klasse=%s, incident_typ=%s, "
                    f"bewertet_am=%s, bewertet_von=%s WHERE fingerprint=%s",
                    (*old_class[:4], new_fp),
                )
                result["outcome"] = "carried_over"
            elif existing[0] != old_class[0] or existing[1] != old_class[1]:
                # two old fingerprints merged into one new one and disagree
                # -- do not guess, force a fresh review.
                cur.execute(
                    f"UPDATE {db.FINGERPRINTS_TABLE} SET klasse=NULL, incident_typ=NULL, "
                    f"bewertet_am=NULL, bewertet_von=NULL WHERE fingerprint=%s",
                    (new_fp,),
                )
                result["outcome"] = "conflict"
                result["conflict_with"] = existing
            else:
                result["outcome"] = "already_consistent"
        elif len(targets) > 1 and classified:
            result["outcome"] = "split_needs_review"
        else:
            result["outcome"] = "unclassified_no_action"

        psycopg2.extras.execute_batch(
            cur,
            f"UPDATE {db.EVENT_FINGERPRINTS_TABLE} SET fingerprint=%s, cleaner_ver=%s, "
            f"normalizer_ver=%s WHERE event_id=%s",
            [(new_fp, CLEANER_VERSION, NORMALIZER_VERSION, eid) for eid, new_fp in event_updates],
        )

        # old_fp is now fully superseded -- every event that produced it
        # has been re-tagged above, so its contribution lives on only in
        # the new fingerprint row(s).
        cur.execute(f"DELETE FROM {db.FINGERPRINTS_TABLE} WHERE fingerprint = %s", (old_fp,))

    conn.commit()
    return result


def main(argv):
    ap = argparse.ArgumentParser(prog="migrate")
    ap.add_argument("--from-cleaner-ver", type=int)
    ap.add_argument("--from-normalizer-ver", type=int)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    conn = db.get_connection()
    try:
        if args.from_cleaner_ver is not None and args.from_normalizer_ver is not None:
            old_c, old_n = args.from_cleaner_ver, args.from_normalizer_ver
        else:
            with conn.cursor() as cur:
                old = detect_old_version(cur)
            if old is None:
                print("[migrate] Keine alte Version im Register gefunden, nichts zu tun.")
                return 0
            old_c, old_n = old

        if (old_c, old_n) == (CLEANER_VERSION, NORMALIZER_VERSION):
            print("[migrate] Alte und aktuelle Version sind identisch, nichts zu tun.")
            return 0

        with conn.cursor() as cur:
            cur.execute(
                f"SELECT DISTINCT fingerprint FROM {db.EVENT_FINGERPRINTS_TABLE} "
                f"WHERE cleaner_ver = %s AND normalizer_ver = %s",
                (old_c, old_n),
            )
            old_fps = [row[0] for row in cur.fetchall()]

        print(
            f"[migrate] {len(old_fps)} alte Fingerprints "
            f"({old_c}.{old_n} -> {CLEANER_VERSION}.{NORMALIZER_VERSION})"
            f"{' [dry-run]' if args.dry_run else ''}",
            flush=True,
        )

        outcomes = {}
        conflicts = []
        splits = []
        for old_fp in old_fps:
            r = migrate_one(conn, old_fp, old_c, old_n, args.dry_run)
            outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
            if r["outcome"] == "conflict":
                conflicts.append(r)
            elif r["outcome"] == "split_needs_review":
                splits.append(r)

        print("[migrate] Zusammenfassung:", outcomes, flush=True)

        if conflicts:
            print(
                f"\n[migrate] {len(conflicts)} WIDERSPRUECHE -- manuell pruefen "
                "(zwei zusammengefuehrte Formen hatten unterschiedliche Klassen, "
                "beide Ziel-Fingerprints wurden auf unklar zurueckgesetzt):",
                flush=True,
            )
            for c in conflicts:
                print(f"  {c['old_fp'][:100]} -> {c['targets']}", flush=True)

        if splits:
            print(
                f"\n[migrate] {len(splits)} aufgespaltene Formen -- neue Fingerprints "
                "stehen unklassifiziert in der Pruefliste:",
                flush=True,
            )
            for s in splits:
                print(f"  {s['old_fp'][:100]} -> {s['targets']}", flush=True)

        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
