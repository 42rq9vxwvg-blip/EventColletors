"""
LLM triage for the fingerprint review queue (Incident-Modell Phase 1).

One-shot batch, not a "follow" style loop: invoked once per night, e.g.
via host crontab -> "docker compose run --rm fingerprint-normalizer triage".
Reads fingerprints with bewertet_von IS NULL (never touched by this job or
by Axel), asks the model for a classification suggestion, and writes the
suggestion back with bewertet_von='llm:<model>'. This does NOT count as a
final review -- see 005_llm_triage_review.sql: "offen fuer Axel" is
bewertet_von IS DISTINCT FROM 'axel', so llm-suggested rows still show up
in the app's review queue until Axel confirms them via the backend.

Runs outside the meldepfad entirely (Projekt-Prompt Regel 2): a bad
suggestion here costs nothing, because nothing downstream acts on klasse/
incident_typ until Axel's confirmation flips bewertet_von to 'axel'.

Batch size and per-run cap follow LLM-Prompt_Fingerprint-Triage.md
(Abschnitt "Hinweise zum Betrieb" / Konzept-C-PDF Abschnitt 12.1):
20 fingerprints per model call, upper bound per run so an update-induced
spike in new fingerprints does not turn one run into an unbounded job.

ASCII-only per project rule 5.
"""

import json
import os
import sys

import anthropic
import psycopg2.extras

import db

MODEL_NAME = os.environ.get("TRIAGE_MODEL", "claude-sonnet-5")
BATCH_SIZE = int(os.environ.get("TRIAGE_BATCH_SIZE", "20"))
MAX_PER_RUN = int(os.environ.get("TRIAGE_MAX_PER_RUN", "60"))

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_API_KEY_FILE = os.environ.get("ANTHROPIC_API_KEY_FILE")
if ANTHROPIC_API_KEY_FILE and os.path.exists(ANTHROPIC_API_KEY_FILE):
    with open(ANTHROPIC_API_KEY_FILE) as f:
        ANTHROPIC_API_KEY = f.read().strip()

_PROMPT_DIR = os.path.join(os.path.dirname(__file__), "prompts")
_SYSTEM_PROMPT_PATH = os.path.join(_PROMPT_DIR, "system_prompt.txt")

VALID_KLASSEN = {"rauschen", "betrieb", "relevant", "kritisch", "unklar"}
VALID_ROLLEN = {"ausloeser", "abschluss", "verlauf", "keine"}
VALID_SEVERITY = {"info", "warning", "error", "critical"}
VALID_ABSCHLUSS = {"paar", "stille", "keiner"}


def load_system_prompt() -> str:
    with open(_SYSTEM_PROMPT_PATH, "r", encoding="utf-8") as f:
        return f.read()


def fetch_open_fingerprints(cur, limit: int) -> list:
    cur.execute(
        f"""
        SELECT fingerprint, host, program, beispiel_roh, erstmals, zuletzt, vorkommen
        FROM {db.FINGERPRINTS_TABLE}
        WHERE bewertet_von IS NULL
        ORDER BY erstmals ASC
        LIMIT %s
        """,
        (limit,),
    )
    return cur.fetchall()


def to_prompt_items(rows: list) -> list:
    items = []
    for row in rows:
        items.append(
            {
                "id": row["fingerprint"],
                "host": row["host"],
                "program": row["program"],
                "fingerprint": row["fingerprint"],
                "beispiel_roh": row["beispiel_roh"],
                "erstmals_gesehen": row["erstmals"].isoformat(),
                "zuletzt_gesehen": row["zuletzt"].isoformat(),
                "vorkommen_gesamt": row["vorkommen"],
            }
        )
    return items


def call_model(client, system_prompt: str, items: list) -> list:
    user_prompt = "Bewerte die folgenden neuen Fingerprints.\n\n" + json.dumps(
        items, ensure_ascii=False, indent=2
    )
    response = client.messages.create(
        model=MODEL_NAME,
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )
    text = "".join(block.text for block in response.content if block.type == "text")
    return json.loads(text)


def is_valid_suggestion(item: dict) -> bool:
    return (
        isinstance(item.get("id"), str)
        and item.get("klasse") in VALID_KLASSEN
        and isinstance(item.get("incident_typ"), str)
        and item.get("rolle") in VALID_ROLLEN
        and item.get("severity") in VALID_SEVERITY
        and item.get("abschluss") in VALID_ABSCHLUSS
    )


def triage_batch(client, system_prompt: str, rows: list) -> tuple:
    """Returns (suggestions_by_id, error_count). Falls back to one call per
    fingerprint on invalid JSON, then to a fixed 'unklar' placeholder if
    even that fails -- per LLM-Prompt_Fingerprint-Triage.md: never block
    the job on a single bad response."""
    items = to_prompt_items(rows)
    suggestions = {}
    error_count = 0

    try:
        results = call_model(client, system_prompt, items)
        for result in results:
            if is_valid_suggestion(result):
                suggestions[result["id"]] = result
            else:
                error_count += 1
    except (json.JSONDecodeError, anthropic.APIError, KeyError, TypeError) as e:
        print(f"[triage] Batch-Antwort ungueltig ({e}), einzeln nachfassen.", flush=True)
        for row in rows:
            single_id = row["fingerprint"]
            try:
                results = call_model(client, system_prompt, to_prompt_items([row]))
                if results and is_valid_suggestion(results[0]):
                    suggestions[single_id] = results[0]
                else:
                    error_count += 1
            except (json.JSONDecodeError, anthropic.APIError, KeyError, TypeError, IndexError) as single_e:
                print(f"[triage] Einzelaufruf fuer {single_id} fehlgeschlagen ({single_e}), als unklar markiert.", flush=True)
                suggestions[single_id] = {
                    "id": single_id,
                    "klasse": "unklar",
                    "incident_typ": "I-00",
                    "rolle": "keine",
                    "severity": "info",
                    "group_key_felder": ["host", "program", "fingerprint"],
                    "abschluss": "stille",
                    "stille_minuten": 60,
                    "bezeichnung": row["beispiel_roh"][:60],
                    "begruendung": "LLM-Aufruf fehlgeschlagen, Platzhalter-Einstufung.",
                    "hinweis": None,
                }
                error_count += 1

    return suggestions, error_count


def write_suggestion(cur, fingerprint: str, suggestion: dict) -> None:
    cur.execute(
        f"""
        UPDATE {db.FINGERPRINTS_TABLE}
        SET klasse = %(klasse)s,
            incident_typ = %(incident_typ)s,
            llm_vorschlag = %(llm_vorschlag)s,
            bewertet_von = %(bewertet_von)s,
            bewertet_am = now()
        WHERE fingerprint = %(fingerprint)s
        """,
        {
            "klasse": suggestion["klasse"],
            "incident_typ": suggestion["incident_typ"],
            "llm_vorschlag": psycopg2.extras.Json(suggestion),
            "bewertet_von": f"llm:{MODEL_NAME}",
            "fingerprint": fingerprint,
        },
    )


def write_heartbeat(conn, batch_size: int, error_count: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO monitoring.llm_triage_heartbeat AS h
                (id, last_tick_at, last_run_at, last_batch_size, last_error_count, model_used)
            VALUES (1, now(),
                    CASE WHEN %(batch_size)s > 0 THEN now() ELSE NULL END,
                    %(batch_size)s, %(error_count)s, %(model_used)s)
            ON CONFLICT (id) DO UPDATE SET
                last_tick_at = EXCLUDED.last_tick_at,
                last_run_at = COALESCE(EXCLUDED.last_run_at, h.last_run_at),
                last_batch_size = EXCLUDED.last_batch_size,
                last_error_count = EXCLUDED.last_error_count,
                model_used = EXCLUDED.model_used
            """,
            {"batch_size": batch_size, "error_count": error_count, "model_used": MODEL_NAME},
        )
    conn.commit()


def main(argv) -> int:
    dry_run = "--dry-run" in argv

    if db.in_blackout_window():
        print("[triage] Nachtruhe (23:45-04:00), Lauf uebersprungen.", flush=True)
        return 0

    if not ANTHROPIC_API_KEY:
        print("[triage] ANTHROPIC_API_KEY fehlt, Abbruch.", file=sys.stderr, flush=True)
        return 1

    system_prompt = load_system_prompt()
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    conn = db.get_connection()
    total_evaluated = 0
    total_errors = 0
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            rows = fetch_open_fingerprints(cur, MAX_PER_RUN)
        conn.rollback()

        if not rows:
            print("[triage] Keine offenen Fingerprints.", flush=True)
            if not dry_run:
                write_heartbeat(conn, 0, 0)
            return 0

        print(f"[triage] {len(rows)} offene Fingerprints, Batchgroesse {BATCH_SIZE}.", flush=True)

        for start in range(0, len(rows), BATCH_SIZE):
            chunk = rows[start:start + BATCH_SIZE]
            suggestions, error_count = triage_batch(client, system_prompt, chunk)
            total_errors += error_count

            if dry_run:
                for fingerprint, suggestion in suggestions.items():
                    print(f"[triage] (dry-run) {fingerprint}: {suggestion['klasse']} / {suggestion['incident_typ']}", flush=True)
                continue

            with conn.cursor() as cur:
                for fingerprint, suggestion in suggestions.items():
                    write_suggestion(cur, fingerprint, suggestion)
            conn.commit()
            total_evaluated += len(suggestions)
            print(f"[triage] Batch geschrieben: {len(suggestions)} bewertet, {error_count} Fehler.", flush=True)

        if not dry_run:
            write_heartbeat(conn, total_evaluated, total_errors)
        print(f"[triage] Fertig. {total_evaluated} bewertet, {total_errors} Fehler.", flush=True)
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
