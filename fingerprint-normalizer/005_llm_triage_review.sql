-- 005: Phase 1 -- LLM-Triage-Unterstuetzung (Incident-Typologie_Konzept-C.pdf, Abschnitt 12).
--
-- Kein Eingriff in bestehende Spalten oder Constraints aus 001 -- der
-- LLM-Batchjob schreibt weiterhin ueber die vorhandenen Spalten
-- (klasse, incident_typ, bewertet_am, bewertet_von), das CHECK
-- 'axel' | 'llm:%' war dafuer bereits vorbereitet.
--
-- Zwei Ergaenzungen:
--   1. "offen fuer Axel" ist NICHT mehr bewertet_am IS NULL, sobald der
--      Batchjob live ist -- ein llm-bewerteter Fingerprint (bewertet_von
--      LIKE 'llm:%') ist ein VORSCHLAG, kein Abschluss (siehe
--      LLM-Prompt_Fingerprint-Triage.md: "Vorschlag, keine Entscheidung.
--      Erst deine Bestaetigung schreibt Klasse und Typ ins Register.").
--      Der alte Index (fingerprints_offen_idx aus 001) bleibt unveraendert
--      bestehen (andere Abfragen koennten sich noch darauf verlassen),
--      wird von der neuen Pruefliste im Backend aber nicht mehr benutzt.
--   2. Die Modellantwort traegt mehr Felder als die Tabelle bisher fasst
--      (rolle, severity, group_key_felder, abschluss, stille_minuten,
--      bezeichnung, begruendung, hinweis) -- die werden fuer Phase 2
--      (Korrelationsregeln) gebraucht und sollen nicht verloren gehen,
--      nur weil Phase 1 sie noch nicht auswertet. Ablage als JSONB statt
--      eigener Spalten je Feld, weil das Schema der Modellantwort sich
--      mit dem Prompt weiterentwickeln kann, ohne eine weitere Migration
--      zu erzwingen.

ALTER TABLE monitoring.fingerprints
    ADD COLUMN IF NOT EXISTS llm_vorschlag JSONB;

-- Ersetzt fingerprints_offen_idx fuer die Pruefliste: alles, was noch
-- NICHT von Axel final bestaetigt ist (weder unbewertet noch nur
-- llm-vorbewertet). IS DISTINCT FROM statt <> ... OR ... IS NULL, damit
-- der Fall bewertet_von IS NULL sauber mit erfasst wird.
CREATE INDEX IF NOT EXISTS fingerprints_wartet_auf_axel_idx
    ON monitoring.fingerprints (erstmals DESC)
    WHERE bewertet_von IS DISTINCT FROM 'axel';

-- Herzschlag/Log des LLM-Triage-Batchjobs, analog zu
-- 004_normalizer_heartbeat.sql und aus demselben Grund: eine ruhige
-- Nacht ohne neue Fingerprints (0 offene Formen) darf in der App nicht
-- wie ein toter/nie gelaufener Job aussehen. last_run_at wird nur bei
-- tatsaechlicher Verarbeitung gesetzt, nicht bei "nichts zu tun".
CREATE TABLE IF NOT EXISTS monitoring.llm_triage_heartbeat (
    id                 SMALLINT PRIMARY KEY,
    last_tick_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_at        TIMESTAMPTZ,          -- NULL = seit Start noch kein Batch verarbeitet
    last_batch_size    INTEGER NOT NULL DEFAULT 0,
    last_error_count   INTEGER NOT NULL DEFAULT 0,
    model_used         TEXT,

    CONSTRAINT llm_triage_heartbeat_single_row CHECK (id = 1)
);

GRANT SELECT, INSERT, UPDATE ON monitoring.llm_triage_heartbeat TO monitoring_mcp;
GRANT SELECT, INSERT, UPDATE ON monitoring.fingerprints TO monitoring_mcp;
-- monitoring_mcp hatte laut db.py bereits SELECT/INSERT/UPDATE auf
-- fingerprints -- das zweite GRANT hier ist ein no-op falls das noch gilt,
-- schadet aber nicht und dokumentiert die Annahme explizit fuer diese
-- Migration.

-- ACHTUNG wie schon bei 004: das Dashboard-Backend liest
-- monitoring.fingerprints und (fuer den Log-Status in der App) kuenftig
-- auch llm_triage_heartbeat, verbindet sich aber ueber einen eigenen
-- User (siehe database.py im event-monitoring-Repo). Falls das nicht
-- ebenfalls monitoring_mcp ist, hier ergaenzen:
--   GRANT SELECT ON monitoring.fingerprints TO <backend_user>;
--   GRANT SELECT ON monitoring.llm_triage_heartbeat TO <backend_user>;
--   GRANT UPDATE (klasse, incident_typ, bewertet_am, bewertet_von) ON monitoring.fingerprints TO <backend_user>;
