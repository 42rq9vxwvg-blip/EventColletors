-- Phase 0: fingerprints register (Incident-Typologie_Konzept-C.pdf, Abschnitt 11.5)
-- Passiv: nur Lese-Backfill schreibt hierhin, kein Ausfuehrungspfad haengt daran.
--
-- Schema explizit "monitoring" (nicht public) -- so ist es am 2026-08-21
-- tatsaechlich entstanden (per search_path des n8n-Admin-Users) und alle
-- anderen Tabellen (events, sync_status, wifi_linkrate) liegen dort auch.
-- Explizit statt implizit, damit ein Re-Run anderswo nicht vom Zufall des
-- jeweiligen search_path abhaengt.

CREATE SCHEMA IF NOT EXISTS monitoring;

CREATE TABLE IF NOT EXISTS monitoring.fingerprints (
    fingerprint     TEXT PRIMARY KEY,           -- host|program|normalisierte Form
    host            TEXT NOT NULL,
    program         TEXT NOT NULL,
    beispiel_roh    TEXT NOT NULL,               -- VORGEREINIGT (Stufe 1), nie die Rohform
    erstmals        TIMESTAMPTZ NOT NULL DEFAULT now(),
    zuletzt         TIMESTAMPTZ NOT NULL DEFAULT now(),
    vorkommen       BIGINT NOT NULL DEFAULT 1,
    cleaner_ver     INTEGER NOT NULL,            -- Version der Vorreinigung (Stufe 1)
    normalizer_ver  INTEGER NOT NULL,            -- Version der Normalisierung (Stufe 2)
    klasse          TEXT,                        -- rauschen|betrieb|relevant|kritisch|unklar
    incident_typ    TEXT,                        -- I-00 .. I-13
    bewertet_am     TIMESTAMPTZ,                 -- NULL = steht in der Pruefliste
    bewertet_von    TEXT,                        -- 'llm:claude-sonnet-5' | 'axel'

    CONSTRAINT fingerprints_klasse_valid CHECK (
        klasse IS NULL OR klasse IN ('rauschen', 'betrieb', 'relevant', 'kritisch', 'unklar')
    ),
    CONSTRAINT fingerprints_incident_typ_valid CHECK (
        incident_typ IS NULL OR incident_typ ~ '^I-(0[0-9]|1[0-3])$'
    ),
    -- bewertet_von ist bewusst kein starres CHECK-IN, weil der LLM-Wert das
    -- Modell mitfuehrt (Projekt-Prompt kann Modellversionen wechseln); nur
    -- das Praefix ist die Quelle der Wahrheit.
    CONSTRAINT fingerprints_bewertet_von_prefix CHECK (
        bewertet_von IS NULL OR bewertet_von = 'axel' OR bewertet_von LIKE 'llm:%'
    ),
    -- bewertet_am und bewertet_von muessen zusammen gesetzt oder beide leer sein
    CONSTRAINT fingerprints_bewertung_konsistent CHECK (
        (bewertet_am IS NULL) = (bewertet_von IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS fingerprints_offen_idx ON monitoring.fingerprints (erstmals DESC)
    WHERE bewertet_am IS NULL;

CREATE INDEX IF NOT EXISTS fingerprints_host_program_idx ON monitoring.fingerprints (host, program);

-- Fuer den Selbsttest aus Abschnitt 12.2 (Saettigungskurve): neue
-- Fingerprints pro Tag. Ein Teilindex auf erstmals reicht dafuer bereits
-- aus (s.o.), kein zusaetzlicher Index noetig.
