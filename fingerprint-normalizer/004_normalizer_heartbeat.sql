-- Phase 0: Herzschlag des Normalizers.
--
-- Warum eine eigene Tabelle und nicht MAX(computed_at) aus
-- event_fingerprints: dieser Wert waechst nur, wenn tatsaechlich etwas
-- verarbeitet wurde. Eine ruhige Nacht ohne neue Ereignisse ist davon
-- nicht von einem toten Container zu unterscheiden -- genau die
-- Verwechslung, die am 2026-08-24 zu einer Fehldiagnose gefuehrt hat
-- ("haengt schon wieder", obwohl schlicht nichts anstand).
--
-- last_tick_at  = der Prozess lebt (wird JEDEN Zyklus geschrieben,
--                 auch im Leerlauf und waehrend der Nachtruhe)
-- last_work_at  = zuletzt wurde tatsaechlich etwas verarbeitet
--
-- Nur diese beiden zusammen erlauben die Unterscheidung:
--   tick frisch, work alt   -> laeuft, nichts zu tun (normal)
--   tick alt                -> Prozess haengt oder ist tot (Alarm)

CREATE TABLE IF NOT EXISTS monitoring.normalizer_heartbeat (
    id              SMALLINT PRIMARY KEY,
    mode            TEXT NOT NULL,              -- follow|backfill|migrate
    last_tick_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_work_at    TIMESTAMPTZ,                -- NULL = seit Start nichts verarbeitet
    last_pending    BIGINT NOT NULL DEFAULT 0,  -- Rueckstand beim letzten Tick
    last_batch_size INTEGER NOT NULL DEFAULT 0, -- im letzten Tick verarbeitet
    cleaner_ver     INTEGER NOT NULL,
    normalizer_ver  INTEGER NOT NULL,

    -- Genau eine Zeile: der Herzschlag ist ein Zustand, keine Historie.
    -- Verlauf steckt bereits in event_fingerprints.computed_at.
    CONSTRAINT normalizer_heartbeat_single_row CHECK (id = 1)
);

-- Der Container schreibt unter monitoring_mcp (siehe db.py). Ohne diese
-- Rechte laeuft der erste Tick nach dem Deploy in einen Permission-Fehler,
-- der dank des Reconnect-Handlers in follow.py als Endlosschleife aus
-- Reconnect-Versuchen sichtbar wuerde, nicht als klarer Abbruch.
GRANT SELECT, INSERT, UPDATE ON monitoring.normalizer_heartbeat TO monitoring_mcp;

-- ACHTUNG: Das Dashboard-Backend liest diese Tabelle ebenfalls
-- (/api/fingerprints/stats). Es verbindet sich unter einem anderen User --
-- welchem, steht in database.py des Backend-Containers, mir lag die Datei
-- nicht vor. Falls das nicht ebenfalls monitoring_mcp ist, hier ergaenzen:
--   GRANT SELECT ON monitoring.normalizer_heartbeat TO <backend_user>;
