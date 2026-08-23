-- Bridge zwischen Ereignistabelle und fingerprints-Register.
-- Zwei Zwecke:
--   1. Watermark: MAX(event_id) ist der einzige Fortschrittszeiger. Kein
--      separates Watermark-File -- der Zeiger lebt in derselben Transaktion
--      wie die fingerprints-Schreibvorgaenge, dadurch nie inkonsistent bei
--      einem Absturz mitten im Batch.
--   2. Migrationsbruecke: haelt fest, welcher Fingerprint (und unter
--      welcher Regel-Version) aus welchem Ereignis entstanden ist. Ohne das
--      liesse sich bei einem Normalisierer-Update nicht mehr rekonstruieren,
--      welcher alte Fingerprint zu welchem neuen wird -- der alte Code ist
--      dann ja bereits ueberschrieben.

CREATE TABLE IF NOT EXISTS monitoring.event_fingerprints (
    event_id        BIGINT PRIMARY KEY,
    fingerprint     TEXT NOT NULL,
    cleaner_ver     INTEGER NOT NULL,
    normalizer_ver  INTEGER NOT NULL,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- DEFERRABLE: pipeline.py inserts event_fingerprints BEFORE fingerprints
    -- within the same transaction (see pipeline.py docstring for why --
    -- it's what makes reprocessing-safety enforceable at the SQL level,
    -- not just "by convention" via the watermark). The FK is still
    -- guaranteed to hold by commit time.
    CONSTRAINT event_fingerprints_fp_fk FOREIGN KEY (fingerprint)
        REFERENCES monitoring.fingerprints (fingerprint)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX IF NOT EXISTS event_fingerprints_fp_idx ON monitoring.event_fingerprints (fingerprint);
CREATE INDEX IF NOT EXISTS event_fingerprints_version_idx
    ON monitoring.event_fingerprints (cleaner_ver, normalizer_ver);
