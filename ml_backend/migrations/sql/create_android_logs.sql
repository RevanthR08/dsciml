-- Native Android log rows (linked to scans). Run after `scans` exists.
-- Matches CSV: timestamp, pid, tid, level, tag, package_r, detail, score, penalty,
-- root, selinux, adb, devOpts, mock, temp, ram, net, label + derived fields.

CREATE TABLE IF NOT EXISTS android_logs (
    android_log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,

    logged_at TIMESTAMPTZ NOT NULL,
    pid INTEGER,
    tid INTEGER,
    level TEXT,
    tag TEXT,
    package_r TEXT,
    detail TEXT,

    score INTEGER,
    penalty INTEGER,
    root INTEGER,
    selinux INTEGER,
    adb INTEGER,
    devopts INTEGER,
    mock INTEGER,
    temp INTEGER,
    ram INTEGER,
    net TEXT,

    label TEXT,
    is_anomalous BOOLEAN NOT NULL DEFAULT FALSE,
    attack_category TEXT NOT NULL DEFAULT 'Normal'
);

CREATE INDEX IF NOT EXISTS ix_android_logs_scan_logged
    ON android_logs (scan_id, logged_at DESC);

CREATE INDEX IF NOT EXISTS ix_android_logs_package_r
    ON android_logs (package_r);

CREATE INDEX IF NOT EXISTS ix_android_logs_anomalous
    ON android_logs (scan_id)
    WHERE is_anomalous = TRUE;
