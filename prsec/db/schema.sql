-- PRSec schema. Postgres is both the job queue (scans) and the findings index.

CREATE TABLE IF NOT EXISTS scans (
    id              BIGSERIAL PRIMARY KEY,
    scm             TEXT        NOT NULL DEFAULT 'github',
    repo            TEXT        NOT NULL,
    pr              INTEGER     NOT NULL,
    head_sha        TEXT        NOT NULL,
    base_sha        TEXT,
    installation_id BIGINT,
    skills_version  TEXT        NOT NULL,
    reason          TEXT        NOT NULL DEFAULT 'opened',
    status          TEXT        NOT NULL DEFAULT 'queued',  -- queued|running|done|skipped|failed|superseded
    not_before      TIMESTAMPTZ NOT NULL DEFAULT now(),    -- debounce
    lease_until     TIMESTAMPTZ,
    attempts        INTEGER     NOT NULL DEFAULT 0,
    supersede_count INTEGER     NOT NULL DEFAULT 0,        -- inherited from superseded predecessors
    triage          JSONB,
    error           TEXT,
    cost_usd        NUMERIC(10,4) NOT NULL DEFAULT 0,
    sarif_uri       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    UNIQUE (repo, pr, head_sha, skills_version)
);
-- lease_token: generation of the current lease; only its holder may heartbeat/finish/record.
-- retries: how often a failed scan of this head was re-queued (capped, with backoff).
ALTER TABLE scans ADD COLUMN IF NOT EXISTS lease_token TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS retries INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS scans_queue_idx ON scans (status, not_before) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS scans_pr_idx ON scans (repo, pr);

CREATE TABLE IF NOT EXISTS stage_runs (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         BIGINT      NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    task_id         TEXT        NOT NULL UNIQUE,
    stage           TEXT        NOT NULL,
    harness         TEXT        NOT NULL,
    harness_version TEXT,
    model           TEXT        NOT NULL,
    status          TEXT        NOT NULL,
    attempts        INTEGER     NOT NULL DEFAULT 1,
    usage           JSONB       NOT NULL DEFAULT '{}',
    output          JSONB,
    errors          JSONB       NOT NULL DEFAULT '[]',
    transcript_uri  TEXT,
    duration_s      DOUBLE PRECISION,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS stage_runs_scan_idx ON stage_runs (scan_id);

-- One row per distinct finding (repo + fingerprint); occurrences link it to scans.
CREATE TABLE IF NOT EXISTS findings (
    id              BIGSERIAL PRIMARY KEY,
    repo            TEXT        NOT NULL,
    fingerprint     TEXT        NOT NULL,
    bug_class       TEXT        NOT NULL,
    vuln_class      TEXT        NOT NULL,
    title           TEXT        NOT NULL,
    severity        TEXT        NOT NULL,
    label           TEXT        NOT NULL,              -- latest label
    introduced      BOOLEAN,
    sink_file       TEXT        NOT NULL,
    sink_line       INTEGER     NOT NULL,
    first_scan_id   BIGINT      NOT NULL REFERENCES scans(id),
    last_scan_id    BIGINT      NOT NULL REFERENCES scans(id),
    last_pr         INTEGER     NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'open',   -- open|stale|fixed
    triage_state    TEXT        NOT NULL DEFAULT 'new',    -- new|tp|fp|accepted
    triage_note     TEXT,
    data            JSONB       NOT NULL,              -- latest full Finding
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repo, fingerprint)
);

CREATE TABLE IF NOT EXISTS finding_occurrences (
    finding_id      BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_id         BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    label           TEXT   NOT NULL,
    PRIMARY KEY (finding_id, scan_id)
);
