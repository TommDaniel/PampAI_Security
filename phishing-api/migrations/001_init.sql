-- Migration 001: Initial schema
-- Creates organisations, phishing_events and alert_configs tables.

-- ---------------------------------------------------------------------------
-- organizations
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS organizations (
    id          SERIAL PRIMARY KEY,
    org_id      VARCHAR(64)  UNIQUE NOT NULL,
    api_key     VARCHAR(128) UNIQUE NOT NULL,
    name        VARCHAR(255),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- phishing_events
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS phishing_events (
    id                BIGSERIAL PRIMARY KEY,
    org_id            VARCHAR(64)  REFERENCES organizations(org_id) ON DELETE SET NULL,
    user_email        VARCHAR(320),                 -- header X-User-Email (per-user attribution)
    event_type        VARCHAR(16)  NOT NULL,        -- 'url' | 'email'
    -- URL fields
    url               TEXT,
    -- Email fields
    email_subject     TEXT,
    email_sender      TEXT,
    -- Detection result
    is_phishing       BOOLEAN      NOT NULL,
    confidence        FLOAT        NOT NULL,
    label             VARCHAR(16)  NOT NULL,        -- PHISHING | LEGITIMO | SUSPICIOUS
    analysis          TEXT,
    inference_ms      FLOAT,
    source            VARCHAR(16),                  -- bert | cascade | catboost | email_bert
    -- Email-specific extras
    email_score       FLOAT,
    language_detected VARCHAR(16),
    translated        BOOLEAN      DEFAULT FALSE,
    -- Extension metadata
    extension_id      VARCHAR(128),
    user_agent        TEXT,
    -- Timestamp
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_phishing_events_org_id     ON phishing_events (org_id);
CREATE INDEX IF NOT EXISTS idx_phishing_events_created_at ON phishing_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_phishing_events_is_phishing ON phishing_events (is_phishing);
CREATE INDEX IF NOT EXISTS idx_phishing_events_user_email ON phishing_events (user_email);

-- ---------------------------------------------------------------------------
-- alert_configs
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_configs (
    id          SERIAL PRIMARY KEY,
    org_id      VARCHAR(64)  NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    alert_type  VARCHAR(16)  NOT NULL,              -- 'webhook' | 'email'
    endpoint    TEXT         NOT NULL,              -- webhook URL or email address
    enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_configs_org_id ON alert_configs (org_id);
