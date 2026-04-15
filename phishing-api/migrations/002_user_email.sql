-- Migration 002: add user_email column for per-user attribution
-- The extension already sends the X-User-Email header. This migration adds storage and indexing.
ALTER TABLE phishing_events ADD COLUMN IF NOT EXISTS user_email VARCHAR(320);
CREATE INDEX IF NOT EXISTS idx_phishing_events_user_email ON phishing_events (user_email);
