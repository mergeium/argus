-- Event Store: append-only domain events table (immutable — INSERT only)
-- PDF §11.3.1: Event Store Tablo Yapısı

CREATE TABLE IF NOT EXISTS domain_events (
    id                  BIGSERIAL       PRIMARY KEY,
    aggregate_type      TEXT            NOT NULL,
    aggregate_id        UUID            NOT NULL,
    aggregate_version   BIGINT          NOT NULL,
    event_type          TEXT            NOT NULL,
    payload             JSONB           NOT NULL,
    metadata            JSONB           NOT NULL DEFAULT '{}',
    tenant_id           UUID            NOT NULL,
    schema_version      SMALLINT        NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),

    CONSTRAINT uq_aggregate_version UNIQUE (aggregate_type, aggregate_id, aggregate_version)
);

CREATE INDEX IF NOT EXISTS idx_events_aggregate_id ON domain_events (aggregate_id);
CREATE INDEX IF NOT EXISTS idx_events_tenant_type ON domain_events (tenant_id, aggregate_type);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON domain_events (created_at);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON domain_events (event_type);

ALTER TABLE domain_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_events ON domain_events
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
