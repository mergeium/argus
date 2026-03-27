-- Read Model: users projection (PDF §11.3.2)
CREATE TABLE IF NOT EXISTS users (
    id              UUID            PRIMARY KEY,
    tenant_id       UUID            NOT NULL,
    email           TEXT            NOT NULL,
    email_verified  BOOLEAN         NOT NULL DEFAULT false,
    display_name    TEXT,
    phone           TEXT,
    phone_verified  BOOLEAN         NOT NULL DEFAULT false,
    status          TEXT            NOT NULL DEFAULT 'pending_verification',
    password_hash   TEXT,
    metadata        JSONB           NOT NULL DEFAULT '{}',
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    CONSTRAINT uq_user_email_tenant UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_status ON users (status);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_users ON users
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Read Model: organizations
CREATE TABLE IF NOT EXISTS organizations (
    id              UUID            PRIMARY KEY,
    tenant_id       UUID            NOT NULL,
    name            TEXT            NOT NULL,
    slug            TEXT            NOT NULL,
    logo_url        TEXT,
    metadata        JSONB           NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    CONSTRAINT uq_org_slug_tenant UNIQUE (tenant_id, slug)
);
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_orgs ON organizations
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Read Model: active sessions
CREATE TABLE IF NOT EXISTS active_sessions (
    id              UUID            PRIMARY KEY,
    user_id         UUID            NOT NULL REFERENCES users(id),
    tenant_id       UUID            NOT NULL,
    client_id       UUID,
    device_id       UUID,
    ip              TEXT            NOT NULL,
    user_agent      TEXT            NOT NULL DEFAULT '',
    mfa_level       TEXT            NOT NULL DEFAULT 'none',
    risk_score      DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ     NOT NULL,
    last_active_at  TIMESTAMPTZ     NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON active_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON active_sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON active_sessions (tenant_id);
ALTER TABLE active_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_sessions ON active_sessions
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Read Model: MFA factors
CREATE TABLE IF NOT EXISTS mfa_factors (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID            NOT NULL REFERENCES users(id),
    tenant_id       UUID            NOT NULL,
    factor_type     TEXT            NOT NULL,
    factor_id       TEXT,
    is_primary      BOOLEAN         NOT NULL DEFAULT false,
    metadata        JSONB           NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_mfa_user ON mfa_factors (user_id, factor_type);

-- Read Model: passkeys
CREATE TABLE IF NOT EXISTS passkeys (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID            NOT NULL REFERENCES users(id),
    tenant_id       UUID            NOT NULL,
    credential_id   TEXT            NOT NULL UNIQUE,
    public_key      BYTEA           NOT NULL,
    aaguid          UUID,
    sign_count      BIGINT          NOT NULL DEFAULT 0,
    backup_eligible BOOLEAN         NOT NULL DEFAULT false,
    backup_state    BOOLEAN         NOT NULL DEFAULT false,
    transports      TEXT[]          NOT NULL DEFAULT '{}',
    name            TEXT,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys (user_id);

-- Read Model: OIDC clients
CREATE TABLE IF NOT EXISTS oidc_clients (
    client_id       UUID            PRIMARY KEY,
    tenant_id       UUID            NOT NULL,
    client_name     TEXT            NOT NULL,
    client_secret_hash TEXT,
    redirect_uris   TEXT[]          NOT NULL DEFAULT '{}',
    scopes          TEXT[]          NOT NULL DEFAULT '{}',
    grant_types     TEXT[]          NOT NULL DEFAULT '{}',
    jwt_template    JSONB,
    rate_limit      JSONB,
    is_active       BOOLEAN         NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oidc_tenant ON oidc_clients (tenant_id);
ALTER TABLE oidc_clients ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_oidc ON oidc_clients
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Read Model: authorization tuples (ReBAC / Zanzibar — PDF §10.2)
CREATE TABLE IF NOT EXISTS authz_tuples (
    id              BIGSERIAL       PRIMARY KEY,
    tenant_id       UUID            NOT NULL,
    user_ref        TEXT            NOT NULL,
    relation        TEXT            NOT NULL,
    object_type     TEXT            NOT NULL,
    object_id       TEXT            NOT NULL,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    CONSTRAINT uq_tuple UNIQUE (tenant_id, user_ref, relation, object_type, object_id)
);
CREATE INDEX IF NOT EXISTS idx_authz_object ON authz_tuples (object_type, object_id, relation);
CREATE INDEX IF NOT EXISTS idx_authz_user ON authz_tuples (user_ref);
ALTER TABLE authz_tuples ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_authz ON authz_tuples
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Read Model: API keys
CREATE TABLE IF NOT EXISTS api_keys (
    key_id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID            NOT NULL,
    prefix          TEXT            NOT NULL UNIQUE,
    secret_hash     TEXT            NOT NULL,
    owner_id        UUID            NOT NULL,
    owner_type      TEXT            NOT NULL DEFAULT 'user',
    scopes          TEXT[]          NOT NULL DEFAULT '{}',
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    is_active       BOOLEAN         NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_apikey_prefix ON api_keys (prefix);

-- Read Model: connectors
CREATE TABLE IF NOT EXISTS connectors (
    connector_id    UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID            NOT NULL,
    connector_type  TEXT            NOT NULL,
    config          JSONB           NOT NULL DEFAULT '{}',
    status          TEXT            NOT NULL DEFAULT 'inactive',
    last_sync_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors (tenant_id, connector_type);

-- Read Model: trusted devices
CREATE TABLE IF NOT EXISTS trusted_devices (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID            NOT NULL REFERENCES users(id),
    tenant_id       UUID            NOT NULL,
    name            TEXT            NOT NULL DEFAULT '',
    fingerprint     TEXT            NOT NULL,
    status          TEXT            NOT NULL DEFAULT 'trusted',
    last_seen_at    TIMESTAMPTZ     NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON trusted_devices (user_id);

-- Read Model: audit log (immutable, write-once)
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL       PRIMARY KEY,
    tenant_id       UUID            NOT NULL,
    event_type      TEXT            NOT NULL,
    principal_id    TEXT,
    resource_type   TEXT,
    resource_id     TEXT,
    decision        TEXT,
    reason          TEXT,
    context         JSONB           NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_principal ON audit_log (principal_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log (created_at);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log (event_type);
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_audit ON audit_log
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Projection checkpoint table
CREATE TABLE IF NOT EXISTS projection_checkpoints (
    projection_name TEXT            PRIMARY KEY,
    last_event_id   BIGINT          NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);
