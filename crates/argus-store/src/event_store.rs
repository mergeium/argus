use chrono::{DateTime, Utc};
use uuid::Uuid;

use argus_core::error::{ArgusError, ArgusResult};
use argus_core::events::{Aggregate, NewEvent, StoredEvent};
use argus_core::id::TenantId;

/// The core EventStore trait — storage backend abstraction.
#[allow(async_fn_in_trait)]
pub trait EventStore: Send + Sync {
    /// Append events with optimistic concurrency.
    /// Fails with `ConcurrencyConflict` if expected_version doesn't match.
    async fn append(
        &self,
        events: &[NewEvent],
        expected_version: i64,
    ) -> ArgusResult<Vec<StoredEvent>>;

    /// Load all events for an aggregate.
    async fn load_events(
        &self,
        aggregate_type: &str,
        aggregate_id: Uuid,
        tenant_id: &TenantId,
    ) -> ArgusResult<Vec<StoredEvent>>;

    /// Load events since a specific version (for catch-up).
    async fn load_events_since(
        &self,
        aggregate_type: &str,
        aggregate_id: Uuid,
        tenant_id: &TenantId,
        since_version: i64,
    ) -> ArgusResult<Vec<StoredEvent>>;

    /// Load all events after a global sequence ID (for projections).
    async fn load_all_events_after(
        &self,
        after_id: i64,
        batch_size: i64,
    ) -> ArgusResult<Vec<StoredEvent>>;
}

/// Load and hydrate an aggregate from its event stream.
pub async fn load_aggregate<A: Aggregate, S: EventStore>(
    store: &S,
    aggregate_id: Uuid,
    tenant_id: &TenantId,
) -> ArgusResult<A> {
    let events = store
        .load_events(A::AGGREGATE_TYPE, aggregate_id, tenant_id)
        .await?;

    if events.is_empty() {
        return Err(ArgusError::AggregateNotFound(aggregate_id.to_string()));
    }

    let mut aggregate = A::default();
    for event in &events {
        aggregate.apply(event);
    }
    Ok(aggregate)
}

/// Set the current tenant context for RLS policies.
/// Must be called before any tenant-scoped query.
///
/// Since PostgreSQL `SET LOCAL` does not support parameterized queries (`$1`),
/// we validate the UUID format before interpolating to prevent SQL injection.
pub async fn set_tenant_context(pool: &sqlx::PgPool, tenant_id: &Uuid) -> ArgusResult<()> {
    // Uuid::to_string() always produces a valid UUID string, so this is safe.
    // We re-parse to be defensive against future changes.
    let validated = Uuid::parse_str(&tenant_id.to_string())
        .map_err(|e| ArgusError::Validation(format!("invalid tenant UUID: {e}")))?;
    sqlx::query(&format!("SET LOCAL app.current_tenant_id = '{validated}'"))
        .execute(pool)
        .await
        .map_err(|e| ArgusError::Database(e.to_string()))?;
    Ok(())
}

/// Set the current tenant context within an existing transaction.
/// This is the preferred variant since `SET LOCAL` only takes effect within a transaction.
pub async fn set_tenant_context_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &Uuid,
) -> ArgusResult<()> {
    let validated = Uuid::parse_str(&tenant_id.to_string())
        .map_err(|e| ArgusError::Validation(format!("invalid tenant UUID: {e}")))?;
    sqlx::query(&format!("SET LOCAL app.current_tenant_id = '{validated}'"))
        .execute(&mut **tx)
        .await
        .map_err(|e| ArgusError::Database(e.to_string()))?;
    Ok(())
}

/// PostgreSQL-backed event store implementation.
pub struct PgEventStore {
    pool: sqlx::PgPool,
}

impl PgEventStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

impl EventStore for PgEventStore {
    async fn append(
        &self,
        events: &[NewEvent],
        expected_version: i64,
    ) -> ArgusResult<Vec<StoredEvent>> {
        if events.is_empty() {
            return Ok(vec![]);
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ArgusError::Database(e.to_string()))?;
        let mut stored = Vec::with_capacity(events.len());

        for (i, event) in events.iter().enumerate() {
            let version = expected_version + i as i64 + 1;
            let metadata_json = serde_json::to_value(&event.metadata)
                .map_err(|e| ArgusError::Internal(format!("serialize metadata: {e}")))?;

            let row = sqlx::query_as::<_, StoredEventRow>(
                r#"
                INSERT INTO domain_events (
                    aggregate_type, aggregate_id, aggregate_version,
                    event_type, payload, metadata, tenant_id, schema_version
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id, aggregate_type, aggregate_id, aggregate_version,
                          event_type, payload, metadata, tenant_id, schema_version, created_at
                "#,
            )
            .bind(&event.aggregate_type)
            .bind(event.aggregate_id)
            .bind(version)
            .bind(&event.event_type)
            .bind(&event.payload)
            .bind(&metadata_json)
            .bind(event.tenant_id.as_uuid())
            .bind(event.schema_version)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
                    ArgusError::ConcurrencyConflict {
                        aggregate_id: event.aggregate_id.to_string(),
                        expected: expected_version,
                        actual: version,
                    }
                } else {
                    ArgusError::Database(e.to_string())
                }
            })?;

            stored.push(row.into_stored_event(&event.metadata));
        }

        tx.commit()
            .await
            .map_err(|e| ArgusError::Database(e.to_string()))?;
        Ok(stored)
    }

    async fn load_events(
        &self,
        aggregate_type: &str,
        aggregate_id: Uuid,
        tenant_id: &TenantId,
    ) -> ArgusResult<Vec<StoredEvent>> {
        let rows = sqlx::query_as::<_, StoredEventRow>(
            r#"
            SELECT id, aggregate_type, aggregate_id, aggregate_version,
                   event_type, payload, metadata, tenant_id, schema_version, created_at
            FROM domain_events
            WHERE aggregate_type = $1
              AND aggregate_id = $2
              AND tenant_id = $3
            ORDER BY aggregate_version ASC
            "#,
        )
        .bind(aggregate_type)
        .bind(aggregate_id)
        .bind(tenant_id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArgusError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| r.into_stored_event_from_db())
            .collect())
    }

    async fn load_events_since(
        &self,
        aggregate_type: &str,
        aggregate_id: Uuid,
        tenant_id: &TenantId,
        since_version: i64,
    ) -> ArgusResult<Vec<StoredEvent>> {
        let rows = sqlx::query_as::<_, StoredEventRow>(
            r#"
            SELECT id, aggregate_type, aggregate_id, aggregate_version,
                   event_type, payload, metadata, tenant_id, schema_version, created_at
            FROM domain_events
            WHERE aggregate_type = $1
              AND aggregate_id = $2
              AND tenant_id = $3
              AND aggregate_version > $4
            ORDER BY aggregate_version ASC
            "#,
        )
        .bind(aggregate_type)
        .bind(aggregate_id)
        .bind(tenant_id.as_uuid())
        .bind(since_version)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArgusError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| r.into_stored_event_from_db())
            .collect())
    }

    async fn load_all_events_after(
        &self,
        after_id: i64,
        batch_size: i64,
    ) -> ArgusResult<Vec<StoredEvent>> {
        let rows = sqlx::query_as::<_, StoredEventRow>(
            r#"
            SELECT id, aggregate_type, aggregate_id, aggregate_version,
                   event_type, payload, metadata, tenant_id, schema_version, created_at
            FROM domain_events
            WHERE id > $1
            ORDER BY id ASC
            LIMIT $2
            "#,
        )
        .bind(after_id)
        .bind(batch_size)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArgusError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| r.into_stored_event_from_db())
            .collect())
    }
}

// Internal row type for sqlx mapping
#[derive(sqlx::FromRow)]
struct StoredEventRow {
    id: i64,
    aggregate_type: String,
    aggregate_id: Uuid,
    aggregate_version: i64,
    event_type: String,
    payload: serde_json::Value,
    metadata: serde_json::Value,
    tenant_id: Uuid,
    schema_version: i16,
    created_at: DateTime<Utc>,
}

impl StoredEventRow {
    fn into_stored_event(
        self,
        original_metadata: &argus_core::events::EventMetadata,
    ) -> StoredEvent {
        StoredEvent {
            id: self.id,
            aggregate_type: self.aggregate_type,
            aggregate_id: self.aggregate_id,
            aggregate_version: self.aggregate_version,
            event_type: self.event_type,
            payload: self.payload,
            metadata: original_metadata.clone(),
            tenant_id: TenantId::from(self.tenant_id),
            schema_version: self.schema_version,
            created_at: self.created_at,
        }
    }

    fn into_stored_event_from_db(self) -> StoredEvent {
        let metadata: argus_core::events::EventMetadata =
            serde_json::from_value(self.metadata.clone()).unwrap_or_else(|e| {
                tracing::warn!(
                    event_id = self.id,
                    "failed to deserialize event metadata: {e}"
                );
                argus_core::events::EventMetadata::default()
            });
        StoredEvent {
            id: self.id,
            aggregate_type: self.aggregate_type,
            aggregate_id: self.aggregate_id,
            aggregate_version: self.aggregate_version,
            event_type: self.event_type,
            payload: self.payload,
            metadata,
            tenant_id: TenantId::from(self.tenant_id),
            schema_version: self.schema_version,
            created_at: self.created_at,
        }
    }
}
