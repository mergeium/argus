use std::sync::Arc;
use tokio::time::{self, Duration};

use argus_core::error::{ArgusError, ArgusResult};
use argus_core::events::StoredEvent;

use crate::event_store::EventStore;

/// Trait for event projections (read model updaters).
/// Each projection processes events and updates its read model table.
pub trait Projection: Send + Sync {
    /// The unique name of this projection (used for checkpoint tracking).
    fn name(&self) -> &'static str;

    /// Process a single event and update the read model.
    /// Implementations should be idempotent (safe to replay).
    fn handle(
        &self,
        event: &StoredEvent,
    ) -> impl std::future::Future<Output = ArgusResult<()>> + Send;
}

/// Tracks the last processed event ID for each projection.
pub struct ProjectionCheckpoint {
    pub projection_name: String,
    pub last_event_id: i64,
}

impl ProjectionCheckpoint {
    pub async fn load(pool: &sqlx::PgPool, name: &str) -> ArgusResult<Self> {
        let row = sqlx::query_as::<_, (String, i64)>(
            "SELECT projection_name, last_event_id FROM projection_checkpoints WHERE projection_name = $1",
        )
        .bind(name)
        .fetch_optional(pool)
        .await
        .map_err(|e| argus_core::error::ArgusError::Database(e.to_string()))?;

        match row {
            Some((name, id)) => Ok(Self {
                projection_name: name,
                last_event_id: id,
            }),
            None => Ok(Self {
                projection_name: name.to_string(),
                last_event_id: 0,
            }),
        }
    }

    pub async fn save(&self, pool: &sqlx::PgPool) -> ArgusResult<()> {
        sqlx::query(
            r#"
            INSERT INTO projection_checkpoints (projection_name, last_event_id, updated_at)
            VALUES ($1, $2, now())
            ON CONFLICT (projection_name) DO UPDATE
            SET last_event_id = EXCLUDED.last_event_id, updated_at = now()
            "#,
        )
        .bind(&self.projection_name)
        .bind(self.last_event_id)
        .execute(pool)
        .await
        .map_err(|e| argus_core::error::ArgusError::Database(e.to_string()))?;

        Ok(())
    }
}

/// A worker that continuously catches up a projection by polling for new events.
pub struct ProjectionWorker<P: Projection, S: EventStore> {
    projection: Arc<P>,
    event_store: Arc<S>,
    pool: sqlx::PgPool,
    batch_size: i64,
    poll_interval: Duration,
}

impl<P: Projection + 'static, S: EventStore + 'static> ProjectionWorker<P, S> {
    pub fn new(
        projection: Arc<P>,
        event_store: Arc<S>,
        pool: sqlx::PgPool,
        batch_size: i64,
        poll_interval: Duration,
    ) -> Self {
        Self {
            projection,
            event_store,
            pool,
            batch_size,
            poll_interval,
        }
    }

    /// Run a single catch-up cycle: load checkpoint, fetch new events, project, save checkpoint.
    /// Returns the number of events processed.
    pub async fn run_once(&self) -> ArgusResult<usize> {
        let mut checkpoint = ProjectionCheckpoint::load(&self.pool, self.projection.name()).await?;

        let events = self
            .event_store
            .load_all_events_after(checkpoint.last_event_id, self.batch_size)
            .await?;

        if events.is_empty() {
            return Ok(0);
        }

        let count = events.len();
        for event in &events {
            self.projection.handle(event).await.map_err(|e| {
                ArgusError::Internal(format!(
                    "projection '{}' failed on event {}: {e}",
                    self.projection.name(),
                    event.id
                ))
            })?;
            checkpoint.last_event_id = event.id;
        }

        checkpoint.save(&self.pool).await?;

        tracing::info!(
            projection = self.projection.name(),
            events_processed = count,
            last_event_id = checkpoint.last_event_id,
            "projection batch complete"
        );

        Ok(count)
    }

    /// Run the projection worker in a loop, polling for new events at the configured interval.
    /// This method runs indefinitely until the provided `shutdown` signal resolves.
    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        tracing::info!(
            projection = self.projection.name(),
            "starting projection worker"
        );

        let mut interval = time::interval(self.poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.run_once().await {
                        Ok(_) => {}
                        Err(e) => {
                            tracing::error!(
                                projection = self.projection.name(),
                                error = %e,
                                "projection worker error, will retry next tick"
                            );
                        }
                    }
                }
                _ = shutdown.changed() => {
                    tracing::info!(
                        projection = self.projection.name(),
                        "projection worker shutting down"
                    );
                    break;
                }
            }
        }
    }
}
