/// SQL migrations embedded from the top-level `migrations/` directory.
///
/// For production: use `sqlx migrate run` with the `migrations/` folder.
/// For programmatic use: these constants embed the same SQL.
pub const MIGRATION_001_EVENT_STORE: &str = include_str!("../../../migrations/001_event_store.sql");
pub const MIGRATION_002_READ_MODELS: &str = include_str!("../../../migrations/002_read_models.sql");

/// Run all migrations programmatically (for migrate_on_start mode).
pub async fn run_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(MIGRATION_001_EVENT_STORE).execute(pool).await?;
    sqlx::query(MIGRATION_002_READ_MODELS).execute(pool).await?;
    tracing::info!("all migrations completed successfully");
    Ok(())
}
