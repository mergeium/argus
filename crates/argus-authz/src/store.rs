use chrono::Utc;
use uuid::Uuid;

use argus_core::error::{ArgusError, ArgusResult};

use crate::model::{RelationTuple, WriteRequest};

/// PostgreSQL-backed tuple store for ReBAC authorization.
pub struct PgTupleStore {
    pool: sqlx::PgPool,
}

impl PgTupleStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Write (upsert) and delete tuples in a single transaction.
    pub async fn write(&self, req: &WriteRequest) -> ArgusResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| ArgusError::Database(e.to_string()))?;

        // Deletes first
        for del in &req.deletes {
            sqlx::query(
                r#"
                DELETE FROM authz_tuples
                WHERE tenant_id = $1
                  AND user_ref = $2
                  AND relation = $3
                  AND object_type = $4
                  AND object_id = $5
                "#,
            )
            .bind(req.store_id)
            .bind(&del.user_ref)
            .bind(&del.relation)
            .bind(&del.object_type)
            .bind(&del.object_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| ArgusError::Database(e.to_string()))?;
        }

        // Writes (upsert)
        for w in &req.writes {
            sqlx::query(
                r#"
                INSERT INTO authz_tuples (tenant_id, user_ref, relation, object_type, object_id, created_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (tenant_id, user_ref, relation, object_type, object_id) DO NOTHING
                "#,
            )
            .bind(req.store_id)
            .bind(&w.user_ref)
            .bind(&w.relation)
            .bind(&w.object_type)
            .bind(&w.object_id)
            .bind(Utc::now())
            .execute(&mut *tx)
            .await
            .map_err(|e| ArgusError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| ArgusError::Database(e.to_string()))?;

        tracing::debug!(
            store_id = %req.store_id,
            writes = req.writes.len(),
            deletes = req.deletes.len(),
            "tuple write completed"
        );

        Ok(())
    }

    /// Read tuples matching the given filter.
    pub async fn read(
        &self,
        store_id: Uuid,
        user_ref: Option<&str>,
        relation: Option<&str>,
        object_type: Option<&str>,
        object_id: Option<&str>,
    ) -> ArgusResult<Vec<RelationTuple>> {
        // Build dynamic query with optional filters
        let mut query = String::from(
            "SELECT tenant_id, user_ref, relation, object_type, object_id, created_at \
             FROM authz_tuples WHERE tenant_id = $1",
        );
        let mut param_idx = 2u32;

        if user_ref.is_some() {
            query.push_str(&format!(" AND user_ref = ${param_idx}"));
            param_idx += 1;
        }
        if relation.is_some() {
            query.push_str(&format!(" AND relation = ${param_idx}"));
            param_idx += 1;
        }
        if object_type.is_some() {
            query.push_str(&format!(" AND object_type = ${param_idx}"));
            param_idx += 1;
        }
        if object_id.is_some() {
            query.push_str(&format!(" AND object_id = ${param_idx}"));
        }

        query.push_str(" ORDER BY created_at ASC LIMIT 1000");

        let mut q = sqlx::query_as::<_, TupleRow>(&query).bind(store_id);
        if let Some(v) = user_ref {
            q = q.bind(v);
        }
        if let Some(v) = relation {
            q = q.bind(v);
        }
        if let Some(v) = object_type {
            q = q.bind(v);
        }
        if let Some(v) = object_id {
            q = q.bind(v);
        }

        let rows = q
            .fetch_all(&self.pool)
            .await
            .map_err(|e| ArgusError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Check if a direct tuple exists (step 1 of the check algorithm).
    pub async fn exists(
        &self,
        store_id: Uuid,
        user_ref: &str,
        relation: &str,
        object_type: &str,
        object_id: &str,
    ) -> ArgusResult<bool> {
        let row: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT 1 as found FROM authz_tuples
            WHERE tenant_id = $1
              AND user_ref = $2
              AND relation = $3
              AND object_type = $4
              AND object_id = $5
            LIMIT 1
            "#,
        )
        .bind(store_id)
        .bind(user_ref)
        .bind(relation)
        .bind(object_type)
        .bind(object_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ArgusError::Database(e.to_string()))?;

        Ok(row.is_some())
    }

    /// Find all users that have a given relation on an object (for expand).
    pub async fn find_users(
        &self,
        store_id: Uuid,
        relation: &str,
        object_type: &str,
        object_id: &str,
    ) -> ArgusResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT user_ref FROM authz_tuples
            WHERE tenant_id = $1
              AND relation = $2
              AND object_type = $3
              AND object_id = $4
            ORDER BY created_at ASC
            "#,
        )
        .bind(store_id)
        .bind(relation)
        .bind(object_type)
        .bind(object_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArgusError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Find all objects a user can access via a given relation.
    pub async fn find_objects(
        &self,
        store_id: Uuid,
        user_ref: &str,
        relation: &str,
        object_type: &str,
    ) -> ArgusResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT object_id FROM authz_tuples
            WHERE tenant_id = $1
              AND user_ref = $2
              AND relation = $3
              AND object_type = $4
            ORDER BY created_at ASC
            "#,
        )
        .bind(store_id)
        .bind(user_ref)
        .bind(relation)
        .bind(object_type)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ArgusError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }
}

#[derive(sqlx::FromRow)]
struct TupleRow {
    tenant_id: Uuid,
    user_ref: String,
    relation: String,
    object_type: String,
    object_id: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<TupleRow> for RelationTuple {
    fn from(r: TupleRow) -> Self {
        Self {
            store_id: r.tenant_id,
            user_ref: r.user_ref,
            relation: r.relation,
            object_type: r.object_type,
            object_id: r.object_id,
            created_at: r.created_at,
        }
    }
}
