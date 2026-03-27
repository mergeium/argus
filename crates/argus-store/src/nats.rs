use std::time::Duration;

use argus_core::error::{ArgusError, ArgusResult};
use async_nats::jetstream::{self, stream};
use bytes::Bytes;
use tracing::{info, instrument};

/// NATS JetStream event bus for publishing domain events, webhooks, audit logs,
/// lifecycle actions, notifications, and LDAP sync messages.
///
/// Implements the stream topology defined in the Argus architecture:
///
/// | Stream              | Subject Pattern                              | Retention          |
/// |---------------------|----------------------------------------------|--------------------|
/// | `argus-events`      | `argus.events.{tenant}.{aggregate_type}`     | Limits (7 days)    |
/// | `argus-webhooks`    | `argus.webhooks.{tenant}.{event_type}`       | WorkQueue          |
/// | `argus-lifecycle`   | `argus.lifecycle.{tenant}.{action}`          | WorkQueue          |
/// | `argus-notifications`| `argus.notify.{tenant}.{channel}`           | Limits (1 day)     |
/// | `argus-audit`       | `argus.audit.{tenant}`                       | Limits (90 days)   |
/// | `argus-ldap`        | `argus.ldap.{tenant}.{connector}`            | WorkQueue          |
pub struct NatsEventBus {
    jetstream: jetstream::Context,
}

impl NatsEventBus {
    /// Connect to a NATS server and create a JetStream context.
    ///
    /// # Errors
    /// Returns `ArgusError::Messaging` if the connection fails.
    #[instrument(skip_all, fields(url = %url))]
    pub async fn new(url: &str) -> ArgusResult<Self> {
        let client = async_nats::connect(url)
            .await
            .map_err(|e| ArgusError::Messaging(format!("NATS connect failed: {e}")))?;

        let jetstream = jetstream::new(client);

        info!("Connected to NATS JetStream at {url}");

        Ok(Self { jetstream })
    }

    /// Create all six JetStream streams with the proper configuration.
    ///
    /// Uses `get_or_create_stream` so this is idempotent: existing streams
    /// are left untouched, missing streams are created.
    ///
    /// # Errors
    /// Returns `ArgusError::Messaging` if any stream creation fails.
    #[instrument(skip_all)]
    pub async fn setup_streams(&self) -> ArgusResult<()> {
        // 1. argus-events — all domain events, consumed by projection-worker & audit-forwarder
        self.ensure_stream(stream::Config {
            name: "argus-events".to_string(),
            subjects: vec!["argus.events.>".to_string()],
            retention: stream::RetentionPolicy::Limits,
            max_age: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            storage: stream::StorageType::File,
            num_replicas: 1,
            discard: stream::DiscardPolicy::Old,
            description: Some(
                "All domain events; consumed by projection-worker and audit-forwarder".to_string(),
            ),
            ..Default::default()
        })
        .await?;

        // 2. argus-webhooks — webhook triggers, work-queue retention
        self.ensure_stream(stream::Config {
            name: "argus-webhooks".to_string(),
            subjects: vec!["argus.webhooks.>".to_string()],
            retention: stream::RetentionPolicy::WorkQueue,
            storage: stream::StorageType::File,
            num_replicas: 1,
            discard: stream::DiscardPolicy::Old,
            description: Some(
                "Webhook delivery triggers; consumed by webhook-delivery worker".to_string(),
            ),
            ..Default::default()
        })
        .await?;

        // 3. argus-lifecycle — deprovisioning, SCIM push
        self.ensure_stream(stream::Config {
            name: "argus-lifecycle".to_string(),
            subjects: vec!["argus.lifecycle.>".to_string()],
            retention: stream::RetentionPolicy::WorkQueue,
            storage: stream::StorageType::File,
            num_replicas: 1,
            discard: stream::DiscardPolicy::Old,
            description: Some(
                "Lifecycle actions (deprovisioning, SCIM push); consumed by lifecycle-worker"
                    .to_string(),
            ),
            ..Default::default()
        })
        .await?;

        // 4. argus-notifications — email, push, SMS
        self.ensure_stream(stream::Config {
            name: "argus-notifications".to_string(),
            subjects: vec!["argus.notify.>".to_string()],
            retention: stream::RetentionPolicy::Limits,
            max_age: Duration::from_secs(24 * 60 * 60), // 1 day
            storage: stream::StorageType::File,
            num_replicas: 1,
            discard: stream::DiscardPolicy::Old,
            description: Some(
                "Notifications (email, push, SMS); consumed by email-worker, push-worker, sms-worker"
                    .to_string(),
            ),
            ..Default::default()
        })
        .await?;

        // 5. argus-audit — audit log stream, 90-day retention
        self.ensure_stream(stream::Config {
            name: "argus-audit".to_string(),
            subjects: vec!["argus.audit.>".to_string()],
            retention: stream::RetentionPolicy::Limits,
            max_age: Duration::from_secs(90 * 24 * 60 * 60), // 90 days
            storage: stream::StorageType::File,
            num_replicas: 1,
            discard: stream::DiscardPolicy::Old,
            description: Some(
                "Audit log stream; consumed by audit-exporter and siem-forwarder".to_string(),
            ),
            ..Default::default()
        })
        .await?;

        // 6. argus-ldap — LDAP delta sync, work-queue retention
        self.ensure_stream(stream::Config {
            name: "argus-ldap".to_string(),
            subjects: vec!["argus.ldap.>".to_string()],
            retention: stream::RetentionPolicy::WorkQueue,
            storage: stream::StorageType::File,
            num_replicas: 1,
            discard: stream::DiscardPolicy::Old,
            description: Some("LDAP delta sync messages; consumed by ldap-sync-worker".to_string()),
            ..Default::default()
        })
        .await?;

        info!("All 6 JetStream streams configured");
        Ok(())
    }

    /// Publish a domain event to `argus.events.{tenant_id}.{aggregate_type}`.
    ///
    /// # Errors
    /// Returns `ArgusError::Messaging` if the publish or server ack fails.
    #[instrument(skip(self, payload), fields(subject))]
    pub async fn publish_event(
        &self,
        tenant_id: &str,
        aggregate_type: &str,
        payload: &[u8],
    ) -> ArgusResult<()> {
        let subject = format!("argus.events.{tenant_id}.{aggregate_type}");
        self.publish(&subject, payload).await
    }

    /// Publish a webhook trigger to `argus.webhooks.{tenant_id}.{event_type}`.
    ///
    /// # Errors
    /// Returns `ArgusError::Messaging` if the publish or server ack fails.
    #[instrument(skip(self, payload), fields(subject))]
    pub async fn publish_webhook(
        &self,
        tenant_id: &str,
        event_type: &str,
        payload: &[u8],
    ) -> ArgusResult<()> {
        let subject = format!("argus.webhooks.{tenant_id}.{event_type}");
        self.publish(&subject, payload).await
    }

    /// Publish an audit log entry to `argus.audit.{tenant_id}`.
    ///
    /// # Errors
    /// Returns `ArgusError::Messaging` if the publish or server ack fails.
    #[instrument(skip(self, payload), fields(subject))]
    pub async fn publish_audit(&self, tenant_id: &str, payload: &[u8]) -> ArgusResult<()> {
        let subject = format!("argus.audit.{tenant_id}");
        self.publish(&subject, payload).await
    }

    /// Publish a lifecycle action to `argus.lifecycle.{tenant_id}.{action}`.
    ///
    /// # Errors
    /// Returns `ArgusError::Messaging` if the publish or server ack fails.
    #[instrument(skip(self, payload), fields(subject))]
    pub async fn publish_lifecycle(
        &self,
        tenant_id: &str,
        action: &str,
        payload: &[u8],
    ) -> ArgusResult<()> {
        let subject = format!("argus.lifecycle.{tenant_id}.{action}");
        self.publish(&subject, payload).await
    }

    /// Publish a notification to `argus.notify.{tenant_id}.{channel}`.
    ///
    /// # Errors
    /// Returns `ArgusError::Messaging` if the publish or server ack fails.
    #[instrument(skip(self, payload), fields(subject))]
    pub async fn publish_notification(
        &self,
        tenant_id: &str,
        channel: &str,
        payload: &[u8],
    ) -> ArgusResult<()> {
        let subject = format!("argus.notify.{tenant_id}.{channel}");
        self.publish(&subject, payload).await
    }

    /// Publish an LDAP sync message to `argus.ldap.{tenant_id}.{connector}`.
    ///
    /// # Errors
    /// Returns `ArgusError::Messaging` if the publish or server ack fails.
    #[instrument(skip(self, payload), fields(subject))]
    pub async fn publish_ldap(
        &self,
        tenant_id: &str,
        connector: &str,
        payload: &[u8],
    ) -> ArgusResult<()> {
        let subject = format!("argus.ldap.{tenant_id}.{connector}");
        self.publish(&subject, payload).await
    }

    /// Return a reference to the underlying JetStream context for advanced usage
    /// (e.g. creating consumers, pull subscriptions).
    pub fn jetstream_context(&self) -> &jetstream::Context {
        &self.jetstream
    }

    // ── Internal helpers ──────────────────────────────────────────────

    /// Idempotently create or verify a JetStream stream.
    async fn ensure_stream(&self, config: stream::Config) -> ArgusResult<()> {
        let name = config.name.clone();
        self.jetstream
            .get_or_create_stream(config)
            .await
            .map_err(|e| ArgusError::Messaging(format!("failed to create stream {name}: {e}")))?;
        info!(stream = %name, "JetStream stream ready");
        Ok(())
    }

    /// Publish a message to a JetStream subject and await the server acknowledgment.
    async fn publish(&self, subject: &str, payload: &[u8]) -> ArgusResult<()> {
        let ack_future = self
            .jetstream
            .publish(subject.to_string(), Bytes::copy_from_slice(payload))
            .await
            .map_err(|e| ArgusError::Messaging(format!("NATS publish to {subject} failed: {e}")))?;

        // Await the server-side acknowledgment to guarantee the message was persisted.
        ack_future.await.map_err(|e| {
            ArgusError::Messaging(format!("NATS publish ack for {subject} failed: {e}"))
        })?;

        Ok(())
    }
}
