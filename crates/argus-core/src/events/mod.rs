pub mod api_key;
pub mod audit;
pub mod connector;
pub mod device;
pub mod invitation;
pub mod lifecycle;
pub mod mfa;
pub mod oidc_client;
pub mod org;
pub mod permission;
pub mod project;
pub mod session;
pub mod tenant_policy;
pub mod user;
pub mod webhook;

pub use api_key::ApiKeyEvent;
pub use audit::AuditEvent;
pub use connector::ConnectorEvent;
pub use device::DeviceEvent;
pub use invitation::InvitationEvent;
pub use lifecycle::LifecycleEvent;
pub use mfa::MfaEvent;
pub use oidc_client::OidcClientEvent;
pub use org::OrgEvent;
pub use permission::PermissionEvent;
pub use project::ProjectEvent;
pub use session::SessionEvent;
pub use tenant_policy::TenantPolicyEvent;
pub use user::UserEvent;
pub use webhook::WebhookEvent;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::id::TenantId;

/// Metadata attached to every domain event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    pub causation_id: Option<Uuid>,
    pub correlation_id: Uuid,
    pub actor_id: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl Default for EventMetadata {
    fn default() -> Self {
        Self {
            causation_id: None,
            correlation_id: Uuid::now_v7(),
            actor_id: None,
            ip: None,
            user_agent: None,
        }
    }
}

/// A stored domain event (write model row).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: i64,
    pub aggregate_type: String,
    pub aggregate_id: Uuid,
    pub aggregate_version: i64,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub metadata: EventMetadata,
    pub tenant_id: TenantId,
    pub schema_version: i16,
    pub created_at: DateTime<Utc>,
}

/// Envelope for appending a new event (before it gets an `id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewEvent {
    pub aggregate_type: String,
    pub aggregate_id: Uuid,
    pub aggregate_version: i64,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub metadata: EventMetadata,
    pub tenant_id: TenantId,
    pub schema_version: i16,
}

/// Trait for domain aggregates that can be built from events.
pub trait Aggregate: Default + Send + Sync {
    const AGGREGATE_TYPE: &'static str;

    fn aggregate_id(&self) -> Uuid;
    fn version(&self) -> i64;
    fn apply(&mut self, event: &StoredEvent);
}
