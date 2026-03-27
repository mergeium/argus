use uuid::Uuid;

use crate::events::oidc_client::OidcClientEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone)]
pub struct OidcClientAggregate {
    pub id: Uuid,
    pub version: i64,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub secret_hash: String,
    pub rate_limit: serde_json::Value,
    pub jwt_template: serde_json::Value,
    pub settings: serde_json::Value,
    pub active: bool,
    pub deleted: bool,
}

impl Default for OidcClientAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            client_name: String::new(),
            redirect_uris: Vec::new(),
            grant_types: Vec::new(),
            scopes: Vec::new(),
            secret_hash: String::new(),
            rate_limit: serde_json::Value::Null,
            jwt_template: serde_json::Value::Null,
            settings: serde_json::Value::Null,
            active: true,
            deleted: false,
        }
    }
}

impl Aggregate for OidcClientAggregate {
    const AGGREGATE_TYPE: &'static str = "OidcClient";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(oidc_event) = serde_json::from_value::<OidcClientEvent>(event.payload.clone())
        else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize OidcClientEvent payload"
            );
            return;
        };

        match oidc_event {
            OidcClientEvent::ClientCreated {
                client_name,
                redirect_uris,
                grant_types,
            } => {
                self.client_name = client_name;
                self.redirect_uris = redirect_uris;
                self.grant_types = grant_types;
                self.active = true;
                self.deleted = false;
            }
            OidcClientEvent::ClientSecretRotated { secret_hash } => {
                self.secret_hash = secret_hash;
            }
            OidcClientEvent::ClientRedirectUriAdded { uri } => {
                if !self.redirect_uris.contains(&uri) {
                    self.redirect_uris.push(uri);
                }
            }
            OidcClientEvent::ClientScopeAdded { scope } => {
                if !self.scopes.contains(&scope) {
                    self.scopes.push(scope);
                }
            }
            OidcClientEvent::ClientGrantTypeSet { grant_types } => {
                self.grant_types = grant_types;
            }
            OidcClientEvent::ClientRateLimitSet { rate_limit } => {
                self.rate_limit = rate_limit;
            }
            OidcClientEvent::ClientJwtTemplateSet { template } => {
                self.jwt_template = template;
            }
            OidcClientEvent::ClientSettingsChanged { settings } => {
                self.settings = settings;
            }
            OidcClientEvent::ClientDeactivated => {
                self.active = false;
            }
            OidcClientEvent::ClientDeleted => {
                self.deleted = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventMetadata, StoredEvent};
    use crate::id::TenantId;
    use chrono::Utc;

    fn make_stored_event(
        aggregate_id: Uuid,
        version: i64,
        event_type: &str,
        payload: serde_json::Value,
    ) -> StoredEvent {
        StoredEvent {
            id: version,
            aggregate_type: "OidcClient".to_string(),
            aggregate_id,
            aggregate_version: version,
            event_type: event_type.to_string(),
            payload,
            metadata: EventMetadata::default(),
            tenant_id: TenantId::new(),
            schema_version: 1,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_client_created() {
        let mut agg = OidcClientAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "ClientCreated",
            serde_json::json!({
                "type": "ClientCreated",
                "data": {
                    "client_name": "My App",
                    "redirect_uris": ["https://app.example.com/callback"],
                    "grant_types": ["authorization_code"]
                }
            }),
        ));

        assert_eq!(agg.id, id);
        assert_eq!(agg.version(), 1);
        assert_eq!(agg.client_name, "My App");
        assert_eq!(agg.redirect_uris, vec!["https://app.example.com/callback"]);
        assert_eq!(agg.grant_types, vec!["authorization_code"]);
        assert!(agg.active);
        assert!(!agg.deleted);
    }

    #[test]
    fn test_client_full_lifecycle() {
        let mut agg = OidcClientAggregate::default();
        let id = Uuid::now_v7();

        let events = vec![
            make_stored_event(
                id,
                1,
                "ClientCreated",
                serde_json::json!({
                    "type": "ClientCreated",
                    "data": {
                        "client_name": "App",
                        "redirect_uris": ["https://app.com/cb"],
                        "grant_types": ["authorization_code"]
                    }
                }),
            ),
            make_stored_event(
                id,
                2,
                "ClientSecretRotated",
                serde_json::json!({
                    "type": "ClientSecretRotated",
                    "data": { "secret_hash": "hash_abc" }
                }),
            ),
            make_stored_event(
                id,
                3,
                "ClientScopeAdded",
                serde_json::json!({
                    "type": "ClientScopeAdded",
                    "data": { "scope": "openid" }
                }),
            ),
            make_stored_event(
                id,
                4,
                "ClientDeactivated",
                serde_json::json!({"type": "ClientDeactivated"}),
            ),
        ];

        for event in &events {
            agg.apply(event);
        }

        assert_eq!(agg.version(), 4);
        assert_eq!(agg.secret_hash, "hash_abc");
        assert_eq!(agg.scopes, vec!["openid"]);
        assert!(!agg.active);
    }
}
