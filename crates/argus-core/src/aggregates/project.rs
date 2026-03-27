use uuid::Uuid;

use crate::events::project::ProjectEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone)]
pub struct ProjectAggregate {
    pub id: Uuid,
    pub version: i64,
    pub name: String,
    pub description: Option<String>,
    pub oidc_clients: Vec<String>,
    pub saml_clients: Vec<String>,
    pub roles: Vec<(String, Vec<String>)>,
    pub deleted: bool,
}

impl Default for ProjectAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            name: String::new(),
            description: None,
            oidc_clients: Vec::new(),
            saml_clients: Vec::new(),
            roles: Vec::new(),
            deleted: false,
        }
    }
}

impl Aggregate for ProjectAggregate {
    const AGGREGATE_TYPE: &'static str = "Project";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(project_event) = serde_json::from_value::<ProjectEvent>(event.payload.clone())
        else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize ProjectEvent payload"
            );
            return;
        };

        match project_event {
            ProjectEvent::ProjectCreated { name, description } => {
                self.name = name;
                self.description = description;
                self.deleted = false;
            }
            ProjectEvent::ProjectNameChanged { new_name, .. } => {
                self.name = new_name;
            }
            ProjectEvent::OIDCClientAdded { client_id } => {
                if !self.oidc_clients.contains(&client_id) {
                    self.oidc_clients.push(client_id);
                }
            }
            ProjectEvent::SAMLClientAdded { client_id } => {
                if !self.saml_clients.contains(&client_id) {
                    self.saml_clients.push(client_id);
                }
            }
            ProjectEvent::ProjectRoleAdded {
                role_name,
                permissions,
            } => {
                self.roles.retain(|(name, _)| name != &role_name);
                self.roles.push((role_name, permissions));
            }
            ProjectEvent::ProjectDeleted => {
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
            aggregate_type: "Project".to_string(),
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
    fn test_project_created() {
        let mut agg = ProjectAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "ProjectCreated",
            serde_json::json!({
                "type": "ProjectCreated",
                "data": { "name": "My Project", "description": "A test project" }
            }),
        ));

        assert_eq!(agg.id, id);
        assert_eq!(agg.version(), 1);
        assert_eq!(agg.name, "My Project");
        assert_eq!(agg.description, Some("A test project".to_string()));
        assert!(!agg.deleted);
    }

    #[test]
    fn test_project_full_replay() {
        let mut agg = ProjectAggregate::default();
        let id = Uuid::now_v7();

        let events = vec![
            make_stored_event(
                id,
                1,
                "ProjectCreated",
                serde_json::json!({
                    "type": "ProjectCreated",
                    "data": { "name": "Proj", "description": null }
                }),
            ),
            make_stored_event(
                id,
                2,
                "ProjectNameChanged",
                serde_json::json!({
                    "type": "ProjectNameChanged",
                    "data": { "old_name": "Proj", "new_name": "Project Alpha" }
                }),
            ),
            make_stored_event(
                id,
                3,
                "OIDCClientAdded",
                serde_json::json!({
                    "type": "OIDCClientAdded",
                    "data": { "client_id": "oidc_1" }
                }),
            ),
            make_stored_event(
                id,
                4,
                "SAMLClientAdded",
                serde_json::json!({
                    "type": "SAMLClientAdded",
                    "data": { "client_id": "saml_1" }
                }),
            ),
            make_stored_event(
                id,
                5,
                "ProjectRoleAdded",
                serde_json::json!({
                    "type": "ProjectRoleAdded",
                    "data": { "role_name": "admin", "permissions": ["read", "write"] }
                }),
            ),
            make_stored_event(
                id,
                6,
                "ProjectDeleted",
                serde_json::json!({"type": "ProjectDeleted"}),
            ),
        ];

        for event in &events {
            agg.apply(event);
        }

        assert_eq!(agg.version(), 6);
        assert_eq!(agg.name, "Project Alpha");
        assert_eq!(agg.oidc_clients, vec!["oidc_1"]);
        assert_eq!(agg.saml_clients, vec!["saml_1"]);
        assert_eq!(agg.roles.len(), 1);
        assert_eq!(agg.roles[0].0, "admin");
        assert!(agg.deleted);
    }
}
