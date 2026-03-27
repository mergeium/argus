use uuid::Uuid;

use crate::events::org::OrgEvent;
use crate::events::{Aggregate, StoredEvent};

#[derive(Debug, Clone)]
pub struct OrgAggregate {
    pub id: Uuid,
    pub version: i64,
    pub name: String,
    pub slug: String,
    pub logo_url: Option<String>,
    pub domains: Vec<String>,
    pub verified_domains: Vec<String>,
    pub branding: serde_json::Value,
    pub policy: serde_json::Value,
    pub deleted: bool,
}

impl Default for OrgAggregate {
    fn default() -> Self {
        Self {
            id: Uuid::nil(),
            version: 0,
            name: String::new(),
            slug: String::new(),
            logo_url: None,
            domains: Vec::new(),
            verified_domains: Vec::new(),
            branding: serde_json::Value::Null,
            policy: serde_json::Value::Null,
            deleted: false,
        }
    }
}

impl Aggregate for OrgAggregate {
    const AGGREGATE_TYPE: &'static str = "Organization";

    fn aggregate_id(&self) -> Uuid {
        self.id
    }

    fn version(&self) -> i64 {
        self.version
    }

    fn apply(&mut self, event: &StoredEvent) {
        self.id = event.aggregate_id;
        self.version = event.aggregate_version;

        let Ok(org_event) = serde_json::from_value::<OrgEvent>(event.payload.clone()) else {
            tracing::warn!(
                event_type = %event.event_type,
                "Failed to deserialize OrgEvent payload"
            );
            return;
        };

        match org_event {
            OrgEvent::OrgCreated { name, slug } => {
                self.name = name;
                self.slug = slug;
                self.deleted = false;
            }
            OrgEvent::OrgNameChanged { new_name, .. } => {
                self.name = new_name;
            }
            OrgEvent::OrgLogoSet { logo_url } => {
                self.logo_url = Some(logo_url);
            }
            OrgEvent::OrgDomainAdded { domain } => {
                if !self.domains.contains(&domain) {
                    self.domains.push(domain);
                }
            }
            OrgEvent::OrgDomainVerified { domain } => {
                if !self.verified_domains.contains(&domain) {
                    self.verified_domains.push(domain);
                }
            }
            OrgEvent::OrgBrandingSet { branding } => {
                self.branding = branding;
            }
            OrgEvent::OrgPolicySet { policy } => {
                self.policy = policy;
            }
            OrgEvent::OrgDeleted => {
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
            aggregate_type: "Organization".to_string(),
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
    fn test_org_created() {
        let mut agg = OrgAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "OrgCreated",
            serde_json::json!({
                "type": "OrgCreated",
                "data": { "name": "Acme Inc", "slug": "acme-inc" }
            }),
        ));

        assert_eq!(agg.id, id);
        assert_eq!(agg.version(), 1);
        assert_eq!(agg.name, "Acme Inc");
        assert_eq!(agg.slug, "acme-inc");
        assert!(!agg.deleted);
    }

    #[test]
    fn test_org_full_replay() {
        let mut agg = OrgAggregate::default();
        let id = Uuid::now_v7();

        let events = vec![
            make_stored_event(
                id,
                1,
                "OrgCreated",
                serde_json::json!({
                    "type": "OrgCreated",
                    "data": { "name": "Acme", "slug": "acme" }
                }),
            ),
            make_stored_event(
                id,
                2,
                "OrgNameChanged",
                serde_json::json!({
                    "type": "OrgNameChanged",
                    "data": { "old_name": "Acme", "new_name": "Acme Corp" }
                }),
            ),
            make_stored_event(
                id,
                3,
                "OrgLogoSet",
                serde_json::json!({
                    "type": "OrgLogoSet",
                    "data": { "logo_url": "https://acme.com/logo.png" }
                }),
            ),
            make_stored_event(
                id,
                4,
                "OrgDomainAdded",
                serde_json::json!({
                    "type": "OrgDomainAdded",
                    "data": { "domain": "acme.com" }
                }),
            ),
            make_stored_event(
                id,
                5,
                "OrgDomainVerified",
                serde_json::json!({
                    "type": "OrgDomainVerified",
                    "data": { "domain": "acme.com" }
                }),
            ),
            make_stored_event(
                id,
                6,
                "OrgBrandingSet",
                serde_json::json!({
                    "type": "OrgBrandingSet",
                    "data": { "branding": {"color": "#ff0000"} }
                }),
            ),
            make_stored_event(
                id,
                7,
                "OrgPolicySet",
                serde_json::json!({
                    "type": "OrgPolicySet",
                    "data": { "policy": {"mfa_required": true} }
                }),
            ),
        ];

        for event in &events {
            agg.apply(event);
        }

        assert_eq!(agg.version(), 7);
        assert_eq!(agg.name, "Acme Corp");
        assert_eq!(agg.logo_url, Some("https://acme.com/logo.png".to_string()));
        assert_eq!(agg.domains, vec!["acme.com"]);
        assert_eq!(agg.verified_domains, vec!["acme.com"]);
        assert_eq!(agg.branding, serde_json::json!({"color": "#ff0000"}));
        assert_eq!(agg.policy, serde_json::json!({"mfa_required": true}));
        assert!(!agg.deleted);
    }

    #[test]
    fn test_org_deleted() {
        let mut agg = OrgAggregate::default();
        let id = Uuid::now_v7();

        agg.apply(&make_stored_event(
            id,
            1,
            "OrgCreated",
            serde_json::json!({
                "type": "OrgCreated",
                "data": { "name": "Gone", "slug": "gone" }
            }),
        ));
        agg.apply(&make_stored_event(
            id,
            2,
            "OrgDeleted",
            serde_json::json!({"type": "OrgDeleted"}),
        ));

        assert!(agg.deleted);
        assert_eq!(agg.version(), 2);
    }
}
