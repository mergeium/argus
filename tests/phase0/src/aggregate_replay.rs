//! Cross-crate integration tests for event sourcing aggregates.
//! These test the public API from outside argus-core — verifying that
//! aggregates, events, and serialization work together correctly.
//!
//! Unit tests for individual aggregate apply() logic live inside
//! each aggregate file (e.g. crates/argus-core/src/aggregates/user.rs).

use argus_core::aggregates::*;
use argus_core::events::{Aggregate, EventMetadata, StoredEvent};
use argus_core::id::TenantId;
use uuid::Uuid;

fn stored_event(
    agg_type: &str,
    agg_id: Uuid,
    version: i64,
    payload: serde_json::Value,
) -> StoredEvent {
    StoredEvent {
        id: version,
        aggregate_type: agg_type.to_string(),
        aggregate_id: agg_id,
        aggregate_version: version,
        event_type: agg_type.to_string(),
        payload,
        metadata: EventMetadata::default(),
        tenant_id: TenantId::new(),
        schema_version: 1,
        created_at: chrono::Utc::now(),
    }
}

/// Verify all 15 aggregates are exported and have the correct AGGREGATE_TYPE constant.
#[test]
fn all_15_aggregates_exported_with_correct_type() {
    let types: Vec<(&str, &str)> = vec![
        (UserAggregate::AGGREGATE_TYPE, "User"),
        (OrgAggregate::AGGREGATE_TYPE, "Organization"),
        (SessionAggregate::AGGREGATE_TYPE, "Session"),
        (ProjectAggregate::AGGREGATE_TYPE, "Project"),
        (OidcClientAggregate::AGGREGATE_TYPE, "OidcClient"),
        (MfaAggregate::AGGREGATE_TYPE, "Mfa"),
        (PermissionAggregate::AGGREGATE_TYPE, "Permission"),
        (ApiKeyAggregate::AGGREGATE_TYPE, "ApiKey"),
        (InvitationAggregate::AGGREGATE_TYPE, "Invitation"),
        (ConnectorAggregate::AGGREGATE_TYPE, "Connector"),
        (WebhookAggregate::AGGREGATE_TYPE, "Webhook"),
        (AuditAggregate::AGGREGATE_TYPE, "Audit"),
        (TenantPolicyAggregate::AGGREGATE_TYPE, "TenantPolicy"),
        (DeviceAggregate::AGGREGATE_TYPE, "Device"),
        (LifecycleAggregate::AGGREGATE_TYPE, "Lifecycle"),
    ];
    assert_eq!(types.len(), 15);
    for (actual, expected) in &types {
        assert_eq!(actual, expected, "AGGREGATE_TYPE mismatch");
    }
}

/// Verify event replay idempotency — applying the same event stream twice
/// produces identical aggregate state. Critical for event sourcing correctness.
#[test]
fn event_replay_is_idempotent() {
    use argus_core::events::user::UserEvent;

    let id = Uuid::now_v7();
    let events = vec![
        stored_event(
            "User",
            id,
            1,
            serde_json::to_value(UserEvent::UserCreated {
                email: "alice@test.com".into(),
                display_name: Some("Alice".into()),
                password_hash: "$argon2id$v=19$hash".into(),
            })
            .unwrap(),
        ),
        stored_event(
            "User",
            id,
            2,
            serde_json::to_value(UserEvent::UserEmailVerified).unwrap(),
        ),
        stored_event(
            "User",
            id,
            3,
            serde_json::to_value(UserEvent::UserPhoneAdded {
                phone: "+905551234567".into(),
            })
            .unwrap(),
        ),
    ];

    let replay = |evts: &[StoredEvent]| -> UserAggregate {
        let mut agg = UserAggregate::default();
        for e in evts {
            agg.apply(e);
        }
        agg
    };

    let run1 = replay(&events);
    let run2 = replay(&events);

    assert_eq!(run1.version(), run2.version());
    assert_eq!(run1.email, run2.email);
    assert_eq!(run1.email_verified, run2.email_verified);
    assert_eq!(run1.phone, run2.phone);
    assert_eq!(run1.aggregate_id(), run2.aggregate_id());
}

/// Verify cross-aggregate event isolation — applying org events to a user
/// aggregate must not cause panics or state corruption.
#[test]
fn wrong_event_type_does_not_corrupt_state() {
    use argus_core::events::org::OrgEvent;
    use argus_core::events::user::UserEvent;

    let id = Uuid::now_v7();
    let mut user_agg = UserAggregate::default();

    // Apply a valid user event
    user_agg.apply(&stored_event(
        "User",
        id,
        1,
        serde_json::to_value(UserEvent::UserCreated {
            email: "safe@test.com".into(),
            display_name: None,
            password_hash: "hash".into(),
        })
        .unwrap(),
    ));

    // Apply an org event payload to user aggregate — must not panic
    user_agg.apply(&stored_event(
        "User",
        id,
        2,
        serde_json::to_value(OrgEvent::OrgCreated {
            name: "Acme".into(),
            slug: "acme".into(),
        })
        .unwrap(),
    ));

    // User state must remain intact
    assert_eq!(user_agg.email, "safe@test.com");
}

/// Verify multiple aggregates can be built from interleaved event streams
/// (simulating loading from a shared event store).
#[test]
fn multiple_aggregates_from_shared_event_store() {
    use argus_core::events::org::OrgEvent;
    use argus_core::events::user::UserEvent;

    let user_id = Uuid::now_v7();
    let org_id = Uuid::now_v7();

    // Simulated event store — interleaved events for different aggregates
    let all_events = vec![
        stored_event(
            "User",
            user_id,
            1,
            serde_json::to_value(UserEvent::UserCreated {
                email: "bob@acme.com".into(),
                display_name: Some("Bob".into()),
                password_hash: "h".into(),
            })
            .unwrap(),
        ),
        stored_event(
            "Org",
            org_id,
            1,
            serde_json::to_value(OrgEvent::OrgCreated {
                name: "Acme".into(),
                slug: "acme".into(),
            })
            .unwrap(),
        ),
        stored_event(
            "User",
            user_id,
            2,
            serde_json::to_value(UserEvent::UserEmailVerified).unwrap(),
        ),
        stored_event(
            "Org",
            org_id,
            2,
            serde_json::to_value(OrgEvent::OrgDomainAdded {
                domain: "acme.com".into(),
            })
            .unwrap(),
        ),
    ];

    // Filter and build each aggregate
    let mut user = UserAggregate::default();
    let mut org = OrgAggregate::default();

    for event in &all_events {
        match event.aggregate_type.as_str() {
            "User" if event.aggregate_id == user_id => user.apply(event),
            "Org" if event.aggregate_id == org_id => org.apply(event),
            _ => {}
        }
    }

    assert_eq!(user.email, "bob@acme.com");
    assert!(user.email_verified);
    assert_eq!(user.version(), 2);

    assert_eq!(org.name, "Acme");
    assert_eq!(org.version(), 2);
}
