use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! define_id {
    ($name:ident, $prefix:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            pub fn to_string_prefixed(&self) -> String {
                format!("{}_{}", $prefix, self.0.as_simple())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, self.0.as_simple())
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }
    };
}

define_id!(UserId, "usr");
define_id!(OrgId, "org");
define_id!(ProjectId, "prj");
define_id!(SessionId, "sess");
define_id!(ClientId, "cli");
define_id!(TenantId, "tnt");
define_id!(KeyId, "key");
define_id!(EventId, "evt");
define_id!(DeviceId, "dev");
define_id!(ConnectorId, "conn");
define_id!(WebhookId, "whk");
define_id!(ApiKeyId, "ak");
define_id!(InvitationId, "inv");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_is_v7_and_prefixed() {
        let id = UserId::new();
        let s = id.to_string();
        assert!(s.starts_with("usr_"));
        assert_eq!(id.as_uuid().get_version(), Some(uuid::Version::SortRand));
    }

    #[test]
    fn ids_are_unique() {
        let a = UserId::new();
        let b = UserId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn id_roundtrip_serde() {
        let id = OrgId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: OrgId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}
