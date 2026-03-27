use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ProjectEvent {
    ProjectCreated {
        name: String,
        description: Option<String>,
    },
    ProjectNameChanged {
        old_name: String,
        new_name: String,
    },
    OIDCClientAdded {
        client_id: String,
    },
    SAMLClientAdded {
        client_id: String,
    },
    ProjectRoleAdded {
        role_name: String,
        permissions: Vec<String>,
    },
    ProjectDeleted,
}
