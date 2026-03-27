use std::time::Instant;
use uuid::Uuid;

use argus_core::error::ArgusResult;

use crate::model::CheckResponse;
use crate::store::PgTupleStore;

/// The check algorithm from the spec (section 10.3):
///
/// 1. Direct tuple lookup: does (user, relation, object) exist? → true
/// 2. Computed userset: relation includes another relation?
///    e.g. "editor includes owner" → check (user, owner, object)
/// 3. Tuple-to-userset: object has parent? membership in parent grants access?
/// 4. Recursive expansion: group memberships resolved transitively
///
/// This is the Phase 0 implementation (steps 1 + 3 group expansion).
/// Full computed userset and recursive CTE will be Phase 2.
pub async fn check(
    store: &PgTupleStore,
    store_id: Uuid,
    user_ref: &str,
    relation: &str,
    object_type: &str,
    object_id: &str,
) -> ArgusResult<CheckResponse> {
    let start = Instant::now();
    let mut resolution_path = Vec::new();

    // Step 1: Direct tuple lookup
    if store
        .exists(store_id, user_ref, relation, object_type, object_id)
        .await?
    {
        resolution_path.push(format!(
            "direct:({user_ref},{relation},{object_type}:{object_id})"
        ));
        return Ok(CheckResponse {
            allowed: true,
            resolution_path,
            duration_us: start.elapsed().as_micros() as u64,
        });
    }

    // Step 3: Group membership expansion
    // Find all groups the user belongs to, then check if any group has the relation
    let groups = store
        .find_objects(store_id, user_ref, "member", "group")
        .await?;
    for group in &groups {
        let group_ref = format!("group:{group}");
        if store
            .exists(store_id, &group_ref, relation, object_type, object_id)
            .await?
        {
            resolution_path.push(format!("group_member:({user_ref},member,group:{group})"));
            resolution_path.push(format!(
                "group_has:({group_ref},{relation},{object_type}:{object_id})"
            ));
            return Ok(CheckResponse {
                allowed: true,
                resolution_path,
                duration_us: start.elapsed().as_micros() as u64,
            });
        }
    }

    // Step 3b: Role-based expansion
    // Find all roles assigned to the user, check if role grants the permission
    let roles = store
        .find_objects(store_id, user_ref, "assignee", "role")
        .await?;
    for role in &roles {
        let perm_ref = format!("role:{role}");
        let perm_key = format!("{object_type}:{relation}");
        if store
            .exists(store_id, &perm_ref, "grantee", "permission", &perm_key)
            .await?
        {
            resolution_path.push(format!("role_assignee:({user_ref},assignee,role:{role})"));
            resolution_path.push(format!(
                "role_grants:(role:{role},grantee,permission:{perm_key})"
            ));
            return Ok(CheckResponse {
                allowed: true,
                resolution_path,
                duration_us: start.elapsed().as_micros() as u64,
            });
        }
    }

    Ok(CheckResponse {
        allowed: false,
        resolution_path: vec!["no_match".into()],
        duration_us: start.elapsed().as_micros() as u64,
    })
}
