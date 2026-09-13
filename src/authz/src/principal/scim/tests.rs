use std::collections::BTreeMap;

use crate::principal::IPrincipalDiscovery;

use super::*;

#[tokio::test]
async fn provisions_users_and_groups_with_stable_external_keys() {
    let discovery = ScimPrincipalDiscovery::new(
        "corporate-scim",
        "https://identity.example.com/scim/customer-growth",
    )
    .expect("discovery");
    let user = discovery
        .discover(ScimProvisioningRequest::UpsertUser {
            principal_id: "principal-user-42".to_string(),
            resource: ScimUserResource {
                schemas: vec![USER_SCHEMA.to_string()],
                id: None,
                external_id: Some("oidc-sub-42".to_string()),
                user_name: "alice".to_string(),
                display_name: Some("Alice Analyst".to_string()),
                active: Some(true),
                emails: Vec::new(),
                meta: None,
                attributes: BTreeMap::new(),
            },
        })
        .await
        .expect("user");
    let group = discovery
        .discover(ScimProvisioningRequest::UpsertGroup {
            principal_id: "principal-group-7".to_string(),
            resource: ScimGroupResource {
                schemas: vec![GROUP_SCHEMA.to_string()],
                id: None,
                external_id: Some("group:growth-team-uuid".to_string()),
                display_name: "Growth Team".to_string(),
                members: Vec::new(),
                meta: None,
                attributes: BTreeMap::new(),
            },
        })
        .await
        .expect("group");

    let ScimProjectionEvent::Upsert { projection: user, .. } = user else { panic!("upsert user") };
    let ScimProjectionEvent::Upsert { projection: group, .. } = group else {
        panic!("upsert group")
    };
    assert_eq!(user.reference.external_id, "oidc-sub-42");
    assert_eq!(group.reference.external_id, "group:growth-team-uuid");
}

#[test]
fn rfc_models_preserve_wire_names_extensions_and_defaults() {
    let user: ScimUserResource = serde_json::from_value(serde_json::json!({
        "schemas": [
            USER_SCHEMA,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        ],
        "id": "P123",
        "externalId": "EMP00123",
        "userName": "alice",
        "displayName": "Alice",
        "active": true,
        "meta": {
            "resourceType": "User",
            "created": "2026-09-13T01:00:00Z",
            "lastModified": "2026-09-13T02:00:00Z",
            "version": "W/\"42\"",
            "location": "/scim/v2/Users/P123"
        },
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "employeeNumber": "EMP00123"
        }
    }))
    .expect("RFC User resource");
    let wire = serde_json::to_value(user).expect("serialize RFC User resource");
    assert_eq!(wire["externalId"], "EMP00123");
    assert_eq!(wire["meta"]["lastModified"], "2026-09-13T02:00:00Z");
    assert_eq!(
        wire["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["employeeNumber"],
        "EMP00123"
    );

    let query: ScimListQuery = serde_json::from_value(serde_json::json!({})).expect("list query");
    assert_eq!(query.start_index, 1);
    assert_eq!(query.count, 100);
    assert!(query.filter.is_none());

    let patch: ScimPatchRequest = serde_json::from_value(serde_json::json!({
        "schemas": [PATCH_SCHEMA],
        "Operations": [{"op": "replace", "path": "active", "value": false}]
    }))
    .expect("RFC PatchOp request");
    assert_eq!(patch.operations[0].op, ScimPatchVerb::Replace);
}

#[test]
fn list_profile_normalizes_pagination_and_filters_rfc_attributes() {
    let discovery = ScimPrincipalDiscovery::new("corporate-scim", "https://id.example/scim")
        .expect("discovery");
    let resource = ScimResource::User(ScimUserResource {
        schemas: vec![USER_SCHEMA.to_string()],
        id: Some("P123".to_string()),
        external_id: Some("EMP00123".to_string()),
        user_name: "alice".to_string(),
        display_name: Some("Alice".to_string()),
        active: Some(true),
        emails: Vec::new(),
        meta: None,
        attributes: BTreeMap::new(),
    });

    let empty_page = discovery
        .list_page(
            vec![resource.clone()],
            &ScimListQuery { start_index: 0, count: 0, filter: None },
        )
        .expect("zero-count page");
    assert_eq!(empty_page.start_index, 1);
    assert_eq!(empty_page.total_results, 1);
    assert!(empty_page.resources.is_empty());

    let filtered = discovery
        .list_page(
            vec![resource],
            &ScimListQuery {
                start_index: 1,
                count: 100,
                filter: Some("externalId eq \"EMP00123\"".to_string()),
            },
        )
        .expect("filtered page");
    assert_eq!(filtered.items_per_page, 1);
}
