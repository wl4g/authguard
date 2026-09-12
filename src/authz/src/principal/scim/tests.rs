use super::*;

#[tokio::test]
async fn provisions_users_and_groups_with_stable_external_keys() {
    let discovery = ScimPrincipalDiscovery::new(
        "corporate-scim",
        "https://identity.example.com/scim/customer-growth",
    )
    .expect("discovery");
    let user = discovery
        .provision(ScimProvisioningRequest::UpsertUser {
            principal_id: "principal-user-42".to_string(),
            resource: ScimUserResource {
                id: "user-42".to_string(),
                external_id: Some("oidc-sub-42".to_string()),
                user_name: "alice".to_string(),
                display_name: Some("Alice Analyst".to_string()),
                active: Some(true),
                emails: Vec::new(),
                attributes: BTreeMap::new(),
            },
        })
        .await
        .expect("user");
    let group = discovery
        .provision(ScimProvisioningRequest::UpsertGroup {
            principal_id: "principal-group-7".to_string(),
            resource: ScimGroupResource {
                id: "growth-team".to_string(),
                external_id: Some("group:growth-team-uuid".to_string()),
                display_name: "Growth Team".to_string(),
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
