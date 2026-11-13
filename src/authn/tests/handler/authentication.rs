use std::collections::BTreeMap;

use authguard_common::model::{ExternalIdentity, PrincipalKind};
use chrono::Utc;
use serde_json::json;

use super::*;

#[test]
fn projects_only_protocol_neutral_authorization_context() {
    let authentication = AuthenticationResult::new(
        ExternalIdentity {
            provider: "corporate".to_string(),
            issuer: "https://id.example".to_string(),
            subject: "employee-123".to_string(),
            claims: BTreeMap::from([
                ("username".to_string(), json!("alice")),
                ("email".to_string(), json!("alice@example.com")),
                ("tenant_id".to_string(), json!("example-corp")),
                (
                    "authguard_group_ids".to_string(),
                    json!(["principal-team-b", "principal-team-a", "principal-team-a"]),
                ),
                ("access_token".to_string(), json!("must-not-leak")),
            ]),
        },
        ["oidc"],
        None,
        Utc::now(),
    );
    let mut principal = AuthenticatedPrincipalContext {
        principal_id: "principal-alice".to_string(),
        kind: PrincipalKind::User,
        stable_group_ids: Vec::new(),
        trusted_claims: HashMap::new(),
        acr: None,
        amr: Vec::new(),
    };

    project_authorization_context(&mut principal, &authentication);

    assert_eq!(principal.stable_group_ids, ["principal-team-a", "principal-team-b"]);
    assert_eq!(
        principal.trusted_claims,
        HashMap::from([("tenant_id".to_string(), "example-corp".to_string())])
    );
}
