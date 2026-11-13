use super::*;

#[test]
fn decodes_persisted_principal_enums() {
    assert_eq!(PrincipalKind::try_from("USER".to_string()), Ok(PrincipalKind::User));
    assert_eq!(PrincipalStatus::try_from("DISABLED".to_string()), Ok(PrincipalStatus::Disabled));
}

#[test]
fn rejects_unknown_persisted_principal_enums() {
    assert!(PrincipalKind::try_from("DEVICE".to_string()).is_err());
    assert!(PrincipalStatus::try_from("PENDING".to_string()).is_err());
}
