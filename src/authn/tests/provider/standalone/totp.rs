use super::*;

#[test]
fn encrypted_secret_is_bound_to_credential() {
    let service = TotpService::new(TotpAuthnProperties::default(), &STANDARD.encode([7_u8; 32]))
        .expect("TOTP service");
    let encrypted = service.encrypt("JBSWY3DPEHPK3PXP", "cred-1").expect("encrypt");
    assert_ne!(encrypted, "JBSWY3DPEHPK3PXP");
    assert_eq!(service.decrypt(&encrypted, "cred-1").expect("decrypt"), "JBSWY3DPEHPK3PXP");
    assert!(service.decrypt(&encrypted, "cred-2").is_err());
}
