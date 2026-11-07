use super::*;

#[test]
fn canonical_values_are_bounded_and_trimmed() {
    assert!(validate_canonical("P123", "principal_id").is_ok());
    assert!(validate_canonical(" P123", "principal_id").is_err());
    assert!(validate_canonical("P\n123", "principal_id").is_err());
}
