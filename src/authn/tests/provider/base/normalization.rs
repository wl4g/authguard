use super::validate_json_path;

#[test]
fn supports_only_bounded_json_paths() {
    assert!(validate_json_path("$.users[?(@.primary)].id").is_err());
    assert!(validate_json_path("$.data.user.id").is_ok());
}
