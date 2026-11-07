use serde_json::json;

use super::has_accepted_audience;

#[test]
fn validates_string_and_array_audiences() {
    let accepted = vec!["customer-growth".to_string()];
    assert!(has_accepted_audience(&json!({"aud": "customer-growth"}), &accepted));
    assert!(has_accepted_audience(&json!({"aud": ["account", "customer-growth"]}), &accepted));
    assert!(!has_accepted_audience(&json!({"aud": "other"}), &accepted));
    assert!(!has_accepted_audience(&json!({}), &accepted));
}
