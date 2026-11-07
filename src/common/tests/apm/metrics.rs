use super::AuthnMetrics;

#[test]
fn preserves_the_bounded_token_exchange_operation() {
    let metrics = AuthnMetrics::default();
    metrics.record_flow("e2e-keycloak", "token_exchange", "success", 0.01);

    let rendered = metrics.render().expect("render metrics");
    assert!(rendered.contains(
            "authguard_authn_flows_total{provider=\"e2e-keycloak\",operation=\"token_exchange\",outcome=\"success\"} 1"
        ));
}
