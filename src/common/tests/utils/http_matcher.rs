use super::*;

#[test]
fn resolves_path_and_identity_claims_into_resource_urn() {
    let route = CompiledHttpRoute::compile(
        "customer-growth.job.read".to_string(),
        HttpRouteMatcher {
            id: "job-read".to_string(),
            methods: vec!["GET".to_string()],
            hosts: vec!["*.example.com".to_string()],
            path: "/customer-growth/jobs/{job_id}".to_string(),
            resource_urn: "urn:iam:prod:customer-growth:global:{tenant_id}:job/{job_id}"
                .to_string(),
            parent_urns: Vec::new(),
        },
    )
    .expect("route");
    let claims = HashMap::from([("tenant_id".to_string(), "acme".to_string())]);

    let resolved =
        resolve_route(&[route], "GET", "api.example.com", "/customer-growth/jobs/job-1", &claims)
            .expect("resolved");

    assert_eq!(resolved.route_id, "job-read");
    assert_eq!(
        resolved.resource_urn.to_string(),
        "urn:iam:prod:customer-growth:global:acme:job/job-1"
    );
    assert_eq!(resolved.action, "customer-growth.job.read");
}
