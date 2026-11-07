use std::collections::{BTreeMap, BTreeSet};

use authguard_common::config::{
    ApplicationProperties, ApplicationThemeProperties, AuthnProperties,
};
use axum::http::{header, HeaderMap, HeaderValue};

use super::ApplicationResolver;

struct TestFixture;

impl TestFixture {
    fn config() -> AuthnProperties {
        AuthnProperties {
            applications: BTreeMap::from([(
                "example-app".to_string(),
                ApplicationProperties {
                    hosts: BTreeSet::from(["app.example.com".to_string()]),
                    display_name: "Example App".to_string(),
                    logo: "/auth/assets/themes/custom/example-app.svg".to_string(),
                    theme: Some(ApplicationThemeProperties {
                        id: "example-app".to_string(),
                        stylesheet: "/auth/assets/themes/custom/example-app.css".to_string(),
                    }),
                    return_uris: vec!["https://app.example.com/**".to_string()],
                },
            )]),
            ..AuthnProperties::default()
        }
    }

    fn headers(host: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_str(host).expect("host"));
        headers
    }
}

#[test]
fn resolves_brand_and_normalizes_an_allowed_return_path() {
    let config = TestFixture::config();
    let headers = TestFixture::headers("app.example.com");
    let resolver = ApplicationResolver::new(&config, &headers);
    let application = resolver.resolve().expect("application").expect("known");
    assert_eq!(application.id, "example-app");
    assert_eq!(
        application.theme.expect("theme").stylesheet,
        "/auth/assets/themes/custom/example-app.css"
    );
    assert_eq!(
        resolver
            .validate_return_to("https://app.example.com/workflows/123?tab=run")
            .expect("allowed"),
        "/workflows/123?tab=run"
    );
}

#[test]
fn rejects_cross_origin_and_protocol_relative_returns() {
    let config = TestFixture::config();
    let headers = TestFixture::headers("app.example.com");
    let resolver = ApplicationResolver::new(&config, &headers);
    assert!(resolver.validate_return_to("https://attacker.example/").is_err());
    assert!(resolver.validate_return_to("//attacker.example/").is_err());
}

#[test]
fn rejects_return_target_for_an_unknown_application_host() {
    let config = TestFixture::config();
    let headers = TestFixture::headers("unknown.example.com");
    let resolver = ApplicationResolver::new(&config, &headers);

    assert!(resolver.validate_return_to("/workflows/123").is_err());
    assert_eq!(
        resolver
            .validate_response_return_uri("/customer-growth/jobs")
            .expect("safe non-redirecting response URI"),
        "/customer-growth/jobs"
    );
    assert!(resolver.validate_response_return_uri("//attacker.example/").is_err());
}
