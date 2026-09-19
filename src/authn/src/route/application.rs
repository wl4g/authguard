//! Trusted application resolution for same-origin hosted login.
//!
//! This module deliberately has no provider, identity, or token knowledge.
//! It turns a Gateway-preserved `Host` header into presentation metadata and
//! validates post-authentication browser destinations before a protocol
//! handler stores or redirects to them.

use authguard_common::config::{
    ApplicationProperties, ApplicationThemeProperties, AuthnProperties,
};
use axum::http::{header, HeaderMap};

use crate::handler::ApiError;

#[derive(Debug, Clone)]
pub(crate) struct ResolvedApplication {
    pub(crate) id: String,
    pub(crate) display_name: String,
    pub(crate) logo: String,
    pub(crate) theme: Option<ApplicationThemeProperties>,
    properties: ApplicationProperties,
}

/// Resolves trusted application context for a single browser request.
///
/// Keeping host resolution and redirect validation together makes the trust
/// boundary explicit: neither providers nor callers can supply an
/// `application_id` independently of the Gateway-preserved `Host` header.
pub(crate) struct ApplicationResolver<'a> {
    config: &'a AuthnProperties,
    headers: &'a HeaderMap,
}

impl<'a> ApplicationResolver<'a> {
    pub(crate) fn new(config: &'a AuthnProperties, headers: &'a HeaderMap) -> Self {
        Self { config, headers }
    }

    /// Resolves the exact trusted application for the request host.
    ///
    /// No `X-Forwarded-Host` fallback is used: Envoy Gateway must preserve the
    /// original `Host`, so a client cannot select an application's brand itself.
    pub(crate) fn resolve(&self) -> Result<Option<ResolvedApplication>, ApiError> {
        let Some(host) = self.request_host()? else {
            return Ok(None);
        };
        Ok(self.config.applications.iter().find_map(|(id, application)| {
            application.hosts.contains(&host).then(|| ResolvedApplication {
                id: id.clone(),
                display_name: application.display_name.clone(),
                logo: application.logo.clone(),
                theme: application.theme.clone(),
                properties: application.clone(),
            })
        }))
    }

    /// Validates a hosted-login destination and returns a same-origin path.
    ///
    /// Absolute values are normalized to a path only after the configured host
    /// and URI allow-list match. This keeps the response redirect independent of
    /// a browser-supplied scheme or authority and prevents open redirects.
    pub(crate) fn validate_return_to(&self, return_to: &str) -> Result<String, ApiError> {
        self.validate_destination(return_to, true)
    }

    /// Validates the legacy non-redirecting JSON response field.
    ///
    /// A dedicated `AuthN` host may use a safe relative value because the server
    /// never redirects to it. Absolute values still require an Application.
    pub(crate) fn validate_response_return_uri(
        &self,
        return_uri: &str,
    ) -> Result<String, ApiError> {
        self.validate_destination(return_uri, false)
    }

    fn validate_destination(
        &self,
        destination: &str,
        require_application: bool,
    ) -> Result<String, ApiError> {
        if destination.is_empty() {
            return Ok(String::new());
        }
        let host =
            self.request_host()?.ok_or_else(|| ApiError::bad_request("Host header is required"))?;
        let application = self.resolve()?;
        if require_application && application.is_none() {
            return Err(ApiError::bad_request("return_to requires a configured application host"));
        }
        let candidate = if destination.starts_with('/') {
            if destination.starts_with("//")
                || destination.contains('\\')
                || destination.bytes().any(|value| value.is_ascii_control())
            {
                return Err(ApiError::bad_request("return_to must be a same-origin path"));
            }
            reqwest::Url::parse(&format!("https://{host}{destination}"))
                .map_err(|_| ApiError::bad_request("return_to is invalid"))?
        } else {
            let application = application.as_ref().ok_or_else(|| {
                ApiError::bad_request("absolute return_to requires a configured application")
            })?;
            let parsed = reqwest::Url::parse(destination)
                .map_err(|_| ApiError::bad_request("return_to is invalid"))?;
            if parsed.scheme() != "https"
                || parsed.host_str() != Some(host.as_str())
                || parsed.username() != ""
                || parsed.password().is_some()
                || parsed.fragment().is_some()
            {
                return Err(ApiError::bad_request("return_to must target the current HTTPS host"));
            }
            if !Self::matches_return_uri(&application.properties, &parsed) {
                return Err(ApiError::bad_request(
                    "return_to is not configured for this application",
                ));
            }
            parsed
        };
        if application.as_ref().is_some_and(|application| {
            !Self::matches_return_uri(&application.properties, &candidate)
        }) {
            return Err(ApiError::bad_request("return_to is not configured for this application"));
        }
        let mut path = candidate.path().to_string();
        if let Some(query) = candidate.query() {
            path.push('?');
            path.push_str(query);
        }
        Ok(path)
    }

    fn request_host(&self) -> Result<Option<String>, ApiError> {
        let Some(value) = self.headers.get(header::HOST) else {
            return Ok(None);
        };
        let value = value.to_str().map_err(|_| ApiError::bad_request("Host header is invalid"))?;
        if value.is_empty() || value.contains(['/', '@', '\\']) {
            return Err(ApiError::bad_request("Host header is invalid"));
        }
        let parsed = reqwest::Url::parse(&format!("https://{value}"))
            .map_err(|_| ApiError::bad_request("Host header is invalid"))?;
        if parsed.username() != "" || parsed.password().is_some() || parsed.path() != "/" {
            return Err(ApiError::bad_request("Host header is invalid"));
        }
        parsed
            .host_str()
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| ApiError::bad_request("Host header is invalid"))
            .map(Some)
    }

    fn matches_return_uri(application: &ApplicationProperties, candidate: &reqwest::Url) -> bool {
        application.return_uris.iter().any(|configured| {
            let wildcard = configured.ends_with("/**");
            let prefix = configured.strip_suffix("/**").unwrap_or(configured);
            let Ok(configured) = reqwest::Url::parse(prefix) else {
                return false;
            };
            if candidate.scheme() != configured.scheme()
                || candidate.host_str() != configured.host_str()
                || candidate.port_or_known_default() != configured.port_or_known_default()
            {
                return false;
            }
            let path = configured.path().trim_end_matches('/');
            if wildcard {
                path.is_empty()
                    || candidate.path() == path
                    || candidate.path().starts_with(&format!("{path}/"))
            } else {
                candidate.path() == configured.path()
            }
        })
    }
}

#[cfg(test)]
mod tests {
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
}
