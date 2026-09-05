//! Federated Principal search across protocol-specific identity sources.
//!
//! Keycloak speaks its Admin REST API, LDAP speaks RFC 4511, and in-house
//! systems (e.g. an enterprise DSP directory) are integrated through the
//! configurable HTTP/JWT connector. There is no RFC standardizing search
//! across heterogeneous identity stores, so each connector implements the
//! protocol-neutral [`IPrincipalDiscovery`] contract directly instead of
//! wrapping a shared protocol implementation.
//! <https://www.rfc-editor.org/rfc/rfc4511.html>

mod custom;
mod keycloak;
mod ldap;

pub use custom::CustomPrincipalDiscovery;
pub use keycloak::KeycloakPrincipalDiscovery;
pub use ldap::LdapPrincipalDiscovery;
