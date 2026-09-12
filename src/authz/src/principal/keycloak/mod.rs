#[path = "keycloak.rs"]
mod implementation;
mod model;

pub use implementation::KeycloakPrincipalDiscovery;
