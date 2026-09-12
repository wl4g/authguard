#[path = "ldap.rs"]
mod implementation;
mod model;

pub use implementation::LdapPrincipalDiscovery;
