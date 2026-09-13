//! RFC-compatible SCIM 2.0 User and Group provisioning routes.
//!
//! Protocol references:
//! - RFC 7644 resource endpoints and methods:
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.2>
//! - RFC 7644 create, retrieve, replace, PATCH, and delete semantics:
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.3>
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4>
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.5>
//!   <https://www.rfc-editor.org/rfc/rfc7644.html#section-3.6>
//! - RFC 7643 User and Group core schemas:
//!   <https://www.rfc-editor.org/rfc/rfc7643.html#section-4.1>
//!   <https://www.rfc-editor.org/rfc/rfc7643.html#section-4.2>
//!
//! GitHub Enterprise SCIM integration reference:
//! <https://docs.github.com/en/enterprise-cloud@latest/rest/authentication/permissions-required-for-github-apps?apiVersion=2026-03-10#enterprise-permissions-for-enterprise-scim>
//!
//! `AuthGuard` supports the bounded provisioning profile implemented below;
//! unsupported complex PATCH paths and filters fail with a SCIM error instead
//! of being silently accepted.

#[path = "scim.rs"]
mod implementation;
mod model;

pub use implementation::ScimPrincipalDiscovery;
pub(crate) use implementation::{
    ScimProjectionEvent, ScimProvisioningRequest, ScimResource, ScimStoredResource,
};
pub use model::*;

#[cfg(test)]
mod tests;
