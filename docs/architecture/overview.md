# Authguard Architecture Overview

Authguard is a standalone Resource URN authorization system designed for deep
Envoy Gateway integration. It does not reimplement a general API gateway. Envoy
Gateway owns ingress, OIDC/JWT authentication, routing, and traffic policy;
Authguard owns Envoy extAuth gRPC-to-action/Resource-URN mapping, authorization decisions, the
policy control plane, and trusted access context for workload row filtering.

It is most useful for B2B/B2B2C systems with multi-account, multi-role, and
multi-resource access management. The practical boundary is whether multiple
users or workloads collaborate with different scopes inside the same team,
tenant, or resource set. B2C can use it too, but simple owner-only filtering
usually does not require a complete IAM plane.

`iam_principal` is a sparse authorization-side projection of an identity that
an external system has already authenticated. `USER`, `WORKLOAD`, and `GROUP`
share this one abstraction; Authguard stores no password or session. For OIDC,
the only stable key is the verified `(issuer, external_id)` pair, where
`external_id` is `sub`. A bare `sub`, email, or username is not an identity key.

Principals enter Authguard through one generic `IPrincipalDiscovery<Input>` boundary: trusted
JIT projection handles first valid access, control-plane federated search lets
administrators authorize before first login, and SCIM-subset ingestion accepts
optional enterprise lifecycle changes. The shipped federated connectors support
Keycloak Admin API search (including identities federated by Keycloak from
LDAP/AD), direct RFC 4511 LDAP search, and a configurable HTTP + bearer-JWT
connector for in-house identity systems.
The SCIM implementation is an incremental ingestion adapter for a subset of RFC
7643 User and Group data, not a complete RFC 7644 SCIM server. All three paths
normalize and idempotently write the same `iam_principal` table; no
protocol-specific account table is introduced. A SCIM source `issuer` MUST
exactly equal the corresponding OIDC token `iss`; a SCIM User `externalId`
SHOULD equal OIDC `sub`, and a SCIM Group `externalId` SHOULD equal the
provider-stable group ID (the Keycloak group UUID). This makes SCIM, JIT, and
federated discovery converge on the same Principal. Internet deployments with hundreds of millions of
identities use JIT plus federated search as the default path and materialize only
Principals that access or receive authorization. When SCIM is enabled, it should
use incremental provisioning rather than require a full preload.
SCIM is push-oriented: the IdP/provisioning agent is the Client and Authguard
applies submitted changes. `refresh` is not an IdP polling loop; any optional
pull importer is a separate source-specific control-plane connector.

Keycloak can search users federated from LDAP/AD, but that is a Keycloak
administration feature rather than an OIDC protocol feature. Keycloak groups,
realm/client roles, and OIDC scopes remain useful coarse identity claims; they
are not imported as Authguard resource policy. The data plane
never searches Keycloak, LDAP, SCIM, or cloud IAM remotely. Every authorization
request batch-loads the primary and Group Principals from the local repository
by `issuer + external_id`, so disablement and revocation fail closed immediately.
`IAuthorizationCache` stores only short-lived opaque scope-token contexts. The
compiled policy is an immutable in-process snapshot refreshed by durable
repository revision. Neither policies nor Principals enter Memory/Redis cache.

The default `auth.identity.groups_claim` is `authguard_group_ids`. Its values
MUST be issuer-local stable group IDs, which are Keycloak group UUIDs for the
shipped connector. JIT and Keycloak federated discovery both normalize them as
`group:<UUID>`. A group name, display name, or path is display metadata and MUST
NOT be used as a stable authorization key.

```text
User or workload
  -> enterprise IdP / Keycloak issues a short-lived access token
  -> Envoy Gateway strictly validates issuer, audience, and local/remote JWKS
  -> Envoy forwards only the verified JWT token; Authguard extracts issuer + external_id(sub)
  -> Authguard :8080 envoy.service.auth.v3.Authorization/Check (Envoy extAuth only)
  -> Authguard resolves active Principals from the repository and evaluates its compiled L1 snapshot
       (policy refreshes by durable repository revision; Redis stores only scope-token contexts)
  -> Envoy removes client x-authguard-* headers and injects exactly one of:
       x-authguard-context       HMAC-SHA256-signed short-lived allow/deny URN context
       x-authguard-scope-token   short-lived opaque token for a large scope
  -> workload adapter IAccessContextResolver
       HeaderAccessContextResolver decodes the Envoy-injected context
       GrpcAccessContextResolver calls Authguard :8081 gRPC ResolveScope
  -> repository compiles action-specific allow/deny URNs into a SQL scope

IAM administrator
  -> IPrincipalDiscovery<Input>
       JitPrincipalDiscovery        first use of a trusted identity
       KeycloakPrincipalDiscovery   control-plane search (Keycloak Admin API)
       LdapPrincipalDiscovery       control-plane search (direct RFC 4511 LDAP)
       CustomPrincipalDiscovery     control-plane search (configurable HTTP + JWT)
       ScimPrincipalDiscovery       RFC 7643 User/Group subset ingestion
  -> idempotently materialize iam_principal
  -> Authguard /adm/v1/** (policy and role-binding control plane)
```

The login JWT carries stable identity, tenant, group, and MFA claims rather than
large resource-URN lists. Authguard computes the resource scope per request from
principal, action, Resource URN, and request conditions such as IP/TLS/MFA.
JWT mode accepts only an `Authorization: Bearer ...` token already verified by
Envoy; OIDC mode accepts only Envoy's forwarded verified ID token. Authguard
extracts claims from that token, does not repeat JWT signature verification,
and accepts no separate issuer, subject, group, or MFA claim headers.
`auth.scope_delivery.direct_urn_limit` selects direct context versus scope token.
Both forms are short lived, carry `policy_revision`, are action-bound, and fail closed when
missing, expired, or mismatched.
The two gRPC services have distinct listeners: Envoy Check uses `8080`, while
SDK ResolveScope uses `8081`. The default NetworkPolicy independently restricts
them to Envoy and `authguard.io/scope-client` selectors, so workloads cannot
reach the context-issuing Check service.

A direct context is `agctx1.<payload>.<signature>`. Each SDK verifies its
HMAC-SHA256 signature before decoding the Base64URL v3 payload. Authguard and
workloads share a high-entropy key of at least 32 bytes through
`AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY`; unsigned, tampered, or wrong-key contexts
fail closed. Helm can reference an existing Secret through
`authguard.accessContext.existingSecret` and `authguard.accessContext.key`; if
neither an existing Secret nor an explicit signing key is supplied, it
generates and reuses a 64-character key. Independently deployed workloads must
mount the same Secret/environment variable.

The normalized authorization schema has six tables:
`iam_policy`, `iam_principal`, `iam_action`, `iam_role`, `iam_role_action`, and
`iam_role_binding`. Business resources and external account directories remain
their owning systems' source of truth.

The standards basis is explicit: [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
requires the `iss + sub` combination for a stable OIDC End-User key; the
[Keycloak administration guide](https://www.keycloak.org/docs/latest/server_admin/)
documents LDAP/AD user federation; and [SCIM Core Schema RFC 7643](https://www.rfc-editor.org/rfc/rfc7643.html)
with [SCIM Protocol RFC 7644](https://www.rfc-editor.org/rfc/rfc7644.html) defines
standard identity provisioning.

Current implementation structure:

Authorization routes depend on `IAuthorizationHandler`.
`DefaultAuthorizationHandler` contains ACL evaluation and request-access
delivery; `PolicyHandler` coordinates CRUD and durable synchronization, while
`PolicyRuntime` owns the compiled immutable snapshot. No duplicate
authorization service package remains.

```text
src/core/src
  server.rs     API/management listeners and graceful shutdown
  route/        Envoy gRPC and management HTTP protocol adapters
  handler/
    authorization.rs  ACL evaluation and request-access delivery
    policy.rs    policy compilation, immutable runtime, and policy CRUD
    principal.rs Principal projection/discovery use cases
    management.rs health, readiness, status, and metrics use cases
  config/       authguard.yaml loading, environment overrides, validation
  model/        storage-independent authorization models, SQL scopes, and transport DTOs
  principal/
    mod.rs       shared discovery models, traits, and errors
    jit.rs       trusted OIDC just-in-time projection
    federation/   Keycloak, LDAP, and configurable HTTP/JWT federated search
    scim.rs      RFC 7643 User/Group subset ingestion
  storage/      SQLite/PostgreSQL repositories and private row records
  cache/        Memory/Redis opaque scope-token context cache
  utils/        identity parsing, HTTP tuple mapping, OTel tracing, and metrics
src/core/migrations
  001_init.ddl.sql portable authorization schema DDL
  001_init.dml.sql initial singleton-policy DML
src/adapters    Rust, Go, Python, and Java SDKs
use-cases       Enterprise customer-growth analysis-job business-service E2E examples
deploy          One Authguard image, Envoy Gateway Helm, Grafana dashboard
```

Rust models are not persistence entities: the flat `model/` package owns all
storage-independent authorization semantics and boundary DTOs, while
`storage/record.rs` is the sole database-row representation. Both repositories
consume the same numbered DDL/DML migration pair.

See the [IAM authorization whitepaper](iam-authorization-whitepaper.md) for the
canonical model and the [Envoy Gateway implementation plan](../plans/envoy-gateway-integration-implementation-plan_ZH.md)
for the current delivery architecture.
