# Authguard Enterprise IAM Authorization System Design

- **Status:** Architecture Baseline
- **Date:** 2026-09-03
- **Scope:** Authguard / Envoy Gateway external authorization / enterprise IAM / multi-language business services
- **Current landing:** One Authguard Rust service, Envoy Gateway integration, adapters, and use cases

## 1. Summary

- This document defines a generic, standalone, enterprise-grade resource
authorization architecture. It is not bound to any business system. A business
microservice only needs to expose its objects as protected resources, then authorize
them through Resource URNs, actions, roles, role bindings, conditions, and authguard adapters SDK.

- Authguard is a standalone authorization plane designed for deep Envoy Gateway
integration. Envoy Gateway owns ingress, OIDC/JWT authentication, routing, and
traffic policy. Authguard combines enterprise RBAC with resource-oriented URN
role bindings so the external-authorization data plane and business adapters can answer
two questions with one policy model:

  1. May this Principal perform this action on this concrete resource?
  2. Which resource rows may this Principal see inside a business service database
     query?

- From a B2B/B2C scenario access-management perspective, Authguard is most suitable for
B2B and B2B2C systems. The practical boundary is not the business label; it is
whether multiple people or system principals collaborate while holding different
roles and different resource scopes inside the same team, tenant, or resource
set. Enterprise customer-growth analysis jobs, enterprise SaaS, cloud resource platforms, data
platforms, supply-chain/procurement systems, and corporate treasury systems
usually have these characteristics. B2C systems can use the same URN model as
well, especially for merchant consoles, platform operations, support, risk, and
audit back offices. For a simple rule such as "a consumer may only access their
own orders", direct field predicates are usually enough and a full IAM
authorization plane may be heavier than necessary.

- Core decisions:

  - Authentication answers "who is calling".
  - Authorization answers "which action can the caller perform on which resource".
  - `iam_principal` is an authorization-side projection of an identity already
    authenticated by an external system; it never stores credentials.
  - `USER`, `WORKLOAD`, and `GROUP` are one Principal abstraction. OIDC identities
    are uniquely identified by `(issuer, external_id)`, where `external_id` is
    the `sub` claim. A bare `sub`, email address, or username is never an identity
    key.
  - Actions use `iam_action`, roles use `iam_role`, role composition uses
    `iam_role_action`, and assignments use `iam_role_binding`.
  - `IPrincipalDiscovery<Input>` unifies trusted JIT (Just-In-Time) projection, control-plane federated
    search, and RFC 7643 User/Group subset ingestion. All three paths normalize and idempotently
    materialize the same `iam_principal` record. The data plane may perform local
    JIT for an already verified identity; federated search and SCIM ingestion do
    not participate in a data-plane authorization decision.
  - Resource identity uses an internal `urn:iam:...` Resource URN based on the
    RFC 8141 URN syntax style.
  - IAM core does not maintain an `iam_resource` table. Business tables remain the
    source of truth for resource existence, attributes, and lifecycle.
  - Request tuples are route/resource matchers, not the resource permission model.
  - Resource listing is handled by business Resource Adapters that compile the
    action-specific `AuthorizationScope` into SQL scopes.

- The standard deployment consists of the Envoy Gateway controller, its managed
Envoy Proxy data plane, and one Authguard image. Authguard does not reimplement
a general API gateway or copy evaluators into business services. Workloads only
consume trusted access context through adapters.

### 1.1 Minimal model

```text
principal(USER / WORKLOAD / GROUP)
  ─ role binding(effect, resource URN, conditions)
  ─ role
  ─ role action
  ─ action
```

The role-binding target is a Resource URN:

```text
urn:iam:<partition>:<service>:<region>:<tenant>:<resource-path>
```

Examples:

```text
urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score
urn:iam:prod:github:global:octo-org:repo/payment-service
urn:iam:prod:s3:us-east-1:123456789012:bucket/audit-logs/object/2026/08/**
```

Wildcard rules must remain small and predictable:

- `*` matches one segment.
- `**` is allowed only as the final resource-path segment.
- Partial segment wildcards such as `pay*` are not supported.

This restriction is what makes binding patterns safe to compile into SQL
predicates.

### 1.2 A minimal authorization story

Alice signs in through an OIDC provider. The provider proves Alice's identity;
it does not decide which business resources she may access. After Envoy has
verified the token, Authguard JIT-projects the trusted external identity:

```text
issuer      = https://idp.example.com/realms/company
external_id = 00u123                    # verified OIDC sub
kind        = USER
  -> iam_principal:alice
```

An administrator could reach the same record by federated search before Alice's
first request. The administrator binds the projected Principal to `reader`:

```text
iam_principal:alice
  -> iam_role_binding
       effect       = ALLOW
       resource_urn = urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*
  -> iam_role:reader
  -> iam_role_action
  -> iam_action:customer-growth.job.read
  -> iam_action:customer-growth.job.run.read
```

When Alice requests a customer-growth analysis job run:

```text
GET /customer-growth/workspaces/customer-insights/projects/retention-analytics/jobs/daily-churn-risk-score/runs/run-123
```

The route matcher produces:

```text
action       = customer-growth.job.run.read
resource_urn = urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score/run/run-123
parent_urns  = [
  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score,
  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics,
  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights
]
```

The evaluator finds Alice's active role binding, verifies that `reader` contains
`customer-growth.job.run.read`, and confirms that its URN pattern covers the
requested job. The request is allowed.

## 2. Goals

### 2.1 Functional goals

- Accept Envoy Gateway-verified OIDC/JWT user and workload identities.
- Support principals, roles, role bindings, action catalogs, conditions, and
  route/resource matchers.
- Discover Principals through trusted JIT (Just-In-Time) projection, control-plane federated
  search, and RFC 7643 User/Group subset ingestion without requiring an IdP-wide
  preload.
- Support platform, tenant/domain, and resource-level authorization.
- Support a GitHub-like organization/repository authorization experience without
  binding the model to GitHub concepts.
- Support arbitrary business resource types such as repositories, customer-growth jobs,
  bots, workflows, datasets, and channels.
- Support hierarchical inheritance, such as a workspace owner inheriting access
  to customer-growth jobs under that workspace.
- Enforce authorization through Envoy Gateway external authorization.
- Expose UI auth context for menus, buttons, and access-denied states.
- Observe authorization decisions and management requests through Prometheus/OTel;
  authentication auditing belongs to Envoy/IdP, and a durable authorization
  audit event store is not implemented yet.

### 2.2 Engineering goals

- High cohesion: protocol routing, authorization evaluation, policy runtime,
  identity resolution, persistence, and observability remain explicit
  responsibilities with narrow interfaces.
- Low coupling: IAM core does not depend on business table schemas.
- No duplicate resource truth: IAM does not mirror business resources into a
  core resource table.
- Cross-language portability: Java, Go, Python, and Rust implementations share
  model semantics, decision algorithms, and test contracts.
- One deployment shape: Authguard is Envoy Gateway's external authorization
  service; adapters only provide workload context and SQL scopes.

### 2.3 Non-goals

- UI hiding is not a security boundary.
- Authguard does not mirror every account from an external identity provider.
- A full SCIM mirror or bulk preload is not required by the core authorization
  path. RFC 7643 User/Group subset ingestion is an implemented, opt-in,
  incremental lifecycle integration, not a complete RFC 7644 server.
- Authguard is not a general API gateway, OIDC session manager, login UI, or IdP.
- Request method/path/query is not the resource permission model.
- IAM core does not own business resource lifecycle.
- Arbitrary regex resource patterns are not supported in v1.
- Legacy compatibility models are not retained.

## 3. Overall model

Unified authorization chain:

```text
external identity
  -> iam_principal
  -> iam_role_binding(effect + resource URN + conditions)
  -> iam_role
  -> iam_role_action
  -> iam_action
  -> authorization decision
```

Single-request decision chain:

```text
HTTP request
  -> Envoy Gateway authn filter
  -> route/resource matcher
  -> action identifier
  -> resource URN + parent resource URNs
  -> effective role bindings
  -> role/action check
  -> condition check
  -> ALLOW / DENY
```

Resource-listing chain:

```text
current principal
  -> role-binding evaluation for the requested action
  -> AuthorizationScope(allow Resource URNs, deny Resource URNs)
  -> business Resource Adapter
  -> SQL predicate / query scope
  -> business DB
```

### 3.1 Core relationship map

```text
verified identity ─────▶ iam_principal
                              │
                              ▼
                     iam_role_binding
                   effect + resource_urn
                         + conditions
                              │
                              ▼
                          iam_role
                              │
                              ▼
                       iam_role_action
                              │
request ── matcher ─────▶ iam_action
                              │
                              ▼
                     decision: ALLOW / DENY
```

Only the business system knows its resource tables. IAM sees Resource URNs and
actions; business Resource Adapters translate binding patterns into query scopes.

## 4. Core concepts

### 4.1 Principal

A Principal is the single authorization subject abstraction. `kind` distinguishes
`USER`, `WORKLOAD`, and `GROUP`, so humans, service accounts, microservice
workloads, and externally managed groups use the same binding model without
additional principal subtype tables.

`iam_principal` is a sparse authorization-side projection, not an identity
source of truth. It stores only principals that have been observed through a
trusted authentication flow or selected for authorization by an administrator.
It does not store passwords, sessions, MFA secrets, or the full external user
profile.

### 4.2 External identity reference

Every projected Principal has a source-specific stable reference:

```text
issuer + external_id
```

For OIDC, `issuer` is the exact normalized `iss` claim and `external_id` is the
verified `sub` claim. OpenID Connect defines only the combination of `iss` and
`sub` as a locally unique, never-reassigned identifier for the End-User. A bare
`sub` can collide across issuers; email, preferred username, and display name
can change or be reassigned and MUST NOT be identity keys.

For LDAP, SCIM, cloud IAM, or a custom enterprise IdP, `IPrincipalDiscovery<Input>`
normalizes the source's stable account ID into the same pair. `issuer` is the
canonical authority URI configured for that source. If a source does not
guarantee identifiers are unique across Principal kinds, its implementation
MUST namespace `external_id` before projection. Human-readable profile fields
are display metadata only.

Groups likewise require issuer-local stable identifiers. The default
`auth.identity.groups_claim` is `authguard_group_ids`. With Keycloak, claim
values MUST be group UUIDs and are normalized to
`external_id = group:<UUID>`. JIT and Keycloak federated discovery use that same
UUID, preventing a group name/path and UUID from creating two Principals. Group
names, display names, and paths are display metadata and MUST NOT be stable
role-binding keys.

### 4.3 Principal discovery and projection

Authguard implements three complementary acquisition paths behind one public
`IPrincipalDiscovery<Input>` boundary:

1. **Trusted JIT (Just-In-Time) projection:** after Envoy verifies a user or workload token,
   Authguard idempotently upserts the `(issuer, external_id)` projection. This
   records only identities that actually use protected applications.
2. **Control-plane federated search:** when an administrator configures a
   policy in the Authguard UI/API for an employee account, a machine/service
   account, or another workload account, they normally do not know the external
   authentication identifier (OIDC `sub`, LDAP `entryUUID`, and so on). The
   administrator searches a configured discovery source. Authguard ships a
   Keycloak Admin API connector (which also exposes identities federated by
   Keycloak from LDAP/AD) and a direct RFC 4511 LDAP connector. Authguard
   re-resolves a selected candidate server-side by its stable reference before
   materializing the Principal and creating a role binding.
3. **SCIM-subset ingestion:** the implemented adapter accepts bounded RFC 7643
   User/Group fields and normalizes user/group upserts or delete events into the
   same Principal projection. Delete marks an existing projection `DISABLED`.

Federated search must cover account identifiers; `GROUP` is searched as well,
but only to fetch display metadata such as group name/path so administrators
can recognize candidates in the binding UI. The stable authorization key is
always the immutable `issuer + external_id` (for example `group:<UUID>`), never
a display name from search results. Search discovers and displays external
groups; it never copies Keycloak groups, realm roles, or similar external
objects into a second authorization-policy authority inside Authguard.

The three modes suit different authorization scenarios, and the difference is
structural. **JIT projection** fits 2C Internet consumer authorization. A
consumer flow is single-owner by nature: users do not collaborate in teams
with differing permissions, each user owns only their own data, and there is
no administrator who pre-assigns rights before access happens. Every consumer
request traverses the same gateway, so the first verified register/login is
the moment Authguard first observes the identity — JIT materializes the
Principal then and there, with no provisioning pipeline and no full-directory
preload. That Principal also enables defense in depth behind the gateway: the
business microservice can double-check authorization from the context
Authguard injects, compiling it into a SQL scope so a consumer can only CRUD
their own rows. **SCIM ingestion and federated search** fit 2B enterprise
scenarios, where the shape is the opposite: employees and workload/service
accounts collaborate under differing permissions, an administrator grants
rights — often before the account has ever logged in — and the IdP/HR system
centrally owns the account lifecycle: federated search finds the external
identifier, SCIM applies pushed lifecycle changes.

JIT plus federated search is the default for Internet platforms, including
identity populations of hundreds of millions: Authguard stores only Principals
that actually access a protected application or receive a binding. SCIM-subset
ingestion remains opt-in and incremental; enabling it does not require a full
preload. The current endpoint is not a complete RFC 7644 SCIM server: it does not
expose `/scim/v2/Users` or `/scim/v2/Groups`, SCIM discovery, filtering, or bulk
protocol endpoints. Delete ingestion disables the projection without cascading
through role bindings.

SCIM provisioning is push-oriented: an IdP or provisioning agent acts as the
SCIM Client and sends lifecycle changes to the Service Provider. The adapter's
`refresh` operation means “apply this supplied change”; it does not poll an IdP.
A source-specific pull importer, when required, is a separate control-plane
connector or scheduled bridge and is not presented as SCIM. Its machine
credential and the SCIM Client credential are distinct, least-privilege
service identities and never participate in data-plane authorization.

JIT means insert when first observed and absent, not write on every request. To
avoid TTL-delayed Principal disablement or revocation, every authorization
request batch-loads the primary and Group Principals from the local repository
by `issuer + external_id` and checks their status. Authentication-account
disablement remains enforced by the IdP/Gateway and short access-token lifetime;
local Principal disablement and role-binding revocation fail closed immediately.

Keycloak can search users from configured LDAP/Active Directory federation
providers through its administration capabilities. That is a Keycloak feature,
not an OIDC feature: OIDC standardizes authentication and claims, but does not
define an API for globally searching an issuer's user population.
Keycloak groups, realm/client roles, client scopes, and protocol mappers remain
valid ways to emit coarse identity claims. Authguard discovers only stable
Principal identifiers and bounded display metadata; it does not copy those
objects into a second authorization-policy authority.

Federated search and SCIM ingestion are control-plane/provisioning functions.
The authorization data path resolves trusted identity references against the
local Principal repository and immutable policy snapshot; it MUST NOT call
Keycloak, LDAP, a SCIM server, or cloud IAM on each request.
`IAuthorizationCache` stores only short-lived opaque scope-token contexts. It
does not cache policies or Principals. Policy evaluation uses an immutable
in-process `PolicyRuntime` refreshed directly from durable storage by revision.

The protocol-neutral application boundary is deliberately named
`IPrincipalDiscovery<Input>`, not `IPrincipalDirectory` or
`IPrincipalSearcher`: directories are only one possible source, while discovery
also covers verified JIT identity and SCIM-subset lifecycle events. It is a generic,
strongly typed contract rather than one tagged request with unsupported modes:

```text
IPrincipalDiscovery<Input>
  provider() -> 'static str              -- JIT / SCIM / FED_KEYCLOAK / FED_LDAP / FED_CUSTOM
  Discover(input: Input) -> Output
  ResolvePrincipal(reference) -> Option<PrincipalProjection>

JitPrincipalDiscovery
  IPrincipalDiscovery<VerifiedOidcPrincipal> -> PrincipalProjection

KeycloakPrincipalDiscovery
  IPrincipalDiscovery<PrincipalSearchQuery> -> PrincipalSearchPage
  Keycloak Admin API connector, provider = FED_KEYCLOAK

LdapPrincipalDiscovery
  IPrincipalDiscovery<PrincipalSearchQuery> -> PrincipalSearchPage
  RFC 4511 connector, provider = FED_LDAP

CustomPrincipalDiscovery
  IPrincipalDiscovery<PrincipalSearchQuery> -> PrincipalSearchPage
  Configurable HTTP + bearer-JWT connector, provider = FED_CUSTOM
  request/response schema mapped in configuration for in-house systems

ScimPrincipalDiscovery
  IPrincipalDiscovery<ScimRefreshRequest> -> ScimProjectionEvent
  Refresh(input: ScimRefreshRequest) -> ScimProjectionEvent
```

Each implementation validates only its own input and produces a strongly typed
result containing the canonical `issuer`, `external_id`, `kind`, source
identifier, and bounded metadata needed to upsert `iam_principal`. Storage and
authorization handlers consume the normalized projection rather than any OIDC,
Keycloak, LDAP, custom HTTP, cloud-IAM, or SCIM payload. The control-plane flow is:

Source-level API documentation links the standards governing each implemented
boundary: JIT identity projection links OpenID Connect Core, the Keycloak
connector links Keycloak Admin/User Storage documentation, the LDAP connector
links RFC 4511 (protocol), RFC 4515 (filters), and RFC 2696 (paging), and SCIM
data normalization links RFC 7643 and RFC 7644. The custom connector has no
external standard to cite; it is the escape hatch for in-house systems (e.g. an
enterprise DSP directory) whose vendor API has no public protocol, mapped
through configurable URL/request/response bindings plus a pre-issued bearer JWT.
These links delimit protocol
responsibility; they neither claim a complete RFC 7644 server nor create a
data-plane dependency.

```text
GET  /adm/v1/principals
     -> search local projections
POST /adm/v1/principal-discovery/search
     -> federated search against the selected configured sources
POST /adm/v1/principal-discovery/materialize
     -> server-side re-resolution, then materialize the selected candidate
POST /adm/v1/principal-discovery/scim/refresh
     -> ingest one RFC 7643 User/Group subset upsert/delete change
POST /adm/v1/role-bindings
     -> bind the internal principal_id
```

External candidates never become binding targets directly. Materialization
produces the stable internal `principal_id` referenced by `iam_role_binding`.

### 4.4 Action

Action means "what to do" and uses dot-separated names, e.g:

```text
resource.read
resource.write
resource.delete
resource.access.manage
resource.run.trigger
resource.trace.read
domain.member.manage
platform.admin
```

The table is named `iam_action`, not `iam_permission`. Permission is the runtime
authorization result; action is the atomic operation that roles compose.

Resource targets are not encoded in action strings. They are resolved by
route/resource matchers and role bindings.

### 4.5 Role

Role is a collection of actions. Normal bindings SHOULD assign roles instead of
loose individual actions.

Recommended built-in roles:

| Role | Scope | Capability |
|---|---|---|
| owner | resource/domain | Full management, including access |
| maintainer | resource/domain | Manage resources, but not access owners |
| writer | resource | Modify resources and trigger execution |
| operator | resource | Execute, cancel, approve, but not modify definitions |
| reader | resource/domain | Read only |
| auditor | platform/domain | Read-only audit and evidence access |

### 4.6 Role binding

A role binding is one explicit authorization relation:

```text
principal
  has one role
  on resource_urn
  with effect ALLOW or DENY
  under optional conditions
```

One row binds exactly one Principal and one Role. Multiple roles require
multiple rows; this keeps revocation, uniqueness, evaluation, and audit simple.

### 4.7 Resource URN

A protected resource is any business object. IAM identifies resources with
Resource URNs.

The internal format follows the RFC 8141 URN syntax style:

```text
urn:iam:<partition>:<service>:<region>:<tenant>:<resource-path>
```

Segments:

| Segment | Meaning |
|---|---|
| `iam` | Internal URN namespace identifier |
| `partition` | Management partition or environment, such as `prod`, `staging`, `corp` |
| `service` | Business system or microservice, such as `customer-growth`, `collaboration` |
| `region` | Region; use `global` for non-regional resources |
| `tenant` | Stable isolation boundary such as tenant, organization, namespace, or account |
| `resource-path` | Business-defined path, recommended as `<type>/<id>[/<subtype>/<id>]` |

Examples:

```text
urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights
urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics
urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score
urn:iam:prod:collaboration:global:acme:channel/customer-support
urn:iam:prod:collaboration:global:acme:dataset/customer-faq
```

Wildcard pattern examples:

```text
urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*
urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/**
urn:iam:prod:collaboration:global:acme:channel/*
urn:iam:prod:*:global:*:**
```

v1 wildcard rules MUST remain predictable, compilable, and query-pushdown
friendly:

- Exact segments match exactly.
- `*` matches one colon segment or one resource-path segment.
- `**` is allowed only at the end of `resource-path` and matches a subtree.
- Arbitrary regex is not supported.
- Partial segment globbing such as `foo*bar` is not supported.

### 4.8 URN, ARN, and request tuples

ARN is the AWS resource naming convention. This design borrows the resource
locator idea but does not reuse the `arn:` prefix, because that would imply AWS
ARN compatibility.

RFC 8141 defines the outer URN syntax as `urn:<NID>:<NSS>`. This design uses
`iam` as an internal NID and defines fixed NSS segments. If public
cross-organization interoperability is required later, a formal NID registration
or explicit namespace compatibility statement is required.

Request tuples such as method, URI/path, query params, and path params are only
used by route/resource matchers:

```text
request tuple
  -> action
  -> resource URN
  -> parent resource URNs
```

They do not replace Resource URNs. The currently implemented source IP, method,
TLS, MFA, and trusted-claim constraints belong in role-binding `conditions`.

### 4.9 Why `parent_urns` exists

A request usually targets a leaf resource, but authorization is often granted on
a parent scope.

Examples:

```text
GitHub:             repo inherits from org
Customer growth:    job inherits from project and workspace
S3:                 object inherits from bucket or access point
```

If the matcher returned only the leaf Resource URN, an org/namespace/bucket
binding would require one of two bad designs:

- materialize bindings to every child resource;
- make the evaluator query business tables to discover parents.

Both break the goal of keeping IAM core independent from business data. Instead,
the route/resource matcher returns a deterministic chain:

```text
resource_urn = concrete leaf resource
parent_urns  = concrete parent resources, nearest first
```

Example:

```text
resource_urn = urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score
parent_urns  = [
  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics,
  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights
]
```

`parent_urns` MUST contain concrete URNs, not wildcard patterns. Wildcards belong
only in `iam_role_binding.resource_urn`. The evaluator checks the binding pattern against
`[resource_urn] + parent_urns`.

This keeps inheritance explicit, avoids binding expansion, and lets each business
service define its own parent chain without coupling IAM core to business
tables.

### 4.10 Why IAM core has no resource table

IAM core does not maintain an `iam_resource` table. Resource existence,
attributes, and lifecycle are owned by business tables, such as customer-growth
workspace/project/job tables or collaboration channel/dataset tables.

Reasons:

- Avoid dual-write inconsistency between IAM resource tables and business
  resource tables.
- Avoid binding IAM core to concrete business schemas.
- Avoid deleted resource leakage caused by stale IAM resource rows.
- Allow different services to protect different resource types with the same IAM
  model.

IAM stores only authorization targets:

```text
iam_role_binding.resource_urn
```

Resource search, authorization pickers, cross-service inventory, and offline
audit indexes remain owning-service or observability projections outside the
Authguard authorization schema. Their staleness MUST NOT affect authorization
correctness.

## 5. Data model

The normalized authorization schema intentionally contains six tables:

```text
iam_policy
iam_principal
iam_action
iam_role
iam_role_action
iam_role_binding
```

The schema is initialized by one numbered pair:
`migrations/001_init.ddl.sql` contains structural DDL and
`migrations/001_init.dml.sql` contains only initial singleton-policy data.
SQLite and PostgreSQL consume this same logical migration. The flat `model/`
package owns storage-independent authorization models and HTTP/gRPC DTOs;
persistence row mapping remains private to `storage/record.rs`. A storage row
is deliberately called a record rather than a business model.

External account directories, business resources, sessions, credentials,
resource inventories, and audit pipelines remain outside this core schema.

### 5.1 `iam_policy`

```text
id
name
description
revision
created_at
updated_at
```

v1 enforces exactly one `iam_policy` row with a database unique index. It is the
singleton aggregate root for the current authorization catalog, not a collection
of independent policies or a serialized snapshot table, and it does not duplicate normalized
role/action/binding data. `revision` is an optimistic concurrency token used by
control-plane updates and immutable `PolicyRuntime` publication. If historical versions
are required later, they belong in an append-only audit/event store rather than
another table in the hot authorization model.

### 5.2 `iam_principal`

```text
id
kind             -- USER / WORKLOAD / GROUP
issuer
external_id      -- OIDC sub or another provider-stable identifier
display_name
status
attributes
last_seen_at
created_at
updated_at
```

Constraints and boundaries:

- `unique(issuer, external_id)` is the external identity key across Authguard.
- For OIDC, use the verified `iss + sub`; never deduplicate by a bare `sub`,
  email, username, or display name.
- The row is an authorization projection only. It contains no password, token,
  session, MFA secret, or locally managed credential.
- `attributes` is bounded display/authorization metadata from a trusted
  discovery source. PostgreSQL uses JSONB and SQLite uses JSON-valid TEXT.
- JIT projection, a server-resolved federated candidate, and a SCIM-subset ingestion
  change all use the same idempotent upsert.
- Without SCIM, identities that never access Authguard and never receive a
  binding are not materialized. When SCIM is enabled, only changes accepted by
  the configured provisioning scope are projected; a full directory mirror is
  not required.

### 5.3 `iam_action`

`iam_action` stores action identifiers and HTTP route/resource matchers.

```text
policy_id
identifier      -- for example customer-growth.job.read
description
route_matchers  -- PostgreSQL JSONB array / SQLite validated JSON TEXT
```

Matcher element:

```json
{
  "id": "customer-growth-job-read",
  "methods": ["GET"],
  "hosts": ["growth.example.com"],
  "path": "/api/v1/customer-growth/jobs/{job_id}",
  "resource_urn": "urn:iam:prod:customer-growth:global:{tenant_id}:workspace/customer-insights/project/retention-analytics/job/{job_id}",
  "parent_urns": [
    "urn:iam:prod:customer-growth:global:{tenant_id}:workspace/customer-insights/project/retention-analytics",
    "urn:iam:prod:customer-growth:global:{tenant_id}:workspace/customer-insights"
  ]
}
```

Rules:

- `(policy_id, identifier)` is the primary key and identifies an action in the
  singleton policy.
- `route_matchers` contains all HTTP tuple-to-resource matchers protected by the action.
- A matcher has exactly `id`, `methods`, `hosts`, `path`, `resource_urn`, and
  `parent_urns` fields.
- `path` is a segment template: `{name}` captures one segment, `*` matches one
  segment, and a trailing `**` matches the remainder.
- `resource_urn` and `parent_urns` may reference path variables, `method`,
  `host`, and trusted identity claims. Missing variables or invalid generated
  URNs fail closed.
- `parent_urns` lists concrete parent Resource URNs used for inheritance checks.
- `route_matchers=[]` means the action is internal or role-composition only and does
  not directly match HTTP routes.

### 5.4 `iam_role`

```text
id
policy_id
name
description
```

`(policy_id, id)` is the primary key and `(policy_id, name)` is unique. Current
roles carry neither status nor built-in flags.

### 5.5 `iam_role_action`

```text
policy_id
role_id
action_identifier
```

Constraint:

```text
primary key (policy_id, role_id, action_identifier)
```

### 5.6 `iam_role_binding`

```text
policy_id
id
principal_id
role_id
effect                       -- ALLOW / DENY
resource_urn                 -- exact URN or limited wildcard expression
conditions                   -- PostgreSQL JSONB object / SQLite validated JSON TEXT
```

Constraints:

- The referenced Role belongs to `policy_id`; the Principal is a global external
  identity projection reusable across policies.
- One binding references exactly one Principal and one Role.
- `resource_urn` may be exact or use only the supported `*`/trailing `**`
  wildcard grammar.
- `(policy_id, id)` is the current database uniqueness boundary for bindings;
  the implementation does not claim content-based deduplication of otherwise
  equivalent bindings.
- Explicit DENY bindings take precedence over ALLOW bindings.

Group membership is not stored in a separate v1 table. A trusted authentication
context or `IPrincipalDiscovery` implementation may resolve external groups as
`GROUP` Principals, after which their role bindings use this same table. If
Authguard later owns local group membership, that is a separately versioned
capability rather than a nullable or self-referential addition to the six-table
core.

## 6. Authorization decision

### 6.1 Request algorithm

```text
1. Authn middleware verifies the caller.
2. Identity resolver derives the exact issuer + external_id pair.
3. A repository batch lookup by issuer + external_id resolves active
   iam_principal records, including GROUP Principals for trusted stable group
   IDs. Principals are never read from the authorization cache.
4. Route matcher finds action/resource_urn/parent_urns from `iam_action.route_matchers`.
5. Evaluator loads active iam_role_binding rows for those Principals.
6. Evaluator expands each binding's role through iam_role_action.
7. Evaluator checks action match.
8. Evaluator checks binding `resource_urn` against request `resource_urn` and `parent_urns`.
9. Evaluator checks `conditions`.
10. Explicit DENY wins.
11. Default deny.
12. Record bounded decision metrics and a tracing event.
```

### 6.2 Core pseudocode

Single-request authorization can be reduced to this pseudocode:

```text
function Authorize(request):
    identity = Authenticate(request)
    if identity is None:
        return DENY("unauthenticated")

    principals = ResolveRepositoryPrincipals(identity.issuer, identity.externalId,
                                             identity.stableGroupExternalIds)

    match = MatchAction(request.method, request.path, request.query)
    if match is None:
        return DENY("no matching protected action")

    resource_urns = [match.resource_urn] + match.parent_urns
    bindings = LoadActiveRoleBindings(principals)

    decision = DENY("default deny")

    for binding in bindings:
        if not AnyPatternMatches(binding.resource_urn, resource_urns):
            continue

        role_actions = ActionsOfRole(binding.role_id)
        if match.action not in role_actions:
            continue

        if not ConditionsMatch(binding.conditions, request, principals, match.resource_urn):
            continue

        if binding.effect == "DENY":
            return DENY("explicit deny", binding.id)

        decision = ALLOW("matched role binding", binding.id)

    return decision
```

This pseudocode intentionally does not read business resource tables. Business
handlers or Resource Adapters decide whether the resource exists. The evaluator
only decides whether the current principal may access the Resource URN if it
exists.

### 6.3 Effective role bindings

Effective authorization comes from:

```text
direct Principal role bindings
+ trusted GROUP Principal role bindings
```

Resource inheritance is not materialized as extra bindings. It is evaluated by
matching binding patterns against `resource_urn` and `parent_urns`.

### 6.4 Conditions

`conditions` expresses ABAC conditions, not resource identity.

Example:

```json
{
  "sourceIp": {
    "inCidr": ["10.0.0.0/8"],
    "notInCidr": ["10.20.0.0/16"]
  },
  "request": {
    "methods": ["GET", "POST"],
    "secureTransport": true
  },
  "subject": {
    "mfa": true,
    "claims": {"department": "growth"}
  }
}
```

Attribute sources:

- Source IP, request method, and transport scheme come from Envoy's
  `CheckRequest`.
- MFA and subject claims come from the verified identity token and explicitly
  configured trusted-claim mappings.

If a required condition attribute cannot be obtained reliably, the condition
does not match. Time-window and resource-tag/resource-attribute conditions are
not implemented currently.

## 7. Resource listing and Resource Adapters

Request interception answers "can this request execute". Enterprise systems
also need "which resources can the user see".

IAM does not list resources. The business service lists resources and compiles
IAM authorization scopes into its query.

### 7.1 Current SDK resource-mapping contract

Each business service defines a `ResourceSqlMapping` that maps URN segments to
its table columns. The four current SDKs validate the request action and compile
allow/deny URN expressions into a parameterized SQL scope:

```text
ResourceSqlMapping + RequestAccess(action, allow_urns, deny_urns)
  -> parameterized SQL predicate + arguments
```

Responsibilities:

- IAM core evaluates active `RoleBinding` values for the current Principal set
  and emits an action-specific `AuthorizationScope`.
- Resource Adapter understands business tables and compiles
  `urn` into query scopes.
- Business DB remains the source of truth for existence, attributes, and
  lifecycle.

Resource-listing pseudocode:

```text
function ListResources(principal, action, resourceType, filters):
    principals = ResolveLocalPrincipals(principal)
    bindings = LoadActiveRoleBindings(principals)

    allowed_patterns = []
    denied_patterns = []

    for binding in bindings:
        if action not in ActionsOfRole(binding.role_id):
            continue

        if not ConditionsMatchForList(binding.conditions, principals):
            continue

        if binding.effect == "DENY":
            denied_patterns.append(binding.resource_urn)
        else:
            allowed_patterns.append(binding.resource_urn)

    scope = ResourceAdapter(resourceType).CompileListScope(
        allow = allowed_patterns,
        deny  = denied_patterns,
        filters = filters
    )

    return BusinessDB.Query(resourceType, scope)
```

The key rule is that IAM emits an `AuthorizationScope` containing allow/deny
Resource URN expressions, while business adapters emit SQL predicates. IAM must
not scan business tables directly.

### 7.2 Enterprise customer growth job query example

Action-specific `AuthorizationScope` derived from effective role bindings:

```text
allow urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/**
allow urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/lifetime-value-forecasting/job/daily-customer-lifetime-value-forecast
deny  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit
```

The customer growth job Resource Adapter can compile this scope into:

```sql
WHERE
  tenant_id = 'example-corp'
  AND workspace_id = 'customer-insights'
  AND (
    project_id = 'retention-analytics'
    OR (
      project_id = 'lifetime-value-forecasting'
      AND job_id = 'daily-customer-lifetime-value-forecast'
    )
  )
  AND NOT (
    project_id = 'retention-analytics'
    AND job_id = 'vip-retention-risk-audit'
  )
```

This demonstrates a real team member combining project-wide access, one direct
job binding, and an explicit sensitive-job denial in the same list query.

### 7.3 Pattern pushdown limits

To support stable SQL pushdown, v1 role-binding `resource_urn` patterns support only:

```text
exact
*
trailing /*
trailing /**
```

Arbitrary regex is not supported. Otherwise evaluation degrades to full scan
plus application filtering, which is not acceptable for enterprise systems.

### 7.4 Consistency strategy

Business tables are the source of truth, so there is no dual-write consistency
problem between IAM resources and business resources.

Role-binding creation can use either strategy:

- Strong validation: call the business Resource Adapter before creating a role binding.
- Weak validation: allow bindings for future resources.

After a resource is deleted, bindings may be cleaned asynchronously. Lists come
from business tables, so deleted resources are not shown because a stale binding
exists. Requests still return not found from business handlers.

## 8. Authorization scenarios

### 8.1 Growth analysts read one workspace subtree

Role binding:

```text
iam_principal:growth-analysts (GROUP)
  -> bind reader
  -> urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/**
```

Request:

```text
GET /customer-growth/jobs
```

Matcher:

```text
action      = customer-growth.job.read
resource_urn = urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics
```

Decision:

```text
ALLOW
```

Reason: the binding pattern covers the job and the reader role contains
`customer-growth.job.read`.

### 8.2 A user has access to one customer-retention job

Role binding:

```text
iam_principal:revenue-analyst (USER)
  -> bind reader
  -> urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score
```

For a list request, the business repository pushes authorization scope and
business predicates into the same query:

```sql
WHERE tenant_id = 'example-corp'
  AND workspace_id = 'customer-insights'
  AND project_id = 'retention-analytics'
  AND job_id = 'daily-churn-risk-score'
```

The result contains only `daily-churn-risk-score`; membership in the same
workspace does not expose other jobs.

### 8.3 Read access cannot update a job

Role binding:

```text
iam_principal:growth-auditors (GROUP)
  -> bind reader
  -> urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/**
```

Request:

```text
PUT /customer-growth/jobs/1
```

Matcher:

```text
action = customer-growth.job.update
```

Decision:

```text
DENY
```

Reason: the reader role does not contain `customer-growth.job.update`, even though
the Resource URN matches.

### 8.4 Explicit DENY wins

Role bindings:

```text
iam_principal:growth-editors (GROUP)
  -> bind writer
  -> urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*

iam_principal:external-analyst (USER)
  -> bind DENY writer
  -> urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit
```

The Principal can update other jobs in the retention project, but cannot update
`vip-retention-risk-audit`.

### 8.5 A Workload Principal has an independent resource scope

An automation workload uses the `WORKLOAD` Principal kind and receives a
separate role binding with an exact read scope:

```text
allowed_actions = [customer-growth.job.read]
allowed_urns = [
  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/lifetime-value-forecasting/job/daily-customer-lifetime-value-forecast
]
```

The workload can read only that job and does not inherit extra permissions from
any human Principal. Credential issuance and secret storage remain the IdP's
responsibility.

### 8.6 Deleted resource with stale role binding

A role binding still exists:

```text
bind reader on urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/retired-cohort-job
```

But `retired-cohort-job` has been deleted from the business job table.

Result:

- list jobs does not show `retired-cohort-job`, because lists come from business tables.
- direct requests return not found.
- asynchronous cleanup may delete the stale binding, but the stale binding does not
  create privilege escalation.

### 8.7 GitHub-like organization and repository authorization

GitHub organization/repository access is hierarchical: an organization owns
repositories; teams or users receive repository roles; organization-level
settings can apply broad defaults. The same shape maps directly to this IAM
model.

```text
GitHub org       -> tenant/domain
GitHub team      -> iam_principal(kind=GROUP)
GitHub repo      -> Resource URN
GitHub repo role -> iam_role
```

Example URNs:

```text
urn:iam:prod:github:global:analytics-labs:org/analytics-labs
urn:iam:prod:github:global:analytics-labs:repo/analytics
urn:iam:prod:github:global:analytics-labs:repo/analytics-ui
```

Team role binding:

```text
iam_principal:platform-team (GROUP)
  -> bind maintainer
  -> urn:iam:prod:github:global:analytics-labs:repo/analytics
```

Organization-wide role binding:

```text
iam_principal:security-reviewers (GROUP)
  -> bind reader
  -> urn:iam:prod:github:global:analytics-labs:repo/*
```

List repositories compiles to:

```sql
WHERE org = 'analytics-labs'
  AND (
    repo = 'analytics'
    OR :has_all_org_repo_read = true
  )
```

This is the same model used for customer-growth analysis workspaces and jobs. The resource
names differ, but Principal/Role/RoleBinding/Action semantics do not.

### 8.8 AWS S3-style cross-region resource authorization

S3 is a different shape from GitHub: bucket names are global, object keys are
paths, access points can be regional, and Multi-Region Access Points provide a
global endpoint over buckets in multiple regions. The same URN model still
works because region and resource-path are first-class segments.

Bucket and object examples:

```text
urn:iam:prod:s3:global:111122223333:bucket/company-audit-logs
urn:iam:prod:s3:global:111122223333:bucket/company-audit-logs/object/2026/08/22/report.json
```

Regional access point:

```text
urn:iam:prod:s3:us-west-2:111122223333:access-point/audit-reader
urn:iam:prod:s3:us-west-2:111122223333:access-point/audit-reader/object/*
```

Multi-region access point:

```text
urn:iam:prod:s3:global:111122223333:multi-region-access-point/audit-global/object/*
```

Role binding:

```text
iam_principal:global-auditors (GROUP)
  -> bind reader
  -> urn:iam:prod:s3:*:111122223333:access-point/audit-reader/object/**
```

Condition:

```json
{
  "sourceIp": {"inCidr": ["10.0.0.0/8"]},
  "request": {"tls": true}
}
```

The important point is that region is just one URN segment. GitHub-like resources
can use `global`; S3-like resources can use concrete regions or `global` for
global endpoints. The evaluator remains unchanged.

## 9. Authentication boundary and identity input

Authguard does not implement OAuth/OIDC sessions, cookies, LDAP binds, or login
pages. Envoy Gateway's native OIDC filter handles the browser authorization-code
callback; Helm `redirectURL` is the public callback. LDAP, password, and other
sources should first be converted by an enterprise IdP into OIDC/JWT identity
that Envoy can verify.

```text
login or workload identity
  -> enterprise IdP / Keycloak issues an audience-restricted access token
  -> Envoy Gateway strictly validates issuer, audience, and local/remote JWKS
  -> forward the verified JWT to Authguard gRPC ext_authz
  -> Authguard extracts issuer + external_id(sub), groups, and trusted claims
  -> resolve local Principal projections and map action + Resource URN
  -> evaluate source IP, TLS, HTTP method, MFA, and claims
```

Authguard decodes claims from the trusted token but does not describe payload
decoding as signature verification. The production trust boundary must include
an Envoy authentication policy, cluster network isolation for the Authguard
Service, and no workload bypass around the Gateway. Login access tokens carry
stable identity and coarse claims, not large allow/deny URN lists; Authguard
computes resource permissions for each request to avoid oversized JWTs, delayed
revocation, and audience leakage.

OIDC Core requires the `iss + sub` combination when an application needs a
stable identifier. `sub` alone is only locally unique within one issuer. Authguard
therefore maps verified `iss` to `iam_principal.issuer` and verified `sub` to
`iam_principal.external_id`; email and username remain mutable display metadata.

Principal acquisition is deliberately sparse:

- Trusted JIT projection idempotently records a Principal after its first valid
  request. At Internet scale, this avoids importing tens or hundreds of millions
  of accounts that never receive an Authguard binding.
- Federated search lets an administrator pre-authorize a user, workload, or
  group that has not accessed the application. The protocol-neutral
  `KeycloakPrincipalDiscovery` / `LdapPrincipalDiscovery` /
  `CustomPrincipalDiscovery` connectors normalize source candidates, and
  Authguard re-resolves the selected candidate before insertion. The custom
  connector maps an in-house system's request/response schema in configuration
  and authenticates with a pre-issued bearer JWT.
- SCIM-subset ingestion accepts normalized RFC 7643 User/Group upsert/delete
  changes through `ScimPrincipalDiscovery`. It supports enterprise
  pre-provisioning and prompt disablement while remaining incremental and
  opt-in; it is not an RFC 7644 server.

Keycloak can federate LDAP/Active Directory and expose those users through its
administration search. Generic OIDC itself does not define an administrative
user-search protocol. Authguard also ships a direct LDAP connector and a
configurable HTTP/JWT custom connector for in-house systems; future
cloud-IAM connectors use the same boundary. Every connector is confined to the
control plane. Every runtime authorization request
loads local `iam_principal` state from the repository and uses an immutable
policy snapshot plus trusted token claims; an IdP or directory outage must not
enter the data-plane dependency chain. Principals are not stored in
`IAuthorizationCache`.

All three implementations use the generic `IPrincipalDiscovery<Input>` contract
and converge on the same `iam_principal` upsert. JIT projection targets 2C
Internet consumer authorization with on-demand materialization; federated
search and SCIM ingestion target 2B enterprise authorization for centrally
managed employees and workload/service accounts. JIT plus federated search
remains the minimal/default Internet deployment; enabling the implemented SCIM
adapter does not add SCIM or an external directory to the runtime authorization
path.

## 10. Workload access context

An allow decision creates a short-lived context carrying `policy_revision` and bound to the
Principal, action, and request resource. `auth.scope_delivery.direct_urn_limit`
selects exactly one delivery form:

- When allow plus deny count is less than or equal to the threshold, the gRPC `CheckResponse` overwrites
  `x-authguard-context` with versioned Base64URL JSON containing allow/deny URN
  expressions.
- Above the threshold, or when the direct header exceeds its size limit,
  Authguard stores the full context in the configured `IAuthorizationCache`
  with a short TTL and injects only an unpredictable `x-authguard-scope-token`;
  the workload adapter resolves it through Authguard `:8081` gRPC `ResolveScope`.

Every successful response first removes client-supplied `x-authguard-context`
and `x-authguard-scope-token` through gRPC `headers_to_remove`, then overwrites
exactly one result. Both headers present, expiration, unknown token, action
mismatch, or resolver failure must fail closed.

All SDKs expose the same `IAccessContextResolver` boundary:
`HeaderAccessContextResolver` decodes an Envoy-injected direct context, while
`GrpcAccessContextResolver` calls internal gRPC for a scope token. The
filter/interceptor owns only request lifecycle and framework glue. Repositories
combine action-aware Resource SQL mappings with business predicates for
list/get/update/delete; create evaluates the candidate Resource URN first.

Envoy `Authorization/Check` exclusively uses `:8080`, and workload
`ResolveScope` exclusively uses `:8081`. The default NetworkPolicy restricts
these ports independently using Envoy and `authguard.io/scope-client`
selectors; a workload cannot call the Envoy Check listener that issues direct
contexts or scope tokens.

Each Authguard replica evaluates policy against the immutable compiled snapshot
owned by `PolicyRuntime`. A background task refreshes it directly from the
durable repository by revision. A Redis Cluster deployment serves only as the
cross-replica scope-token store; scope-token cache misses or failures fail
closed. Policies and Principals are never stored in the Memory/Redis cache.

## 11. Control-plane credential and initial policy

`/adm/v1/**` uses a distinct Bearer credential injected from a Kubernetes Secret
as `AUTHGUARD__AUTH__ADMIN_TOKEN`. The control plane is disabled when it is
absent. `GET|PUT /adm/v1/policy` reads or atomically replaces the singleton
policy aggregate; actions, roles, and role bindings expose collection/resource
CRUD. Principal APIs list/read local projections, update status, and delete an
unreferenced projection safely. Separate Principal discovery APIs provide
federated search, server-side materialization, and SCIM-subset ingestion. A policy mutation validates the complete
aggregate, persists it through SQLite or PostgreSQL, and only then atomically
publishes the immutable in-memory revision. Failure
at either stage leaves the active snapshot unchanged. Replicas synchronize by
repository revision while every hot authorization path reads only its immutable L1
snapshot. Multi-replica production uses PostgreSQL plus Redis Cluster. Workload
OIDC/JWT credentials must not be reused for control-plane access.

## 12. Example of [Flowgent](https://github.com/flowgent-labs/flowgent)

| Flowgent concept | Generic IAM concept |
|---|---|
| namespace | tenant / resource domain |
| agent flow | protected resource |
| flow run / task / trace | child resource or execution evidence under agent-flow |
| LLM provider / MCP / skill / notification channel | other protected resources |

Route matcher example:

```json
{
  "id": "flow-run-trace-read",
  "methods": ["GET"],
  "hosts": [],
  "path": "/api/v1/{namespace}/flows/{flow}/runs/{run}/trace",
  "resource_urn": "urn:iam:prod:flowgent:global:{namespace}:agent-flow/{flow}/run/{run}",
  "parent_urns": [
    "urn:iam:prod:flowgent:global:{namespace}:agent-flow/{flow}",
    "urn:iam:prod:flowgent:global:{namespace}:namespace/{namespace}",
    "urn:iam:prod:flowgent:global:platform:platform/root"
  ]
}
```

`agent-flow` is only an example protected resource type. It is not built into
the IAM model.

## 13. Example of [Sigbot](https://github.com/sigbot-projects/sigbot-core) integration

| Sigbot concept | Generic IAM concept |
|---|---|
| organization / team | tenant / resource domain |
| bot | protected resource |
| skill / tool / channel / memory | protected resource or bot child resource |
| conversation / evidence | evidence resource under bot or channel |

Examples:

```text
urn:iam:prod:sigbot:global:strategy:bot/customer-support
urn:iam:prod:sigbot:global:strategy:bot/customer-support/memory/customer-faq
urn:iam:prod:sigbot:global:strategy:channel/slack-main
```

## 14. Module boundaries

### 14.1 Authguard Rust workspace

`route/authorization.rs` depends on the narrow `IAuthorizationHandler`
interface. `DefaultAuthorizationHandler` owns ACL evaluation and access-context
delivery; `PolicyHandler` owns policy use cases and durable synchronization,
while `PolicyRuntime` owns the compiled immutable snapshot. There is no
duplicate authorization service layer.

```text
core/route   -- Envoy authorization gRPC and management HTTP protocol adapters
core/handler/authorization.rs -- ACL evaluation and request-access delivery
core/handler/policy.rs        -- policy compilation, immutable runtime, policy CRUD
core/handler/principal.rs     -- Principal projection/discovery use cases
core/handler/management.rs    -- health, readiness, status, and metrics use cases
core/storage -- SQLite/PostgreSQL policy persistence
core/cache   -- Memory/Redis opaque scope-token context cache
core/config  -- authguard.yaml loading, environment overrides, validation
core/model        -- storage-independent authorization models, SQL scopes, and transport DTOs
core/principal/mod.rs        -- discovery models, traits, and errors
core/principal/jit.rs        -- trusted OIDC JIT projection
core/principal/federation/   -- Keycloak, LDAP, and custom HTTP/JWT federated search connectors
core/principal/scim.rs       -- RFC 7643 User/Group subset ingestion
core/storage/record.rs       -- private SQLite/PostgreSQL row records
core/utils        -- identity parsing, HTTP tuple-to-URN mapping, OTel, metrics
core/migrations/001_init.ddl.sql -- authorization schema DDL
core/migrations/001_init.dml.sql -- initial singleton-policy DML
```

### 14.2 Language adapters

```text
adapters/rust    -- Rust SDK and SQL scope helpers
adapters/golang  -- Go SDK and SQL scope helpers
adapters/python  -- Python SDK and SQL scope helpers
adapters/java    -- Java/Spring SDK and SQL scope helpers
```

### 14.3 Business service use cases

```text
use-cases/customer-growth-job-service/e2e/deploy/rust-sqlx-service
use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service
use-cases/customer-growth-job-service/e2e/deploy/python-sqlalchemy-service
use-cases/customer-growth-job-service/e2e/deploy/springboot-jdbc-service
use-cases/customer-growth-job-service/e2e/deploy/springboot-jpa-service
```

Shared across languages:

- Resource URN grammar.
- Action identifier naming.
- `iam_action.route_matchers` JSON schema.
- Role-binding evaluation algorithm.
- Auth context API contract.
- Golden test fixtures.

## 15. Security principles

1. Default deny.
2. DENY takes precedence over ALLOW.
3. External identities are authorized only through their local Principal projection.
4. Browser JavaScript does not read HttpOnly JWTs.
5. OIDC identities are keyed by verified `iss + sub`, never by mutable profile fields.
6. Principal status is checked from the repository on every request; cache TTL
   must not delay disablement or revocation.
7. Secrets do not enter IAM audit metadata.
8. Role bindings are explicitly created, updated, and deleted through revision-safe control-plane APIs.
9. Federated identity search and SCIM-subset ingestion never participate in a
   data-plane decision.
10. UI authorization is experience only; middleware/gateway is the security boundary.
11. Business tables own resource truth; IAM core does not maintain a core resource table.
12. Current decisions emit bounded metrics and tracing; a durable audit event
    store is a follow-up capability.

## 16. References

- RFC 8141: Uniform Resource Names (URNs): <https://www.rfc-editor.org/rfc/rfc8141.html>
- OpenID Connect Core 1.0, `iss` and `sub`: <https://openid.net/specs/openid-connect-core-1_0.html>
- Keycloak Server Administration Guide, user federation: <https://www.keycloak.org/docs/latest/server_admin/>
- Keycloak Admin REST API, user search: <https://www.keycloak.org/docs-api/latest/rest-api/index.html>
- Keycloak Server Developer Guide, User Storage SPI: <https://www.keycloak.org/docs/latest/server_development/index.html>
- RFC 4511: Lightweight Directory Access Protocol (LDAP): <https://www.rfc-editor.org/rfc/rfc4511.html>
- RFC 7643: SCIM Core Schema: <https://www.rfc-editor.org/rfc/rfc7643.html>
- RFC 7644: SCIM Protocol: <https://www.rfc-editor.org/rfc/rfc7644.html>
- AWS IAM Amazon Resource Names (ARNs): <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html>
- GitHub repository roles for an organization: <https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization>
- Amazon S3 IAM resource types and policy resources: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/security_iam_service-with-iam.html>
