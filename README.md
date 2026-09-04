# Authguard

Authguard is a standalone, high-performance Resource URN authorization service
designed for deep Envoy Gateway integration. Envoy owns ingress, OIDC/JWT
authentication, routing, and traffic policy; Authguard provides external
authorization decisions and a separate IAM control plane.

The URN model covers S3-style bucket/object/path scopes and GitHub-style
organization/repository/team collaboration without coupling authorization to a
business domain. It is particularly useful when multiple users, workloads, or
systems collaborate with different roles over different resource scopes.

## Structure

```text
src/core/src/
  server.rs              process and listener lifecycle
  route/                 Envoy gRPC and management HTTP protocol adapters
  handler/
    authorization.rs     ACL evaluation and request-access delivery
    policy.rs            policy compilation, immutable runtime, and policy CRUD
    principal.rs         Principal projection/discovery use cases
    management.rs        health, readiness, status, and metrics use cases
  config/                authguard.yaml loading and validation
  model/                 authorization models, SQL-scope semantics, and transport DTOs
  principal/
    mod.rs               shared discovery models, traits, and errors
    jit.rs               trusted OIDC just-in-time projection
    federation/
      mod.rs             protocol-neutral federated search composition
      keycloak.rs        Keycloak Admin API connector
      ldap.rs            direct RFC 4511 LDAP connector
    scim.rs              RFC 7643 User/Group subset ingestion
  storage/               SQLite/PostgreSQL repositories and private row records
  cache/                 Memory/Redis opaque scope-token context cache
  utils/                 identity parsing, HTTP tuple mapping, OTel, and metrics
src/core/migrations/
  001_init.ddl.sql       portable authorization schema DDL
  001_init.dml.sql       initial singleton-policy DML
src/adapters/             Rust, Go, Python, and Java client SDKs
use-cases/                enterprise customer-growth-job E2E services
deploy/                   image, Helm, and observability assets
etc/authguard.yaml        canonical service configuration
```

Rust models are not database row entities. The flat `model/` package owns all
storage-independent authorization semantics and transport DTOs, while the
persistence-only row shape remains private to `storage/record.rs`. SQLite and
PostgreSQL share the same numbered DDL/DML migration pair.

`src/gateway` and `src/common` are intentionally absent. Authguard ships one
Rust service image; gateway features remain in Envoy Gateway, while service
runtime utilities remain cohesive inside core.

## Service contracts

- `envoy.service.auth.v3.Authorization/Check`: Envoy Gateway gRPC extAuth.
- Port `8080` is reserved for the Envoy Check service; workload SDKs cannot use it.
- Port `8081` serves only `authguard.access.v1.AccessContextService/ResolveScope`.
- `GET|PUT /adm/v1/policy`: read or atomically replace the singleton policy aggregate.
- `GET|POST /adm/v1/actions` and `GET|PUT|DELETE /adm/v1/actions/{action_id}`.
- `GET|POST /adm/v1/roles` and `GET|PUT|DELETE /adm/v1/roles/{role_id}`.
- `GET|POST /adm/v1/role-bindings` and
  `GET|PUT|DELETE /adm/v1/role-bindings/{binding_id}`.
- `GET /adm/v1/principals` and
  `GET|PATCH|DELETE /adm/v1/principals/{principal_id}` for local projections.
- `POST /adm/v1/principal-discovery/search`,
  `POST /adm/v1/principal-discovery/materialize`, and
  `POST /adm/v1/principal-discovery/scim/refresh`; the latter ingests an RFC
  7643 User/Group subset and is not a complete RFC 7644 server.
- `POST /adm/v1/authorize`: explicit URN decision for administration/debugging.
- `GET /adm/v1/status`: policy and service status.
- Management listener: `/healthz`, `/readyz`, and `/metrics`.

An allowed extAuth response carries exactly one request-scoped authorization
result:

- `x-authguard-context`: a small HMAC-SHA256-signed compact context
  (`agctx1.<payload>.<signature>`) containing the current action and allow/deny
  Resource URNs; or
- `x-authguard-scope-token`: a short-lived opaque token when the complete scope
  would make an unsafe HTTP header. The SDK resolves it through Authguard's
  `authguard.access.v1.AccessContextService/ResolveScope` gRPC method.

SDK filters never reinterpret the login JWT as an AuthorizationScope. Configure
the reusable token resolver connection with:

```bash
AUTHGUARD_GRPC_TARGET=authguard.authguard.svc.cluster.local:8081
AUTHGUARD_GRPC_TLS=false
```

`AUTHGUARD_GRPC_TARGET` is a gRPC target rather than an HTTP base URL. A
`dns:///host:port` target is also accepted. Direct contexts remain zero-network;
missing, conflicting, expired, or unresolvable contexts fail closed.
Direct contexts are accepted only after their HMAC signature is verified. Set
the same high-entropy key (at least 32 bytes) on Authguard and each workload as
`AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY`; unsigned, tampered, or wrong-key contexts
fail closed. Helm can generate/reuse this key or reference an existing Secret
through `authguard.accessContext.existingSecret` and `authguard.accessContext.key`.
The Helm NetworkPolicy admits `8080` from Envoy and admits `8081` only from
namespaces/pods selected as `authguard.io/scope-client`.

The top-level `cache` configuration has `Memory` and `Redis` providers. The
canonical local [`authguard.yaml`](etc/authguard.yaml) defaults to Memory for a
zero-dependency startup. Helm defaults to Redis Cluster only for opaque
scope-token contexts shared across Authguard replicas. Authorization decisions
use an immutable compiled in-process policy snapshot refreshed by revision from
SQLite/PostgreSQL. Principal status is loaded from the repository on every
request; neither policies nor Principals are stored in `IAuthorizationCache`.

The identity ingress accepts only the configured JWT token header after Envoy
has verified issuer, audience, signature, and expiry. JWT mode forwards the
Bearer token; OIDC mode forwards Envoy's verified ID token. Authguard decodes
claims from that verified token and never trusts separate client-controlled
issuer, subject, group, or MFA claim headers.

## Run

The embedded defaults load [`etc/authguard.yaml`](etc/authguard.yaml), persist
policies in SQLite, and initialize a default-deny snapshot when storage is empty:

```bash
cargo run -p authguard-core --bin authguard
```

Use environment overrides for containers or local development:

```bash
AUTHGUARD__STORAGE__SQLITE__URL=sqlite:///tmp/authguard.db \
AUTHGUARD__AUTH__ADMIN_TOKEN=local-admin-token \
cargo run -p authguard-core --bin authguard
```

Install Authguard with Envoy Gateway:

```bash
helm upgrade --install authguard deploy/helm/authguard \
  --namespace authguard \
  --create-namespace
```

The repository vendors the official Envoy Gateway and Redis Cluster charts, and
the default values use the required Aliyun images. Existing Envoy Gateway
clusters reuse their controller with `--set envoy-gateway.enabled=false`; the
independent `authguardIntegration.enabled` switch still applies gRPC ext_auth.

## Verification

```bash
make test
```

The matrix covers the Rust service, Helm rendering, and four adapters. Each SDK
runs the same `22` access/filter/resolver plus `24` codec/URN/SQL scenarios
(`46` total). The portable
five-project business E2E suite is available through
`make e2e`; see
[`use-cases/customer-growth-job-service`](use-cases/customer-growth-job-service/README.md).
The real k3s path is `make e2e-k3s`; it deploys all five services against one
PostgreSQL instance with five isolated `e2e_` schemas.

Architecture references:

- [`docs/index.md`](docs/index.md)
- [`docs/index_ZH.md`](docs/index_ZH.md)
- [`docs/architecture/iam-authorization-whitepaper.md`](docs/architecture/iam-authorization-whitepaper.md)
- [`docs/architecture/iam-authorization-whitepaper_ZH.md`](docs/architecture/iam-authorization-whitepaper_ZH.md)
