# AuthGuard

AuthGuard is a standalone, unified, high-performance authentication and resource-authorization product with first-class Envoy Gateway integration.

Its default runtime consists of exactly three components:

```text
Envoy Gateway
authguard-authn
authguard-authz
```

Envoy owns the edge and acts as the PEP. AuthN authenticates and normalizes external identities, including account linking. AuthZ authorizes one stable canonical Principal. External IdPs remain external.

Keycloak is supported as an optional enterprise IdP and Principal-discovery integration, but is never required or deployed by the AuthGuard chart. AuthGuard introduces no Kubernetes CRD/Controller and does not implement OAuth login in Lua or Wasm.

## Modules

```text
src/authn/       authguard-authn
  provider/      OAuth/OAuth-like adapter and minimal Provider SPI
  principal/jit.rs  policy-gated identity binding/JIT Principal resolution
  route/         authentication entry points
  handler/       authentication flow orchestration
  server.rs      process initialization and listener lifecycle

src/common/      authguard-common
  config/        one AppConfig model/singleton; YAML plus nested env overrides
  model/         principal.rs, identity.rs, role.rs, policy.rs
  storage/       entity-neutral DB bases plus one aggregate repo per service/DB
  principal/     common discovery contract and HTTP directory connector
  route/         shared management endpoints
  apm/cache/utils
                 shared observability, cache, access-context and matcher utilities

src/authz/        authguard-authz
  handler/       authorization management and Envoy ext_authz orchestration
  route/         authorization management and Envoy ext_authz entry points
  principal/     optional control-plane Keycloak/LDAP/SCIM discovery
  server.rs      AuthZ process initialization and listeners

src/adapters/    workload access-context SDKs
use-cases/       cross-language business-service E2E examples
deploy/          Envoy Gateway + AuthN + AuthZ Helm deployment
migrations/      the single authoritative IAM schema for both services
```

The Rust package names are `authguard-authn`, `authguard-authz`, and
`authguard-common`. Both services and the Rust workload SDK depend inward on
`common`; AuthN and AuthZ never depend on each other.

Configuration precedence is `defaults < authguard.yaml < environment`.
Any nested property can be overridden with a double-underscore path, such as
`AUTHGUARD__AUTHN__SESSION__AUDIENCE` or
`AUTHGUARD__STORAGE__POSTGRES__MAX_CONNECTIONS`.

## Identity model

An external identity is not a Principal:

```text
ExternalIdentity(provider, issuer, subject, claims)
  -> Account Linking / iam_principal_identity
  -> Principal(internal stable principal_id, kind, status)
```

One Principal can bind multiple external identities. `(provider, issuer, subject)` is globally unique in the identity-binding table, while every AuthZ RoleBinding references only `principal_id`.

AuthN emits:

```text
AuthenticatedPrincipalContext {
  principalId
  kind
  stableGroupIds
  trustedClaims
  acr
  amr
}
```

AuthZ rejects unknown or disabled canonical Principals and never JIT-creates one from `iss/sub`. GitHub IDs, WeChat openid/unionid, DSP tokens, OAuth codes, and Provider access tokens never enter AuthZ.

## Configuration

Both services read the same [`etc/authguard.yaml`](etc/authguard.yaml). Each process deserializes only the section it owns; there is no second AuthN configuration file.

Provider YAML describes protocol mechanics only. Account governance is centralized:

```yaml
authn:
  providers:
    github:
      type: oauth2
      issuer: https://github.com
      authorization:
        endpoint: https://github.com/login/oauth/authorize
        scopes: [read:user, user:email]
      token:
        endpoint: https://github.com/login/oauth/access_token
        method: POST
      identity:
        endpoint: https://api.github.com/user
        subject: $.id
        username: $.login
        email: $.email

    corporate-dsp:
      type: custom
      adapter: corporate-dsp
      issuer: https://dsp.example.com

  accountLinking:
    strategy: explicit
    authoritativeProviders: [corporate-dsp]
    allowLink:
      corporate-dsp: [github, wechat]
```

The default strategy is `explicit`; equal email addresses never cause automatic linking. Internet deployments may explicitly choose `first-login`.

AuthZ reads its canonical identity claims from the same file:

```yaml
authz:
  identity:
    token_header: authorization
    principal_id_claim: principal_id
    principal_kind_claim: principal_kind
    groups_claim: authguard_group_ids
```

## Request path

The normal hot path is:

```text
client -> Envoy Gateway jwt_authn -> authguard-authz ext_authz -> business service
```

Standard OIDC should prefer Envoy Gateway native OIDC/JWT support. AuthN maps the verified external identity to a canonical Principal at login/session establishment. GitHub, WeChat, and proprietary DSP callback/token/identity differences remain in AuthN behind Envoy.

An allowed AuthZ response carries exactly one authorization-scope form:

- `x-authguard-context`: a short-lived HMAC-SHA256-signed direct context; or
- `x-authguard-scope-token`: a short-lived opaque token resolved through `authguard.access.v1.AccessContextService/ResolveScope`.

The optional `authz.resign_token` replaces the upstream authorization header with an AuthZ-signed RS256 JWT whose `sub` and `principal_id` are the canonical Principal ID. Provider subject values are not reintroduced.

## Run

Run both services against the same configuration:

```bash
AUTHGUARD_CONFIG_FILE=etc/authguard.yaml \
cargo run -p authguard-authn --bin authguard-authn

AUTHGUARD_CONFIG_FILE=etc/authguard.yaml \
cargo run -p authguard-authz --bin authguard-authz
```

The AuthZ defaults use SQLite and an in-memory scope-token cache for local development. Use PostgreSQL and Redis for multi-replica deployments.

Install the default Envoy Gateway + AuthN + AuthZ topology:

```bash
helm upgrade --install authguard deploy/helm/authguard \
  --namespace authguard \
  --create-namespace
```

The chart mounts one `authguard.yaml` ConfigMap into both AuthN and AuthZ. Existing Envoy Gateway installations can set `envoy_gateway.enabled=false` while retaining AuthGuard integration.

## Verify

Before Rust builds, confirm `target/` is below 10 GiB; clean it first if necessary.

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
```

The repository also contains Helm rendering checks and portable/k3s cross-language E2E scenarios under [`use-cases/customer-growth-job-service`](use-cases/customer-growth-job-service/README.md).

See the [architecture overview](docs/architecture/overview.md) and [full whitepaper](docs/architecture/iam-authorization-whitepaper.md).
