# AuthGuard: Unified Authentication and Resource Authorization Architecture

## 1. Product position

AuthGuard is a standalone, unified, general-purpose, high-performance authentication and authorization product for enterprise and internet systems. It integrates directly with Envoy Gateway and is organized around two core modules:

- `authguard-authn`: authentication, external identity normalization, and account linking;
- `authguard-authz`: resource authorization for stable canonical Principals.

The default runtime topology is:

```text
Envoy Gateway
authguard-authn
authguard-authz
```

Keycloak, Entra, Okta, GitHub, WeChat, and corporate DSP platforms remain external identity systems. They are supported integrations, not AuthGuard runtime dependencies.

> Envoy owns the edge. AuthGuard AuthN authenticates and normalizes external identities, including account linking. AuthGuard AuthZ authorizes one stable canonical Principal. External IdPs remain external.

## 2. Non-goals

This architecture does not introduce:

- a required or default Keycloak deployment;
- AuthGuard Kubernetes CRDs, Controllers, or Operators;
- OAuth login protocols implemented in Lua or Wasm;
- Envoy patches for GitHub, WeChat, or other providers;
- a complex authentication DSL;
- provider-specific login code in AuthZ;
- unsafe email-based automatic account linking.

AuthGuard also does not replace Envoy Gateway or copy business resources into its IAM database.

## 3. Component responsibilities

### 3.1 Envoy Gateway: edge and **PEP(Policy Enforcement Point)**

Envoy Gateway owns the common entry point for Biz UI login requests, callbacks, and business traffic. It owns TLS, routing, traffic policy, canonical JWT verification, and the hot-path `jwt_authn -> ext_authz(authguard-authz)` chain.

For requests carrying an AuthN-issued canonical session/token, Envoy verifies signature, issuer, audience, and lifetime before forwarding the trusted token to AuthZ. AuthZ does not implement OAuth protocols or repeat provider authentication.

Standard OIDC authorization redirects, callbacks, discovery, token exchange, ID Token verification, and optional UserInfo run in AuthN, exactly like OAuth2-like and proprietary Provider flows. Envoy never receives provider authorization codes or provider tokens; it verifies only AuthN-issued canonical JWTs on business routes.

### 3.2 authguard-authn

AuthN is a lightweight Rust Authentication / Identity Provider Adapter Engine. It owns:

- authorize request construction;
- callback, state, PKCE, and login-session boundaries;
- authorization-code token exchange;
- optional identity/userinfo lookup;
- stable subject extraction;
- claims normalization;
- `ExternalIdentity` creation;
- identity binding lookup and account linking;
- canonical Principal Context output.

The bounded configuration model covers common provider differences:

- GET or POST token exchange;
- client credentials in header, body, or query;
- different token response shapes;
- `sub`, GitHub `id`, WeChat `unionid/openid`, or a corporate employee ID;
- optional identity APIs;
- simple JSON field-path extraction;
- corporate DSP token translation.

Configuration is preferred. A minimal Provider SPI handles protocols that cannot be expressed cleanly in YAML.

### 3.3 authguard-authz

AuthZ owns only authorization concerns:

- canonical Principal materialization and status;
- `USER`, `WORKLOAD`, and `GROUP`;
- RoleBinding, Role, and Action;
- Resource URNs and parent resources;
- conditions and ALLOW/DENY evaluation;
- Authorization Scope and trusted workload access context;
- optional control-plane Principal federation/discovery integrations.

AuthZ never processes OAuth callbacks, passwords, LDAP login binds, GitHub `/user`, WeChat userinfo, DSP tokens, provider access tokens, authorization codes, login sessions, or account linking.

LDAP, Keycloak, and custom directory connectors pull candidates when an administrator pre-authorizes a Principal; SCIM complements them by pushing later employee and group lifecycle changes through `/scim/v2/Users` and `/scim/v2/Groups` into the same canonical Principal projection. Neither direction participates in the AuthZ hot path. SCIM is HTTP provisioning, not a WebSocket or long-poll channel; an upstream that cannot push must use an external reconciliation connector rather than an AuthZ refresh scheduler.

## 4. Principal is not an external identity

```text
ExternalIdentity
----------------
provider
issuer
subject
claims
        │
        │ account linking / identity binding
        ▼
Principal
---------
internal stable principal_id
USER / WORKLOAD / GROUP
status
authorization state
```

An `ExternalIdentity` is the normalized result of provider authentication. A `Principal` is an AuthGuard-owned stable authorization subject. They are separate objects.

One Principal can have multiple login identities:

```text
                 Principal P123
                       ▲
             ┌─────────┴─────────┐
             │                   │
Corporate DSP identity      GitHub identity
sub=EMP00123               id=987654
```

Every AuthZ `RoleBinding.principal_id` references `P123`, never a GitHub ID, WeChat openid/unionid, DSP subject, email, or username.

### 4.1 Persistence model

```sql
iam_principal
  id
  kind
  display_name
  status
  authorization_state

iam_principal_identity
  principal_id
  provider
  issuer
  subject
  claims
```

The identity table enforces:

```text
UNIQUE(provider, issuer, subject)
```

One external identity cannot be bound to multiple Principals, while one Principal may have many identities. AuthN owns `iam_principal_identity`; AuthZ consumes or projects only the canonical Principal ID.

### 4.2 Canonical AuthN output

Every identity source must become:

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

`stableGroupIds` contains internal Group Principal IDs, not provider group names. Provider IDs, provider subjects, access/refresh tokens, authorization codes, and raw token responses never enter AuthZ.

## 5. Provider configuration

`authguard-authn` and `authguard-authz` read one shared `authguard.yaml`. The
`authn` root section is owned by AuthN; authorization/runtime sections are owned
by AuthZ. Each process deserializes only its boundary, so sharing the file does
not create a crate dependency. There is no separate AuthN YAML.

A Provider entry answers only:

1. How do I authenticate?
2. How do I obtain a stable external identity?

```yaml
authn:
  providers:
    corporate-oidc:
      type: oidc
      issuer: https://sso.example.com/realms/corporate
      clientId: authguard
      clientSecret: ${AUTHGUARD_CORPORATE_OIDC_CLIENT_SECRET}
      callbackUrl: https://app.example.com/auth/v1/providers/corporate-oidc/callback
      scopes: [openid, profile, email]
      userinfo: true
      # Optional RFC 7662 path for WORKLOAD bearer-token translation. Browser
      # Authorization Code login still validates its signed ID Token + nonce.
      tokenIntrospection:
        endpoint: https://sso.example.com/realms/corporate/protocol/openid-connect/token/introspect
        acceptedAudiences: [customer-growth-job-service]
      identity:
        subject: $.sub
        username: $.preferred_username
        email: $.email

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

    wechat:
      type: oauth2-like
      issuer: https://open.weixin.qq.com
      authorization:
        endpoint: https://open.weixin.qq.com/connect/qrconnect
        scopes: [snsapi_login]
      token:
        endpoint: https://api.weixin.qq.com/sns/oauth2/access_token
        method: GET
        query:
          appid: ${clientId}
          secret: ${clientSecret}
          code: ${authorizationCode}
      identity:
        subject: $.unionid
        fallbackSubject: $.openid

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

Simple field paths such as `$.data.user.id` are supported. Conditional expressions, functions, scripts, and a general-purpose DSL are intentionally excluded.

Provider entries must not declare `authoritative`, `secondary`, `canCreatePrincipal`, or `canLink`. Account governance belongs only to `accountLinking`.

For `type: oidc`, browser login uses discovery, Authorization Code + PKCE,
nonce-bound ID Token verification, and optional UserInfo. UserInfo is not an ID
Token. A WORKLOAD token-exchange request uses RFC 7662 introspection when
`tokenIntrospection` is configured and requires an exact issuer plus one
explicitly accepted audience; AuthN never treats an unverified JWT payload as
identity.

### 5.1 Minimal Provider SPI

The custom SPI has one core responsibility:

```rust
async fn authenticate(callback: ProviderCallback) -> Result<ExternalIdentity, ProviderError>;
```

A custom adapter may implement corporate signatures, token translation, or proprietary endpoints, but it must still return `ExternalIdentity`. It cannot write authorization policy or pass provider tokens into AuthZ.

## 6. Account linking

The secure default is:

```yaml
accountLinking:
  strategy: explicit
```

Equal email addresses never cause automatic linking. Email is profile or human-verification metadata, not an identity key.

Recommended enterprise flow:

```text
first Corporate DSP login
  -> create Principal P123
  -> bind DSP identity to P123

authenticated P123 session
  -> user explicitly links GitHub
  -> authenticate GitHub
  -> bind GitHub identity to P123

later GitHub login
  -> lookup GitHub identity binding
  -> P123
  -> AuthZ
```

An unbound secondary-provider login must require authoritative-provider confirmation instead of creating a second Principal. `accountLinking.strategy` supports `explicit` (the secure default) and `first-login`. In `first-login`, any previously unbound `(provider, issuer, subject)` creates one Principal and binding, which fits 2C signup. It does not infer that identities from different Providers belong to the same human and never links by email; additional login methods still require an authenticated explicit-link flow.

Principal creation and the first identity binding must be transactional. `UNIQUE(provider, issuer, subject)` prevents concurrent double binding; conflicts fail closed.

## 7. Protocol semantics

### 7.1 GitHub OAuth is not OIDC

GitHub OAuth commonly returns an access token and requires the GitHub user API to obtain identity. AuthGuard must not assume an OIDC ID Token or parse an OIDC `sub` from the access token.

### 7.2 ID Token is not UserInfo

- ID Token: OIDC authentication-event claims for the OIDC Client;
- Access Token: credential for a resource API;
- UserInfo: optional OIDC endpoint called with an access token;
- provider identity API: for example GitHub `/user`, which does not become OIDC UserInfo merely because it returns user data.

AuthN selects the correct source, extracts a stable subject, and normalizes immediately. AuthZ is unaware of the distinction.

## 8. Typical flows

### 8.1 Standard OIDC

```text
Enterprise OIDC / Keycloak / Entra
  -> Envoy Gateway -> authguard-authn authorize/callback
  -> OIDC discovery / code exchange / ID Token verification / optional UserInfo
  -> ExternalIdentity -> binding lookup
  -> canonical session/token
  -> Envoy jwt_authn
  -> authguard-authz ext_authz
  -> Biz Service
```

For non-browser workloads, AuthN may normalize an external enterprise bearer
through its bounded token-translation endpoint and then issue the same
canonical Principal token. The external token never enters AuthZ.

### 8.2 GitHub / WeChat

```text
GitHub / WeChat
  -> Envoy Gateway
  -> authguard-authn callback / token exchange / identity lookup
  -> ExternalIdentity
  -> Account Linking
  -> Canonical Principal Context
  -> Envoy jwt_authn -> authguard-authz
```

### 8.3 Corporate DSP

```text
Corporate DSP
  -> Envoy Gateway
  -> authguard-authn DSP Provider Adapter
  -> ExternalIdentity
  -> Account Linking
  -> Canonical Principal Context
  -> authguard-authz
```

## 9. Authorization model

The minimal AuthZ request is:

```text
AuthorizationRequest {
  principal_id
  group_principal_ids
  action
  resource_urn
  parent_urns
  conditions
}
```

AuthZ verifies that the canonical Principal is materialized and active, maps the HTTP route to Action and Resource URN, matches user/group RoleBindings, applies conditions, gives explicit DENY precedence, and otherwise defaults to deny.

An identity whose `principal_id` is absent from `iam_principal` is rejected with `UNAUTHENTICATED`; AuthZ never creates a Principal and has no allow-unknown bypass. A 2C route requiring only authentication should omit `ext_authz`. A 2C route requiring subscription, tenant, entitlement, or resource authorization uses AuthN `first-login` first, so AuthZ still receives a materialized canonical Principal.

Authorization Scope continues to be delivered as a signed direct context or a short-lived opaque scope token for workload SDK resource filtering.

## 10. Keycloak position

Keycloak is an optional external enterprise IdP integration, never an AuthGuard runtime dependency. Enterprises often already operate Keycloak, Entra, Okta, a corporate DSP, or SAML/Kerberos federation. AuthGuard integrates with the existing platform and never requires another Keycloak deployment.

Existing Keycloak Principal discovery/federation remains an optional management-plane integration. The default Helm topology does not deploy Keycloak.

> Keycloak is supported, never required.

## 11. Module and dependency boundaries

```text
src/authn                       authguard-authn crate
  provider/                     configurable adapter and minimal SPI
  principal/jit.rs              policy-gated account linking/JIT materialization
  route/authentication.rs       OAuth/OAuth-like HTTP entry points
  handler/authentication.rs     authentication flow orchestration
  server.rs                     process initialization and listener lifecycle

src/common                      authguard-common crate
  config/config.rs              one AppConfig model/singleton and nested ENV overlay
  model/{principal,identity,role,policy}.rs
                                cohesive IAM contracts and persistence projections
  storage/base_{sqlite,postgres}.rs
                                entity-neutral pools and schema initialization
  storage/principal_{sqlite,postgres}.rs
                                shared canonical Principal and identity binding persistence
  storage/authn/flow_{sqlite,postgres}.rs
                                AuthN flow repositories
  storage/authz/role_{sqlite,postgres}.rs
                                AuthZ role and authorization catalog repositories
  principal/{mod,custom}.rs     common discovery contract and custom HTTP connector
  route/management.rs           health, metrics, and runtime diagnostics
  apm/cache/utils               genuinely shared infrastructure

src/authz                        authguard-authz crate
  route/mod.rs                  authenticated composition of AuthGuard APIs
  route/{policy,principal}.rs   transport-only control-plane APIs
  route/authorization.rs        Envoy ext_authz/access-context gRPC entry points
  handler/{authorization,principal}.rs
                                authorization catalog and Principal use cases
  handler/authorization.rs      ext_authz evaluation and scope delivery
  handler/policy.rs             authorization catalog CRUD and compilation
  principal/{ldap,keycloak,scim}/
                                optional 2B control-plane federation connectors
  server.rs                     process initialization and listener lifecycle

migrations/                     single authoritative IAM schema
```

Dependency rules:

- AuthN does not depend on AuthZ policy implementation;
- AuthZ does not depend on AuthN Provider implementations;
- AuthN, AuthZ, and the Rust workload SDK depend on `authguard-common`; the SDK
  never imports the AuthZ server crate;
- the modules cooperate through a versioned canonical Principal Context or equivalent wire contract;
- provider-specific types never appear in AuthZ public APIs;
- business services depend on AuthGuard access context, not an IdP SDK.

AuthN and AuthZ normally use one logical IAM database and one schema. A second
database is not required: `iam_principal` is defined once as the shared
aggregate root, AuthN owns `iam_principal_identity` and transient
`iam_authn_flow`, and AuthZ owns policy/action/role/binding tables. The single
top-level migration is serialized during startup. This ownership boundary keeps
a future physical split possible without duplicating today's schema.

Configuration initialization follows Spring Boot-like precedence:
`built-in defaults < authguard.yaml < environment`. A nested property is
addressed dynamically with `AUTHGUARD__<SECTION>__<...>`, so adding a field to
the serializable configuration model does not require a new environment-variable
mapping.

Both servers publish Prometheus metrics and structured tracing events for their
critical flows. Workload SDKs do not initialize global exporters; Rust emits
`tracing` events directly, while Go/Python/Java expose application-owned logger
and telemetry-observer bridges so the host service can attach its existing OTel
Meter/Tracer without creating a second SDK provider.

## 12. Flowgent and Sigbot

Flowgent, Sigbot, and other business systems only deploy or reuse Envoy Gateway, `authguard-authn`, and `authguard-authz`. Provider selection and account linking remain AuthN configuration and state. Business code never handles provider callbacks, token exchange, or identity binding.

## 13. Final principles

- Envoy owns the edge;
- AuthN owns external authentication normalization and account linking;
- AuthZ owns authorization for one stable canonical Principal;
- Principal is not `(issuer, subject)`;
- Provider configuration describes protocols, not account governance;
- explicit linking is the safe default, with no email auto-linking;
- Keycloak is supported, never required;
- external IdPs remain external.
