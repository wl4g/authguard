# AuthGuard Helm chart

This chart is the Kubernetes installation entry point for the default AuthGuard topology:

```text
Envoy Gateway
authguard-authn
authguard-authz
```

It does not deploy Keycloak and introduces no AuthGuard CRD or Controller. Disable the vendored Envoy Gateway only when the cluster already operates a compatible installation.

## Install

```bash
helm dependency build deploy/helm/authguard
helm upgrade --install authguard deploy/helm/authguard \
  --namespace authguard \
  --create-namespace
```

Default component settings:

- `envoy_gateway.enabled=true`;
- `authguard.authn.enabled=true`, two replicas;
- `authguard.authz.replicaCount=1` for the SQLite AuthZ default;
- Redis Cluster enabled for shared opaque scope-token contexts.

Select PostgreSQL before using independently replicated AuthN/AuthZ, and Redis
before scaling AuthZ's opaque-scope delivery.

The public values surface is intentionally grouped by product boundary:

```yaml
envoy_gateway:
  deployment: {}
  ext_authz: {}

authguard:
  authn: {}
  authz: {}
  authguard-config: |-
    # One shared authguard.yaml

redis_cluster: {}
secrets: {}
```

## One shared configuration file

AuthN and AuthZ mount and read the same `/etc/authguard/authguard.yaml`. The complete content is held in `authguard.authguard-config`; do not create a second AuthN YAML.

```yaml
authguard:
  authn:
    # authguard-authn deployment settings
  authz:
    # authguard-authz deployment settings
  authguard-config: |
    authn:
      providers: {}
      accountLinking:
        strategy: explicit
        authoritativeProviders: []
        allowLink: {}

    server:
      # authguard-authz runtime
      # ...
    authz:
      identity:
        token_header: authorization
        principal_id_claim: principal_id
        principal_kind_claim: principal_kind
        groups_claim: authguard_group_ids
```

Both services deserialize the same strongly typed `AppConfigProperties` snapshot. Startup resolves only the service-owned secret subtree (`authn` or `authz`), so one `authguard.yaml` remains the source of truth without introducing a Provider-to-AuthZ dependency.

Provider entries describe protocol mechanics only. `authoritativeProviders` and `allowLink` remain centralized under `accountLinking`; never repeat authoritative/secondary roles inside each Provider.

`accountLinking.strategy` supports two modes:

- `explicit` (default): only an authoritative Provider can create a Principal; another identity is linked from an already authenticated Principal session according to `allowLink`.
- `first-login`: any previously unbound Provider identity creates a Principal and its identity binding, which is useful for 2C signup.

`first-login` reuses an existing binding only for the same `(provider, issuer, subject)`. It never merges identities from different Providers by matching email; users link additional login methods through the authenticated explicit-link flow.

## Envoy Gateway boundary

Envoy Gateway is the common edge and PEP(Policy Enforcement Point). All standard OIDC and OAuth-like
authorization, callback, token exchange, ID Token validation, UserInfo, and
normalization run in AuthN. Envoy validates only the AuthN-issued canonical JWT;
the request hot path is `jwt_authn -> ext_authz(authguard-authz)`.

The managed Gateway uses a `protected` listener for business routes and a
separate `authn` listener for `/auth/` authorize/callback routes. The
SecurityPolicy targets only `sectionName: protected`, so a user can establish a
session while every business request still requires canonical JWT verification
and AuthZ. External IdP issuers are deliberately absent from this SecurityPolicy.

The AuthN Service is `<release>-authguard-authn:8082`. The AuthZ Service exposes:

- `8080`: Envoy `envoy.service.auth.v3.Authorization/Check`;
- `8081`: workload `authguard.access.v1.AccessContextService/ResolveScope`;
- `9091`: management, health, readiness, and metrics when enabled.

NetworkPolicy admits AuthN and the AuthZ Check listener from Envoy-selected pods, the scope listener from `authguard.io/scope-client`, and management from `authguard.io/management-client`.

## Identity and Principal contract

AuthN resolves `(provider, issuer, subject)` through `iam_principal_identity` and produces only a canonical Principal context. AuthZ never consumes provider subjects or tokens.

An unbound secondary Provider fails under the default `strategy: explicit`; equal email addresses never create a binding. Internet deployments may explicitly choose `first-login`.

## Secrets

Secrets remain in their owning configuration block and are injected through the selected Kubernetes, Vault, GCP Secret Manager, or AWS Secrets Manager mechanism. The chart does not create a second unified application-secret model.

Common environment keys include:

| Purpose | Configuration owner | Environment key |
|---|---|---|
| Redis scope cache | AuthZ cache | `AUTHGUARD__CACHE__REDIS__PASSWORD` (Kubernetes) or `AUTHGUARD_REDIS_PASSWORD` (env-file reference) |
| PostgreSQL | shared IAM storage | `AUTHGUARD__STORAGE__POSTGRES__URL`, `AUTHGUARD__STORAGE__POSTGRES__USERNAME`, `AUTHGUARD__STORAGE__POSTGRES__PASSWORD` |
| AuthN canonical-session key | AuthN | `AUTHGUARD_AUTHN_SESSION_PRIVATE_KEY` when referenced by `authn.session.privateKey` |
| Provider credentials | AuthN | deployment-defined keys referenced by `${...}` in the Provider entry |
| Keycloak discovery service account | optional AuthZ integration | `AUTHGUARD_KEYCLOAK_CLIENT_SECRET` |
| LDAP discovery bind | optional AuthZ integration | `AUTHGUARD_LDAP_BIND_PASSWORD` |
| Direct access-context HMAC | AuthZ and workloads | `AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY` |
| AuthZ resign key | AuthZ delivery | `AUTHGUARD__AUTHZ__RESIGN__PRIVATE_KEY_B64` |

Provider client secrets for AuthN are likewise secret-injected and must not be committed in Provider YAML. Keycloak secrets are needed only when the optional Keycloak integration is enabled.

### Access-context signing

AuthZ and each workload share a high-entropy HMAC key through
`AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY`. Put that key in the selected top-level
`secrets` provider; for the default Kubernetes provider, the referenced Opaque
Secret exposes it directly as an environment key:

```yaml
secrets:
  provider: kubernetes
  kubernetes:
    existingSecret: authguard-secrets
```

### Optional resign token

When `authz.resign.enabled=true`, AuthZ reads the base64 PKCS#8 key directly,
then replaces the upstream authorization header with a short-lived RS256 token.
Its expiry is bounded by both `max_ttl` and the source canonical JWT's remaining
lifetime. There is no key-decoding init container.

```yaml
authguard:
  authguard-config: |
    authn:
      providers: {}
      accountLinking: { strategy: explicit }
    authz:
      resign:
        enabled: true
        max_ttl: 60s
        private_key_b64: "${AUTHGUARD__AUTHZ__RESIGN__PRIVATE_KEY_B64}"
```

## Keycloak

Keycloak is supported, never required. The chart contains no Keycloak workload. Existing enterprises can configure Keycloak as an external OIDC Provider and optionally enable Keycloak Admin API Principal discovery.

## Render verification

```bash
helm lint deploy/helm/authguard
helm template authguard deploy/helm/authguard --namespace authguard >/tmp/authguard-rendered.yaml
```

The repository defaults to mirrored images suitable for mainland-China environments. If dependency or build access is blocked by GFW, use `HTTPS_PROXY=http://127.0.0.1:8800`.
