# Authguard Helm chart

This chart is the single Kubernetes installation entry point for Authguard. It
vendors two upstream charts under `charts/` so normal installation and CI
rendering do not download dependencies:

- Envoy Gateway `v1.9.0` (the current stable upstream release).
- Bitnami Redis Cluster `8.8.2`, the final chart line built for Redis 7.0.x.

The values have three separate ownership boundaries:

- `envoy-gateway`: the official controller deployment. It is enabled by
  default; set only `envoy-gateway.enabled=false` when the cluster already has
  a compatible Envoy Gateway. Its `deployment.resources` configure the
  control-plane container directly.
- `envoy_gateway.ext_authz`: Authguard's Gateway, JWT/OIDC, and gRPC ext_auth
  binding. It remains independent from controller installation, so it can be
  applied to an existing GKE/Kubernetes Gateway.
- `redis-cluster`: the independent Redis Cluster release subtree used for the
  shared opaque request-access tokens; each server keeps its validated policy
  snapshot in-process and refreshes it from durable storage by revision.

The generated `SecurityPolicy` is intentionally opinionated: ext_auth uses the
standard Envoy v3 gRPC API, fails closed, receives only the fixed trusted input
headers, and targets the configured Gateway. Routine users only toggle
`envoy_gateway.ext_authz.enabled`; protocol and security defaults are not
exposed as unnecessary values.

Envoy data-plane tracing is independently opt-in. When enabled, the generated
`EnvoyProxy` exports OTLP/gRPC spans to a Kubernetes Service and uses Envoy
Gateway's OpenTelemetry `AlwaysOn` sampler; a collector or backend should apply
the production sampling policy centrally:

```yaml
envoy_gateway:
  ext_authz:
    tracing:
      enabled: true
      backendRef:
        name: otel-collector
        port: 4317
      serviceName: authguard-envoy
```

`backendRef.namespace` is optional and defaults to the release namespace. A
cross-namespace Service reference also requires a Gateway API `ReferenceGrant`
in the collector namespace. An empty `serviceName` delegates to Envoy Gateway's
`<gateway>.<namespace>` default. These settings only configure an `EnvoyProxy`
created by this chart (`envoy_gateway.ext_authz.gateway.create=true`); when a
Gateway is externally owned, configure tracing on its owning `EnvoyProxy`.

## Install

The default installation deploys Envoy Gateway, Redis Cluster, Authguard, a
Gateway, and the external-authorization integration:

```bash
helm upgrade --install authguard deploy/helm/authguard \
  --namespace authguard \
  --create-namespace
```

When Envoy Gateway is already managed by the cluster, reuse it without creating
another controller:

```bash
helm upgrade --install authguard deploy/helm/authguard \
  --namespace authguard \
  --create-namespace \
  --set envoy-gateway.enabled=false \
  --set envoy_gateway.ext_authz.gateway.create=false \
  --set envoy_gateway.ext_authz.gateway.name=shared-gateway
```

Disabling `gateway.create` means the referenced Gateway and its compatible
GatewayClass/EnvoyProxy configuration are owned elsewhere; the Authguard
`SecurityPolicy` is still applied.

Production values must provide the environment secrets (see below) and a valid
JWT or OIDC identity configuration. Envoy verifies the credential; Authguard
never treats an unverified JWT payload as authentication.

## Runtime configuration (`authguard.authguard-config`)

The main `authguard.yaml` is one multi-line value under `authguard:`
(flowgent-chart style), rendered with Helm `tpl` and mounted at
`/etc/authguard/authguard.yaml`. Because it is Helm-templated, chart values and
helpers can be referenced inside it, and a full override stays one file:

```bash
helm upgrade --install authguard deploy/helm/authguard \
  --set-file authguard.authguard-config=my-authguard.yaml
```

Small tweaks work with `--set` on the knobs the template references (e.g.
`authguard.replicaCount`, `authguard.mgmt.otelEnabled`).

**Authorization policy is deliberately NOT part of Helm values**: policies are
imported into the Authguard storage through the management API as a post-deploy
step (`/adm/v1/policy`), exactly like the use-case E2E runner bootstraps its
policy after the release becomes ready.

### Secrets

The service has exactly six secrets, and each lives inside its OWN config block
— there is no unified secret section:

| Secret | Config block | Environment key |
| --- | --- | --- |
| Redis password | `cache.redis.password` | `AUTHGUARD_REDIS_PASSWORD` |
| PostgreSQL URL/username/password | `storage.postgres` | `AUTHGUARD__STORAGE__POSTGRES__URL`, `...__USERNAME`, `...__PASSWORD` |
| Keycloak search SA | `auth.principal_discovery.keycloak[*].auth` | `AUTHGUARD_KEYCLOAK_CLIENT_SECRET` |
| SCIM sync agent SA | `auth.principal_discovery.scim.auth` | `AUTHGUARD_SCIM_CLIENT_SECRET` |
| LDAP bind SA | `auth.principal_discovery.ldap[*].auth` | `AUTHGUARD_LDAP_BIND_PASSWORD` |
| Resign-JWT RSA private key | `auth.resign_jwt.private_key_file` | `AUTHGUARD_RESIGN_JWT_PRIVATE_KEY` (base64) |

The access-context HMAC key (`AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY`) and the
management API admin token (`AUTHGUARD__AUTH__ADMIN_TOKEN`) travel through the
same injection path.

The top-level `secrets.provider` picks exactly one provider, flowgent
`cache.provider` style:

```yaml
secrets:
  provider: kubernetes  # kubernetes | gcp | aws | vault
  kubernetes:
    existingSecret: my-authguard-secrets   # keys = the env names above
```

- **kubernetes** — the Deployment `envFrom`s the named Opaque Secret.
- **gcp** — exactly ONE `SecretProviderClass` path
  (`secrets.gcp.secretResourceName`); the GCP secret VALUE is the multi-line
  `ENV KEY=VALUE` text, mounted at `/etc/authguard/csi/env` and read through
  `AUTHGUARD_ENV_FILE`.
- **aws** — exactly ONE Secrets Manager secret (`secrets.aws.secretName` +
  `region`) with the same multi-line `KEY=VALUE` content.
- **vault** — the Vault Agent Injector renders `secretPath`'s `env` value to
  `/vault/secrets/env`; `vaultRole`/`vaultAddress` are required.

Values in the config written as `"${ENV_KEY}"` resolve at startup from the
injected environment; an unresolvable reference fails closed. Under
`provider=kubernetes` the config leaves those fields empty so the native
`AUTHGUARD__` environment overrides apply directly.

### Identity: JWT vs OIDC

Exactly one of `envoy_gateway.ext_authz.jwt.enabled` or
`envoy_gateway.ext_authz.oidc.enabled` must be true.

**JWT mode (workloads)** — `jwt.enabled: true`. Envoy verifies
`Authorization: Bearer <token>` against the JWKS below and forwards the
verified token; Authguard extracts the identity. The **public key is required
here** (it is public information):

```yaml
envoy_gateway:
  ext_authz:
    issuer: https://sso.example.com/realms/example-corp
    jwt:
      enabled: true
      audiences: [customer-growth-job-service]
      localJWKS:
        inline: '{"keys":[{"kty":"RSA","kid":"prod-1","n":"...","e":"AQAB"}]}'
      # or remoteJWKS:
      #   uri: https://sso.example.com/realms/example-corp/protocol/openid-connect/certs
```

**OIDC mode (browser users)** — `oidc.enabled: true`. Envoy Gateway's OIDC
filter handles the IdP redirect/callback and the authorization_code token
exchange; users log in on the IdP UI (e.g. GitHub for the flowgent UI). The
forwarded ID token reaches Authguard as `x-authguard-id-token`. The OIDC client
secret references an existing Secret:

```yaml
envoy_gateway:
  ext_authz:
    issuer: https://sso.example.com
    oidc:
      enabled: true
      clientID: authguard
      clientSecretRef: { name: my-oidc-secret, key: client-secret }
      redirectURL: https://app.example.com/oauth2/callback
```

Workloads never use the OIDC browser flow — a machine authenticates with its
own business SA via OAuth2 `client_credentials` and sends the resulting access
token through JWT mode.

### Resign JWT (`auth.resign_jwt` inside authguard-config)

On every allowed request Authguard re-signs the verified client identity as an
RS256 JWT carrying `authguardOrigin: true` and replaces the `authorization`
header for the upstream microservice. **The stable identity is preserved —
all client JWT attributes stay unchanged and only the `authguardOrigin: true`
marker is added** — so a microservice verifying this signature proves the
request passed through Envoy Gateway and rejects clients calling its API
directly. The RSA private key (PKCS#8 PEM, ≥ 2048 bits) stays in Authguard;
workloads hold only the paired public key. Envoy still verifies the original
client credential per its standard JWT/OIDC `SecurityPolicy`.

Enable it inside `authguard.authguard-config` and turn on the deploy-time key
decoder:

```yaml
authguard:
  resignKeyInit: { enabled: true }
  authguard-config: |
    auth:
      resign_jwt:
        enabled: true
        ttl: 60s
        private_key_file: /etc/authguard/secrets/resign-jwt-private-key.pem
```

The key travels as `AUTHGUARD_RESIGN_JWT_PRIVATE_KEY` (base64 of the PEM)
through the configured secret provider; the `resign-key-decode` init container
decodes it into the `private_key_file` referenced from `auth.resign_jwt`.

## Cache

The local [`etc/authguard.yaml`](../../../etc/authguard.yaml) defaults to
`cache.provider: Memory` for zero-dependency development. The Helm default is
Redis, with the independent `redis-cluster` subchart enabled.

The Redis chart owns its Secret, Service, StatefulSet, and cluster-bootstrap
logic. Authguard consumes the generated service endpoint and password Secret
directly (the `AUTHGUARD__CACHE__REDIS__PASSWORD` env). Its runtime image is
pinned to:

```text
registry.cn-shenzhen.aliyuncs.com/wl4g-k8s/bitnami_redis-cluster:7.0.14
```

To use an externally managed cluster, set `redis-cluster.enabled=false` and
provide `AUTHGUARD_REDIS_PASSWORD` through the runtime secret provider (the
`cache.redis.nodes` list inside `authguard-config` points at the external
endpoints).

Business workloads that may receive `x-authguard-scope-token` configure their
SDK resolver with a gRPC target, not an HTTP base URL:

```yaml
env:
  - name: AUTHGUARD_GRPC_TARGET
    value: authguard-authguard.authguard.svc.cluster.local:8081
  - name: AUTHGUARD_GRPC_TLS
    value: "false"
```

The vendored chart and all default runtime images use the configured Aliyun
registry paths needed in mainland China. Keycloak `26.7.0` and PostgreSQL are
isolated to the Customer Growth Job E2E chart and are not production Authguard
dependencies.
