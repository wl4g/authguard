# Authguard Helm chart

This chart is the single Kubernetes installation entry point for Authguard. It
vendors two upstream charts under `charts/` so normal installation and CI
rendering do not download dependencies:

- Envoy Gateway `v1.9.0` (the current stable upstream release).
- Bitnami Redis Cluster `8.8.2`, the final chart line built for Redis 7.0.x.

The values have three separate ownership boundaries:

- `envoy-gateway`: the official controller deployment. It is enabled by
  default; set only `envoy-gateway.enabled=false` when the cluster already has
  a compatible Envoy Gateway.
- `authguardIntegration`: Authguard's Gateway, JWT/OIDC, and gRPC ext_auth
  binding. It remains independent from controller installation, so it can be
  applied to an existing GKE/Kubernetes Gateway.
- `redis-cluster`: the independent Redis Cluster release subtree used for the
  shared opaque request-access tokens; each server keeps its validated policy
  snapshot in-process and refreshes it from durable storage by revision.

The generated `SecurityPolicy` is intentionally opinionated: ext_auth uses the
standard Envoy v3 gRPC API, fails closed, receives only the fixed trusted input
headers, and targets the configured Gateway. Routine users only toggle
`authguardIntegration.enabled`; protocol and security defaults are not exposed
as unnecessary values.

Envoy data-plane tracing is independently opt-in. When enabled, the generated
`EnvoyProxy` exports OTLP/gRPC spans to a Kubernetes Service and uses Envoy
Gateway's OpenTelemetry `AlwaysOn` sampler; a collector or backend should apply
the production sampling policy centrally:

```yaml
authguardIntegration:
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
created by this chart (`authguardIntegration.gateway.create=true`); when a
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
  --set authguardIntegration.gateway.create=false \
  --set authguardIntegration.gateway.name=shared-gateway
```

Disabling `gateway.create` means the referenced Gateway and its compatible
GatewayClass/EnvoyProxy configuration are owned elsewhere; the Authguard
`SecurityPolicy` is still applied.

Production values must provide a real policy snapshot, an admin-token Secret,
and a valid JWT or OIDC identity configuration. Envoy verifies the credential;
Authguard never treats an unverified JWT payload as authentication.

The default single-replica installation uses SQLite and bootstraps the database
from `authguard.policy`. For shared policy persistence, set
`authguard.config.storage.backend=postgres` and inject the database URL using
`authguard.storage.existingSecret`. PostgreSQL is required before increasing
`authguard.replicaCount`; SQLite is intended for local development, CI, and
single-replica installations.

Federated Principal discovery credentials must not be rendered into the
ConfigMap. Put connector secrets in one existing Kubernetes Secret, set
`authguard.principalDiscovery.existingSecret`, and point each configured
Keycloak `client_secret_file` or LDAP `bind_password_file` at the mounted key:

```yaml
authguard:
  principalDiscovery:
    existingSecret: authguard-principal-discovery
  config:
    auth:
      principal_discovery:
        keycloak:
          - client_secret: ""
            client_secret_file: /etc/authguard/principal-discovery/keycloak-client-secret
        ldap:
          - bind_password: ""
            bind_password_file: /etc/authguard/principal-discovery/ldap-bind-password
```

These connectors run only for management-plane discovery/materialization; the
authorization data path never waits on Keycloak or LDAP.

## Business token

On every allowed request Authguard can re-sign a short-lived internal business
JWT (RS256) carrying `authguardOrigin: true` and overwrite the `authorization`
header for the upstream microservice. The RSA private key stays in Authguard;
business workloads verify with the paired public key only (a
`BusinessTokenSigner` exposes it as PKCS#1 PEM for bootstrap tooling). Envoy
still verifies the original client credential per its standard JWT/OIDC
`SecurityPolicy`.

Enable it and provide the PKCS#8 PEM private key, either in an existing Secret
or inline (intended only for local rendering):

```yaml
authguard:
  config:
    auth:
      business_token:
        enabled: true
        ttl: 60s
  businessToken:
    existingSecret: authguard-business-token   # key: rsa-private-key
    # privateKey: |                            # alternative, local rendering only
    #   -----BEGIN PRIVATE KEY-----
```

The chart injects `AUTHGUARD__AUTH__BUSINESS_TOKEN__PRIVATE_KEY` from the
Secret; enabling the feature without a key fails rendering. Disabled (the
default) keeps the original identity token stripped without replacement.

## Cache

The local [`etc/authguard.yaml`](../../../etc/authguard.yaml) defaults to
`cache.provider: Memory` for zero-dependency development. Helm overrides that
service configuration to Redis and enables the independent `redis-cluster`
subchart by default.

The Redis chart owns its Secret, Service, StatefulSet, and cluster-bootstrap
logic. Authguard only consumes the generated service endpoint and password
Secret. Its runtime image is pinned to:

```text
registry.cn-shenzhen.aliyuncs.com/wl4g-k8s/bitnami_redis-cluster:7.0.14
```

To use an externally managed cluster, set `redis-cluster.enabled=false`, fill
`authguard.config.cache.redis.nodes`, and set
`redis-cluster.existingSecret`/`existingSecretPasswordKey` to the credential
Secret that Authguard may read.

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
