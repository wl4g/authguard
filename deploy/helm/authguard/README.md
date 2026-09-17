# AuthGuard Helm chart

The chart installs Envoy Gateway, AuthN, AuthZ, the React UI, Redis Cluster,
and PostgreSQL. Keycloak is always external: it can be an OIDC provider or
principal source, but this chart never installs it.

## Bootstrap credentials

All application and bundled-middleware credentials form one logical payload
named authguard-secrets. The repeatable bootstrap utilities live in
[bootstrap](bootstrap/); use their built-in help rather than copying provider
commands into deployment documentation.

~~~bash
cp deploy/helm/authguard/bootstrap/authguard-secrets.env.example authguard-secrets.env
# Replace every active <PLACEHOLDER> with a single-line value.
${EDITOR:-vi} authguard-secrets.env

# Kubernetes-native secret source.
deploy/helm/authguard/bootstrap/k8s-secrets-setup.sh \
  --secret-file $PWD/authguard-secrets.env
~~~

Every script has the same common arguments: --release, --namespace,
--service-account, --secret-name, --secret-file,
--skip-kubernetes-mirror, and --dry-run. Cloud scripts also generate a
non-secret Helm values override in the working directory.

| Source | Bootstrap command | Helm override |
|---|---|---|
| Kubernetes Secret | bootstrap/k8s-secrets-setup.sh | none |
| GCP Secret Manager | bootstrap/gcp-secrets-setup.sh --project PROJECT --account ACCOUNT | -f authguard-gcp-values.yaml |
| AWS Secrets Manager | bootstrap/aws-secrets-setup.sh --profile PROFILE --region REGION --cluster EKS_CLUSTER | -f authguard-aws-values.yaml |
| Vault KV v2 | bootstrap/vault-secrets-setup.sh | -f authguard-vault-values.yaml |

~~~bash
deploy/helm/authguard/bootstrap/gcp-secrets-setup.sh --help
deploy/helm/authguard/bootstrap/aws-secrets-setup.sh --help
deploy/helm/authguard/bootstrap/vault-secrets-setup.sh --help
~~~

The setup utilities can emit copy-and-edit KMS policy templates without touching
cloud state: `gcp-secrets-setup.sh --write-replication-policy FILE` and
`aws-secrets-setup.sh --write-kms-key-policy FILE`. The AWS utility creates only
the least-privilege secret-reader policy and EKS Pod Identity association. The
Vault utility writes only application policy and
role; Kubernetes auth backend trust and the Agent Injector remain platform
responsibilities.

When bundled PostgreSQL or Redis are enabled, retain the Kubernetes mirror.
Those subcharts use standard Kubernetes Secret references; the external secret
manager remains the single authoritative source. Use
--skip-kubernetes-mirror only with external database and cache credentials.

## Install

~~~bash
export AUTHGUARD_RELEASE=authguard
export AUTHGUARD_NAMESPACE=authguard

helm upgrade --install "$AUTHGUARD_RELEASE" \
  oci://ghcr.io/wl4g/charts/authguard \
  --version 0.1.0 \
  --namespace "$AUTHGUARD_NAMESPACE" --create-namespace \
  --set authguard.authn.image.repository=ghcr.io/wl4g/authguard \
  --set authguard.authz.image.repository=ghcr.io/wl4g/authguard \
  --set authguard.web.image.repository=ghcr.io/wl4g/authguard-web
~~~

For GCP, AWS, or Vault, append the values file produced by its bootstrap
utility. Do not append secrets through Helm --set arguments.

For a no-Kubernetes local deployment, use the [Docker Compose guide](../../docker/README.md).
It starts the same AuthN, AuthZ, Web UI, PostgreSQL, and Redis components and
uses the identical AUTHGUARD__ secret keys in deploy/docker/.env.

## Secret contract

| Purpose | Key | Required when |
|---|---|---|
| AuthGuard PostgreSQL user | AUTHGUARD__STORAGE__POSTGRES__PASSWORD | Bundled PostgreSQL |
| Redis | AUTHGUARD__CACHE__REDIS__PASSWORD | Bundled Redis |
| Canonical JWT signer | AUTHGUARD__AUTHN__TOKEN__PRIVATE_KEY_B64 | AuthN is enabled |
| Direct access-context signer | AUTHGUARD__AUTHZ__SCOPE_DELIVERY__DIRECT_CONTEXT_HMAC_KEY | AuthZ is enabled |
| AuthZ control-plane token | AUTHGUARD__AUTHZ__API_TOKEN | AuthZ management is enabled |
| Standalone credential encryption | AUTHGUARD__AUTHN__STANDALONE__CREDENTIAL_ENCRYPTION_KEY | Password or TOTP is enabled |
| OAuth/OIDC and directory credentials | matching AUTHGUARD__ configuration path | Corresponding provider is enabled |
| AuthZ re-signing key | AUTHGUARD__AUTHZ__RESIGN__PRIVATE_KEY_B64 | authz.resign.enabled is true |

The HMAC key must contain at least 32 random bytes. Optional entries in the
template are commented out. INDEX_0 is the Kubernetes Secret-key-safe spelling
for an array index, for example
AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__LDAP__INDEX_0__AUTH__BIND_PASSWORD.

Rotate an application-only value at the authoritative source, synchronise its
Kubernetes mirror if one is used, then restart AuthN and AuthZ. Redis and
PostgreSQL credentials require their upstream rotation procedures; changing a
live password Secret alone desynchronises stateful workloads.

## Default images and topology

The chart defaults Envoy Gateway, Redis Cluster, and PostgreSQL to controlled
Aliyun mirrors. AuthGuard product images are separate because enterprises
commonly mirror releases to their own registry.

| Component | Default image | Override path |
|---|---|---|
| Envoy Gateway controller | registry.cn-shenzhen.aliyuncs.com/wl4g/envoyproxy_gateway:v1.9.0 | envoy_gateway.global.images.envoyGateway.image |
| Envoy data plane | registry.cn-shenzhen.aliyuncs.com/wl4g/envoyproxy_envoy:distroless-v1.36.4 | envoy_gateway.global.images.envoyProxy.image |
| Redis Cluster | registry.cn-shenzhen.aliyuncs.com/wl4g-k8s/bitnami_redis-cluster:7.0.14 | redis_cluster.image |
| PostgreSQL | registry.cn-shenzhen.aliyuncs.com/wl4g/bitnami_postgresql:18.3 | postgresql.image |
| AuthN/AuthZ | ghcr.io/wl4g/authguard:<chart-appVersion> | authguard.{authn,authz}.image |
| Web UI | ghcr.io/wl4g/authguard-web:<chart-appVersion> | authguard.web.image |

The default topology needs a writable StorageClass. Set postgresql.enabled=false
only after supplying a complete external PostgreSQL storage configuration.
Disable the bundled gateway only when a compatible Envoy Gateway is already
operated by the cluster.

## Shared configuration and boundary

AuthN and AuthZ mount one authguard.yaml from authguard.authguard-config. AuthN
owns protocol verification, account linking, and canonical token issuance; AuthZ
receives only the canonical principal context and evaluates resource policy.

~~~yaml
authguard:
  authguard-config: |
    authn:
      providers: {}
      accountLinking:
        strategy: explicit
        authoritativeProviders: []
        allowLink: {}
    authz:
      scope_delivery:
        direct_context_hmac_key: "${AUTHGUARD__AUTHZ__SCOPE_DELIVERY__DIRECT_CONTEXT_HMAC_KEY}"
~~~

Provider entries describe protocol mechanics. In explicit mode, a secondary
identity can only be linked by an authenticated Principal according to
allowLink. first-login materialises an unbound provider/issuer/subject tuple;
neither mode merges identities by email or profile metadata.

Envoy Gateway is the PEP: protected routes apply canonical JWT validation and
then ext_authz. AuthN routes stay available on the separate authentication
listener for login, callback, passkey, and wallet proofs. AuthZ receives
principal_id, resource, action, and request context; it does not parse OAuth,
wallet, password, or WebAuthn protocols.

Keycloak is optional and external. Configure it as an OIDC provider and, if
needed, a Keycloak Admin API principal-discovery source. Its client credential
uses the matching reflected AUTHGUARD__ secret key.

## Verify

~~~bash
helm dependency list deploy/helm/authguard
helm lint deploy/helm/authguard
helm template authguard deploy/helm/authguard --namespace authguard >/tmp/authguard-rendered.yaml
~~~

Use HTTPS_PROXY=http://127.0.0.1:8800 when dependency access is blocked.

## Provider references

- [Google Secret Manager CMEK](https://cloud.google.com/secret-manager/docs/cmek)
- [GCP Secrets Store CSI provider](https://github.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp)
- [AWS Secrets Manager CLI](https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/create-secret.html) and [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-association.html)
- [Vault Kubernetes auth](https://developer.hashicorp.com/vault/docs/auth/kubernetes)
