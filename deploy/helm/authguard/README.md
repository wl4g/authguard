# AuthGuard Helm chart

Installs Envoy Gateway, AuthN, AuthZ, Web, Redis Cluster, and PostgreSQL.
Keycloak remains an external OIDC or Principal-discovery integration.

## 1. Prepare

Require Helm 3, a writable StorageClass, and an existing Kubernetes cluster.
Create one logical Secret payload; all active values must be single-line.

```bash
cp deploy/helm/authguard/bootstrap/authguard-secrets.env.example authguard-secrets.env && \
${EDITOR:-vi} authguard-secrets.env
```

The required base keys are PostgreSQL, Redis, canonical JWT, AuthZ HMAC, and
the AuthZ API token. Optional provider credentials use their matching
`AUTHGUARD__...` path; see the template for examples.

## 2. Initialise the Secret source

Kubernetes Secret is the default and works with bundled PostgreSQL and Redis:

```bash
deploy/helm/authguard/bootstrap/k8s-secrets-setup.sh \
  --secret-file "$PWD/authguard-secrets.env"
```

For a managed Secret store, run one setup command and keep the generated values
file for step 3:

| Source | Setup command | Values file |
| --- | --- | --- |
| GCP | `gcp-secrets-setup.sh --project PROJECT --account ACCOUNT --secret-file FILE` | `authguard-gcp-values.yaml` |
| AWS | `aws-secrets-setup.sh --profile PROFILE --region REGION --cluster EKS_CLUSTER --secret-file FILE` | `authguard-aws-values.yaml` |
| Vault | `vault-secrets-setup.sh --secret-file FILE` | `authguard-vault-values.yaml` |

Use `--help` on a setup script for common flags. Optional IaC templates are
generated without cloud writes via `gcp-secrets-setup.sh --write-replication-policy FILE`
or `aws-secrets-setup.sh --write-kms-key-policy FILE`.

## 3. Install or upgrade

```bash
helm upgrade --install authguard oci://ghcr.io/wl4g/charts/authguard \
  --version 0.1.0 \
  --namespace authguard --create-namespace \
  --set secrets.kubernetes.existingSecret=authguard-secrets \
  --set authguard.authn.image.repository=ghcr.io/wl4g/authguard \
  --set authguard.authz.image.repository=ghcr.io/wl4g/authguard \
  --set authguard.web.image.repository=ghcr.io/wl4g/authguard-web
```

For GCP, AWS, or Vault append `-f authguard-<provider>-values.yaml`. Do not put
Secret values in Helm `--set` arguments. Bundled middleware defaults to Aliyun
mirrors; product image paths above may be replaced with an approved registry.

## 4. Verify and configure

```bash
kubectl -n authguard rollout status deployment/authguard-authn && \
kubectl -n authguard rollout status deployment/authguard && \
kubectl -n authguard get pods
```

AuthN and AuthZ share the typed `authguard.yaml` in
[`values.yaml`](values.yaml). Envoy Gateway is the PEP: protected routes use
canonical JWT validation followed by `ext_authz`; AuthZ receives only Principal,
resource, action, and context. Configure providers, wallet RPC mappings, and
external storage by overriding that one runtime configuration block.

For a local non-Kubernetes deployment, use the [Docker Compose guide](../../docker/README.md).
