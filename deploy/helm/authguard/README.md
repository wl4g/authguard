# AuthGuard Helm chart

Installs Envoy Gateway, AuthN, AuthZ, Web, Redis Cluster, and PostgreSQL.
Keycloak remains an external OIDC or Principal-discovery integration.

## Template layout

The Chart keeps every rendered resource with its owning boundary:
`authn/`, `authz/`, `web/`, `gateway/`, and `platform/` for shared runtime
configuration, secret-store bindings, and the ServiceAccount. Only Helm's
`_helpers.tpl` and release `NOTES.txt` remain at the template root.

For request-path review, start with these non-overlapping route owners:

| Template | Paths and responsibility |
| --- | --- |
| `web/hosted-login-route.yaml` | `GET /auth/login`, account security UI, and `/auth/assets/*` |
| `authn/public-route.yaml` | `/.well-known/*` and remaining `/auth/*` AuthN APIs |
| `gateway/protected-route.yaml` | a labelled business route protected by JWT + `ext_authz` |
| `web/dashboard-route.yaml` | optional dedicated AuthGuard Dashboard hostname |

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

For Hosted Login, set `authguard.authn.applications` with each
trusted business host, display name, optional `/auth/assets/...` logo/theme,
and HTTPS `returnUris`. The chart overlays that map onto the runtime
configuration, including when `authguard.authguard-config` is replaced. Keep
the AuthGuard Web image immutable.

The simplest business integration needs no extra image. Vendor the immutable
AuthGuard tgz, keep CSS/SVG/font files inside the business Chart, and create a
ConfigMap with `.Files.Glob`:

```yaml
# business/Chart.yaml
dependencies:
  - name: authguard
    alias: authguard-middleware
    version: 0.1.0
    repository: oci://ghcr.io/wl4g/charts
    condition: authguard-middleware.enabled
```

```yaml
# business/values.yaml
global:
  authguard:
    themeRevision: v1
    themeConfigMap: '{{ .Release.Name }}-authguard-theme-{{ .Values.global.authguard.themeRevision }}'
authguard-middleware:
  enabled: false
  theme:
    files: files/authguard-theme/*
  authguard:
    authn:
      applications:
        example-app:
          hosts: [app.example.com]
          displayName: Example App
          logo: /auth/assets/themes/custom/example-app.svg
          theme:
            id: example-app
            stylesheet: /auth/assets/themes/custom/example-app.css
          returnUris: [https://app.example.com/**]
```

```yaml
# business/templates/authguard-theme.yaml
{{- $authguard := index .Values "authguard-middleware" }}
{{- if $authguard.enabled }}
{{- $files := .Files.Glob $authguard.theme.files }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ tpl .Values.global.authguard.themeConfigMap . }}
immutable: true
data:
{{ $files.AsConfig | indent 2 }}
{{- end }}
```

Put uniquely named files under `business/files/authguard-theme/`; Helm packages
the directory into the business tgz and AuthGuard mounts it read-only at
`/auth/assets/themes/custom/`. `.Files` can only read files inside the Chart,
not an arbitrary host directory outside its package. Keep ConfigMap-backed
assets below Kubernetes' object-size limit (approximately 1 MiB), so CSS, SVG,
and fonts should remain compact. To update an immutable theme, increment
`global.authguard.themeRevision`; custom URLs are revalidated, while hashed Web
bundles retain their immutable cache policy.

Use a separate one-time middleware release from the same business Chart. This
is important: disabling a dependency in a later upgrade of the *same* release
would delete resources previously owned by that release.

```bash
helm upgrade --install business-authguard ./business \
  --set application.enabled=false \
  --set authguard-middleware.enabled=true \
  --set-string 'authguard-middleware.theme.files=files/authguard-theme/*'

# Frequent application releases keep authguard-middleware.enabled=false and therefore
# never create, upgrade, or remove the separate middleware release.
helm upgrade --install business ./business
```

`application.enabled` represents the business Chart's own workload gate; use
its actual name. The Customer Growth reference uses `support.enabled=false`.

The complete executable reference is
[`use-cases/customer-growth-job-service/e2e/helm`](../../../use-cases/customer-growth-job-service/e2e/helm):
its default business release disables AuthGuard, while a second release enables
the vendored tgz and packages `files/authguard-theme/`. The real Chromium E2E
verifies both that ConfigMap mount and the no-theme fallback.

Repository-aware coding agents can use
[`$authguard-chart-integrator`](../../../.agents/skills/authguard-chart-integrator/SKILL.md)
to discover the latest stable GHCR Chart, vendor and pin that exact release,
obtain the real business service domain, wire the complete opt-in dependency
values, validate disabled/enabled renders, and run an explicitly targeted
deployment smoke test. A scoped local Hosted Login theme remains optional.

Both `logo` and `theme` are optional per Application. If neither is configured,
Hosted Login still replaces the product name from Host-resolved metadata while
rendering the built-in AuthGuard mark and cyan trust-fabric visual. No asset
volume is required for that fallback.
The chart never loads theme JavaScript or arbitrary HTML. The Web HTTPRoute owns only
`GET /auth/login`, `GET /auth/account/security`, and `GET /auth/assets/*`; the
AuthN HTTPRoute owns `/.well-known/*` and the remaining `/auth/*`. This leaves
an application's `/api/*` and `/*` routes to its own chart. Enable
`authguard-middleware.authguard.web.route.dashboard` only on a dedicated AuthGuard Dashboard hostname.

The Gateway has one listener, so Hosted Login remains on the application's
browser origin. Label each protected business `HTTPRoute` with
`authguard.io/protected: "true"`; the chart's route-scoped SecurityPolicy then
applies canonical JWT validation and fail-closed `ext_authz` only there. The
selector is same-namespace by default. For a business route in another
namespace, set `envoy_gateway.ext_authz.protectedRouteSelector.namespaces.from=All`
and create the required Gateway API `ReferenceGrant` in that namespace.

For a local non-Kubernetes deployment, use the [Docker Compose guide](../../docker/README.md).
