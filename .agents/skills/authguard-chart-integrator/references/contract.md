# AuthGuard business service Helm Chart contract

## 1. Dependency state

```yaml
# Chart.yaml
dependencies:
  - name: authguard
    alias: authguard-middleware
    version: "<version-reported-by-helm-show>"
    repository: oci://ghcr.io/wl4g/charts
    condition: authguard-middleware.enabled
```

The resolved latest stable version must be exact. The Chart must contain one matching
`charts/authguard-<version>.tgz` plus Helm-generated `Chart.lock`; forbid floating versions,
multiple AuthGuard archives, and hand-edited lock data.

## 2. Required values

Replace every placeholder with developer-provided values.

```yaml
# values.yaml
authguard:
  enabled: false
  envoy_gateway:
    # Keep false when the cluster already owns a compatible controller.
    enabled: false
  authguard:
    authn:
      enabled: true
      applications:
        "<application-id>":
          hosts: ["<business-service-domain>"]
          displayName: "<business-service-name>"
          returnUris: ["https://<business-service-domain>/**"]
    web:
      enabled: true
    authz:
      enabled: true
```

Obtain every public domain from the developer unless the repository already contains an
unambiguous production value. Hosts are exact lower-case DNS names without schemes or paths.
Return URIs are HTTPS URLs for those hosts and may use only a trailing `/**` wildcard.

Configure PostgreSQL, Redis, Envoy Gateway, images, storage, replicas, and observability according
to actual ownership. Reuse the business service Helm Chart's Secret mechanism; never store
production credentials in values. Keep `authguard-middleware.enabled: false` for normal service
releases and enable it only for the separately managed AuthGuard release.

## 3. Routing boundary

Web owns `/auth/login`, `/auth/account/security`, and `/auth/assets/*` (including the federation entry); AuthN owns
`/.well-known/*` and `/auth/*`. Web also publishes `/auth/assets/authguard-remoteEntry.js`. The dedicated `/auth/management/api/*` route rewrites to the AuthZ management API without claiming the business API namespace. The business service Helm Chart retains `/api/*` and `/*`. The
browser-facing business Web route MUST use that same Gateway origin; a NodePort, port-forward, or
direct Service URL bypasses Hosted Login routing and is not a valid integration endpoint. Protect
only intended business HTTPRoutes by setting their **`metadata.labels`**, for example:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: business-api
  labels:
    authguard.io/protected: "true"
# spec: retain the business application's Gateway, hostnames, matches and backendRefs.
```

The AuthGuard Chart renders an Envoy Gateway `SecurityPolicy` when both
`envoy_gateway.ext_authz.enabled` and `authguard.authz.enabled` are true. Its
`spec.targetSelectors` targets `kind: HTTPRoute` using
`envoy_gateway.ext_authz.protectedRouteSelector.matchLabels` (the label above by default).
Envoy Gateway reconciles these resources and configures Envoy to validate canonical JWTs and
call AuthGuard's fail-closed gRPC `ext_authz` Check service for selected routes. AuthGuard's
authorization service does not read Pod annotations to activate protection. Putting this key in
`HTTPRoute.metadata.annotations`, Pod labels, or Pod annotations does not match this selector.

Selection defaults to the policy's namespace (`protectedRouteSelector.namespaces.from: Same`).
For cross-namespace selection, configure the selector's namespaces explicitly and a matching
`ReferenceGrant` in the target namespace; the target namespace must be watched by Envoy Gateway.
Verify the route labels, active policy selector, and policy/route acceptance status; the label
alone does not create a policy or prove that requests are protected. Never attach the AuthGuard
Dashboard catch-all to a business service domain. Resolve Applications from the
Gateway-preserved `Host`, never query parameters or `X-Forwarded-Host`.

## 4. Optional Hosted Login theme

When requested, merge `theme.files: files/authguard-theme/*` into the existing top-level
`authguard-middleware` map. Under its existing Application, add `logo`, `theme.id`, and `theme.stylesheet`
using `/auth/assets/themes/custom/<application-id>.*`; do not create another values root. Set the
ConfigMap name through `global.authguard.themeConfigMap` and version it with
`global.authguard.themeRevision`.

Store assets under `files/authguard-theme/` and the ConfigMap template at
`templates/authguard-theme.yaml`. Use unique basenames and only CSS, SVG, PNG, WebP, WOFF, or WOFF2
within the 900 KiB safety budget. Mount it read-only only in Web at
`/usr/share/nginx/html/assets/themes/custom`. Increment `themeRevision` when content changes;
without this delta, retain the built-in cyan fallback.

## 5. Acceptance

- The locked version equals GHCR's latest stable version at integration time.
- The default render contains no AuthGuard dependency resources; the enabled render contains them.
- Only selected components and infrastructure render, with correct Applications, routes, and Secrets.
- The authorized test release reaches Helm `deployed` and its workloads become ready.
- Metadata, Hosted Login/AuthN, and one protected route pass smoke tests.
- A real business-page sign-out reaches `POST /auth/logout`, clears the canonical cookie, and
  returns to `GET /auth/login` through the same Gateway origin without a 404.
- Optional theme assets mount only in Web, and the no-theme fallback remains functional.
- Normal service upgrades cannot own, upgrade, or delete the separate AuthGuard release.

React applications also complete the default [federation integration](federation.md) and its acceptance checks.
