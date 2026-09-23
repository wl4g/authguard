---
name: authguard-chart-integrator
description: Integrate the latest stable AuthGuard Helm Chart into any business service Helm Chart. Use when a service needs to discover and fetch the newest AuthGuard tgz from GHCR into charts/, add an opt-in authguard-middleware.enabled lifecycle, obtain the real business service domain from the developer, configure AuthN/AuthZ/Web/Gateway/Application values and secrets, optionally add a Hosted Login theme, validate disabled and enabled renders, or run an authorized Kubernetes deployment smoke test.
---

# AuthGuard Chart Integrator

Integrate the complete AuthGuard release lifecycle into a business service Helm Chart. Treat
Hosted Login theme customization as an optional extension, not the purpose of the integration.

## Workflow

1. Read [references/contract.md](references/contract.md) completely before editing.
2. Locate the business service Helm Chart from its `Chart.yaml`; never assume a fixed repository
   path. Inspect its values hierarchy, workload gates, Gateway ownership, secrets conventions,
   application hosts, and existing dependencies before editing.
3. Establish the Chart root, enabled components, infrastructure ownership, image registry policy,
   secret sources, and target test environment. Find the real public business service domain(s),
   allowed return paths, and workload gate in the request or repository. If any domain is unknown,
   stop and ask the developer for it; never substitute a reserved documentation domain, another
   invented domain, or a localhost value intended only for tests.
4. Query `oci://ghcr.io/wl4g/charts/authguard` for its latest stable version, fetch that version
   into the discovered Chart's `charts/` directory with `helm pull` (Helm 3's replacement for
   legacy `helm fetch`), then pin the resolved version in `Chart.yaml`. Alias the dependency as
   `authguard-middleware`, gate it with `authguard-middleware.enabled`, and run
   `helm dependency update` to generate `Chart.lock`; never hand-edit the lock or leave a floating
   dependency.
5. Use exactly one top-level `authguard-middleware:` map in business `values.yaml`. Put
   `enabled: false`, the AuthGuard Chart values unchanged, and business integration fields under
   that map; never add a parallel AuthGuard root. Configure only required components and runtime
   dependencies, reuse the service's secret mechanism, and never commit secret values. Prefix
   child overrides accordingly, for example `authguard-middleware.authguard.authz.enabled`.
6. Configure host-derived `authn.applications`, safe HTTPS return URIs, Gateway routes, protected
   route labels, and namespace grants from the actual service topology. Route the browser-facing
   business Web workload through the same Gateway origin as `/auth/*`; never validate UI behavior
   through its NodePort, port-forward, or direct Service address. Keep the normal service release
   independent from the explicit AuthGuard middleware release.
7. Only when a custom Hosted Login theme is requested, create `files/authguard-theme/`, add the optional
   ConfigMap template, and apply the rules below. Use [assets/theme.css](assets/theme.css) and
   [assets/authguard-theme.yaml](assets/authguard-theme.yaml) as starting points without changing
   AuthGuard Web source.
8. Run `scripts/validate.py` to verify the pinned GHCR dependency, lock/tgz, opt-in values, lint,
   and both disabled/enabled renders. Add `--application-id` for Application validation. Use its
   explicit deployment arguments only for an authorized disposable or designated test namespace.
9. For deployment validation, wait atomically for the explicit middleware release, inspect Helm
   status and workload readiness, then exercise the relevant metadata, Hosted Login, AuthN, and
   protected-route smoke paths. Remove the test release only when cleanup is authorized.
10. Report dependency/version/digest, values and ownership decisions, render and deployment
    evidence, optional theme files, and any operator-supplied secrets still required. Do not publish
    or deploy to an unspecified cluster.

## Optional theme rules

- Scope every rule under `:root[data-application-theme='<application_id>']`.
- Preserve all authentication controls and focus/disabled/error states.
- Define light and dark tokens; keep mobile behavior below 900px and respect reduced motion.
- Forbid `@import`, remote URLs, JavaScript, HTML, `foreignObject`, tracking pixels, and executable SVG.
- Keep the ConfigMap safely below 1 MiB and asset basenames unique.
- Verify that an Application without theme assets uses AuthGuard's built-in cyan fallback.

## Validation

Fetch the latest stable release before editing the dependency:

```bash
helm show chart oci://ghcr.io/wl4g/charts/authguard
helm pull oci://ghcr.io/wl4g/charts/authguard \
  --version <version-reported-by-helm-show> \
  --destination <path-to-business-service-helm-chart>/charts
# On Helm installations retaining the legacy alias, `helm fetch` accepts the same arguments.
helm dependency update <path-to-business-service-helm-chart>
```

Render-only validation:

```bash
python3 .agents/skills/authguard-chart-integrator/scripts/validate.py \
  --chart <path-to-business-service-helm-chart> \
  --application-id <application-id> \
  --application-host <developer-provided-business-service-domain> \
  --set <business-workload-gate>=false
```

Authorized deployment validation:

```bash
python3 .agents/skills/authguard-chart-integrator/scripts/validate.py \
  --chart <path-to-business-service-helm-chart> \
  --application-id <application-id> \
  --application-host <developer-provided-business-service-domain> \
  --set <business-workload-gate>=false \
  --deploy-release <authguard-test-release> \
  --deploy-namespace <authguard-test-namespace> \
  --cleanup-deployment
```

Repeat `--values` and `--set` for service-specific prerequisites. Deployment arguments mutate the
current Kubernetes context; use them only after confirming the target cluster and namespace.
