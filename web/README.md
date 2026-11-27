# AuthGuard Web

React Hosted Login and AuthGuard Dashboard. One image serves business-branded
Hosted Login and an independently accessible Dashboard. Business React applications can also load
management pages through ESM Module Federation; Hosted Login continues to use normal redirects.

```bash
npm ci
npm run dev
```

Production routes are deliberately narrow:

- `GET /auth/login` — Hosted Login SPA entry;
- `GET /auth/account/security` — authenticated credential enrollment;
- `GET /auth/assets/*` — Vite assets and configured branding images;
- `/.well-known/*`, `POST /auth/*` — AuthN, routed by Envoy;
- `/` and `/api/*` — either a dedicated AuthGuard Dashboard host or the relying
  business application's own routes.

The Vite development server proxies AuthN to `AUTHGUARD_AUTHN_TARGET`
(`http://127.0.0.1:8082` by default) and AuthZ APIs to
`AUTHGUARD_AUTHZ_TARGET` (`http://127.0.0.1:9090` by default). `authn.applications`
drives per-host metadata and branding. Browser authentication uses the
`HttpOnly` `authguard_token` cookie; this UI never writes an AuthGuard JWT to
localStorage.

Application entries may declare a same-origin Theme Pack:

```yaml
theme:
  id: customer
  stylesheet: /auth/assets/themes/custom/customer.css
```

The stylesheet can override AuthGuard CSS variables and layout selectors. The
Web image remains immutable: a business Chart normally packages its local
theme directory with `.Files.Glob` and exposes it through
`global.authguard.themeConfigMap`. AuthGuard does not execute theme JavaScript
or inject configurable HTML.

`web/public/` does not need an `assets` placeholder. Vite emits imported
application bundles to `dist/assets/`; production Nginx maps `/auth/assets/*`
to that directory, and Kubernetes may mount a business ConfigMap only at its
`themes/custom/` child. The generated bundle and deploy-time theme therefore
share a URL namespace without sharing a build or release lifecycle.

Brand text does not require a Theme Pack. With only `displayName` configured,
Hosted Login uses the built-in AuthGuard mark and cyan trust-fabric CSS while
still rendering the Host-resolved Application name. Application assets belong
in the integrating business Chart, not in `web/`.

Wallet discovery is implemented with Reown AppKit as a client-only connection
and signing transport. Set `VITE_REOWN_PROJECT_ID`; AuthGuard remains the SIWX
challenge authority and signature verifier.
For extension-managed browsers and deterministic E2E, the same component also
accepts a standard injected EIP-1193 provider; no wallet vendor state crosses
the AuthN API boundary.

OAuth uses a normal full-page authorization-code redirect. Provider
`callbackUrl` must route `/auth/oauth2/{provider}/callback` through the same
public origin; AuthN validates `return_to`, sets the cookie, and redirects to
the relying application.

## Module Federation

The remote is named `authguard`; configure an ESM remote pointing to
`/auth/assets/authguard-remoteEntry.js` on the same Gateway origin. React, React DOM and the JSX
runtime must be compatible singletons. Set `shareStrategy: 'loaded-first'` in the host to keep the
remote unloaded until the user enters Access Management. Exposes: `AccessManagement`, `Overview`, `Policy`,
`Principals`, `AccountSecurity`, and `settings`. Only `AccessManagement` supplies the management
sidebar; none supplies the standalone profile menu/header. Individual pages load independently.

```tsx
import * as authguard_react from 'react'
const authguard_remote = { access: authguard_react.lazy(() => import('authguard/AccessManagement')) }
// Render in place of the business sidebar/content; retain its header.
<authguard_react.Suspense fallback="Loading…">
  <authguard_remote.access authguard_locale="en_US" authguard_theme="light"
    authguard_modules={['overview', 'policy', 'principals', 'accountSecurity']}
    authguard_on_return={() => authguard_navigate(authguard_previous_workspace_route)}/>
</authguard_react.Suspense>
```

Wrap the slot with a host error boundary. Each page accepts the same `authguard_locale`,
`authguard_theme`, optional in-memory `authguard_api_token`, and required `authguard_on_return`.
The management API uses `/auth/management/api/*`; the Chart rewrites it to AuthZ `/api/*`, leaving
the host API namespace available. Credentials must come from an authorized session flow, never a
bundled service token. The standalone optional API credential input is under System settings.

Alternatively load `authguard/settings` and call `authguard_set_locale('zh_CN')` or
`authguard_set_theme('dark')`. They affect mounted/future remotes; explicit props take precedence.
Settings never modify host document attributes. Remotes isolate CSS in Shadow DOM and use a
MemoryRouter. All CSS classes/tokens/animations use `authguard-`, and new internal identifiers
use `authguard_`. Theme Packs now target `.authguard-root[data-application-theme='…']` and
`data-authguard-theme`, using `--authguard-*` tokens.

The complete host integration workflow and typed starter are maintained in
[the integrator skill](../.agents/skills/authguard-chart-integrator/references/federation.md).

Locale codes: `en_US`, `zh_CN`, `zh_TW`, `ja_JP`, `ko_KR`, `de_DE`, `fr_FR`. All catalogs have the same typed keys. The compact switch displays `EN / 中 / 繁 / 日語 / 한글 / DE / FR`; an explicit saved preference takes precedence over the browser locale.
