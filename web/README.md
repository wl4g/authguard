# AuthGuard Web

React Hosted Login and AuthGuard console. One image serves business-branded
Hosted Login without an SDK, iframe, Module Federation, or copied UI code.

```bash
npm ci
npm run dev
```

Production routes are deliberately narrow:

- `GET /auth/login` — Hosted Login SPA entry;
- `GET /auth/account/security` — authenticated credential enrollment;
- `GET /auth/assets/*` — Vite assets and configured branding images;
- `/.well-known/*`, `POST /auth/*` — AuthN, routed by Envoy;
- `/` and `/api/*` — either a dedicated AuthGuard Console host or the relying
  business application's own routes.

The Vite development server proxies AuthN to `AUTHGUARD_AUTHN_TARGET`
(`http://127.0.0.1:8082` by default) and AuthZ management APIs to
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
