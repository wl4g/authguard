# AuthGuard Web

React control-plane UI for AuthGuard authentication, Principal lifecycle, and
authorization policy administration.

```bash
npm ci
npm run dev
```

The Vite development server proxies AuthN to `AUTHGUARD_AUTHN_TARGET`
(`http://127.0.0.1:8082` by default) and AuthZ management APIs to
`AUTHGUARD_AUTHZ_TARGET` (`http://127.0.0.1:9090` by default). Production uses
same-origin `/auth`, `/.well-known/authn.json`, and `/api` routes by default;
set `VITE_AUTHN_BASE_URL` or `VITE_AUTHZ_BASE_URL` only when the gateway exposes
separate origins.

Wallet discovery is implemented with Reown AppKit as a client-only connection
and signing transport. Set `VITE_REOWN_PROJECT_ID`; AuthGuard remains the SIWX
challenge authority and signature verifier.
For extension-managed browsers and deterministic E2E, the same component also
accepts a standard injected EIP-1193 provider; no wallet vendor state crosses
the AuthN API boundary.

OAuth popups must return through the same public origin as this UI so the
opener can consume AuthGuard's JSON callback result. Provider `callbackUrl`
therefore needs to route `/auth/oauth2/{provider}/callback` through that origin.
