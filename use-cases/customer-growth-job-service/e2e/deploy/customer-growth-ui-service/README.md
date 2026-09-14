# Customer Growth UI Service

Minimal React application used by customer-growth UI automation. Authentication
capabilities are discovered from `/.well-known/authn.json`; GitHub, Google,
WeChat, QQ, password/TOTP, and CAIP wallet flows call the same AuthGuard AuthN
deployment.

The ordered `s19_customer_growth_ui_verifier.py` scenario loads the deployed
SPA through Envoy, checks its automation selectors and assets, validates dynamic
capability discovery, and proves `/auth/wallet/*` takes precedence over the SPA
fallback route.

```bash
npm ci
VITE_REOWN_PROJECT_ID=<public-project-id> npm run build
```

Reown AppKit is client-only wallet discovery and signing transport. The browser
signs the exact SIWX message returned by AuthGuard, then sends only
`challengeId` and `signature` to `/auth/wallet/verify`.
