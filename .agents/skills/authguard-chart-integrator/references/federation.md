# React business UI integration

Default to completing the business React UI integration along with the Chart. Inspect the actual
package manager, React version, build tool, router, header dropdown, sidebar and session mechanism.
Do not stop at snippets: install dependencies, edit the real host configuration and mount the remote.
Use the pinned release's federation contract; a release without the remote entry must be upgraded
or reported as blocked, never silently replaced with an iframe.

## Remote and routing contract

AuthGuard is an ESM Module Federation remote named `authguard`. Register it with explicit
`type: 'module'` and entry `/auth/assets/authguard-remoteEntry.js` on the **business Gateway origin**.
This path is already covered by the Web assets HTTPRoute; do not route the business catch-all to Web.
The stable entry must revalidate (`Cache-Control: no-cache`); hashed chunks can be immutable.
AuthGuard management calls use `/auth/management/api/*`, rewritten by the Chart to AuthZ `/api/*`.
Keep the host's own `/api/*` ownership. Enable AuthZ management API only when required and obtain
any management credential from the existing authorized server/session flow. Never put a shared
service API token in `VITE_*`, source files or a frontend bundle. An in-memory, short-lived token can
be passed as `authguard_api_token`; hiding menu items is not server-side authorization.

For a Vite host, install `@module-federation/vite` as a dev dependency with the host's package
manager, preserving its lockfile. Reuse an existing federation configuration; otherwise add:

```ts
import { federation as authguard_federation } from '@module-federation/vite'
// Merge into the existing plugins array, retaining its framework plugin.
authguard_federation({
  name: 'authguard_business_host',
  shareStrategy: 'loaded-first',
  remotes: {
    authguard: { type: 'module', name: 'authguard', entry: '/auth/assets/authguard-remoteEntry.js' },
  },
  shared: {
    react: { singleton: true },
    'react-dom': { singleton: true },
    'react/jsx-runtime': { singleton: true },
  },
})
```

For Webpack/Rspack, use the corresponding Module Federation enhanced plugin with the same ESM
remote and singleton contract. Check the actual host/remote React compatibility; do not silently
force a second React copy. Copy/adapt [remote declarations](../assets/authguard-remotes.d.ts) into
the host's TypeScript include path. Retain the host's routing and authentication controls.

## Mount and navigation

- Add a left first-level `Access Management` / `访问管理` entry and a matching item in the existing
  top-right dropdown. Inside that dropdown, use compact `EN / 中 / 繁 / 日語 / 한글 / DE / FR` language buttons and adjacent `Light / Dark`
  buttons with `aria-pressed` for direct selection; do not nest preference selects or submenus.
  Both navigation entries activate the **same** host route/state. Default to `/access-management/*`
  if the host has no convention. Remember the previous business route and preserve browser history.
- In that mode, replace the host body (sidebar + content) with `authguard/AccessManagement`; keep
  the business header mounted. The remote contains only its management sidebar and pages, never
  AuthGuard's standalone header/profile dropdown. Do not render both sidebars together.
- Pass `authguard_on_return` to restore the prior workspace route/sidebar, with a safe workspace
  fallback for direct deep links. The remote has a persistent lower-left return button for every
  selected page. Use client navigation, never a full-page reload for mode changes.
- Pass the host's current `authguard_locale` (`en_US`, `zh_CN`, `zh_TW`, `ja_JP`, `ko_KR`, `de_DE`, `fr_FR`) and `authguard_theme`
  (`light`/`dark`/`system`) as reactive props. Alternatively import `authguard/settings` and call
  `authguard_set_locale()` / `authguard_set_theme()`; these update mounted and future remotes.
  Controlled props take precedence over setters. Never change host HTML attributes from a remote.
- Default to all pages. Limit `authguard_modules` to `overview`, `policy`, `principals`,
  `accountSecurity` when explicitly requested. For a host-owned sidebar, import only the required
  `authguard/Overview`, `/Policy`, `/Principals`, `/AccountSecurity` modules. Each page accepts the
  same environment and return callback props and owns its providers; do not wrap host providers
  around it or import AuthGuard `main.tsx`.
- Lazy-load behind Suspense and an error boundary with a return action. The
  [host slot](../assets/authguard-access.tsx) is a starting point; adapt it to host styling and
  its error recovery convention. Preserve business state and header while loading or failing.

## Isolation and acceptance

All AuthGuard CSS classes, variables, animations and new internal identifiers use `authguard-`
or `authguard_` prefixes. Remotes mount styles inside Shadow DOM, scope tokens to `.authguard-root`,
and own a MemoryRouter. Never copy global resets into the host or move remote dialogs to `body`.
Hosted Login Theme Packs target `.authguard-root[data-application-theme='<application-id>']` and
`data-authguard-theme`, with `--authguard-*` tokens.

Run the host's typecheck/build and real browser checks through the Gateway. Exercise both entry
points, every selected remote page, return from each page, repeated switches, back/forward,
refresh/deep link, locale/theme changes while mounted and unmounted, dark/system, narrow layouts,
remote load failure, session expiry and recovery. Assert exactly one sidebar and one host header,
no document-level preference/style changes, no host computed-style changes, no horizontal overflow,
no duplicate React errors and no remote entry requests before first activation. Report measured
switch latency and test evidence; never claim full backend E2E from mocked browser fixtures.

Use the repository standard runner (`runner.py --scenario 32`) for local production-bundle browser
acceptance. Preserve its round report/evidence paths; never write screenshots to a separate root.
