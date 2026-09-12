# AuthGuard Architecture Overview

AuthGuard is a standalone, unified authentication and authorization product designed for deep Envoy Gateway integration. Its default topology is:

```text
Envoy Gateway
authguard-authn
authguard-authz
```

AuthN and AuthZ mount and read the same `authguard.yaml`; configuration is
partitioned by root section, not by duplicating files.

Responsibilities are intentionally narrow:

- Envoy Gateway owns the edge, TLS, routing, standard OIDC/JWT capabilities, and the PEP;
- `authguard-authn` owns Provider protocols, `ExternalIdentity` normalization, and account linking;
- `authguard-authz` authorizes only internal stable `principal_id` values.

> Envoy owns the edge. AuthGuard owns identity normalization and authorization.

## Identity and Principal

External identity and authorization Principal are separate:

```text
(provider, issuer, subject)
          │
          │ iam_principal_identity / Account Linking
          ▼
internal stable principal_id
```

One Principal may bind corporate DSP, GitHub, WeChat, and other identities. AuthZ never receives a GitHub ID, openid/unionid, DSP token, authorization code, or Provider access token.

AuthN emits one canonical contract:

```text
AuthenticatedPrincipalContext {
  principalId
  kind
  stableGroupIds
  trustedClaims
  acr
  amr
}
```

The AuthZ hot path batch-loads local Principal state by canonical IDs. Unknown or disabled Principals fail closed; AuthZ no longer JIT-creates a Principal from `iss/sub`.

## Providers and account linking

Provider YAML describes only authorization endpoints, token exchange, optional identity APIs, stable-subject extraction, and simple claim mapping. GET/POST differences, credentials in header/body/query, GitHub `/user`, WeChat `unionid/openid`, and DSP token translation remain inside AuthN.

The default account-linking strategy is `explicit`. Equal email addresses never cause automatic linking. Enterprises can declare a corporate DSP authoritative and allow users to explicitly bind GitHub/WeChat from an authenticated Principal session. Internet deployments may explicitly choose `first-login`.

## AuthZ model

AuthZ retains:

- `USER`, `WORKLOAD`, and `GROUP`;
- Action, Role, and RoleBinding;
- Resource URNs, parent URNs, and conditions;
- explicit DENY precedence and default deny;
- signed access contexts and opaque scope tokens;
- optional control-plane Keycloak, LDAP, and SCIM Principal federation/materialization.

Discovery connectors do not participate in login or the hot path. Materializing a candidate requires the canonical `principal_id` already resolved by AuthN.

## Protocol boundary

- GitHub OAuth is not OIDC; it commonly uses an access token to call GitHub `/user`;
- an ID Token is not UserInfo, and an Access Token is not a user identity;
- standard OIDC should prefer Envoy Gateway native support;
- GitHub/WeChat/DSP variance belongs in AuthN, without Envoy patches or Lua/Wasm;
- AuthGuard introduces no Kubernetes CRD or Controller.

## Keycloak

Keycloak is an optional external enterprise IdP integration, never a runtime dependency. Existing Keycloak Principal discovery/federation remains an optional management-plane capability. The default Helm topology does not deploy Keycloak.

> Keycloak is supported, never required.

## Source structure

```text
src/authn/       authguard-authn: Providers, ExternalIdentity, linking, identity bindings
src/authz/        authguard-authz: Principals, policy, ext_authz, Authorization Scope
src/adapters/    workload access-context SDKs
deploy/          default Envoy Gateway + AuthN + AuthZ deployment
```

See the [authentication and authorization whitepaper](iam-authorization-whitepaper.md) for the complete model and flows.
