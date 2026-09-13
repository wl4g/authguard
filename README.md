# AuthGuard — one edge, one identity, one authorization decision

AuthGuard is a standalone, high-performance AuthN/AuthZ product for enterprise and internet applications. Envoy Gateway owns the edge and acts as the PEP; AuthGuard normalizes real-world OIDC/OAuth-like identities, links them to one stable Principal, and authorizes that Principal against resource-level policy.

```mermaid
flowchart LR
    subgraph Requesters[External requesters — same trust boundary]
        Browser[Browser / human user]
        Workload[Workload / external business system]
    end
    Admin[Enterprise administrator]
    EnterpriseIAM[Enterprise DSP / IAM platform]

    subgraph Edge[Edge / PEP(Policy Enforcement Point)]
        Envoy[Envoy Gateway<br/>TLS · routing · jwt_authn · ext_authz]
    end

    subgraph Guard[AuthGuard — one image, two runtime services]
        AuthN[authguard-authn<br/>OIDC / OAuth-like token exchange<br/>identity normalization · account linking<br/>sign canonical principal_id JWT]
        AuthZ[authguard-authz<br/>policy lookup by principal_id<br/>ALLOW / DENY · scope · JWT re-sign]
        IAM[(Shared IAM database<br/>Principal · Identity Binding<br/>Role · Action · RoleBinding)]
        Cache[(Redis<br/>opaque authorization scopes)]
        AuthN <--> IAM
        AuthZ <--> IAM
        AuthZ <--> Cache
    end

    IdP[External IdPs<br/>Keycloak · Entra · GitHub<br/>Google · WeChat · Corporate DSP]
    Directory[Enterprise directories<br/>Keycloak Admin API · LDAP · Custom HTTP]
    Biz[Biz microservices<br/>verify AuthGuard re-signed JWT<br/>apply SQL/resource scope]

    Browser <-->|1a. authorization redirect| IdP
    Workload <-->|1b. workload grant / proprietary login| IdP
    Browser -->|2. authorize + callback through edge| Envoy
    Workload -->|2. token exchange through edge| Envoy
    Envoy -->|3. authentication routes| AuthN
    AuthN <-->|4. code / token / ID Token / UserInfo| IdP
    AuthN -->|5. canonical JWT response| Envoy

    Browser -->|6. Biz request + canonical JWT| Envoy
    Workload -->|6. Biz request + canonical JWT| Envoy
    Envoy -->|7. ext_authz with principal_id| AuthZ
    AuthZ -->|8. ALLOW / DENY + resource scope<br/>short-lived authguardOrigin JWT| Envoy
    Envoy -->|9. authorized request| Biz

    Admin -->|A. pre-authorize / CRUD| AuthZ
    AuthZ -->|B. pull candidate search| Directory
    EnterpriseIAM -->|C. SCIM push lifecycle changes<br/>/scim/v2/Users · /scim/v2/Groups| AuthZ
```

The model has four boundaries: external Providers prove an identity; AuthN
normalizes it and resolves an identity binding; AuthZ sees only the internal
stable `principal_id`; Biz services accept only requests that passed Envoy and
apply the returned Resource URN scope. Browser and Workload are peer external
requesters; only their authentication grants differ. Keycloak/LDAP pull discovery
and SCIM push provisioning are complementary optional integrations, never runtime
dependencies.

- One `authguard` binary and image: `authn`, `authz`, and `console` subcommands.
- One shared `authguard.yaml`; Provider configuration describes protocol only, while account-linking policy owns account governance.
- GitHub is OAuth2, not OIDC; ID Token and UserInfo are different artifacts. Provider-specific IDs and tokens never enter AuthZ.
- Keycloak, Entra, LDAP, SCIM, DSP, and social IdPs are integrations—never runtime dependencies.
- No AuthGuard CRD/controller, no Lua/Wasm OAuth implementation, and no email-based automatic linking.

## 1. Build and run

Requirements: Rust 1.88+, Go 1.24+, JDK 21, Python 3.12, Helm 3.17+, and a Docker-compatible builder.

```bash
git clone https://github.com/wl4g/authguard.git
cd authguard
make build

# Both services read the same file.
./target/debug/authguard --config etc/authguard.yaml authn --bind 0.0.0.0:8082
./target/debug/authguard --config etc/authguard.yaml authz

# Interactive control-plane console, or append a batch operation.
AUTHGUARD_CONSOLE_TOKEN='<control-plane-secret>' \
  ./target/debug/authguard console --endpoint http://127.0.0.1:9091
```

`make test` runs Rust, adapter, use-case, and Helm checks. `make release` builds the release binary inside the image builder, publishes `ghcr.io/wl4g/authguard` plus the Aliyun mirror, publishes the chart to `oci://ghcr.io/wl4g/charts/authguard`, and pull-verifies it.

## 2. Deploy with Helm

Create the referenced Secret through your secret manager, then install the immutable OCI chart:

```bash
helm upgrade --install authguard oci://ghcr.io/wl4g/charts/authguard \
  --version 0.1.0 \
  --namespace authguard --create-namespace \
  --set authguard.authn.image.repository=ghcr.io/wl4g/authguard \
  --set authguard.authz.image.repository=ghcr.io/wl4g/authguard \
  --set secrets.kubernetes.existingSecret=authguard-runtime
```

Choose the smallest topology that matches the product:

| Scenario | AuthN | AuthZ | Account-linking policy |
|---|---:|---:|---|
| 2B collaboration and administrator pre-authorization | on | on | `explicit`; corporate IdP is authoritative |
| 2C with resource/tenant authorization | on | on | `first-login`; every new external identity may create a Principal |
| 2C authentication-only application | on | off | application owns its own coarse access rules |

Authentication-only 2C deployment:

```bash
helm upgrade --install authguard oci://ghcr.io/wl4g/charts/authguard \
  --version 0.1.0 --namespace authguard --create-namespace \
  --set authguard.authz.enabled=false \
  --set envoy_gateway.ext_authz.enabled=false
```

When AuthZ is disabled, do not attach Envoy `ext_authz`; standard OIDC and OAuth-like login still go through AuthN, and Envoy accepts only the resulting canonical AuthN JWT. When AuthZ is enabled, an unknown or disabled `principal_id` always fails closed.

Both Deployments mount the same `authguard.authguard-config`. Supply a complete production file with `--set-file authguard.authguard-config=authguard.yaml`; nested values can also be overridden by `AUTHGUARD__...` environment variables.

Enterprise federation uses renewable credentials, not pasted access tokens:

- Keycloak discovery stores a confidential service-account `client_id`/`client_secret`; AuthGuard performs `client_credentials` and refreshes the access token before Admin REST calls.
- LDAP uses a least-privilege bind DN/password because LDAP bind does not issue JWTs.
- SCIM is push provisioning. The enterprise provisioner obtains its own short-lived workload credential and calls the protected RFC 7644 `/scim/v2/Users` and `/scim/v2/Groups` resources; no SCIM access token is stored in `authguard.yaml`.
- Secrets belong in Kubernetes Secret, Vault, AWS Secrets Manager, or GCP Secret Manager references. Keycloak remains optional and is never installed by this chart.

See [`deploy/helm/authguard/values.yaml`](deploy/helm/authguard/values.yaml) for connector examples and [`etc/authguard.yaml`](etc/authguard.yaml) for the complete shared schema.

## 3. Pre-authorize with the console

The console talks only to AuthZ `/api/v1`; it preserves validation, reference checks, cache invalidation, logs, metrics, and optimistic policy revision control.

```bash
export AUTHGUARD_CONSOLE_ENDPOINT=http://authguard.authguard.svc:9091
export AUTHGUARD_CONSOLE_TOKEN='<control-plane-secret>'

# Federated administrator flow: search, materialize, then bind a role.
authguard console discover --file principal-search.json
authguard console materialize --file principal-materialization.json
authguard console create action --file action.json
authguard console create role --file role.json
authguard console create role-binding --file role-binding.json

authguard console list principals
authguard console policy get
authguard console status
```

## 4. Access a protected Biz service

Browser user through a social/OAuth-like Provider:

```text
Open https://app.example.com/auth/v1/providers/github/authorize
  → Envoy → AuthN authorize/callback/token exchange/UserInfo
  → ExternalIdentity → identity binding → canonical principal_id
  → Envoy jwt_authn → AuthZ ext_authz → Biz UI/API
```

Workload through enterprise OAuth2 client credentials:

```bash
EXTERNAL_TOKEN=$(curl -fsS https://idp.example.com/oauth2/token \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d grant_type=client_credentials -d audience=customer-growth-job-service \
  | jq -r .access_token)

WORKLOAD_TOKEN=$(curl -fsS https://app.example.com/auth/v1/providers/corporate-oidc/token-exchange \
  -H 'content-type: application/json' \
  -d "{\"subjectToken\":\"${EXTERNAL_TOKEN}\",\"kind\":\"WORKLOAD\"}" \
  | jq -r .accessToken)

curl -fsS https://jobs.example.com/api/v1/customer-growth/jobs \
  -H "Authorization: Bearer ${WORKLOAD_TOKEN}"
```

The hot path is `Envoy jwt_authn → AuthGuard ext_authz → Biz Service`. Business services see canonical identity and signed/opaque authorization scope only. The reproducible Helm-to-database/log/metric/Jaeger validation lives in [`use-cases/customer-growth-job-service/e2e`](use-cases/customer-growth-job-service/e2e).

Architecture details: [`docs/architecture/iam-authorization-whitepaper.md`](docs/architecture/iam-authorization-whitepaper.md).
