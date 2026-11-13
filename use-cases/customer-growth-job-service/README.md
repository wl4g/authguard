# Customer Growth Job Authorization

This portable E2E use case models an enterprise data team that collaborates on
customer growth jobs in the same workspace. Analysts, job runners, workspace owners,
external users, and auditors have different Resource URN grants while querying
the same `customer_growth_jobs` business table.

The example exercises the complete application-side authorization path:

```text
caller -> Envoy JWT authentication -> AuthGuard AuthZ (ext_authz)
       -> signed Authorization Scope -> business SDK -> scoped SQL -> database
```

Every `sNN_description.py` exposes `E2ESNNDescriptionVerifier` with
`deploy(context)`, `init(context)`, and `verifier(context)` in that order.
Scenario 00 owns the complete deployment; other scenarios reuse it unless they
explicitly require redeployment or initialization. Scenario 10 still orchestrates
its protocol sub-scenarios 11–15 with the same prerequisite ordering and assertions.
The 11 runner groups cover deployment and the real request path. OTEL signals are metrics (40), tracing (41), and logs (42); persistent data is verified inside the AuthN, AuthZ, gateway, or browser scenario that produces it. There is no separate storage/cache scenario. All five business services are checked through HTTP and PostgreSQL; SDK unit tests are outside the E2E runner.
The architecture boundaries in `docs/architecture/overview_ZH.md` and the two IAM
whitepapers remain covered by authentication, Principal federation/provisioning,
SDK scopes, gateway CRUD, browser login and runtime evidence. Planned capabilities
listed as gaps in `docs/plans/iam-implementation-gaps_ZH.md` are not claimed as implemented tests.



The suite deploys the complete request path through Kubernetes or Docker Compose:
Keycloak as an E2E-only external IdP, Envoy Gateway or Envoy, AuthN/AuthZ, Redis,
PostgreSQL, LDAP, Jaeger, local Anvil/Solana nodes, and all five HTTP services.
It also deploys the repository's production `authguard-web` image on the AuthN
listener. Playwright drives real headless Chromium journeys for GitHub, Google,
WeChat, QQ, password, WebAuthn, CAIP wallet, Principal, and Policy controls.
It additionally proves the Envoy Gateway JWT public-key requirement with a
deterministic realm key, the workload OAuth2 client_credentials flow, and the
resign-JWT Authguard-origin boundary inside a business microservice.

## Structure

```text
customer-growth-job-service/
  deploy/                              horizontal service/component ownership
    <component>/
      source/                          deployable mock service implementation only
      Dockerfile                       buildable component only; upstream middleware uses pinned images
      docker-compose.yaml              component-owned Compose service
      helm/                            component-owned Chart, values and templates
    authguard/config/                  AuthGuard deployment overrides and E2E signing keys
    authguard/Dockerfile                link to the production server Dockerfile
    postgresql/source/init.sql         shared SQL seed data
  verifier/                            vertical scenario ownership
    context.py                         VerificationContext and shared runtime/result contract
    scenarios.json                     shared verification inputs and expected outcomes
    infra/s00..s02_*.py
    authn/s10..s15_*.py
    authz/s20_*.py, s26_*.py
    web/s30..s31_*.py
    otel/s40_metrics.py, s41_tracing.py, s42_logs.py
  util/
    process.py                         E2EProcessHelper
    images.py                          E2EImagesDefinitions; the only image matrix
    constant.py                        E2EOtherDefinitions; case paths and topology
    postgres.py, sqlite.py             reusable import/query helpers
    kubernetes.py, docker.py           backend deployers, cleaners and runtime detection
    report.py                          E2EReportHelper; Markdown and rolling archives
    helm/                              shared Helm library
    maven/settings.xml                 common build-tool configuration
    .venv/                             ignored local Python environment
  reports/                             ignored reports, evidence and archived rounds
  runner.py                            common entry point
  docker-compose.yaml                  component composition and dependencies
  requirements.txt
```

Each locally built mock business service keeps only its deployable implementation
in `source/`, beside its Dockerfile, Compose definition and Helm Chart.
Configuration-only middleware keeps its custom input under `source/`; AuthGuard
deployment overrides and test signing keys live under `deploy/authguard/config/`.

All E2E verification code under `verifier/` is Python. Services contain no
acceptance-test source directories or external UT profiles. AuthZ 26 verifies
all five deployed services: JWT/authorization gates, scoped row visibility,
query-filter intersections, complete JSON request/response fields, CRUD,
PostgreSQL persistence, unchanged seed rows after denied calls, and distributed
traces. The existing AuthN, Principal, browser, metrics, tracing and log checks
remain in their owning scenarios.

SDK unit tests belong to [`src/sdk`](../../src/sdk) and run through the normal
product test targets. They are not invoked or counted by the E2E runner.
Use `runner.py`, `make e2e`, `e2e-k8s`, or `e2e-docker` for deployment verification.

The canonical resource shape is:

```text
urn:iam:prod:customer-growth:<region>:<tenant_id>:workspace/<workspace_id>/project/<project_id>/job/<job_id>
```

## Run

Run one clean round from the repository root:

```bash
make e2e
```

Run repeated clean rebuilds or one verifier directly:

```bash
# Run this block from use-cases/customer-growth-job-service/.
python3 -m venv util/.venv
util/.venv/bin/python -m pip install -r requirements.txt
util/.venv/bin/python -m playwright install --only-shell chromium
util/.venv/bin/python runner.py --rounds 3
util/.venv/bin/python runner.py --scenario 01,02
util/.venv/bin/python runner.py --list
util/.venv/bin/python runner.py --scenario 01,02,00,20,10,26,30,31,40,41,42 --cleanup-after-run
```

By default, every round cleans the selected deployment, builds its service images,
and verifies the deployed request path. `--skip-clean` is available for local
diagnosis. Reports are written to `reports/`; previous reports are archived
before the next invocation.
Deployment resources are retained by default for troubleshooting. Add
`--cleanup-after-run` to remove resources owned by the selected backend after
success, failure, or interruption.

Run the real Kubernetes path from the repository root:

```bash
HTTPS_PROXY=http://127.0.0.1:8800 make e2e-k8s
```

The Kubernetes deployer uses the current `KUBECONFIG`/context; CI supplies its
native K3s kubeconfig explicitly. Runtime differences stay in one image loader:

| Environment | Local image handling |
| --- | --- |
| Colima Docker/K3s | Use the profile's Docker context and verify it shares the VM daemon; no import or image deletion |
| Colima containerd/K3s | Export from Docker and import through `colima -p <profile> ssh -- ... ctr` |
| OrbStack Docker/Kubernetes | Use Docker context `orbstack`; Pods share its image store |
| Native Docker-backed Kubernetes | Reuse the local node's Docker daemon |
| Native K3s/Kubernetes containerd | Import on the node through local `k3s ctr` or `ctr` |

Standalone Docker Compose continues to use the selected Docker context. Existing
kind, minikube, and K3d loaders are also retained. Set
`AUTHGUARD_E2E_KUBERNETES_IMAGE_LOADER` to one of those values to select it
explicitly; set `AUTHGUARD_E2E_KUBERNETES_CLUSTER` when an explicit kind or
K3d target is not encoded in the current context. Host-containerd loading is
only selected when the active Kubernetes node resolves to the local host.

The image policy is centralized in `util/images.py`. macOS, Linux and Windows
use Linux container engines and select **`linux/amd64` for every normal service**,
including on ARM64 nodes with instruction translation enabled. Solana on macOS is
the sole native ARM64 exception. The loader never changes the default platform
back to the Kubernetes node architecture.

| Host | Network | Solana reference | Solana platform | Other images |
| --- | --- | --- | --- | --- |
| macOS | IN_GFW / NON_GFW | `registry.cn-shenzhen.aliyuncs.com/wl4g/anza_solana:3.1.14-arm64` | `linux/arm64` | `linux/amd64` |
| Linux / Windows | IN_GFW | `registry.cn-shenzhen.aliyuncs.com/wl4g/anza_solana:3.1.14` | `linux/amd64` | `linux/amd64` |
| Linux / Windows | NON_GFW | `docker.io/anzaxyz/agave:v3.1.14` | `linux/amd64` | `linux/amd64` |

The macOS Solana mirror is the explicit exception in both regions, matching the
AgentVault audited image policy. To use the already-loaded short tag instead,
set `AUTHGUARD_E2E_SOLANA_IMAGE=solana:3.1.14-arm64`. This is a local alias; the
runner requires it to be preloaded and does not try to download a nonexistent
Docker Hub `library/solana` image. `AUTHGUARD_E2E_SOLANA_PLATFORM` is exported by
the matrix and consumed by Compose, pull/cache checks and containerd imports.

IN_GFW resolves dependencies/build bases through Aliyun; NON_GFW resolves their
official Docker Hub, GHCR or Quay repositories. Anvil uses the pinned official
`ghcr.io/foundry-rs/foundry:v1.7.1` image overseas, with an explicit `anvil`
entrypoint. Test application images are local build outputs tagged under the
selected Aliyun/GHCR namespace. Explicit CI image overrides remain supported.
The normal E2E build does not rebuild Anvil or Solana from source.
Aliyun Python uses `python:3.12-slim-amd64`; the existing ARM64-only
`python:3.12-slim` tag is preserved for other consumers.

`deploy/solana/Dockerfile` is an exact copy of the audited AgentVault Dockerfile.
For an explicit source build, its context must be a clean official Agave checkout
including `.git`, at the pinned version/revision. `RUST_BUILDER_IMAGE` and
`RUNTIME_IMAGE` are supplied by the matrix as the common Rust 1.99.1 Slim and
Debian Trixie Slim bases; the Dockerfile retains source and dependency lockfiles
in the output image. A macOS build through `util/images.py` selects ARM64 for
this component without changing the other E2E images. Follow the audited
Dockerfile example with `E2E_IMAGE_NETWORK=NON_GFW` for an ARM64 source build:
the current Aliyun Rust/Debian base tags contain AMD64 only. The normal E2E
uses the already-published native ARM64 Solana image and does not require
this expensive source build.

The two CI E2E jobs use separate Ubuntu 24.04 runners. The fixed OS baseline
avoids Ubuntu 26.04's containerd/AppArmor stacked-profile signal regression
([containerd#14485](https://github.com/containerd/containerd/issues/14485)), which
can leave PostgreSQL in startup while denying its internal process signals.
Self-hosted affected nodes need the corrected runtime AppArmor policy; the
workloads retain their normal confinement. `AUTHGUARD_E2E_RUNNER` still selects
an explicitly managed runner.

PostgreSQL uses the same 18.6 upstream build in both image sources. Its Kubernetes
startup probe checks the Pod's TCP listener rather than the temporary loopback
server used during initialization. Rollout failures include Pod state, recent
container logs and Kubernetes events in the report before cleanup.

Each round removes and recreates an `e2e-` namespace and installs component-scoped Helm releases.
The normal Customer Growth support/workload release uses the business Chart's
default `authguard.enabled=false`. A separate one-time release of that same
Chart enables its vendored `charts/authguard-0.1.0.tgz`; `.Files.Glob` packages
`files/authguard-theme/` into an immutable ConfigMap. This models normal
business upgrades without rebuilding a theme image or owning the AuthGuard
middleware lifecycle.

All image references (including build bases and AuthGuard's own modules) are
selected by `util/images.py`. Component Charts keep image fields empty and
component Compose files require the matrix environment; Dockerfiles receive
base-image arguments from the same catalog. Environment overrides are applied
once there. Do not add a versioned image URL to a component definition.

From `use-cases/customer-growth-job-service/`, the same wrapper supports standard standalone deployment commands:

```bash
util/.venv/bin/python util/images.py -- helm template jaeger deploy/jaeger/helm -n e2e-authguard-system
util/.venv/bin/python util/images.py -- helm install jaeger deploy/jaeger/helm -n e2e-authguard-system --create-namespace
util/.venv/bin/python util/images.py -- docker compose -f deploy/jaeger/docker-compose.yaml up -d
util/.venv/bin/python util/images.py -- docker build -f deploy/biz-rust-sqlx-service/Dockerfile ../..
```

Each Chart owns its resources; PostgreSQL owns shared database bootstrap, and
the AuthGuard integration Chart owns shared credentials. The runner supplies
those integration values to dependent services. Five business Charts reuse one
local Helm library instead of copying deployment logic. The Envoy Gateway
controller requires Kubernetes even when run through its optional Compose
profile; the Compose test topology uses the separate native Envoy component.
The E2E signing test data are test-only, not production secrets.

Run the equivalent Docker Compose path when Kubernetes is unavailable:

```bash
HTTPS_PROXY=http://127.0.0.1:8800 make e2e-docker
```

It runs the same real PostgreSQL, Redis Cluster, Keycloak, LDAP, Jaeger,
Anvil, Solana, AuthN/AuthZ/Web, native Envoy PEP, and five business workloads.
The business theme directory is bind-mounted only into AuthGuard Web. Use
`make e2e-cleanup E2E_DEPLOYER=docker` to remove its isolated project and
volumes.
Authguard first starts with the Action/Role catalog and no RoleBinding. A mock
external social IdP then drives the real browser protocol through Envoy's
public AuthN listener: authorize redirect, callback, POST token exchange,
userinfo lookup, `ExternalIdentity` normalization, durable account linking,
and canonical-token issuance. AuthN and AuthZ share one PostgreSQL IAM schema,
so AuthZ sees the resulting internal Principal without learning the provider
subject. The administrator binds those Principal IDs in one revision-checked
policy replacement. A second login must resolve to the same IDs before any
business request is sent. Equal email values are never used for linking.

Wallet success cases do not mock chain RPC. A disposable Anvil node validates
ERC-1271 contract wallets, while a real local Solana validator anchors the test
account and CAIP-2 genesis reference. EVM EOA, Solana Ed25519, and Bitcoin
BIP-322 authentication requests are then verified entirely offline by AuthN;
only contract-wallet chains receive a server-configured RPC. The mock IdP has
one wallet endpoint solely for deterministic RPC-timeout fault injection.

The same verifier exercises every supported Principal-discovery path with live
dependencies. Repeated materialization proves canonical projection is idempotent.
Authguard then searches one LDAP-only user through the Keycloak Admin API and
materializes it twice, proving Keycloak's LDAP federation path; a separate
RFC 4511 connector resolves the same directory entry by its immutable UUID and
also materializes it idempotently. Finally, SCIM RFC 7643 User and Group events
exercise repeated upsert, disabled tombstone, and reactivation behavior. SCIM
records converge only when the request supplies the same canonical
`principal_id`; equal external subjects or emails never trigger a merge. The generated report
contains provider paths, lifecycle results, counts, and stable-identity
assertions, but never bearer tokens, client secrets, or LDAP bind credentials.

### Deterministic realm signing key

The realm imports a fixed RSA key pair (see `deploy/authguard/config/jwt-keys/`) through the
realm `keys[]` signing data instead of letting Keycloak generate one at first start.
The paired public JWKS is rendered as a ConfigMap by the support chart, and the
Authguard SecurityPolicy consumes it through `localJWKS.existingConfigMap`, so
Envoy Gateway JWT verification never depends on a dynamic realm key that would
invalidate existing tokens or drift across `--skip-clean` redeploys. The
verifier asserts the SecurityPolicy loads that exact ConfigMap.

### Workload client_credentials (machine identity)

The realm defines the confidential client `e2e-growth-job-runner` with service
accounts enabled, an audience mapper stamping `customer-growth-job-service`,
and canonical `principal_id`/`principal_kind=WORKLOAD` claims. The verifier exchanges the SA secret for an
access token with `grant_type=client_credentials` — no browser, no user login —
asserts the audience claim, then sends it through Envoy: the JWT provider
verifies the signature (foreign tokens would fail with HTTP 401) and Authguard
denies the unbound SA with HTTP 403, proving both gates ran on the
machine-identity flow.

### Resign-JWT origin boundary

Authguard re-signs every allowed request as a short-lived RS256 JWT carrying
`authguardOrigin: true`. The rust-sqlx service mounts the paired public key
(`resign-jwt-key.pub.pem`) and enforces the boundary in its middleware: the
valid user JWT re-signed by Authguard passes through Envoy and is accepted,
while the same AuthN canonical token sent directly to the workload — bypassing Envoy —
is rejected with HTTP 401, proving business microservices can refuse direct
client calls.

The services share database `e2e_customer_growth`. AuthN and AuthZ share the
dedicated `e2e_authguard` login and `authguard` IAM schema; that schema has one
`iam_principal` table plus the AuthN-owned identity bindings and AuthZ-owned
policy tables. Business services connect through separate login roles and schemas:
`e2e_customer_growth_go_sqlx`, `e2e_customer_growth_rust_sqlx`,
`e2e_customer_growth_python_sqlalchemy`, `e2e_customer_growth_spring_jdbc`, and `e2e_customer_growth_spring_jpa`.
Cross-schema `USAGE` is denied and verified. The Python verifier calls the same
HTTP list/get/create/update/delete contract for every implementation, verifies
direct and opaque scope delivery, and checks that rejected writes do not mutate
PostgreSQL.

The Kubernetes verifier also proves the authentication and authorization order
from live runtime evidence: a tampered AuthN JWT increments Envoy's
`jwt_authn.denied` counter without calling Authguard, while a valid AuthN JWT
increments `jwt_authn.allowed`, `ext_authz.ok`, and exactly one
`envoy.service.auth.v3.Authorization/Check` request. It inspects Envoy's runtime
xDS configuration to require `jwt_authn -> ext_authz -> router`, then queries the
Jaeger API for one W3C trace containing `e2e-keycloak`, `e2e-envoy-proxy`, and
`authguard-authz` spans. The trace models the real causality as two verifier client
branches—an auxiliary workload token issuance from optional Keycloak, followed
by the protected request to Envoy;
Authguard's Check span must be an Envoy descendant. The report records the trace
ID and a local Jaeger UI command for independent review.

Runtime and build images default to the Aliyun mirror. Exact versions for both
Aliyun and global sources are maintained only in `util/images.py`.

Portable-mode prerequisites are the same local toolchains used by the
repository: Rust/Cargo, Go, Python 3 with SQLAlchemy, Java 17/Maven, and their
cached or reachable package repositories. Kubernetes mode additionally needs
Docker, Helm, kubectl, and a local Kubernetes cluster. The authentication verifiers use PyOTP as
an RFC 6238 authenticator-app oracle, FIDO2 CBOR plus `cryptography` for a real
virtual ES256 WebAuthn ceremony, and `viem` for browser-wallet-equivalent
EIP-191 signing. AuthGuard still performs every server-side verification.

Shared verifier modules are limited to actual reuse: `authn/authn_protocol.py`
provides protocol-neutral login assertions to five authentication protocols;
`otel/otel_contract.py` provides trace generation, Jaeger queries and
trace graph assertions to authentication and authorization scenarios;
`web/browser_authenticator.py` provides the wallet and CTAP2 browser transport
to both browser journeys; `sdk/sdk_scenario.py` runs the five service test suites
and checks their shared authorization matrix. Metrics and log assertions live in
their numbered scenarios.

Persistent-state checks follow the function being exercised:

| Scenario | Persistent assertions |
| --- | --- |
| 00 infrastructure | AuthGuard IAM schema migrations |
| 10 authentication | identity bindings, active password/TOTP/WebAuthn credentials, canonical CAIP identities |
| 20 administrator pre-authorization | materialized enterprise Principals, roles, actions and bindings |
| 26 gateway/business CRUD | five business schemas/tables, denied cross-schema privileges and row results |
| 30 browser administration | Action counts restored and deleted Principals leave no identity/credential rows |
| 31 hosted login | account state after browser login and passkey/wallet operations |

`verifier/` directories describe functional journeys. PostgreSQL, pgvector, Redis,
Kafka or EMQX assertions belong to the scenario that invokes the feature; shared
query/import mechanics belong to the whitelisted `util/` classes.

`util/docker.py` and `util/kubernetes.py` contain reusable transport, runtime
selection, image loading and cleanup operations. Scenario 00 owns this case's
service topology and backend specializations. `verifier/context.py` contains
shared verification state/results and evidence clients, not deployment recipes.
The process helper owns the common subprocess/runtime contract.

Both `IN_GFW=true|false` and `NON_GFW=true|false` are accepted by the runner/image
matrix and Make entry points; `E2E_IMAGE_NETWORK=IN_GFW|NON_GFW` is also accepted;
`AUTHGUARD_E2E_IMAGE_SOURCE=aliyun|global` remains the explicit override. Each deployment resolves its image catalog from the current
environment, rather than freezing a catalog during module import.

Metrics read the management port and path from `etc/authguard.yaml`, retain the
previous business-event samples, check counter/histogram accounting, and assert
that three controlled AuthN/AuthZ requests each increment their labelled counter
by exactly three. E2E AuthGuard uses `sample_rate: 1.0`; every business workload
explicitly uses `OTEL_TRACES_SAMPLER=always_on`.
