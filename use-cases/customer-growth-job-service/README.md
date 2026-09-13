# Customer Growth Job Authorization

This portable E2E use case models an enterprise data team that collaborates on
customer growth jobs in the same workspace. Analysts, job runners, workspace owners,
external users, and auditors have different Resource URN grants while querying
the same `customer_growth_jobs` business table.

The example exercises the complete application-side authorization path:

```text
trusted x-authguard-context
  -> framework filter/interceptor
  -> request-scoped principal/action/resource plus allow/deny Resource URNs
  -> action validation for each CRUD operation
  -> SDK SQL-scope compiler
  -> business query criteria
  -> scoped repository create/read/update/delete query
  -> authorized customer-growth-job DTOs
```

The use case has two complementary execution modes. Portable mode requires no
identity provider, Kubernetes cluster, or external database: `authguard-authz`
evaluates the condition matrix, and each project tests the SDK-to-SQL boundary
against SQLite or H2. Deployment mode starts the complete request path on k3s:
Keycloak as an E2E-only external IdP, Envoy Gateway, `authguard-authn`, one
`authguard-authz` replica, Redis Cluster, one shared
PostgreSQL instance, an LDAP directory, Jaeger, and all five HTTP microservices.
It additionally proves the Envoy Gateway JWT public-key requirement with a
deterministic realm key, the workload OAuth2 client_credentials flow, and the
resign-JWT Authguard-origin boundary inside a business microservice.

## Structure

```text
customer-growth-job-service/
  e2e/
    config/
      init.sql                       shared schema and deterministic rows
      authguard-e2e-scenarios.json   AuthN, federation, and 53 AuthZ scenarios
      keycloak-realm.json            external IdP and workload-client fixture
      e2e-jwt-keys/                  fixed realm-signing and resign-JWT keys
    common/                            process, project lifecycle, and reports
    deploy/
      golang-sqlx-service/             Go + sqlx + SQLite/PostgreSQL
      rust-sqlx-service/               Rust + sqlx + SQLite/PostgreSQL
      python-sqlalchemy-service/       Python + SQLAlchemy + SQLite/PostgreSQL
      springboot-jdbc-service/         Spring Boot + JDBC + SQLite/PostgreSQL
      springboot-jpa-service/          Spring Boot + JPA + H2/PostgreSQL
    helm/                              shared PostgreSQL and five workloads
    verifier/                          independent sNN verifier groups
    reports/                           ignored execution evidence
    runner.py                          clean rebuild, rounds, selection, summary
```

Each deploy project is an independent, enterprise-style service module with
authorization mapping, controller, DTO, entity, service, repository, and E2E
test boundaries. All five consume the same SQL and JSON files; language-local
copies of business fixtures are intentionally forbidden.

The canonical resource shape is:

```text
urn:iam:prod:customer-growth:<region>:<tenant_id>:workspace/<workspace_id>/project/<project_id>/job/<job_id>
```

Every implementation executes the same 53 independent scenarios against a
fresh database. They cover all CRUD operations, read versus write action
isolation, exact URNs, `*`, trailing `**`, segment wildcards, allow unions,
explicit deny precedence, tenant/region/service boundaries, and business
criteria intersections. Conditional cases cover source-IP allow/deny CIDRs,
secure transport, HTTP method, MFA, subject claims, combined conditions, and
missing trusted context; unavailable attributes fail closed.

These business scenarios complement, rather than duplicate, the adapter test
matrix. Each Java, Go, Python, and Rust SDK independently executes the same 42
contract scenarios: 18 request-access/filter/resolver cases and 24 URN parsing,
allow/deny SQL compilation, codec, and action-aware scope cases.

## Run

Run one clean round from the repository root:

```bash
make e2e
```

Run repeated clean rebuilds or one verifier directly:

```bash
python3 use-cases/customer-growth-job-service/e2e/runner.py --rounds 3
python3 use-cases/customer-growth-job-service/e2e/runner.py --scenario 12
python3 use-cases/customer-growth-job-service/e2e/runner.py --list
python3 use-cases/customer-growth-job-service/e2e/runner.py --scenario 00,15,16,17,21 --cleanup-after-run
```

By default, every round removes project-local generated artifacts and performs
a fresh project build before testing. `--skip-clean` is available for local
diagnosis. Reports are written to `e2e/reports/`; previous reports are archived
before the next invocation.
Kubernetes resources are retained by default for troubleshooting. Add
`--cleanup-after-run` to uninstall all three E2E Helm releases and delete the
isolated namespace after success, failure, or interruption.

Run the real Kubernetes path on local k3s:

```bash
HTTPS_PROXY=http://127.0.0.1:8800 make e2e-k3s
```

Each round removes and recreates an `e2e-` namespace and three Helm releases.
Authguard first starts with the Action/Role catalog and no RoleBinding. A mock
external social IdP then drives the real browser protocol through Envoy's
public AuthN listener: authorize redirect, callback, POST token exchange,
userinfo lookup, `ExternalIdentity` normalization, durable account linking,
and canonical-session issuance. AuthN and AuthZ share one PostgreSQL IAM schema,
so AuthZ sees the resulting internal Principal without learning the provider
subject. The administrator binds those Principal IDs in one revision-checked
policy replacement. A second login must resolve to the same IDs before any
business request is sent. Equal email values are never used for linking.

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

The realm imports a fixed RSA key pair (see `e2e/config/e2e-jwt-keys/`) through the
realm `keys[]` fixture instead of letting Keycloak generate one at first start.
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

All runtime and build images use `registry.cn-shenzhen.aliyuncs.com`. The E2E
runtime pins Envoy `distroless-v1.36.4`, Envoy Gateway `v1.9.0`, Redis Cluster
`7.0.14`, Keycloak `26.7.0`, GLAUTH `2.5.0`, Jaeger `1.76.0`, and PostgreSQL
`18.3`.

Portable-mode prerequisites are the same local toolchains used by the
repository: Rust/Cargo, Go, Python 3 with SQLAlchemy, Java 17/Maven, and their
cached or reachable package repositories. Kubernetes mode additionally needs
Docker, Helm, kubectl, and local k3s. The runner itself uses only the Python
standard library.
