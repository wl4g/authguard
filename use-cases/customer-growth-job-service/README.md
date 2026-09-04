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
identity provider, Kubernetes cluster, or external database: Authguard core
evaluates the condition matrix, and each project tests the SDK-to-SQL boundary
against SQLite or H2. Deployment mode starts the complete request path on k3s:
Keycloak, Envoy Gateway, one Authguard replica, Redis Cluster, one shared
PostgreSQL instance, an LDAP directory, Jaeger, and all five HTTP microservices.

## Structure

```text
customer-growth-job-service/
  config/
    init.sql                shared schema and deterministic rows
    authorization-scenarios.json      53 shared gateway and business scenarios
    principal-discovery-scenarios.json  JIT, federation, LDAP, and SCIM fixtures
  e2e/
    common/                            process, project lifecycle, and reports
    deploy/
      golang-sqlx-service/             Go + sqlx + SQLite/PostgreSQL
      rust-sqlx-service/               Rust + sqlx + SQLite/PostgreSQL
      python-sqlalchemy-service/       Python + SQLAlchemy + SQLite/PostgreSQL
      springboot-jdbc-service/         Spring Boot + JDBC + SQLite/PostgreSQL
      springboot-jpa-service/          Spring Boot + JPA + H2/PostgreSQL
    kubernetes/                        shared PostgreSQL and five workloads
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
```

By default, every round removes project-local generated artifacts and performs
a fresh project build before testing. `--skip-clean` is available for local
diagnosis. Reports are written to `e2e/reports/`; previous reports are archived
before the next invocation.

Run the real Kubernetes path on local k3s:

```bash
HTTPS_PROXY=http://127.0.0.1:8800 make e2e-k3s
```

Each round removes and recreates an `e2e-` namespace and three Helm releases.
Authguard first starts with the Action/Role catalog and no RoleBinding. The
verifier sends authenticated warm-up requests through Envoy to JIT-project the
Keycloak users and groups, resolves each group by the exact `(issuer,
external_id)` key through the management API, then installs every RoleBinding
with one revision-checked, atomic policy replacement. This keeps
identity-provider IDs out of static policy configuration and remains idempotent
when `--skip-clean` is used. The disposable cluster explicitly permits its
internal HTTP OIDC issuer for JIT; production issuers should remain HTTPS-only.

The same verifier exercises every supported Principal-discovery path with live
dependencies. Repeated OIDC requests prove JIT projection is idempotent.
Authguard then searches one LDAP-only user through the Keycloak Admin API and
materializes it twice, proving Keycloak's LDAP federation path; a separate
RFC 4511 connector resolves the same directory entry by its immutable UUID and
also materializes it idempotently. Finally, SCIM RFC 7643 User and Group events
exercise repeated upsert, disabled tombstone, and reactivation behavior. SCIM
records using the same OIDC `(issuer, sub/externalId)` key must converge on the
existing JIT Principal rather than creating a duplicate. The generated report
contains provider paths, lifecycle results, counts, and stable-identity
assertions, but never bearer tokens, client secrets, or LDAP bind credentials.

The services share database `e2e_customer_growth`, but connect through separate login
roles and schemas: `e2e_customer_growth_go_sqlx`, `e2e_customer_growth_rust_sqlx`,
`e2e_customer_growth_python_sqlalchemy`, `e2e_customer_growth_spring_jdbc`, and `e2e_customer_growth_spring_jpa`.
Cross-schema `USAGE` is denied and verified. The Python verifier calls the same
HTTP list/get/create/update/delete contract for every implementation, verifies
direct and opaque scope delivery, and checks that rejected writes do not mutate
PostgreSQL.

The Kubernetes verifier also proves the authentication and authorization order
from live runtime evidence: a tampered Keycloak JWT increments Envoy's
`jwt_authn.denied` counter without calling Authguard, while a valid Keycloak JWT
increments `jwt_authn.allowed`, `ext_authz.ok`, and exactly one
`envoy.service.auth.v3.Authorization/Check` request. It inspects Envoy's runtime
xDS configuration to require `jwt_authn -> ext_authz -> router`, then queries the
Jaeger API for one W3C trace containing `e2e-keycloak`, `e2e-envoy-proxy`, and
`e2e-authguard` spans. The trace models the real causality as two verifier client
branches—token issuance to Keycloak, followed by the protected request to Envoy;
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
