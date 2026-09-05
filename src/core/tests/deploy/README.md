# IT middleware stacks

Real-middleware dependency stacks for
[`../principal_discovery_it.rs`](../principal_discovery_it.rs). Each stack is a
standalone `docker-compose` project living in its own directory:

| Directory  | Service  | Port        | Purpose                                            |
| ---------- | -------- | ----------- | -------------------------------------------------- |
| `keycloak` | Keycloak 26.7.0 (preview features, SCIM v2) | `8080` | `FED_KEYCLOAK` search + SCIM refresh ingestion |
| `glauth`   | GLauth v2 | `3389` (LDAP) | `FED_LDAP` search + materialize                |

## Running

```bash
cd src/core/tests/deploy/<middleware>
docker-compose up -d
```

The Keycloak stack runs a `bootstrap` one-shot container that idempotently
provisions the deterministic `authguard-it` realm (users `adalwin`/`bchen`/
`ckumar`, groups `growth-team`/`ops-team`, the confidential `authguard-it`
service-account client, and the literal SCIM audience mapper). Re-running the
bootstrap converges instead of failing.

The GLauth stack serves the static directory from `config.cfg` (users under
`ou=users`, groups under `ou=groups`, bind account
`cn=svc-authguard,ou=Users,dc=example,dc=com`).

## Running the tests

```bash
AUTHGUARD_IT_KEYCLOAK_URL=http://127.0.0.1:8080 \
AUTHGUARD_IT_LDAP_URL=ldap://127.0.0.1:3389 \
cargo test -p authguard-core --test principal_discovery_it
```

Without the environment variables the middleware-dependent tests are skipped,
so `cargo test --workspace` stays green on machines without the stacks.
