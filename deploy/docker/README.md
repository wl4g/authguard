# AuthGuard Docker Compose

Local single-node deployment: PostgreSQL, Redis Cluster, Jaeger, AuthN, AuthZ, Web,
and Envoy. Runtime settings and secrets use the same `AUTHGUARD__...` keys as Helm.

## 1. Prepare the local Secret file

```bash
cp deploy/docker/.env.example deploy/docker/.env && \
${EDITOR:-vi} deploy/docker/.env
```

Replace every active placeholder. OAuth/OIDC and wallet-chain settings belong in
[`config/authguard.yaml`](config/authguard.yaml).

## 2. Start

```bash
docker compose --env-file deploy/docker/.env \
  -f deploy/docker/docker-compose.yaml up -d
```

`make docker-up` is equivalent.

The example enables `postgresql,redis,jaeger,envoy` through `COMPOSE_PROFILES`.
AuthN, AuthZ and Web run independently of those profiles. To use existing
middleware, omit its profile and configure the corresponding connection:

| Profile | External connection |
| --- | --- |
| `postgresql` | `storage.postgres` in `config/authguard.yaml` or its `AUTHGUARD__STORAGE__POSTGRES__...` overrides |
| `redis` | `cache.redis` and its credentials in the same runtime configuration |
| `jaeger` | `AUTHGUARD_OTEL_ENDPOINT`, or `AUTHGUARD_OTEL_ENABLED=false` |
| `envoy` | An existing gateway configured with canonical JWT verification and AuthZ `ext_authz` |

Compose uses native Envoy; the Envoy Gateway controller belongs to Kubernetes.
Configure business routes in `config/envoy.yaml`. Image and configuration-file
overrides are declared beside their defaults in `docker-compose.yaml`.

The local Redis service creates a single-node development cluster, matching the
AuthGuard client protocol. Kubernetes uses the bundled multi-node Redis Cluster
Chart. Jaeger stores bounded traces in memory.


## 3. Use

- Same-origin Dashboard/Hosted Login/AuthN/AuthZ API and protected demonstrator: `http://localhost:8080`

Hosted Login is available at `http://localhost:8080/auth/login`; authenticated
credential enrollment is at `/auth/account/security`. For a real
application host, add its `authn.applications` entry to
[`config/authguard.yaml`](config/authguard.yaml) and route only
`GET /auth/login`, `GET /auth/account/security`, `GET /auth/assets/*`,
`/.well-known/*`, and `/auth/*` to AuthGuard. Keep the application's `/` and
`/api/*` routes in its own Gateway. Mount custom theme files read-only at
`/usr/share/nginx/html/assets/themes/custom` through a Compose override.

Envoy obtains AuthN's public key from `/.well-known/jwks.json`; no script,
init image, or private-key mount is required.

## 4. Inspect or stop

```bash
docker compose --env-file deploy/docker/.env \
  -f deploy/docker/docker-compose.yaml logs -f
docker compose --env-file deploy/docker/.env \
  -f deploy/docker/docker-compose.yaml down
```

The `/` catch-all enforces `jwt_authn → ext_authz`; it routes to Web only as a
small demonstrator upstream. Replace that upstream in
[`config/envoy.yaml`](config/envoy.yaml) for application integration.

The Customer Growth E2E includes this Compose file and merges test credentials,
SQL initialization data, builds, themes and temporary ports. It uses the same middleware
definitions as this stack.
