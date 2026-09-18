# AuthGuard Docker Compose

Local single-node deployment: PostgreSQL, Redis, AuthN, AuthZ, Web, and Envoy.
All user-supplied values use the same `AUTHGUARD__...` keys as Helm.

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

## 3. Use

- Same-origin UI/AuthN/AuthZ management and protected demonstrator: `http://localhost:8080`

Hosted Login is available at `http://localhost:8080/auth/login`; authenticated
credential enrollment is at `/auth/account/security`. For a real
application host, add its `authn.applications` entry to
[`config/authguard.yaml`](config/authguard.yaml) and route only
`GET /auth/login`, `GET /auth/account/security`, `GET /auth/assets/*`,
`/.well-known/*`, and `/auth/*` to AuthGuard. Keep the application's `/` and
`/api/*` routes in its own Gateway. Custom Theme Packs can be added with a
derived `authguard-web` image under `/usr/share/nginx/html/assets/themes/custom`.

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
