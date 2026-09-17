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

- UI/AuthN/AuthZ management: `http://localhost:8080`
- Protected Envoy PEP: `http://localhost:8081`

Envoy obtains AuthN's public key from `/.well-known/jwks.json`; no script,
init image, or private-key mount is required.

## 4. Inspect or stop

```bash
docker compose --env-file deploy/docker/.env \
  -f deploy/docker/docker-compose.yaml logs -f
docker compose --env-file deploy/docker/.env \
  -f deploy/docker/docker-compose.yaml down
```

The `:8081` listener enforces `jwt_authn → ext_authz`; it routes to Web only as
a small demonstrator upstream. Replace that upstream in
[`config/envoy.yaml`](config/envoy.yaml) for application integration.
