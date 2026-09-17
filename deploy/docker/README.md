# AuthGuard Docker Compose

Complete local AuthGuard deployment: PostgreSQL, Redis, AuthN, AuthZ, Web, and
single-node Envoy. `.env` uses the same `AUTHGUARD__...` secret keys as Helm.

```bash
cp deploy/docker/.env.example deploy/docker/.env && \
${EDITOR:-vi} deploy/docker/.env && \
docker compose --env-file deploy/docker/.env \
  -f deploy/docker/docker-compose.yaml up -d
```

Open `http://localhost:8080`. The UI is same-origin proxied to AuthN (`/auth`,
`/.well-known/authn.json`) and AuthZ management (`/api`); enter
`AUTHGUARD__AUTHZ__API_TOKEN` in the UI control-token input to manage policies
and Principals.

```bash
docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yaml logs -f
docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yaml down
# Equivalent repository target: make docker-down
```

Envoy exposes `:8080` for UI/AuthN/API and `:8081` for the real
`jwt_authn → ext_authz` protected listener. It obtains AuthN's public JWKS from
`/.well-known/jwks.json`; no local script, init image, or private-key mount is
needed. The protected listener points to Web as a small demonstrator upstream.

Runtime files live in `config/`; OAuth/OIDC and wallet chain settings belong in
`config/authguard.yaml`.
