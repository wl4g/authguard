"""E2E mock in-house identity directory.

Serves the Authguard CustomPrincipalDiscovery connector contract:
- GET /identity/api/v1/{kind}/search with `search`/`offset`/`limit`
  query parameters (kind = user | group | workload) returns the paged
  array at `data.items`; the same route with an `id` query parameter
  returns ONE flat entry (id_attr at the top level) or 404, matching
  the connector's resolve_principal contract,
- a pre-issued bearer JWT (`jwt_token` in the connector config) is required.
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, request

EXPECTED_BEARER_TOKEN = os.environ.get(
    "MOCKSVC_EXPECTED_BEARER_TOKEN", "e2e-mocksvc-directory-token"
)

# The same identity as the direct-LDAP fixture, published from an independent
# in-house directory. The immutable external id proves the projection can be
# materialized from a vendor API without any proprietary protocol code.
IDENTITIES = [
    {
        "id": "mocksvc-retention-analyst-001",
        "displayName": "Mock Directory Retention Analyst",
        "username": "mocksvc-retention-analyst",
        "email": "mocksvc-retention-analyst@example-corp.example",
        "active": True,
        "kind": "user",
    }
]

app = Flask(__name__)


@app.before_request
def require_bearer() -> None:
    if request.path == "/healthz":
        return None
    authorization = request.headers.get("Authorization", "")
    if authorization != f"Bearer {EXPECTED_BEARER_TOKEN}":
        return jsonify(error="invalid bearer token"), 401
    return None


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/identity/api/v1/<kind>/search")
def search(kind: str):
    # Resolve mode: the connector appends the external_id_param (`id`) to the
    # search path and expects one FLAT entry at the response top level, or 404.
    requested_id = request.args.get("id")
    if requested_id is not None:
        entries = [
            identity
            for identity in IDENTITIES
            if identity["kind"] == kind and identity["id"] == requested_id
        ]
        if len(entries) != 1:
            return jsonify(error="not found"), 404
        return jsonify(entries[0])
    text = request.args.get("search", "").strip()
    offset = int(request.args.get("offset", "0"))
    limit = int(request.args.get("limit", "20"))
    entries = [
        identity
        for identity in IDENTITIES
        if identity["kind"] == kind
        and (not text or text in identity["username"] or text in identity["email"])
    ]
    return jsonify({"data": {"items": entries[offset : offset + limit]}})
