"""Realistic in-cluster identity-provider contracts for Authguard E2E.

The service models the wire differences that matter to AuthN: GitHub uses a
POST token exchange plus a separate user API, Google uses standard OAuth2 plus
UserInfo, and WeChat uses ``appid`` and a GET token exchange whose stable
identity is ``unionid`` with ``openid`` fallback. It also exposes an
authenticated enterprise-directory endpoint for ``CustomPrincipalDiscovery``.
"""

from __future__ import annotations

import os
import secrets

from flask import Flask, jsonify, redirect, request

DIRECTORY_TOKEN = os.environ.get(
    "MOCK_IDP_DIRECTORY_TOKEN", "e2e-mock-idp-directory-token"
)
CLIENTS = {
    "github-e2e-client": {
        "provider": "github",
        "secret": "github-e2e-secret",
        "identity": {
            "id": 987654,
            "login": "github-reader",
            "email": "github-reader@example.net",
            "tenant_id": "example-corp",
        },
    },
    "google-e2e-client": {
        "provider": "google",
        "secret": "google-e2e-secret",
        "identity": {
            "sub": "google-editor-001",
            "name": "google-editor",
            "email": "google-editor@example.net",
            "tenant_id": "example-corp",
        },
    },
    "wechat-e2e-app": {
        "provider": "wechat",
        "secret": "wechat-e2e-secret",
        "identity": {
            "unionid": "wechat-union-001",
            "openid": "wechat-open-001",
            "tenant_id": "example-corp",
        },
    },
}
DIRECTORY_IDENTITIES = [
    {
        "id": "mock-idp-retention-analyst-001",
        "displayName": "Mock IdP Retention Analyst",
        "username": "mock-idp-retention-analyst",
        "email": "mock-idp-retention-analyst@example-corp.example",
        "active": True,
        "kind": "user",
    }
]
AUTHORIZATION_CODES: dict[str, tuple[str, str, str]] = {}
ACCESS_TOKENS: dict[str, str] = {}

app = Flask(__name__)


@app.before_request
def require_directory_token():
    if request.path.startswith("/identity/"):
        if request.headers.get("Authorization") != f"Bearer {DIRECTORY_TOKEN}":
            return jsonify(error="invalid bearer token"), 401
    return None


@app.get("/healthz")
def healthz():
    return {"status": "ok", "providers": ["github", "google", "wechat"]}


@app.get("/<provider>/authorize")
@app.get("/<provider>/login/oauth/authorize")
@app.get("/<provider>/o/oauth2/v2/auth")
@app.get("/<provider>/connect/qrconnect")
def authorize(provider: str):
    client_key = "appid" if provider == "wechat" else "client_id"
    client_id = request.args.get(client_key, "")
    redirect_uri = request.args.get("redirect_uri", "")
    state = request.args.get("state", "")
    client = CLIENTS.get(client_id)
    if (
        request.args.get("response_type") != "code"
        or client is None
        or client["provider"] != provider
        or not redirect_uri.startswith("http://authn.customer-growth.local")
        or "/auth/v1/providers/" not in redirect_uri
        or not state
    ):
        return jsonify(error="invalid authorization request"), 400
    code = secrets.token_urlsafe(24)
    AUTHORIZATION_CODES[code] = (provider, client_id, redirect_uri)
    separator = "&" if "?" in redirect_uri else "?"
    return redirect(f"{redirect_uri}{separator}code={code}&state={state}", code=302)


@app.post("/github/login/oauth/access_token")
@app.post("/google/token")
def post_token():
    provider = "github" if request.path.startswith("/github/") else "google"
    return exchange_token(
        provider=provider,
        code=request.form.get("code", ""),
        client_id=request.form.get("client_id", ""),
        client_secret=request.form.get("client_secret", ""),
        redirect_uri=request.form.get("redirect_uri", ""),
    )


@app.get("/wechat/sns/oauth2/access_token")
def wechat_token():
    response = exchange_token(
        provider="wechat",
        code=request.args.get("code", ""),
        client_id=request.args.get("appid", ""),
        client_secret=request.args.get("secret", ""),
        redirect_uri=None,
    )
    if isinstance(response, tuple):
        return response
    payload = response.get_json()
    payload.update(CLIENTS["wechat-e2e-app"]["identity"])
    return jsonify(payload)


@app.get("/github/user")
@app.get("/google/oauth2/v3/userinfo")
def userinfo():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    client_id = ACCESS_TOKENS.pop(token, None)
    if client_id is None:
        return jsonify(error="invalid_token"), 401
    return jsonify(CLIENTS[client_id]["identity"])


@app.get("/identity/api/v1/<kind>/search")
def directory_search(kind: str):
    requested_id = request.args.get("id")
    entries = [item for item in DIRECTORY_IDENTITIES if item["kind"] == kind]
    if requested_id is not None:
        matched = [item for item in entries if item["id"] == requested_id]
        if len(matched) != 1:
            return jsonify(error="not found"), 404
        return jsonify(matched[0])
    text = request.args.get("search", "").strip()
    offset = int(request.args.get("offset", "0"))
    limit = int(request.args.get("limit", "20"))
    matched = [
        item
        for item in entries
        if not text or text in item["username"] or text in item["email"]
    ]
    return jsonify({"data": {"items": matched[offset : offset + limit]}})


def exchange_token(
    *, provider: str, code: str, client_id: str, client_secret: str, redirect_uri: str | None
):
    flow = AUTHORIZATION_CODES.pop(code, None)
    client = CLIENTS.get(client_id)
    valid_redirect = flow is not None and (redirect_uri is None or flow[2] == redirect_uri)
    if (
        flow is None
        or flow[:2] != (provider, client_id)
        or not valid_redirect
        or client is None
        or not secrets.compare_digest(client["secret"], client_secret)
    ):
        return jsonify(error="invalid_grant"), 400
    access_token = secrets.token_urlsafe(32)
    ACCESS_TOKENS[access_token] = client_id
    return jsonify(access_token=access_token, token_type="Bearer", expires_in=60)
