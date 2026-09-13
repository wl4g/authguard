"""E2E contracts for GitHub, Google, WeChat, and QQ OAuth-like APIs.

This service deliberately does not implement OpenID Connect discovery, JWKS,
or ID tokens. The E2E suite verifies standards-based OIDC against its real
Keycloak deployment.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from urllib.parse import urlencode

from flask import Flask, Response, jsonify, redirect, request

CLIENTS = {
    "e2e-authguard-github-client": {
        "provider": "github",
        "secret": os.environ.get("MOCK_IDP_GITHUB_CLIENT_SECRET", ""),
        "identity": {
            "id": 987654,
            "login": "github-reader",
            "email": "github-reader@example.net",
        },
    },
    "e2e-authguard-google-client": {
        "provider": "google",
        "secret": os.environ.get("MOCK_IDP_GOOGLE_CLIENT_SECRET", ""),
        "identity": {
            "sub": "google-editor-001",
            "name": "google-editor",
            "email": "google-editor@example.net",
        },
    },
    "e2e-authguard-wechat-app": {
        "provider": "wechat",
        "secret": os.environ.get("MOCK_IDP_WECHAT_CLIENT_SECRET", ""),
        "identity": {
            "unionid": "wechat-union-001",
            "openid": "wechat-open-001",
        },
    },
    "e2e-authguard-qq-app": {
        "provider": "qq",
        "secret": os.environ.get("MOCK_IDP_QQ_CLIENT_SECRET", ""),
        "identity": {"openid": "qq-open-001"},
    },
}
AUTHORIZATION_CODES: dict[str, dict[str, str]] = {}
ACCESS_TOKENS: dict[str, str] = {}
EXPECTED_SCOPES = {
    "github": "read:user user:email",
    "google": "profile email",
    "wechat": "snsapi_login",
    "qq": "get_user_info,get_vip_info",
}

app = Flask(__name__)


@app.get("/healthz")
def healthz():
    """Local Kubernetes probe; this is not an external IdP contract."""
    ready = all(client["secret"] for client in CLIENTS.values())
    status = 200 if ready else 503
    return jsonify(status="ok" if ready else "degraded", providers=sorted(_providers())), status


# GitHub OAuth web flow:
# https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#1-request-a-users-github-identity
@app.get("/github/login/oauth/authorize")
def github_authorize():
    return _authorize("github", "client_id")


# Google OAuth 2.0 web-server flow:
# https://developers.google.com/identity/protocols/oauth2/web-server#httprest_1
@app.get("/google/o/oauth2/v2/auth")
def google_authorize():
    return _authorize("google", "client_id")


# WeChat website login authorization:
# https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
@app.get("/wechat/connect/qrconnect")
def wechat_authorize():
    return _authorize("wechat", "appid")


# QQ server-side authorization-code flow, step 1:
# https://wiki.connect.qq.com/使用authorization_code获取access_token
@app.get("/qq/oauth2.0/authorize")
def qq_authorize():
    return _authorize("qq", "client_id")


# GitHub authorization-code token exchange:
# https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#2-users-are-redirected-back-to-your-site-by-github
@app.post("/github/login/oauth/access_token")
def github_token():
    client_id, client_secret = _client_credentials()
    response = _exchange_token(
        "github",
        request.form.get("code", ""),
        client_id,
        client_secret,
        request.form.get("redirect_uri", ""),
        request.form.get("grant_type", ""),
        request.form.get("code_verifier", ""),
    )
    if isinstance(response, tuple):
        return response
    if "application/json" in request.headers.get("Accept", ""):
        return jsonify(**response, scope="read:user,user:email", token_type="bearer")
    response.update(scope="read:user,user:email", token_type="bearer")
    return _form_response(response)


# Google OAuth 2.0 authorization-code token exchange:
# https://developers.google.com/identity/protocols/oauth2/web-server#exchange-authorization-code
@app.post("/google/token")
def google_token():
    client_id, client_secret = _client_credentials()
    response = _exchange_token(
        "google",
        request.form.get("code", ""),
        client_id,
        client_secret,
        request.form.get("redirect_uri", ""),
        request.form.get("grant_type", ""),
        request.form.get("code_verifier", ""),
    )
    if isinstance(response, tuple):
        return response
    return jsonify(**response, expires_in=3600, scope="profile email", token_type="Bearer")


# WeChat exchanges code, appid, and secret in the query string with GET:
# https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
@app.get("/wechat/sns/oauth2/access_token")
def wechat_token():
    response = _exchange_token(
        "wechat",
        request.args.get("code", ""),
        request.args.get("appid", ""),
        request.args.get("secret", ""),
        None,
        request.args.get("grant_type", ""),
        "",
    )
    if isinstance(response, tuple):
        return response
    identity = CLIENTS["e2e-authguard-wechat-app"]["identity"]
    return jsonify(
        **response,
        expires_in=7200,
        refresh_token=secrets.token_urlsafe(32),
        openid=identity["openid"],
        scope="snsapi_login",
        unionid=identity["unionid"],
    )


# QQ uses GET and query credentials; fmt=json selects its documented JSON form:
# https://wiki.connect.qq.com/使用authorization_code获取access_token
@app.get("/qq/oauth2.0/token")
def qq_token():
    response = _exchange_token(
        "qq",
        request.args.get("code", ""),
        request.args.get("client_id", ""),
        request.args.get("client_secret", ""),
        request.args.get("redirect_uri", ""),
        request.args.get("grant_type", ""),
        "",
    )
    if isinstance(response, tuple):
        return response
    response.update(expires_in=5_184_000, refresh_token=secrets.token_urlsafe(32))
    return jsonify(response) if request.args.get("fmt") == "json" else _form_response(response)


# GitHub REST API for the authenticated OAuth user:
# https://docs.github.com/en/rest/users/users#get-the-authenticated-user
@app.get("/github/user")
def github_user():
    return _bearer_identity("github")


# Google UserInfo called with an OAuth bearer access token (no ID token here):
# https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo
@app.get("/google/oauth2/v3/userinfo")
def google_userinfo():
    return _bearer_identity("google")


# QQ obtains the stable OpenID after token exchange; fmt=json avoids JSONP:
# https://wiki.connect.qq.com/获取用户openid_oauth2-0
@app.get("/qq/oauth2.0/me")
def qq_openid():
    token = request.args.get("access_token", "")
    client_id = ACCESS_TOKENS.get(token)
    client = CLIENTS.get(client_id or "")
    if client is None or client["provider"] != "qq":
        return jsonify(error=100015, error_description="invalid access token"), 401
    payload = {"client_id": client_id, "openid": client["identity"]["openid"]}
    if request.args.get("fmt") == "json":
        return jsonify(payload)
    return Response(f"callback( {json.dumps(payload)} );", mimetype="application/javascript")


def _authorize(provider: str, client_parameter: str):
    client_id = request.args.get(client_parameter, "")
    redirect_uri = request.args.get("redirect_uri", "")
    state = request.args.get("state", "")
    client = CLIENTS.get(client_id)
    if (
        request.args.get("response_type") != "code"
        or client is None
        or client["provider"] != provider
        or not redirect_uri.startswith(
            "http://e2e-authguard-authn.customer-growth.local"
        )
        or f"/auth/v1/providers/{provider}/callback" not in redirect_uri
        or not state
        or request.args.get("scope") != EXPECTED_SCOPES[provider]
    ):
        return jsonify(error="invalid_request"), 400
    code = secrets.token_urlsafe(24)
    AUTHORIZATION_CODES[code] = {
        "provider": provider,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": request.args.get("code_challenge", ""),
    }
    separator = "&" if "?" in redirect_uri else "?"
    return redirect(f"{redirect_uri}{separator}{urlencode({'code': code, 'state': state})}", 302)


def _exchange_token(
    provider: str,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str | None,
    grant_type: str,
    code_verifier: str,
):
    flow = AUTHORIZATION_CODES.get(code)
    client = CLIENTS.get(client_id)
    if (
        grant_type != "authorization_code"
        or flow is None
        or flow["provider"] != provider
        or flow["client_id"] != client_id
        or (redirect_uri is not None and flow["redirect_uri"] != redirect_uri)
        or not _valid_pkce(flow["code_challenge"], code_verifier)
        or client is None
        or not secrets.compare_digest(client["secret"], client_secret)
    ):
        return jsonify(error="invalid_grant"), 400
    AUTHORIZATION_CODES.pop(code)
    access_token = secrets.token_urlsafe(32)
    ACCESS_TOKENS[access_token] = client_id
    return {"access_token": access_token}


def _client_credentials() -> tuple[str, str]:
    return request.form.get("client_id", ""), request.form.get("client_secret", "")


def _bearer_identity(provider: str):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    client_id = ACCESS_TOKENS.get(token)
    client = CLIENTS.get(client_id or "")
    if client is None or client["provider"] != provider:
        return jsonify(error="invalid_token"), 401
    return jsonify(client["identity"])


def _valid_pkce(challenge: str, verifier: str) -> bool:
    if not challenge:
        return True
    digest = hashlib.sha256(verifier.encode()).digest()
    actual = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return secrets.compare_digest(challenge, actual)


def _form_response(payload: dict[str, object]) -> Response:
    return Response(urlencode(payload), mimetype="application/x-www-form-urlencoded")


def _providers() -> set[str]:
    return {client["provider"] for client in CLIENTS.values()}
