"""SCIM background sync agent.

Pulls Users and Groups from the Keycloak SCIM v2 API with a client-credentials
token carrying the SCIM audience, normalizes each resource into Authguard's
ScimRefreshRequest and POSTs it to /adm/v1/principal-discovery/scim/refresh.

One shot per invocation: the CronJob is the cadence. Idempotency is preserved
by both sides — Keycloak SCIM ids and Authguard (issuer, external_id) keys.
"""

from __future__ import annotations

import os
import sys
import uuid
from urllib.parse import urljoin

import requests

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL")
REALM = os.environ.get("KEYCLOAK_REALM", "example-corp")
CLIENT_ID = os.environ.get("SCIM_CLIENT_ID", "e2e-scim-sync")
CLIENT_SECRET = os.environ.get("AUTHGUARD_SCIM_CLIENT_SECRET")
AUTHGUARD_MGMT_URL = os.environ.get("AUTHGUARD_MGMT_URL")
AUTHGUARD_ADMIN_TOKEN = os.environ.get("AUTHGUARD__AUTH__ADMIN_TOKEN")

SCIM_USER_JSON = "application/scim+json"


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(1)


def exchange_token() -> str:
    token_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
    response = requests.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        timeout=10,
    )
    if response.status_code != 200:
        fail(f"client_credentials exchange failed: HTTP {response.status_code}")
    return response.json()["access_token"]


def scim_list(token: str, resource: str) -> list[dict]:
    # RFC 7644 index-based pagination: startIndex/count in,
    # totalResults/itemsPerPage out.
    base = f"{KEYCLOAK_URL}/realms/{REALM}/scim/v2/{resource}"
    page_size = 100
    resources: list[dict] = []
    start_index = 1
    while True:
        response = requests.get(
            base,
            params={"startIndex": start_index, "count": page_size},
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": SCIM_USER_JSON,
            },
            timeout=15,
        )
        if response.status_code != 200:
            fail(f"SCIM {resource} list failed: HTTP {response.status_code}")
        payload = response.json()
        resources.extend(payload.get("Resources", []))
        if start_index + len(resources) >= payload.get("totalResults", 0) + 1:
            break
        start_index += page_size
    return resources


def user_refresh(resource: dict) -> dict:
    emails = [
        {"value": email.get("value"), "primary": bool(email.get("primary"))}
        for email in resource.get("emails", [])
        if email.get("value")
    ]
    return {
        "operation": "upsert_user",
        "resource": {
            "id": resource["id"],
            # externalId converges with the OIDC sub when the IdP publishes it.
            "externalId": resource.get("externalId"),
            "userName": resource["userName"],
            "display_name": resource.get("displayName"),
            "active": resource.get("active", True),
            "emails": emails,
            "attributes": {"source": "keycloak-scim-sync"},
        },
    }


def group_refresh(resource: dict) -> dict:
    return {
        "operation": "upsert_group",
        "resource": {
            "id": resource["id"],
            "externalId": resource.get("externalId"),
            "displayName": resource["displayName"],
            "attributes": {"source": "keycloak-scim-sync"},
        },
    }


def push_refresh(payload: dict) -> None:
    response = requests.post(
        urljoin(AUTHGUARD_MGMT_URL, "/adm/v1/principal-discovery/scim/refresh"),
        json=payload,
        headers={
            "Authorization": f"Bearer {AUTHGUARD_ADMIN_TOKEN}",
            "Host": "authguard-management.local",
            "X-Request-Id": str(uuid.uuid4()),
        },
        timeout=15,
    )
    if response.status_code != 200:
        fail(f"Authguard SCIM refresh failed: HTTP {response.status_code}")


def main() -> None:
    required = {
        "KEYCLOAK_URL": KEYCLOAK_URL,
        "AUTHGUARD_SCIM_CLIENT_SECRET": CLIENT_SECRET,
        "AUTHGUARD_MGMT_URL": AUTHGUARD_MGMT_URL,
        "AUTHGUARD__AUTH__ADMIN_TOKEN": AUTHGUARD_ADMIN_TOKEN,
    }
    for name, value in required.items():
        if not value:
            fail(f"{name} is required")

    token = exchange_token()
    users = scim_list(token, "Users")
    groups = scim_list(token, "Groups")
    for resource in users:
        push_refresh(user_refresh(resource))
    for resource in groups:
        push_refresh(group_refresh(resource))
    print(f"scim sync pushed {len(users)} users and {len(groups)} groups")


if __name__ == "__main__":
    main()
