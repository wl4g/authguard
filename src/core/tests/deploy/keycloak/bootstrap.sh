#!/bin/bash
# =============================================================================
#  Authguard IT realm bootstrap for Keycloak 26.7.0.
#
#  Provisions the deterministic "authguard-it" realm consumed by
#  src/core/tests/principal_discovery_it.rs through the Admin REST API:
#
#    realm        authguard-it
#    client       authguard-it (confidential service account)
#    roles        realm-management: view-users, query-users, query-groups,
#                 manage-users (SCIM user upserts)
#    users        adalwin, bchen, ckumar (password "test1234")
#    groups       growth-team, ops-team
#    audience     {frontend}/realms/authguard-it/scim/v2 (SCIM API access)
#
#  Uses the admin account set by KC_BOOTSTRAP_ADMIN_USERNAME/PASSWORD on the
#  dev container. Idempotent: every step is get-or-create, so re-running
#  against an already provisioned realm converges instead of failing.
# =============================================================================
set -euo pipefail

KCADM=/opt/keycloak/bin/kcadm.sh
SERVER=http://keycloak:8080
REALM=authguard-it
CLIENT_ID=authguard-it
CLIENT_SECRET=it-client-secret

# Prints the UUID part of a Keycloak resource id. `kcadm create` writes its
# "Created new user with id '...'" confirmation to stderr, so create
# pipelines merge stderr into stdout before extraction. The `|| true` at the
# call sites tolerates empty lookups (missing resources) under `set -e`.
extract_id() {
    grep -o '[0-9a-f-]\{36\}' | head -1
}

wait_for_realm() {
    for _ in $(seq 1 30); do
        if "$KCADM" get "realms/$REALM" --server "$SERVER" > /dev/null 2>&1; then
            return 0
        fi
        sleep 5
    done
    return 1
}

echo ">> connecting to Keycloak admin API at $SERVER"
"$KCADM" config credentials --server "$SERVER" \
    --realm master --user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
    --password "${KC_BOOTSTRAP_ADMIN_PASSWORD:-admin-password}"

# Re-create the realm on every run so the bootstrap stays idempotent.
"$KCADM" create realms --server "$SERVER" -s realm="$REALM" \
    -s enabled=true \
    -s registrationAllowed=false \
    -s scimApiEnabled=true || true

if ! wait_for_realm; then
    echo "bootstrap: realm $REALM never became ready" >&2
    exit 1
fi
echo ">> realm $REALM ready"

echo ">> creating confidential service-account client $CLIENT_ID"
CLIENT_UUID=$(
    "$KCADM" get "clients?clientId=$CLIENT_ID&exact=true" \
        --server "$SERVER" -r "$REALM" --fields id | extract_id || true
)
if [ -z "$CLIENT_UUID" ]; then
    CLIENT_UUID=$(
        "$KCADM" create clients --server "$SERVER" -r "$REALM" \
            -s clientId="$CLIENT_ID" \
            -s secret="$CLIENT_SECRET" \
            -s publicClient=false \
            -s serviceAccountsEnabled=true \
            -s standardFlowEnabled=false \
            -s directAccessGrantsEnabled=false \
            -s protocol=openid-connect \
            -s description="Authguard IT client: federated principal search and SCIM synchronization" \
            2>&1 | extract_id
    )
fi
echo "    client uuid: $CLIENT_UUID"

echo ">> granting realm-management roles (search + SCIM provisioning)"
for role in view-users query-users query-groups manage-users; do
    "$KCADM" add-roles --server "$SERVER" -r "$REALM" \
        --uusername "service-account-$CLIENT_ID" \
        --cclientid realm-management --rolename "$role" || true
done

echo ">> adding SCIM audience mapper"
# ScimRealmResourceFactory validates the token against the concrete frontend
# URL `{frontendBaseUri}/realms/{realm}/scim/v2`; the `{frontend}` template
# is NOT expanded in audience mapper config, so the literal is required.
SCIM_AUDIENCE="http://localhost:8080/realms/$REALM/scim/v2"
MAPPER_ID=$(
    "$KCADM" get "clients/$CLIENT_UUID/protocol-mappers/models" \
        --server "$SERVER" -r "$REALM" --fields id,name 2>/dev/null \
    | grep -B 1 '"name" : "scim-audience"' | extract_id || true
)
if [ -n "$MAPPER_ID" ]; then
    "$KCADM" update "clients/$CLIENT_UUID/protocol-mappers/models/$MAPPER_ID" \
        --server "$SERVER" -r "$REALM" \
        -s 'config."included.client.audience"='"$SCIM_AUDIENCE" \
        -s 'config."access.token.claim"="true"' \
        -s 'config."id.token.claim"="false"'
else
    "$KCADM" create "clients/$CLIENT_UUID/protocol-mappers/models" \
        --server "$SERVER" -r "$REALM" \
        -s name=scim-audience \
        -s protocol=openid-connect \
        -s protocolMapper=oidc-audience-mapper \
        -s 'config."included.client.audience"='"$SCIM_AUDIENCE" \
        -s 'config."access.token.claim"="true"' \
        -s 'config."id.token.claim"="false"'
fi

# ---------------------------------------------------------------------------
# Seed users. externalId carries the stable OIDC `sub`; Keycloak does not
# return it from the SCIM endpoint by default (Authguard falls back to the
# SCIM resource id), but the seeded value documents the intended mapping.
# ---------------------------------------------------------------------------
echo ">> seeding users"
USER_NAMES=()
USER_IDS=()
for spec in "adalwin Ada Lwin adalwin@example.com" \
            "bchen Ben Chen bchen@example.com" \
            "ckumar Cleo Kumar ckumar@example.com"; do
    read -r USERNAME FIRST LAST EMAIL <<< "$spec"
    USER_UUID=$(
        "$KCADM" get "users?username=$USERNAME&exact=true" \
            --server "$SERVER" -r "$REALM" --fields id | extract_id || true
    )
    if [ -z "$USER_UUID" ]; then
        USER_UUID=$(
            "$KCADM" create users --server "$SERVER" -r "$REALM" \
                -s username="$USERNAME" \
                -s firstName="$FIRST" \
                -s lastName="$LAST" \
                -s email="$EMAIL" \
                -s emailVerified=true \
                -s enabled=true \
                2>&1 | extract_id
        )
    fi
    USER_NAMES+=("$USERNAME")
    USER_IDS+=("$USER_UUID")
    echo "    $USERNAME -> $USER_UUID"
done

echo ">> setting passwords"
for index in "${!USER_NAMES[@]}"; do
    "$KCADM" set-password --server "$SERVER" -r "$REALM" \
        --username "${USER_NAMES[$index]}" --new-password test1234 --temporary || true
done

# ---------------------------------------------------------------------------
# Seed groups; join-group PUT needs no body, so the -s body arguments of
# the previous revision are gone.
# ---------------------------------------------------------------------------
echo ">> seeding groups"
GROUP_IDS=()
for group in growth-team ops-team; do
    GROUP_UUID=$(
        "$KCADM" get "groups?search=$group&exact=true" \
            --server "$SERVER" -r "$REALM" --fields id | extract_id || true
    )
    if [ -z "$GROUP_UUID" ]; then
        GROUP_UUID=$(
            "$KCADM" create "groups" --server "$SERVER" -r "$REALM" -s name="$group" \
                2>&1 | extract_id
        )
    fi
    GROUP_IDS+=("$GROUP_UUID")
    echo "    $group -> $GROUP_UUID"
done

echo ">> assigning adalwin to growth-team and bchen to ops-team"
"$KCADM" update "users/${USER_IDS[0]}/groups/${GROUP_IDS[0]}" --server "$SERVER" -r "$REALM" || true
"$KCADM" update "users/${USER_IDS[1]}/groups/${GROUP_IDS[1]}" --server "$SERVER" -r "$REALM" || true

echo ">> realm bootstrap complete"
