"""Phase 15: federate Principals and apply administrator pre-authorization."""

from __future__ import annotations

import json
from urllib import parse

from common.kubernetes import GROUP_PRINCIPAL_IDS, WORKLOAD_HOSTS
from common.model import RunContext, VerificationResult
from common.telemetry import E2ETrace
from verifier.base_verifier import BaseVerifier
from verifier.s20_observability_contract import ControlPlaneJaegerTraceVerifier


class PrincipalPreauthorizationVerifier(BaseVerifier):
    scenario_id = "15"
    title = "Core 1/3: Keycloak/LDAP federation and administrator pre-authorization"

    def run(self) -> VerificationResult:
        return self.execute(self.verify_principal_preauthorization)

    def verify_principal_preauthorization(self) -> None:
        """Materialize enterprise identities and apply grants before business login."""
        self.step("verify Envoy jwt_authn -> ext_authz -> router", self._verify_envoy_runtime_filter_chain)
        trace = E2ETrace("customer-growth.administrator-preauthorization.e2e")
        span = trace.start_client(
            "authz.administrator.preauthorization",
            **{"server.address": "authguard-management.local"},
        )
        self.api_trace_headers = {
            "traceparent": span.traceparent,
            "x-request-id": trace.request_id,
        }
        try:
            self.step(
                "pull Keycloak/LDAP Principals, apply SCIM push, and persist grants",
                self._bootstrap_authorization_policy,
            )
        finally:
            self.api_trace_headers = {}
            span.finish()
            trace.finish()
        self.step("export administrator pre-authorization trace", lambda: self._export_verifier_trace(trace))
        verifier = ControlPlaneJaegerTraceVerifier()
        def query_trace() -> dict:
            with self._forward_service(self.jaeger_service, 16686) as query_port:
                return self._jaeger_query(query_port).wait_for_trace(trace, verifier)

        payload = self.step("query and validate the persisted Jaeger trace", query_trace)
        verifier.verify(payload, trace)
        self.details.extend(
            [
                "Jaeger Query API verified administrator federation, materialization, and "
                "revision-checked policy calls in AuthZ",
                f"administrator Jaeger trace ID: {trace.trace_id}",
            ]
        )

    def _bootstrap_authorization_policy(self) -> None:
        """Apply administrator grants to federated enterprise Principals."""
        with self._forward_service(self.authguard_release, 9091) as port:
            canonical_principals = self._materialize_scenario_principals(port)
            self._verify_direct_ldap_principal_discovery(port)
            self._verify_scim_push_provisioning(port, canonical_principals)
            self._required_group_principal_ids(port)

            status, body = self._api_http(port, "/api/v1/policy")
            self._expect_status("read bootstrap policy", status, 200)
            revision = json.loads(body)["revision"]
            replacement = self._authorization_policy(
                revision=revision,
                user_principal_ids={
                    username: principal["id"]
                    for username, principal in canonical_principals["users"].items()
                },
            )
            status, body = self._api_http(
                port,
                "/api/v1/policy",
                method="PUT",
                headers={"If-Match": str(revision)},
                json_body=replacement,
            )
            self._expect_status("bind projected principals atomically", status, 200)
            persisted = json.loads(body)
            if persisted.get("revision", 0) <= revision:
                raise RuntimeError("policy replacement did not advance its revision")
            self.details.append(
                "administrator pre-authorization bound federated canonical user/workload "
                "Principals in one revision-checked policy replacement before business login"
            )

    def _materialize_scenario_principals(
        self,
        api_port: int,
    ) -> dict[str, dict[str, dict]]:
        """Federate and materialize enterprise users, groups, and workloads."""
        resolved: dict[str, dict[str, dict]] = {"users": {}, "groups": {}}
        keycloak = self.principal_scenarios["keycloak"]
        provider_id = keycloak["provider_id"]
        for user in keycloak["users"]:
            candidate = self._search_external_principal(
                api_port,
                provider_id=provider_id,
                identity=user,
                expected_issuer=self.issuer,
                expected_external_id=user["external_id"],
            )
            resolved["users"][user["username"]] = self._materialize_idempotently(
                api_port, candidate, user["principal_id"]
            )
        for group in keycloak["groups"]:
            group_name = group["username"]
            group_candidate = self._search_external_principal(
                api_port,
                provider_id=provider_id,
                identity=group,
                expected_issuer=self.issuer,
                expected_external_id=group["external_id"],
            )
            resolved["groups"][group_name] = self._materialize_idempotently(
                api_port, group_candidate, group["principal_id"]
            )

        workload = keycloak["workload"]
        workload_candidate = self._search_external_principal(
            api_port,
            provider_id=provider_id,
            identity=workload,
            expected_issuer=self.issuer,
        )
        self._materialize_idempotently(
            api_port, workload_candidate, workload["principal_id"]
        )

        self.details.append(
            "the optional Keycloak integration federated and materialized "
            f"{len(resolved['users'])} users, {len(resolved['groups'])} groups, and one "
            "workload before administrator pre-authorization"
        )
        return resolved

    def _verify_direct_ldap_principal_discovery(self, port: int) -> None:
        """Prove native LDAP discovery without making Keycloak an LDAP dependency."""
        fixture = self.principal_scenarios["ldap"]
        identity = fixture["identity"]
        direct = fixture["direct"]
        ldap_candidate = self._search_external_principal(
            port,
            provider_id=direct["provider_id"],
            identity=identity,
            expected_issuer=direct["issuer"],
            expected_external_id=identity["immutable_external_id"],
        )
        self._materialize_idempotently(
            port, ldap_candidate, direct["principal_id"]
        )
        self.details.append(
            "Authguard direct LDAP (RFC 4511) discovery resolved a directory identity "
            "by stable POSIX uidNumber and materialized it idempotently; Keycloak remains "
            "an independent optional IdP integration"
        )

    def _verify_scim_push_provisioning(
        self,
        port: int,
        canonical_principals: dict[str, dict[str, dict]],
    ) -> None:
        """Prove SCIM lifecycle and exact external-identity convergence."""
        fixture = self.principal_scenarios["scim"]
        user_payload = json.loads(json.dumps(fixture["user"]))
        group_payload = json.loads(json.dumps(fixture["group"]))

        self._verify_scim_lifecycle(
            port,
            payload=user_payload,
            expected_kind="USER",
        )
        self._verify_scim_lifecycle(
            port,
            payload=group_payload,
            expected_kind="GROUP",
        )

        canonical_user = canonical_principals["users"]["direct-reader"]
        converged_user = json.loads(json.dumps(user_payload))
        converged_user["resource"].update(
            {
                "id": "scim-canonical-user-convergence",
                "externalId": self.principal_scenarios["keycloak"]["users"][0]["external_id"],
                "userName": "direct-reader",
                "displayName": "Direct Reader",
            }
        )
        projected = self._scim_event(
            port,
            converged_user,
            create=True,
            existing_principal_id=canonical_user["id"],
        )
        if projected["id"] != canonical_user["id"]:
            raise RuntimeError("SCIM User did not converge on the canonical OIDC Principal")
        self._get_principal(port, canonical_user["id"])

        canonical_group = canonical_principals["groups"]["direct-readers"]
        converged_group = json.loads(json.dumps(group_payload))
        converged_group["resource"].update(
            {
                "id": "scim-canonical-group-convergence",
                "externalId": self.principal_scenarios["keycloak"]["groups"][0]["external_id"],
                "displayName": "Direct Readers",
            }
        )
        projected = self._scim_event(
            port,
            converged_group,
            create=True,
            existing_principal_id=canonical_group["id"],
        )
        if projected["id"] != canonical_group["id"]:
            raise RuntimeError("SCIM Group did not converge on the canonical OIDC Principal")
        self._get_principal(port, canonical_group["id"])
        self.details.extend(
            [
                "SCIM RFC 7643 User and Group resources were idempotent across "
                "upsert, disable, and reactivation lifecycle transitions",
                "SCIM and OIDC materialization converged only through the exact "
                "(provider, issuer, externalId) identity key, never through email",
            ]
        )

    def _verify_scim_lifecycle(
        self,
        port: int,
        *,
        payload: dict,
        expected_kind: str,
    ) -> None:
        display_name = payload["resource"]["displayName"]
        existing = next(
            (
                principal
                for principal in self._list_principals(port)
                if principal.get("kind") == expected_kind
                and principal.get("display_name") == display_name
            ),
            None,
        )
        if existing is not None:
            payload["principal_id"] = existing["id"]
            first = self._scim_event(port, payload)
        else:
            first = self._scim_event(port, payload, create=True)
        principal_id = first["id"]
        payload["principal_id"] = principal_id
        second = self._scim_event(port, payload)
        if first["id"] != second["id"]:
            raise RuntimeError(f"SCIM {expected_kind} upsert was not idempotent")
        active = self._get_principal(port, principal_id)
        if active.get("kind") != expected_kind or active.get("status") != "ACTIVE":
            raise RuntimeError(f"SCIM {expected_kind} Principal is not active")
        if active["id"] != first["id"]:
            raise RuntimeError(f"SCIM {expected_kind} lookup returned a different projection")

        self._scim_delete(
            port,
            principal_id,
            expected_kind,
        )
        disabled = self._get_principal(port, principal_id)
        if disabled.get("kind") != expected_kind or disabled.get("status") != "DISABLED":
            raise RuntimeError(f"SCIM {expected_kind} Principal was not tombstoned")
        if disabled["id"] != first["id"]:
            raise RuntimeError(f"SCIM {expected_kind} tombstone changed its local identifier")

        reactivated = self._scim_event(port, payload, create=True)
        if reactivated["id"] != first["id"]:
            raise RuntimeError(f"SCIM {expected_kind} upsert did not reactivate its tombstone")
        if expected_kind == "USER" and reactivated.get("active") is not True:
            raise RuntimeError("SCIM USER reactivation did not restore active=true")
        if expected_kind == "GROUP" and "active" in reactivated:
            raise RuntimeError("SCIM GROUP response exposed non-standard active attribute")

    def _search_external_principal(
        self,
        port: int,
        *,
        provider_id: str,
        identity: dict,
        expected_issuer: str,
        expected_external_id: str | None = None,
    ) -> dict:
        status, body = self._api_http(
            port,
            "/api/v1/principal-discovery/search",
            method="POST",
            json_body={
                "text": identity["username"],
                "kinds": [identity["expected_kind"]],
                "provider_ids": [provider_id],
                "per_provider_limit": 20,
                "cursors": {},
            },
        )
        self._expect_status(f"federated Principal search via {provider_id}", status, 200)
        candidates = []
        lookup_name = identity["username"]
        for candidate in json.loads(body).get("principals", []):
            reference = candidate.get("reference", {})
            if (
                reference.get("provider_id") == provider_id
                and reference.get("issuer") == expected_issuer
                and lookup_name
                in {candidate.get("username"), candidate.get("display_name")}
            ):
                candidates.append(candidate)
        if expected_external_id is not None:
            candidates = [
                candidate
                for candidate in candidates
                if candidate["reference"].get("external_id") == expected_external_id
            ]
        if len(candidates) != 1:
            raise RuntimeError(
                f"{provider_id}: expected exactly one matching federated Principal, "
                f"found {len(candidates)}"
            )
        candidate = candidates[0]
        if (
            candidate.get("kind") != identity["expected_kind"]
            or candidate.get("enabled") is not True
            or not candidate["reference"].get("external_id")
        ):
            raise RuntimeError(
                f"{provider_id}: federated Principal attributes do not match fixture"
            )
        for field in ("display_name", "email"):
            if field in identity and candidate.get(field) != identity[field]:
                raise RuntimeError(
                    f"{provider_id}: federated Principal {field} does not match fixture"
                )
        return candidate

    def _materialize_idempotently(
        self, port: int, candidate: dict, principal_id: str
    ) -> dict:
        reference = candidate["reference"]
        persisted: list[dict] = []
        for attempt in (1, 2):
            status, body = self._api_http(
                port,
                "/api/v1/principal-discovery/materialize",
                method="POST",
                json_body={"principal_id": principal_id, "reference": reference},
            )
            self._expect_status(
                f"materialize {reference['provider_id']} attempt {attempt}", status, 201
            )
            persisted.append(json.loads(body))
        if persisted[0]["id"] != persisted[1]["id"]:
            raise RuntimeError(
                f"{reference['provider_id']}: repeated materialization changed local identifier"
            )
        local = self._get_principal(port, principal_id)
        if local["id"] != persisted[0]["id"]:
            raise RuntimeError(
                f"{reference['provider_id']}: materialized projection cannot be resolved exactly"
            )
        return local

    def _get_principal(self, port: int, principal_id: str) -> dict:
        encoded_id = parse.quote(principal_id, safe="")
        status, body = self._api_http(port, f"/api/v1/principals/{encoded_id}")
        self._expect_status(f"read canonical Principal {principal_id}", status, 200)
        principal = json.loads(body)
        if principal.get("id") != principal_id:
            raise RuntimeError("Principal lookup returned a different canonical identifier")
        return principal

    def _scim_event(
        self,
        port: int,
        payload: dict,
        *,
        create: bool = False,
        existing_principal_id: str | None = None,
    ) -> dict:
        operation = payload["operation"]
        resource_kind = "Users" if operation == "upsert_user" else "Groups"
        resource = dict(payload["resource"])
        schema = (
            "urn:ietf:params:scim:schemas:core:2.0:User"
            if resource_kind == "Users"
            else "urn:ietf:params:scim:schemas:core:2.0:Group"
        )
        resource.setdefault("schemas", [schema])
        resource.pop("id", None)
        path = f"/scim/v2/{resource_kind}"
        method = "POST"
        expected_status = 201
        if not create:
            principal_id = parse.quote(payload["principal_id"], safe="")
            path = f"{path}/{principal_id}"
            method = "PUT"
            expected_status = 200
        status, body = self._api_http(
            port,
            path,
            method=method,
            json_body=resource,
        )
        if status == 409 and create and existing_principal_id is not None:
            return self._get_principal(port, existing_principal_id)
        self._expect_status(f"SCIM {operation}", status, expected_status)
        projected = json.loads(body)
        if not isinstance(projected, dict) or not projected.get("id"):
            raise RuntimeError("SCIM resource operation did not return a persisted Principal")
        return projected

    def _scim_delete(self, port: int, principal_id: str, kind: str) -> None:
        resource_kind = "Users" if kind == "USER" else "Groups"
        encoded_id = parse.quote(principal_id, safe="")
        status, _ = self._api_http(
            port,
            f"/scim/v2/{resource_kind}/{encoded_id}",
            method="DELETE",
        )
        self._expect_status(f"SCIM delete {kind}", status, 204)

    def _list_principals(self, port: int) -> list[dict]:
        status, body = self._api_http(port, "/api/v1/principals?limit=1000")
        self._expect_status("list local Principals", status, 200)
        return json.loads(body).get("items", [])

    def _required_group_principal_ids(self, port: int) -> dict[str, str]:
        for principal_id in GROUP_PRINCIPAL_IDS.values():
            principal = self._get_principal(port, principal_id)
            if principal.get("kind") != "GROUP" or principal.get("status") != "ACTIVE":
                raise RuntimeError(f"canonical group Principal {principal_id!r} is not active")
        return dict(GROUP_PRINCIPAL_IDS)

    def _authorization_policy(
        self,
        *,
        revision: int,
        user_principal_ids: dict[str, str] | None = None,
    ) -> dict:
        route_specs = (
            ("job-list", "GET", "customer-growth.job.read", "/customer-growth/jobs"),
            ("job-read", "GET", "customer-growth.job.read", "/customer-growth/jobs/{id}"),
            ("job-create", "POST", "customer-growth.job.create", "/customer-growth/jobs"),
            ("job-update", "PUT", "customer-growth.job.update", "/customer-growth/jobs/{id}"),
            ("job-delete", "DELETE", "customer-growth.job.delete", "/customer-growth/jobs/{id}"),
        )
        routes_by_action: dict[str, list[dict]] = {}
        for route_id, method, action, path in route_specs:
            routes_by_action.setdefault(action, []).append(
                {
                    "id": route_id,
                    "methods": [method],
                    "hosts": list(WORKLOAD_HOSTS.values()),
                    "path": path,
                    "resource_urn": (
                        "urn:iam:prod:customer-growth:global:{tenant_id}:workspace/"
                        "customer-insights/project/retention-analytics"
                    ),
                    "parent_urns": [],
                }
            )
        action_ids = (
            "customer-growth.job.read",
            "customer-growth.job.create",
            "customer-growth.job.update",
            "customer-growth.job.delete",
        )
        policy = {
            "id": "default",
            "revision": revision,
            "name": "E2E customer growth authorization policy",
            "description": "Canonical Principal team access for five isolated workloads",
            "actions": [
                {
                    "identifier": action,
                    "description": f"Authorize {action.rsplit('.', 1)[-1]} operations",
                    "route_matchers": routes_by_action[action],
                }
                for action in action_ids
            ],
            "roles": [
                {
                    "id": "job.reader",
                    "name": "Customer growth job reader",
                    "description": "Read customer growth jobs within an assigned URN scope",
                    "action_ids": ["customer-growth.job.read"],
                },
                {
                    "id": "job.editor",
                    "name": "Customer growth job editor",
                    "description": "Create, read, update, and delete assigned jobs",
                    "action_ids": list(action_ids),
                },
            ],
            "role_bindings": [],
        }
        if user_principal_ids is None:
            return policy

        workspace = (
            "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights"
        )
        retention = f"{workspace}/project/retention-analytics"
        forecast = (
            f"{workspace}/project/lifetime-value-forecasting/job/"
            "daily-customer-lifetime-value-forecast"
        )
        policy["role_bindings"] = [
            {
                "id": "direct-reader-workspace",
                "principal_id": user_principal_ids["direct-reader"],
                "role_id": "job.reader",
                "effect": "ALLOW",
                "resource_urn": f"{workspace}/**",
                "conditions": {},
            },
            {
                "id": "token-editor-retention",
                "principal_id": user_principal_ids["token-editor"],
                "role_id": "job.editor",
                "effect": "ALLOW",
                "resource_urn": f"{retention}/**",
                "conditions": {},
            },
            {
                "id": "token-editor-forecast-read",
                "principal_id": user_principal_ids["token-editor"],
                "role_id": "job.reader",
                "effect": "ALLOW",
                "resource_urn": forecast,
                "conditions": {},
            },
            {
                "id": "token-editor-vip-deny",
                "principal_id": user_principal_ids["token-editor"],
                "role_id": "job.reader",
                "effect": "DENY",
                "resource_urn": f"{retention}/job/vip-retention-risk-audit",
                "conditions": {},
            },
            {
                "id": "growth-job-runner-read",
                "principal_id": "principal-growth-job-runner",
                "role_id": "job.reader",
                "effect": "ALLOW",
                "resource_urn": f"{retention}/**",
                "conditions": {},
            },
            {
                "id": "no-data-reader-function",
                "principal_id": user_principal_ids["no-data-reader"],
                "role_id": "job.reader",
                "effect": "ALLOW",
                "resource_urn": retention,
                "conditions": {},
            },
        ]
        return policy


def verify(context: RunContext) -> VerificationResult:
    return PrincipalPreauthorizationVerifier(context).run()
