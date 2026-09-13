"""Phase 17: verify user/workload access through Envoy, AuthZ, and Biz."""

from __future__ import annotations

import json
import sqlite3
from urllib import parse, request

from common.config import CONFIG_DIR
from common.kubernetes import AUTHN_HOST, WORKLOAD_HOSTS, WORKLOAD_IMAGES
from common.model import RunContext, VerificationResult
from common.telemetry import E2ETrace
from verifier.base_verifier import BaseVerifier
from verifier.s20_observability_contract import AuthorizationJaegerTraceVerifier, OidcJaegerTraceVerifier


ROW_ACCESS_ORACLE = {
    "principal-direct-reader": frozenset({1, 2, 3, 6}),
    "principal-token-editor": frozenset({1, 3, 6}),
    "principal-no-data-reader": frozenset(),
    "principal-growth-job-runner": frozenset({1, 2, 6}),
}


class GatewayAuthorizationVerifier(BaseVerifier):
    scenario_id = "17"
    title = "Core 3/3: OIDC user/workload, Envoy, AuthZ, and Biz CRUD"

    def run(self) -> VerificationResult:
        return self.execute(lambda: self.verify_gateway_authorization(ROW_ACCESS_ORACLE))

    def verify_gateway_authorization(
        self, row_access_oracle: dict[str, frozenset[int]]
    ) -> None:
        """Verify pre-authorized user/workload requests through Envoy and AuthZ."""
        seeded_job_ids = self.step(
            "compare all five deployed PostgreSQL fixtures with init.sql",
            self._verify_deployed_business_fixtures,
        )

        def issue_external_tokens() -> tuple[str, str, str]:
            with self._forward_service(self.keycloak_service, 8080) as keycloak_port:
                return (
                    self._password_token(
                        keycloak_port, "direct-reader", "direct-reader-password"
                    ),
                    self._password_token(
                        keycloak_port, "token-editor", "token-editor-password"
                    ),
                    self._password_token(
                        keycloak_port, "no-data-reader", "no-data-reader-password"
                    ),
                )

        direct_external_token, editor_external_token, no_data_external_token = self.step(
            "issue three real Keycloak OIDC user tokens", issue_external_tokens
        )
        envoy_service = self._envoy_proxy_service()

        def canonicalize_tokens() -> tuple[str, str, str, E2ETrace]:
            with self._forward_service(envoy_service, 8082) as authn_gateway_port:
                oidc_trace = E2ETrace("customer-growth.authentication.oidc.e2e")
                oidc_span = oidc_trace.start_client("envoy.authn.oidc")
                direct_token = self._canonicalize_token(
                    authn_gateway_port,
                    direct_external_token,
                    "USER",
                    headers={
                        "traceparent": oidc_span.traceparent,
                        "x-request-id": oidc_trace.request_id,
                    },
                )
                oidc_span.finish()
                oidc_trace.finish()
                return (
                    direct_token,
                    self._canonicalize_token(
                        authn_gateway_port, editor_external_token, "USER"
                    ),
                    self._canonicalize_token(
                        authn_gateway_port, no_data_external_token, "USER"
                    ),
                    oidc_trace,
                )

        direct_token, editor_token, no_data_token, oidc_trace = self.step(
            "normalize external identities into canonical AuthN tokens",
            canonicalize_tokens,
        )

        def verify_oidc_trace() -> None:
            self._export_verifier_trace(oidc_trace)
            with self._forward_service(self.jaeger_service, 16686) as query_port:
                verifier = OidcJaegerTraceVerifier("principal-direct-reader")
                payload = self._jaeger_query(query_port).wait_for_trace(
                    oidc_trace, verifier
                )
            verifier.verify(payload, oidc_trace)
            self.details.append(
                "Jaeger verified Keycloak OIDC token normalization through Envoy/AuthN to "
                "canonical principal-direct-reader"
            )

        self.step("query the persisted OIDC normalization trace", verify_oidc_trace)
        for token, principal_id in (
            (direct_token, "principal-direct-reader"),
            (editor_token, "principal-token-editor"),
            (no_data_token, "principal-no-data-reader"),
        ):
            if self._jwt_claims(token).get("principal_id") != principal_id:
                raise RuntimeError(f"AuthN canonical token did not contain {principal_id!r}")

        with (
            self._forward_service(envoy_service, 80) as gateway_port,
            self._forward_service(envoy_service, 8082) as authn_gateway_port,
        ):
            self.step(
                "prove Envoy jwt_authn rejects tampering before ext_authz",
                lambda: self._verify_jwt_gate_precedes_ext_auth(
                    gateway_port,
                    next(iter(WORKLOAD_HOSTS.values())),
                    direct_token,
                ),
            )
            for component, host in WORKLOAD_HOSTS.items():
                self.step(
                    f"{component}: verify CRUD, list scope, and 3×6 user row matrix",
                    lambda component=component, host=host: self._verify_workload_contract(
                        gateway_port,
                        component,
                        host,
                        direct_token,
                        editor_token,
                        no_data_token,
                        seeded_job_ids,
                        row_access_oracle,
                    ),
                )
                self.step(
                    f"{component}: query Envoy/AuthZ/Biz distributed trace",
                    lambda component=component, host=host: self._verify_distributed_trace(
                        gateway_port, component, host, direct_token
                    ),
                )
            self.step(
                "verify create is denied by AuthZ for every Biz service",
                lambda: self._verify_create_denied_by_authz(
                    gateway_port, direct_token, editor_token
                ),
            )
            self.step(
                "verify workload client_credentials and 1×6 row matrix",
                lambda: self._verify_workload_client_credentials(
                    gateway_port,
                    authn_gateway_port,
                    seeded_job_ids,
                    row_access_oracle,
                ),
            )
            self.step(
                "verify Authguard-origin re-signed JWT boundary",
                lambda: self._verify_resign_token_boundary(gateway_port, direct_token),
            )
            self.step("verify route matcher fail-closed denials", self._verify_route_matcher_denials)
        self.step(
            "prove CRUD and denied requests left all seed rows unchanged",
            self._verify_deployed_business_fixtures,
        )

    def _verify_workload_contract(
        self,
        gateway_port: int,
        component: str,
        host: str,
        direct_token: str,
        editor_token: str,
        no_data_token: str,
        seeded_job_ids: frozenset[int],
        row_access_oracle: dict[str, frozenset[int]],
    ) -> None:
        label = f"e2e-authguard-{component}"
        status, _ = self._http(gateway_port, host, "/customer-growth/jobs")
        self._expect_status(f"{label}: missing JWT", status, 401)

        status, body = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            headers={"Authorization": f"Bearer {direct_token}"},
        )
        self._expect_status(f"{label}: direct context list", status, 200)
        self._expect_job_ids(f"{label}: direct context list", body, [1, 2, 3, 6])

        status, body = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: opaque token list", status, 200)
        self._expect_job_ids(f"{label}: opaque token list", body, [1, 3, 6])

        status, body = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            headers={"Authorization": f"Bearer {no_data_token}"},
        )
        self._expect_status(f"{label}: LIST action with empty data scope", status, 200)
        self._expect_job_ids(f"{label}: empty data scope hides every seeded row", body, [])

        self._verify_row_access_matrix(
            gateway_port,
            host,
            label,
            seeded_job_ids,
            row_access_oracle,
            {
                "principal-direct-reader": direct_token,
                "principal-token-editor": editor_token,
                "principal-no-data-reader": no_data_token,
            },
        )

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/2",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: explicit URN deny is hidden", status, 404)

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/5",
            headers={
                "Authorization": f"Bearer {direct_token}",
                "x-authguard-context": "forged-client-context",
            },
        )
        self._expect_status(f"{label}: forged context is removed", status, 404)

        created = {
            "id": 101,
            "region": "global",
            "tenant_id": "example-corp",
            "workspace_id": "customer-insights",
            "project_id": "retention-analytics",
            "job_id": "monthly-retention-review",
            "display_name": "Monthly retention review",
            "status": "READY",
            "owner_user_id": "token-editor",
        }
        status, body = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            method="POST",
            headers={"Authorization": f"Bearer {editor_token}"},
            json_body=created,
        )
        self._expect_status(f"{label}: authorized create", status, 200)
        if json.loads(body)["job_id"] != created["job_id"]:
            raise RuntimeError(f"{label}: authorized create returned the wrong job")

        status, body = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/101",
            method="PUT",
            headers={"Authorization": f"Bearer {editor_token}"},
            json_body={
                "display_name": "Monthly retention review v2",
                "status": "PAUSED",
                "owner_user_id": "token-editor",
            },
        )
        self._expect_status(f"{label}: authorized update", status, 200)
        if json.loads(body)["status"] != "PAUSED":
            raise RuntimeError(f"{label}: authorized update did not persist")

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/101",
            method="DELETE",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: authorized delete", status, 204)
        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/101",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: deleted row stays absent", status, 404)

        # One deterministic outside-world probe: DELETE is an enumerated
        # customer-growth action but is NOT route-mapped, so the route
        # matcher itself must deny it before any resign/replace machinery
        # runs. The request pattern never mutates the backend.
        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/1",
            method="PATCH",
            headers={"Authorization": f"Bearer {direct_token}"},
        )
        self._expect_status(f"{label}: unmapped method is route-denied", status, 403)

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/not-mapped",
            headers={"Authorization": f"Bearer {direct_token}"},
        )
        self._expect_status(f"{label}: unmapped path is gateway route-not-found", status, 404)

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/1",
            method="PUT",
            headers={"Authorization": f"Bearer {direct_token}"},
            json_body={
                "display_name": "forbidden update",
                "status": "FAILED",
                "owner_user_id": "direct-reader",
            },
        )
        self._expect_status(f"{label}: read-only update is forbidden", status, 403)
        status, body = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/1",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: rejected update preserves row", status, 200)
        if json.loads(body)["status"] != "READY":
            raise RuntimeError(f"{label}: rejected update changed the database")

        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/1",
            method="DELETE",
            headers={"Authorization": f"Bearer {direct_token}"},
        )
        self._expect_status(f"{label}: read-only delete is forbidden", status, 403)
        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs/1",
            headers={"Authorization": f"Bearer {editor_token}"},
        )
        self._expect_status(f"{label}: rejected delete preserves row", status, 200)

    def _verify_create_denied_by_authz(
        self, gateway_port: int, read_token: str, editor_token: str
    ) -> None:
        """Prove every forbidden create terminates at AuthZ, before Biz persistence."""
        payload = {
            "id": 102,
            "region": "global",
            "tenant_id": "example-corp",
            "workspace_id": "customer-insights",
            "project_id": "retention-analytics",
            "job_id": "forbidden-create",
            "display_name": "Must not be created",
            "status": "READY",
            "owner_user_id": "direct-reader",
        }
        with self._forward_envoy_admin() as envoy_admin_port:
            before_envoy = self._envoy_auth_counters(envoy_admin_port)
            before_checks = self._authorization_check_count()
            before_denied = sum(self._authorization_denied_reasons().values())
            for component, host in WORKLOAD_HOSTS.items():
                status, _ = self._http(
                    gateway_port,
                    host,
                    "/customer-growth/jobs",
                    method="POST",
                    headers={"Authorization": f"Bearer {read_token}"},
                    json_body=payload,
                )
                self._expect_status(f"{component}: create denied by AuthZ", status, 403)
            after_envoy = self._envoy_auth_counters(envoy_admin_port)
        if self._authorization_check_count() - before_checks != len(WORKLOAD_HOSTS):
            raise RuntimeError("forbidden creates did not map one-to-one to AuthZ Check calls")
        self._expect_counter_delta(
            "forbidden create Envoy ext_authz.denied",
            before_envoy,
            after_envoy,
            "ext_auth_denied",
            len(WORKLOAD_HOSTS),
        )
        if sum(self._authorization_denied_reasons().values()) - before_denied != len(
            WORKLOAD_HOSTS
        ):
            raise RuntimeError("AuthZ denial metrics did not record every forbidden create")
        for component, host in WORKLOAD_HOSTS.items():
            status, _ = self._http(
                gateway_port,
                host,
                "/customer-growth/jobs/102",
                headers={"Authorization": f"Bearer {editor_token}"},
            )
            self._expect_status(f"{component}: rejected create did not mutate Biz DB", status, 404)

    def _verify_jwt_gate_precedes_ext_auth(
        self,
        gateway_port: int,
        host: str,
        valid_token: str,
    ) -> None:
        with self._forward_envoy_admin() as envoy_admin_port:
            before_envoy = self._envoy_auth_counters(envoy_admin_port)
            before_check = self._authorization_check_count()
            status, _ = self._http(
                gateway_port,
                host,
                "/customer-growth/jobs",
                headers={"Authorization": f"Bearer {self._tamper_jwt_signature(valid_token)}"},
            )
            self._expect_status("tampered AuthN JWT rejected by Envoy", status, 401)
            after_invalid_envoy = self._envoy_auth_counters(envoy_admin_port)
            after_invalid_check = self._authorization_check_count()
            if after_invalid_check != before_check:
                raise RuntimeError(
                    "tampered JWT reached Authguard Check; Envoy JWT verification did not run first"
                )
            self._expect_counter_delta(
                "tampered JWT Envoy jwt_authn.denied",
                before_envoy,
                after_invalid_envoy,
                "jwt_denied",
                1,
            )
            for counter in ("ext_auth_ok", "ext_auth_denied", "ext_auth_error"):
                self._expect_counter_delta(
                    f"tampered JWT Envoy {counter}",
                    before_envoy,
                    after_invalid_envoy,
                    counter,
                    0,
                )

            status, _ = self._http(
                gateway_port,
                host,
                "/customer-growth/jobs",
                headers={"Authorization": f"Bearer {valid_token}"},
            )
            self._expect_status("valid AuthN JWT passed Envoy and ext_auth", status, 200)
            after_valid_envoy = self._envoy_auth_counters(envoy_admin_port)
            after_valid_check = self._authorization_check_count()
            if after_valid_check != after_invalid_check + 1:
                raise RuntimeError(
                    "valid JWT did not produce exactly one Authguard Authorization/Check call: "
                    f"before={after_invalid_check}, after={after_valid_check}"
                )
            self._expect_counter_delta(
                "valid JWT Envoy jwt_authn.allowed",
                after_invalid_envoy,
                after_valid_envoy,
                "jwt_allowed",
                1,
            )
            self._expect_counter_delta(
                "valid JWT Envoy ext_authz.ok",
                after_invalid_envoy,
                after_valid_envoy,
                "ext_auth_ok",
                1,
            )
            for counter in ("ext_auth_denied", "ext_auth_error"):
                self._expect_counter_delta(
                    f"valid JWT Envoy {counter}",
                    after_invalid_envoy,
                    after_valid_envoy,
                    counter,
                    0,
                )
        self.details.append(
            "tampered JWT caused zero Authguard Check calls; valid AuthN JWT caused "
            "exactly one envoy.service.auth.v3.Authorization/Check call"
        )

    def _verify_workload_client_credentials(
        self,
        gateway_port: int,
        authn_gateway_port: int,
        seeded_job_ids: frozenset[int],
        row_access_oracle: dict[str, frozenset[int]],
    ) -> None:
        """Prove the machine-identity flow: a business SA exchanges its own
        client secret for an access token (OAuth2 client_credentials — no
        browser, no user login) and the audience mapper stamps the workload
        audience so Envoy accepts it."""
        with self._forward_service(self.keycloak_service, 8080) as keycloak_port:
            exchange = parse.urlencode(
                {
                    "grant_type": "client_credentials",
                    "client_id": "e2e-authguard-growth-job-runner",
                    "client_secret": "e2e-authguard-workload-client-secret",
                    "audience": "customer-growth-job-service",
                }
            ).encode()
            token_request = request.Request(
                f"http://127.0.0.1:{keycloak_port}"
                "/realms/example-corp/protocol/openid-connect/token",
                data=exchange,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            with request.urlopen(token_request, timeout=15) as response:
                workload_external_token = json.loads(response.read())["access_token"]
        workload_token = self._canonicalize_token(
            authn_gateway_port, workload_external_token, "WORKLOAD"
        )
        claims = self._jwt_claims(workload_token)
        audience = claims.get("aud")
        audiences = {audience} if isinstance(audience, str) else set(audience or [])
        if "customer-growth-job-service" not in audiences:
            raise RuntimeError(
                "workload client_credentials token lacks the customer-growth-job-service "
                f"audience: {audience!r}"
            )
        if claims.get("principal_id") != "principal-growth-job-runner":
            raise RuntimeError("workload token lacks its canonical principal_id claim")
        if claims.get("principal_kind") != "WORKLOAD":
            raise RuntimeError("workload token lacks the WORKLOAD principal_kind claim")
        if claims.get("tenant_id") != "example-corp":
            raise RuntimeError("workload token lacks its trusted tenant_id claim")
        forbidden = {
            "id": 103,
            "region": "global",
            "tenant_id": "example-corp",
            "workspace_id": "customer-insights",
            "project_id": "retention-analytics",
            "job_id": "workload-forbidden-create",
            "display_name": "Must not be created",
            "status": "READY",
            "owner_user_id": "growth-job-runner",
        }
        for component, host in WORKLOAD_HOSTS.items():
            status, body = self._http(
                gateway_port,
                host,
                "/customer-growth/jobs",
                headers={"Authorization": f"Bearer {workload_token}"},
            )
            self._expect_status(f"{component}: workload read action", status, 200)
            self._expect_job_ids(
                f"{component}: workload data scope",
                body,
                list(row_access_oracle["principal-growth-job-runner"]),
            )
            self._verify_row_access_matrix(
                gateway_port,
                host,
                f"e2e-authguard-{component}",
                seeded_job_ids,
                row_access_oracle,
                {"principal-growth-job-runner": workload_token},
            )
            status, _ = self._http(
                gateway_port,
                host,
                "/customer-growth/jobs",
                method="POST",
                headers={"Authorization": f"Bearer {workload_token}"},
                json_body=forbidden,
            )
            self._expect_status(
                f"{component}: workload without create action is rejected by AuthZ",
                status,
                403,
            )
        self.details.append(
            "pre-authorized biz SA client_credentials token entered AuthN token exchange, "
            "then all five services enforced its read scope and AuthZ denied create"
        )

    def _canonicalize_token(
        self,
        authn_gateway_port: int,
        external_token: str,
        kind: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> str:
        payload = json.dumps(
            {"subjectToken": external_token, "kind": kind}, separators=(",", ":")
        ).encode()
        exchange = request.Request(
            f"http://127.0.0.1:{authn_gateway_port}"
            "/auth/v1/providers/e2e-authguard-keycloak/token-exchange",
            data=payload,
            method="POST",
            headers={
                "Host": AUTHN_HOST,
                "Content-Type": "application/json",
                **(headers or {}),
            },
        )
        with request.urlopen(exchange, timeout=20) as response:
            login = json.loads(response.read())
        token = login.get("accessToken", "")
        claims = self._jwt_claims(token)
        if claims.get("iss") != self.authn_issuer or claims.get("principal_kind") != kind:
            raise RuntimeError("OIDC token exchange did not return a canonical AuthN token")
        return token

    def _verify_resign_token_boundary(self, gateway_port: int, direct_token: str) -> None:
        """Prove the Authguard-origin boundary on the rust workload.

        Authguard re-signs every allowed request with authguardOrigin: true;
        the rust-sqlx service mounts the paired public key and rejects any
        Authorization header without that signature. A valid user JWT through
        Envoy is re-signed on ALLOW, so the request succeeds and the workload
        logs the verification; the same JWT sent directly to the workload
        (bypassing Envoy) fails the proof boundary with HTTP 401.
        """
        host = WORKLOAD_HOSTS["rust-sqlx"]
        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            headers={"Authorization": f"Bearer {direct_token}"},
        )
        self._expect_status(
            "rust workload accepts the Authguard resign JWT through Envoy", status, 200
        )

        with self._forward_service(self.workload_service("rust-sqlx"), 8080) as workload_port:
            status, body = self._http(
                workload_port,
                host,
                "/customer-growth/jobs",
                headers={"Authorization": f"Bearer {direct_token}"},
            )
            self._expect_status(
                "direct client call without a resign JWT is rejected", status, 401
            )
            if "resign JWT" not in body:
                raise RuntimeError(
                    "direct-call rejection does not identify the resign proof boundary: "
                    f"{body!r}"
                )

        logs = self._run(
            (
                "kubectl",
                "logs",
                "-n",
                self.namespace,
                f"deployment/{self.workload_service('rust-sqlx')}",
                "--tail=200",
            )
        ).output
        if "verified Authguard resign JWT" not in logs:
            raise RuntimeError("rust workload never verified an Authguard resign JWT")
        self.details.append(
            "rust workload verified the re-signed Authguard-origin JWT through Envoy and "
            "rejected a direct client call carrying the unmodified AuthN token"
        )

    @staticmethod
    def _tamper_jwt_signature(token: str) -> str:
        parts = token.split(".")
        if len(parts) != 3 or not parts[2]:
            raise RuntimeError("identity issuer returned a malformed signed JWT")
        replacement = "A" if parts[2][0] != "A" else "B"
        parts[2] = replacement + parts[2][1:]
        return ".".join(parts)

    def _authorization_check_count(self) -> int:
        with self._forward_service(self.authguard_release, 9091) as port:
            with request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=15) as response:
                metrics = response.read().decode()
        total = 0
        for line in metrics.splitlines():
            if not line.startswith("authguard_http_requests_total{"):
                continue
            if 'route="envoy.service.auth.v3.Authorization/Check"' not in line:
                continue
            if 'method="gRPC"' not in line:
                continue
            total += int(float(line.rsplit(maxsplit=1)[1]))
        return total

    @staticmethod
    def _expect_counter_delta(
        label: str,
        before: dict[str, int],
        after: dict[str, int],
        counter: str,
        expected: int,
    ) -> None:
        actual = after[counter] - before[counter]
        if actual != expected:
            raise RuntimeError(f"{label}: expected delta {expected}, got {actual}")

    @staticmethod
    def _envoy_auth_counters(port: int) -> dict[str, int]:
        with request.urlopen(
            f"http://127.0.0.1:{port}/stats?filter=(jwt_authn|ext_authz)&format=json",
            timeout=15,
        ) as response:
            stats = json.loads(response.read()).get("stats", [])
        suffixes = {
            "jwt_allowed": ".jwt_authn.allowed",
            "jwt_denied": ".jwt_authn.denied",
            "ext_auth_ok": ".ext_authz.ok",
            "ext_auth_denied": ".ext_authz.denied",
            "ext_auth_error": ".ext_authz.error",
        }
        counters = {name: 0 for name in suffixes}
        for stat in stats:
            metric = stat.get("name", "")
            if not metric.startswith("http."):
                continue
            for name, suffix in suffixes.items():
                if metric.endswith(suffix):
                    counters[name] += int(stat.get("value", 0))
        return counters

    def _authorization_denied_reasons(self) -> dict[str, int]:
        """Per-reason denial counts from the Authguard decisions metric."""
        with self._forward_service(self.authguard_release, 9091) as port:
            with request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=15) as response:
                metrics = response.read().decode()
        reasons: dict[str, int] = {}
        for line in metrics.splitlines():
            metric = 'authguard_authorization_decisions_total{decision="deny"'
            if not line.startswith(metric):
                continue
            label = line[len(metric):].split("}", 1)[0]
            reasons.setdefault(label, 0)
            reasons[label] += int(line.rsplit(" ", 1)[1])
        return reasons

    def _password_token(
        self,
        port: int,
        username: str,
        password: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> str:
        payload = parse.urlencode(
            {
                "grant_type": "password",
                "client_id": "customer-growth-job-service",
                "username": username,
                "password": password,
                "scope": "openid profile email",
            }
        ).encode()
        token_request = request.Request(
            f"http://127.0.0.1:{port}/realms/example-corp/protocol/openid-connect/token",
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                **(headers or {}),
            },
        )
        with request.urlopen(token_request, timeout=15) as response:
            return json.loads(response.read())["access_token"]

    def _verify_distributed_trace(
        self, gateway_port: int, component: str, host: str, canonical_token: str
    ) -> None:
        trace = E2ETrace(f"customer-growth.authorization.{component}.e2e")
        gateway_span = trace.start_client(
            "envoy.customer_growth_jobs",
            **{
                "server.address": host,
                "http.request.method": "GET",
                "url.path": "/customer-growth/jobs",
            },
        )
        status, _ = self._http(
            gateway_port,
            host,
            "/customer-growth/jobs",
            headers={
                "Authorization": f"Bearer {canonical_token}",
                "traceparent": gateway_span.traceparent,
                "x-request-id": trace.request_id,
            },
        )
        gateway_span.finish()
        self._expect_status("OTel-correlated authorized request", status, 200)

        self._export_verifier_trace(trace)

        with self._forward_service(self.jaeger_service, 16686) as query_port:
            verifier = AuthorizationJaegerTraceVerifier(
                workload_service=f"e2e-authguard-{component}"
            )
            payload = self._jaeger_query(query_port).wait_for_trace(trace, verifier)
        verifier.verify(payload, trace)
        self.details.extend(
            [
                f"{component}: Jaeger verified verifier -> Envoy -> AuthZ and "
                "Envoy -> Biz causal branches",
                f"{component} Jaeger trace ID: {trace.trace_id}",
                (
                    "Jaeger UI: kubectl -n "
                    f"{self.namespace} port-forward service/{self.jaeger_service} "
                    "16686:16686, then open "
                    f"http://127.0.0.1:16686/trace/{trace.trace_id}"
                ),
            ]
        )

    def _verify_route_matcher_denials(self) -> None:
        """The access-condition step must deny before any scope machinery runs."""
        denied = self._authorization_denied_reasons()
        route_denials = sum(
            count
            for label, count in denied.items()
            if "route_not_mapped" in label
        )
        if route_denials < len(WORKLOAD_HOSTS):
            raise RuntimeError(
                "route matcher denials are missing: expected one route_not_mapped "
                "denial per workload for the unmapped-path probes"
            )
        self.details.append(
            f"{route_denials} route_not_mapped authorization denials observed: "
            "the access-condition route matcher rejected unmapped HTTP tuples "
            "before any resign/scope delivery"
        )

    def _verify_deployed_business_fixtures(self) -> frozenset[int]:
        columns = (
            "id",
            "region",
            "tenant_id",
            "workspace_id",
            "project_id",
            "job_id",
            "display_name",
            "status",
            "owner_user_id",
        )
        with sqlite3.connect(":memory:") as database:
            database.row_factory = sqlite3.Row
            database.executescript((CONFIG_DIR / "init.sql").read_text(encoding="utf-8"))
            expected = [
                dict(row)
                for row in database.execute(
                    f"SELECT {', '.join(columns)} "
                    "FROM e2e_authguard_customer_growth_jobs ORDER BY id"
                )
            ]
        pod = self._postgresql_pod()
        for component in WORKLOAD_IMAGES:
            schema = f"e2e_authguard_customer_growth_{component.replace('-', '_')}"
            query = (
                "SELECT COALESCE(json_agg(row_to_json(job) ORDER BY job.id), "
                "'[]'::json)::text FROM (SELECT "
                f"{', '.join(columns)} FROM {schema}.e2e_authguard_customer_growth_jobs"
                ") AS job"
            )
            actual = json.loads(self._postgresql_query(pod, query))
            if actual != expected:
                raise RuntimeError(
                    f"{component}: deployed PostgreSQL fixture differs from init.sql"
                )
        self.details.append(
            f"all five PostgreSQL schemas exactly match {len(expected)} init.sql seed rows"
        )
        return frozenset(row["id"] for row in expected)

    def _verify_row_access_matrix(
        self,
        gateway_port: int,
        host: str,
        component: str,
        seeded_job_ids: frozenset[int],
        oracle: dict[str, frozenset[int]],
        tokens: dict[str, str],
    ) -> None:
        for principal_id, token in tokens.items():
            expected = oracle.get(principal_id)
            if expected is None or not expected <= seeded_job_ids:
                raise RuntimeError(f"invalid row-access oracle for {principal_id}")
            visible: set[int] = set()
            for job_id in sorted(seeded_job_ids):
                status, body = self._http(
                    gateway_port,
                    host,
                    f"/customer-growth/jobs/{job_id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                expected_status = 200 if job_id in expected else 404
                if status != expected_status:
                    raise RuntimeError(
                        f"{component}: {principal_id} row {job_id} expected HTTP "
                        f"{expected_status}, got {status}"
                    )
                if status == 200:
                    returned_id = json.loads(body).get("id")
                    if returned_id != job_id:
                        raise RuntimeError(
                            f"{component}: requested row {job_id}, got {returned_id!r}"
                        )
                    visible.add(job_id)
            if visible != set(expected):
                raise RuntimeError(
                    f"{component}: {principal_id} expected visible rows "
                    f"{sorted(expected)}, got {sorted(visible)}"
                )
        self.details.append(
            f"{component}: row matrix verified {len(tokens)} Principals × "
            f"{len(seeded_job_ids)} deployed rows"
        )


def verify(context: RunContext) -> VerificationResult:
    return GatewayAuthorizationVerifier(context).run()
