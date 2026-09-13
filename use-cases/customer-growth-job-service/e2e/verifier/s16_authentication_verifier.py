"""Phase 16: verify AuthN OAuth-like normalization and account linking."""

from __future__ import annotations

import json
import os
from urllib import error, parse, request

from common.kubernetes import AUTHN_HOST
from common.model import RunContext, VerificationResult
from common.telemetry import E2ETrace
from verifier.base_verifier import BaseVerifier
from verifier.s20_observability_contract import AuthnJaegerTraceVerifier


class AuthenticationVerifier(BaseVerifier):
    scenario_id = "16"
    title = "Core 2/3: AuthN callback, normalization, linking, and tracing"

    def run(self) -> VerificationResult:
        return self.execute(self.verify_authentication)

    def verify_authentication(self) -> None:
        """Exercise OAuth-like AuthN normalization and durable account linking."""
        envoy_service = self._envoy_proxy_service()

        def login_all(round_name: str) -> dict[str, dict]:
            results: dict[str, dict] = {}
            with (
                self._forward_service(envoy_service, 8082) as authn_gateway_port,
                self._forward_service(self.mock_idp_service, 8080) as mock_idp_port,
            ):
                for flow in self.authn_scenarios["provider_flows"]:
                    provider = flow["provider_id"]
                    results[provider] = self.step(
                        f"{round_name} {provider} authorize/callback/token/identity flow",
                        lambda flow=flow: self._social_login(
                            authn_gateway_port,
                            mock_idp_port,
                            flow["provider_id"],
                            flow["external_identity"].get("username"),
                            flow["expected_principal"]["trusted_claims"],
                        ),
                    )
            return results

        first_logins = login_all("first-login")
        repeated_logins = login_all("repeat-login")

        def verify_bindings() -> None:
            for provider, first in first_logins.items():
                repeated = repeated_logins[provider]
                if first["principal"]["principalId"] != repeated["principal"]["principalId"]:
                    raise RuntimeError("repeated social login created a duplicate Principal")

        self.step("verify durable identity bindings reuse canonical Principals", verify_bindings)
        self.step("query and validate all provider traces in Jaeger", self._verify_authn_distributed_traces)

    def _social_login(
        self,
        authn_gateway_port: int,
        mock_idp_port: int,
        provider: str,
        expected_username: str | None,
        trusted_claims: dict[str, object],
    ) -> dict:
        """Drive browser redirects through Envoy and a real OAuth-like adapter flow."""

        trace = E2ETrace(
            "customer-growth.authentication.e2e",
            request_id=f"e2e-authguard-authn-{provider}-{os.urandom(6).hex()}",
        )

        class NoRedirect(request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = request.build_opener(NoRedirect)

        def redirect_location(
            url: str,
            *,
            host: str | None = None,
            headers: dict[str, str] | None = None,
        ) -> str:
            headers = {**({"Host": host} if host else {}), **(headers or {})}
            outgoing = request.Request(url, headers=headers)
            try:
                opener.open(outgoing, timeout=15)
            except error.HTTPError as response:
                if response.code not in (302, 303, 307, 308):
                    raise
                location = response.headers.get("Location")
                if location:
                    return location
            raise RuntimeError(f"expected OAuth redirect from {url}")

        authorize_span = trace.start_client(
            "envoy.authn.authorize",
            **{
                "server.address": AUTHN_HOST,
                "http.request.method": "GET",
            },
        )
        authorize_location = redirect_location(
            f"http://127.0.0.1:{authn_gateway_port}/auth/v1/providers/{provider}/authorize"
            "?return_uri=%2Fcustomer-growth%2Fjobs",
            host=AUTHN_HOST,
            headers={
                "traceparent": authorize_span.traceparent,
                "x-request-id": trace.request_id,
            },
        )
        authorize_span.finish()
        provider_url = parse.urlsplit(authorize_location)
        callback_location = redirect_location(
            f"http://127.0.0.1:{mock_idp_port}{provider_url.path}"
            + (f"?{provider_url.query}" if provider_url.query else "")
        )
        callback_url = parse.urlsplit(callback_location)
        callback_span = trace.start_client(
            "envoy.authn.callback",
            **{
                "server.address": AUTHN_HOST,
                "http.request.method": "GET",
            },
        )
        outgoing = request.Request(
            f"http://127.0.0.1:{authn_gateway_port}{callback_url.path}"
            + (f"?{callback_url.query}" if callback_url.query else ""),
            headers={
                "Host": AUTHN_HOST,
                "traceparent": callback_span.traceparent,
                "x-request-id": trace.request_id,
            },
        )
        with request.urlopen(outgoing, timeout=20) as response:
            if response.status != 200:
                raise RuntimeError(f"AuthN callback returned HTTP {response.status}")
            login = json.loads(response.read())
        callback_span.finish()
        trace.finish()
        self.authn_traces[provider] = trace
        claims = self._jwt_claims(login.get("accessToken", ""))
        principal = login.get("principal", {})
        provider_claims = {"id", "openid", "unionid", "access_token", "authorization_code"}
        if (
            claims.get("iss") != self.authn_issuer
            or claims.get("aud") != "customer-growth-job-service"
            or claims.get("principal_id") != principal.get("principalId")
            or claims.get("principal_kind") != "USER"
            or claims.get("authguard_group_ids") != []
            or provider_claims.intersection(claims)
        ):
            raise RuntimeError(f"{provider}: AuthN emitted an invalid canonical Principal token")
        if any(claims.get(name) != value for name, value in trusted_claims.items()):
            raise RuntimeError(f"{provider}: AuthN emitted invalid trusted claims")
        if expected_username is not None and claims.get("username") != expected_username:
            raise RuntimeError(f"{provider}: AuthN emitted an invalid normalized username")
        self.authn_trace_principals[provider] = principal["principalId"]
        self.details.append(
            f"{provider}: Envoy -> AuthN callback -> token exchange -> identity lookup -> "
            "ExternalIdentity -> durable identity binding -> canonical Principal succeeded"
        )
        return login

    def _verify_authn_distributed_traces(self) -> None:
        expected_providers = tuple(
            flow["provider_id"] for flow in self.authn_scenarios["provider_flows"]
        )
        missing = set(expected_providers) - self.authn_traces.keys()
        if missing:
            raise RuntimeError(f"AuthN trace producers are missing for {sorted(missing)}")
        for provider in expected_providers:
            self._export_verifier_trace(self.authn_traces[provider])

        with self._forward_service(self.jaeger_service, 16686) as query_port:
            jaeger = self._jaeger_query(query_port)
            trace_ids: list[str] = []
            for provider in expected_providers:
                trace = self.authn_traces[provider]
                verifier = AuthnJaegerTraceVerifier(
                    provider=provider,
                    principal_id=self.authn_trace_principals[provider],
                )
                payload = jaeger.wait_for_trace(trace, verifier)
                verifier.verify(payload, trace)
                trace_ids.append(trace.trace_id)
            jaeger.require_services({"authguard-authn"})
        self.details.append(
            "Jaeger Query API verified AuthN authorize/callback server spans and "
            "provider child spans for " + ", ".join(expected_providers)
        )
        self.details.append("AuthN Jaeger trace IDs: " + ", ".join(trace_ids))


def verify(context: RunContext) -> VerificationResult:
    return AuthenticationVerifier(context).run()
