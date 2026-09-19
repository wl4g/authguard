"""Web s31: hosted login branding, return targets, and browser token handoff."""

from __future__ import annotations

import json
import os
import re
from urllib import error, request

from playwright.sync_api import Page, Playwright, expect, sync_playwright

from common.kubernetes import (
    AUTHN_BROWSER_HOST,
    CUSTOMER_GROWTH_FALLBACK_HOST,
    CUSTOMER_GROWTH_HOST,
)
from common.model import RunContext, VerificationResult
from verifier.other.base import BaseVerifier
from verifier.web.fixtures import BrowserWalletFixture, Ctap2BrowserAuthenticator


class HostedLoginVerifier(BaseVerifier):
    """Prove AuthGuard hosts the concrete customer-growth login safely."""

    scenario_id = "31"
    title = "Web: hosted login application branding and return-target safety"

    def __init__(self, context: RunContext) -> None:
        super().__init__(context)
        self.login = f"hosted-r{context.round_number}-{os.urandom(5).hex()}@example.net"
        self.password = "hosted login browser proof password"
        self.page: Page | None = None
        self.authenticator_id = ""
        self.gateway_port = 0

    def run(self) -> VerificationResult:
        return self.execute(self._run_scenario)

    def _run_scenario(self) -> None:
        mock_host = f"{self.mock_idp_service}.{self.namespace}.svc.cluster.local"
        with (
            self._forward_service(self._envoy_proxy_service(), 8082) as gateway_port,
            self._forward_service(self.mock_idp_service, 8080) as mock_port,
        ):
            self.gateway_port = gateway_port
            self.step("HL-01..05: host-derived metadata, assets, and rejected return targets", self._api_contract)
            self.step("HL-06: password response sets an HttpOnly Secure canonical-token cookie", self._cookie_handoff)
            with sync_playwright() as playwright:
                browser = self._launch_browser(
                    playwright, mock_host, gateway_port, mock_port
                )
                try:
                    context = browser.new_context(locale="en-US")
                    context.expose_function(
                        "authguardE2ESign", BrowserWalletFixture.sign_personal_message
                    )
                    context.add_init_script(BrowserWalletFixture.injected_script())
                    self.page = context.new_page()
                    cdp, self.authenticator_id = Ctap2BrowserAuthenticator.install(
                        context, self.page
                    )
                    self.step("HL-07..08: customer-growth host aliases render its hosted brand", self._branded_pages)
                    self.step("HL-09: missing custom theme falls back to AuthGuard's default visual", self._fallback_brand)
                    self.step("HL-10: Hosted password login navigates to the validated business path", self._hosted_password_login)
                    self.step(
                        "HL-11..13: authenticated account security enrolls and reuses a passkey",
                        lambda: self._hosted_passkey(cdp),
                    )
                    self.step(
                        "HL-14: Hosted OAuth callback sets the canonical cookie and returns to business",
                        self._hosted_oauth,
                    )
                    self.step(
                        "HL-15: Hosted SIWX wallet login sets the canonical cookie and returns to business",
                        self._hosted_wallet,
                    )
                    self.step("HL-16: Console keeps the AuthGuard brand and theme boundary", self._console_brand)
                finally:
                    browser.close()

    @property
    def browser_page(self) -> Page:
        if self.page is None:
            raise RuntimeError("Chromium page is not initialized")
        return self.page

    @staticmethod
    def _launch_browser(
        playwright: Playwright,
        mock_host: str,
        gateway_port: int,
        mock_port: int,
    ):
        try:
            return playwright.chromium.launch(
                headless=True,
                args=[
                    "--proxy-server=direct://",
                    "--proxy-bypass-list=*",
                    "--disable-features=AsyncDns,UseDnsHttpsSvcbAlpn",
                    "--host-resolver-rules="
                    f"MAP {CUSTOMER_GROWTH_HOST}:8082 127.0.0.1:{gateway_port}, "
                    f"MAP {CUSTOMER_GROWTH_FALLBACK_HOST}:8082 127.0.0.1:{gateway_port}, "
                    f"MAP {AUTHN_BROWSER_HOST}:8082 127.0.0.1:{gateway_port}, "
                    f"MAP {mock_host}:8080 127.0.0.1:{mock_port}",
                ],
            )
        except Exception as failure:
            raise RuntimeError(
                "Playwright Chromium is unavailable; run `python -m playwright install chromium`"
            ) from failure

    def _api_contract(self) -> None:
        for host in (CUSTOMER_GROWTH_HOST, AUTHN_BROWSER_HOST):
            status, body = self._http(
                self.gateway_port, host, "/.well-known/authn.json"
            )
            self._expect_status("Customer Growth capability metadata", status, 200)
            metadata = json.loads(body)
            if metadata.get("application") != {
                "id": "customer-growth",
                "displayName": "Customer Growth",
                "logo": "/auth/assets/themes/custom/customer-growth.svg",
                "theme": {
                    "id": "customer-growth",
                    "stylesheet": "/auth/assets/themes/custom/customer-growth.css",
                },
            }:
                raise RuntimeError(f"Customer Growth branding metadata mismatch: {metadata}")
            methods = metadata.get("methods", {})
            if not all(methods.get(method) is True for method in ("password", "totp", "webauthn", "wallet")):
                raise RuntimeError(f"Customer Growth metadata did not expose enabled AuthN methods: {methods}")

        status, body = self._http(
            self.gateway_port,
            CUSTOMER_GROWTH_FALLBACK_HOST,
            "/.well-known/authn.json",
        )
        self._expect_status("fallback branding capability metadata", status, 200)
        fallback_application = json.loads(body).get("application")
        if fallback_application != {
            "id": "customer-growth-default",
            "displayName": "Customer Growth",
            "logo": "",
        }:
            raise RuntimeError(
                f"default visual branding metadata mismatch: {fallback_application}"
            )
        status, body = self._http(
            self.gateway_port,
            CUSTOMER_GROWTH_FALLBACK_HOST,
            "/.well-known/authn.json",
            headers={"X-Forwarded-Host": CUSTOMER_GROWTH_HOST},
        )
        self._expect_status("ignore untrusted forwarded host", status, 200)
        if json.loads(body).get("application", {}).get("id") != "customer-growth-default":
            raise RuntimeError("X-Forwarded-Host changed the trusted Application resolution")

        status, body = self._http(
            self.gateway_port,
            CUSTOMER_GROWTH_HOST,
            "/auth/assets/themes/custom/customer-growth.svg",
        )
        self._expect_status("Customer Growth logo static asset", status, 200)
        if "<svg" not in body:
            raise RuntimeError("Customer Growth hosted-logo response was not SVG content")
        status, body, headers = self._http_response(
            self.gateway_port,
            CUSTOMER_GROWTH_HOST,
            "/auth/assets/themes/custom/customer-growth.css",
        )
        self._expect_status("Customer Growth theme stylesheet", status, 200)
        cache_control = headers.get("Cache-Control", "")
        if "no-cache" not in cache_control or "immutable" in cache_control:
            raise RuntimeError(
                f"business theme must be revalidated instead of cached immutably: {cache_control!r}"
            )
        stylesheet_contract = (
            "data-application-theme='customer-growth'",
            "--customer-growth-brand: #6f7cff",
            ".login-card",
            ".account-security-page",
            "@media (max-width: 900px)",
        )
        if missing := [marker for marker in stylesheet_contract if marker not in body]:
            raise RuntimeError(
                f"Customer Growth stylesheet is incomplete; missing {missing}"
            )

        # Validation precedes password verification, so no credential fixture is
        # required to prove that cross-origin and scheme-relative URLs fail closed.
        for target in (
            "https://attacker.example/",
            "//attacker.example/",
            f"http://{CUSTOMER_GROWTH_HOST}/workflows/123",
            f"https://{CUSTOMER_GROWTH_HOST}/workflows/123#fragment",
        ):
            status, body = self._http(
                self.gateway_port,
                CUSTOMER_GROWTH_HOST,
                "/auth/standalone/login",
                method="POST",
                json_body={"login": "unused@example.net", "password": "unused", "returnTo": target},
            )
            self._expect_status(f"reject return target {target!r}", status, 400)
            if json.loads(body).get("code") != "invalid_request":
                raise RuntimeError(f"unsafe return target error contract changed: {body}")
        self.details.append("Host resolution returned application-specific public metadata and rejected open redirects before authentication")

    def _cookie_handoff(self) -> None:
        self._register_standalone()
        status, payload, headers = self._login_response("/workflows/123?tab=overview")
        self._expect_status("hosted password login", status, 200)
        if payload.get("returnUri") != "/workflows/123?tab=overview":
            raise RuntimeError(f"return_to was not normalized to a same-origin path: {payload}")
        cookie = headers.get("Set-Cookie", "")
        for attribute in ("authguard_token=", "HttpOnly", "Secure", "SameSite=Lax", "Path=/"):
            if attribute not in cookie:
                raise RuntimeError(f"canonical-token cookie lacks {attribute!r}: {cookie!r}")
        status, payload, _ = self._login_response(
            f"https://{CUSTOMER_GROWTH_HOST}/workflows/absolute?tab=allowed"
        )
        self._expect_status("absolute allow-listed return target", status, 200)
        if payload.get("returnUri") != "/workflows/absolute?tab=allowed":
            raise RuntimeError(
                f"absolute same-origin return_to was not normalized: {payload}"
            )
        self.details.append(
            "Password AuthN issued the same canonical JWT in an HttpOnly/Secure/Lax "
            "host-only cookie and normalized relative/absolute allow-listed return targets"
        )

    def _branded_pages(self) -> None:
        for case_id, host in (
            ("HL-07", CUSTOMER_GROWTH_HOST),
            ("HL-08", AUTHN_BROWSER_HOST),
        ):
            page = self.browser_page
            page.set_viewport_size(
                {"width": 1280, "height": 1000}
                if case_id == "HL-07"
                else {"width": 390, "height": 844}
            )
            page.goto(f"http://{host}:8082/auth/login?return_to=/workflows/123", wait_until="domcontentloaded")
            expect(page.get_by_role("heading", name="Sign in to Customer Growth")).to_be_visible()
            expect(page.locator(".visual-brand")).to_contain_text("Customer Growth")
            expect(page.locator("html")).to_have_attribute(
                "data-application-theme", "customer-growth"
            )
            expect(page.locator("#authguard-application-theme")).to_have_attribute(
                "href", "/auth/assets/themes/custom/customer-growth.css"
            )
            page.wait_for_function(
                "getComputedStyle(document.documentElement)"
                ".getPropertyValue('--authguard-application-theme').trim() "
                "=== 'customer-growth'",
                timeout=10_000,
            )
            theme_marker = page.evaluate(
                "getComputedStyle(document.documentElement)"
                ".getPropertyValue('--authguard-application-theme').trim()"
            )
            if theme_marker != "customer-growth":
                raise RuntimeError(
                    f"Customer Growth stylesheet was not applied: {theme_marker!r}"
                )
            computed_theme = page.evaluate(
                """() => ({
                  brand: getComputedStyle(document.documentElement)
                    .getPropertyValue('--customer-growth-brand').trim(),
                  cardRadius: getComputedStyle(document.querySelector('.login-card')).borderRadius,
                  logoWidth: getComputedStyle(document.querySelector('.visual-brand img')).width,
                  visualBackground: getComputedStyle(document.querySelector('.login-visual')).backgroundImage,
                })"""
            )
            if (
                computed_theme.get("brand") != "#6f7cff"
                or computed_theme.get("cardRadius") != "24px"
                or computed_theme.get("logoWidth") != "36px"
                or "linear-gradient" not in computed_theme.get("visualBackground", "")
            ):
                raise RuntimeError(
                    f"Customer Growth computed theme contract changed: {computed_theme}"
                )
            if case_id == "HL-07":
                page.get_by_test_id("locale-select").select_option("zh_CN")
                expect(
                    page.get_by_role("heading", name="登录 Customer Growth")
                ).to_be_visible()
                page.get_by_test_id("theme-select").select_option("dark")
                expect(page.locator("html")).to_have_attribute("data-theme", "dark")
                dark_panel = page.evaluate(
                    "getComputedStyle(document.documentElement)"
                    ".getPropertyValue('--panel').trim()"
                )
                if dark_panel != "#101428":
                    raise RuntimeError(
                        f"Customer Growth dark theme was not applied: {dark_panel!r}"
                    )
                self._screenshot("HL-07-dark", "Customer Growth dark zh_CN hosted login")
                page.get_by_test_id("locale-select").select_option("en_US")
                page.get_by_test_id("theme-select").select_option("light")
            else:
                expect(page.locator(".login-visual")).to_be_hidden()
                expect(page.locator(".mobile-brand")).to_be_visible()
            self._screenshot(case_id, f"Customer Growth hosted login on {host}")
        self.browser_page.set_viewport_size({"width": 1280, "height": 1000})

    def _fallback_brand(self) -> None:
        page = self.browser_page
        page.goto(
            f"http://{CUSTOMER_GROWTH_FALLBACK_HOST}:8082/auth/login"
            "?return_to=/workflows/123",
            wait_until="domcontentloaded",
        )
        expect(page.get_by_role("heading", name="Sign in to Customer Growth")).to_be_visible()
        expect(page.locator(".visual-brand")).to_contain_text("Customer Growth")
        expect(page.locator(".visual-brand svg")).to_be_visible()
        if page.locator("#authguard-application-theme").count() != 0:
            raise RuntimeError("unconfigured Application unexpectedly loaded a custom stylesheet")
        if page.locator("html").get_attribute("data-application-theme") is not None:
            raise RuntimeError("unconfigured Application retained an application theme marker")
        accent = page.evaluate(
            "getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()"
        )
        if accent not in {"#00a889", "#19e6b7"}:
            raise RuntimeError(f"default AuthGuard cyan visual was not applied: {accent!r}")
        self._screenshot("HL-09", "Customer Growth default AuthGuard visual fallback")

    def _hosted_password_login(self) -> None:
        page = self.browser_page
        # Chromium treats localhost as a secure development context, so this
        # proves the production Secure/HttpOnly cookie handoff without
        # weakening the cookie attributes for a plain-HTTP test fixture.
        page.goto(
            f"http://{AUTHN_BROWSER_HOST}:8082/auth/login?return_to=/workflows/123",
            wait_until="domcontentloaded",
        )
        expect(page.get_by_role("heading", name="Sign in to Customer Growth")).to_be_visible()
        page.get_by_test_id("login-id").fill(self.login)
        page.get_by_test_id("login-password").fill(self.password)
        page.get_by_test_id("login-password-submit").click()
        page.wait_for_url(
            re.compile(rf"^http://{re.escape(AUTHN_BROWSER_HOST)}:8082/workflows/123$"),
            timeout=20_000,
        )
        self._screenshot("HL-10", "Customer Growth post-authentication navigation")
        page.goto(f"http://{AUTHN_BROWSER_HOST}:8082/auth/session", wait_until="domcontentloaded")
        session = json.loads(page.locator("body").inner_text())
        if not session.get("principal", {}).get("principalId"):
            raise RuntimeError("Hosted Login cookie did not restore the browser AuthN session")
        self.details.append("Hosted Login did not need an SDK, iframe, or copied business UI; browser navigation stayed on the relying host")

    def _hosted_passkey(self, cdp) -> None:
        page = self.browser_page
        page.goto(
            f"http://{AUTHN_BROWSER_HOST}:8082/auth/account/security",
            wait_until="domcontentloaded",
        )
        page.get_by_test_id("security-login-id").fill(self.login)
        page.get_by_test_id("security-password").fill(self.password)
        page.get_by_test_id("account-register-webauthn").click()
        expect(page.get_by_test_id("account-security-result")).to_contain_text(
            "pwd + webauthn", timeout=20_000
        )
        credentials = cdp.send(
            "WebAuthn.getCredentials", {"authenticatorId": self.authenticator_id}
        )["credentials"]
        if len(credentials) != 1:
            raise RuntimeError(
                f"Hosted account-security enrollment stored {len(credentials)} credentials"
            )
        self._screenshot("HL-11", "Authenticated account security passkey enrollment")
        self._screenshot("HL-12", "CTAP2 platform authenticator retained the passkey")

        self._browser_logout()
        page.goto(
            f"http://{AUTHN_BROWSER_HOST}:8082/auth/login?return_to=/workflows/passkey",
            wait_until="domcontentloaded",
        )
        expect(page.get_by_test_id("register-webauthn")).to_have_count(0)
        page.get_by_test_id("login-id").fill(self.login)
        page.get_by_test_id("login-webauthn").click()
        page.wait_for_url(
            re.compile(
                rf"^http://{re.escape(AUTHN_BROWSER_HOST)}:8082/workflows/passkey$"
            ),
            timeout=20_000,
        )
        self._assert_browser_session_amr(["webauthn"])
        self._screenshot("HL-13", "Hosted passkey return target")
        self.details.append(
            "Passkey enrollment required the existing canonical cookie plus password step-up; subsequent Hosted Login used navigator.credentials.get"
        )

    def _hosted_oauth(self) -> None:
        page = self.browser_page
        self._browser_logout()
        page.goto(
            f"http://{AUTHN_BROWSER_HOST}:8082/auth/login?return_to=/workflows/oauth",
            wait_until="domcontentloaded",
        )
        page.get_by_test_id("login-provider-github").click()
        page.wait_for_url(
            re.compile(
                rf"^http://{re.escape(AUTHN_BROWSER_HOST)}:8082/workflows/oauth$"
            ),
            timeout=25_000,
        )
        self._assert_browser_session_amr(["oauth2"])
        self._screenshot("HL-14", "Hosted OAuth callback return target")

    def _hosted_wallet(self) -> None:
        page = self.browser_page
        self._browser_logout()
        page.goto(
            f"http://{AUTHN_BROWSER_HOST}:8082/auth/login?return_to=/workflows/wallet",
            wait_until="domcontentloaded",
        )
        page.get_by_test_id("login-wallet").click()
        page.wait_for_url(
            re.compile(
                rf"^http://{re.escape(AUTHN_BROWSER_HOST)}:8082/workflows/wallet$"
            ),
            timeout=20_000,
        )
        self._assert_browser_session_amr(["wallet", "siwx", "eoa"])
        self._screenshot("HL-15", "Hosted SIWX wallet return target")

    def _browser_logout(self) -> None:
        status = self.browser_page.evaluate(
            "async () => (await fetch('/auth/logout', {method: 'POST'})).status"
        )
        if status != 204:
            raise RuntimeError(f"browser logout returned HTTP {status}")

    def _assert_browser_session_amr(self, expected: list[str]) -> None:
        session = self.browser_page.evaluate(
            "async () => { const response = await fetch('/auth/session'); "
            "return {status: response.status, body: await response.json()}; }"
        )
        actual = session.get("body", {}).get("principal", {}).get("amr")
        if session.get("status") != 200 or actual != expected:
            raise RuntimeError(
                f"Hosted canonical cookie session mismatch: expected amr={expected}, got {session}"
            )

    def _console_brand(self) -> None:
        page = self.browser_page
        page.goto(f"http://{AUTHN_BROWSER_HOST}:8082/login", wait_until="domcontentloaded")
        expect(page.locator(".visual-brand")).to_contain_text("AuthGuard")
        expect(page.locator(".visual-brand")).not_to_contain_text("Customer Growth")
        expect(page.locator("html")).not_to_have_attribute(
            "data-application-theme", "customer-growth"
        )
        expect(page.locator("#authguard-application-theme")).to_have_count(0)
        self._screenshot("HL-16", "AuthGuard console login branding")

    def _register_standalone(self) -> None:
        status, body = self._http(
            self.gateway_port,
            CUSTOMER_GROWTH_HOST,
            "/auth/standalone/register",
            method="POST",
            json_body={"login": self.login, "displayName": "Hosted Login E2E", "password": self.password},
        )
        self._expect_status("hosted standalone registration", status, 200)
        if not json.loads(body).get("principal", {}).get("principalId"):
            raise RuntimeError("hosted standalone registration did not create a canonical Principal")

    def _login_response(self, return_to: str) -> tuple[int, dict, object]:
        outgoing = request.Request(
            f"http://127.0.0.1:{self.gateway_port}/auth/standalone/login",
            data=json.dumps({"login": self.login, "password": self.password, "returnTo": return_to}).encode(),
            method="POST",
            headers={"Host": CUSTOMER_GROWTH_HOST, "Content-Type": "application/json"},
        )
        try:
            with request.urlopen(outgoing, timeout=15) as response:
                return response.status, json.loads(response.read()), response.headers
        except error.HTTPError as failure:
            return failure.code, json.loads(failure.read()), failure.headers

    def _screenshot(self, case_id: str, title: str) -> None:
        path = self.evidence_path(case_id, title, "png")
        self.browser_page.screenshot(path=str(path), full_page=True, animations="disabled")
        self.record_evidence(case_id, title, "image/png", path)


def verify(context: RunContext) -> VerificationResult:
    return HostedLoginVerifier(context).run()
