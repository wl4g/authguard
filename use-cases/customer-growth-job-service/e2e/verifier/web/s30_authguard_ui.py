"""Web s30: real Chromium journeys through the shipped AuthGuard React UI."""

from __future__ import annotations

import json
import os
import re
from typing import Any

from playwright.sync_api import (
    Page,
    Playwright,
    TimeoutError as PlaywrightTimeoutError,
    expect,
    sync_playwright,
)

from common.kubernetes import AUTHGUARD_API_TOKEN, AUTHN_BROWSER_HOST
from common.model import RunContext, VerificationResult
from verifier.authn.wallet.s15_wallet import (
    ANVIL_ACCOUNT_0_ADDRESS,
    EVM_OFFLINE_EOA_CHAIN_REFERENCE,
    EvmWallet,
)
from verifier.other.base import BaseVerifier


UI_ORIGIN = f"http://{AUTHN_BROWSER_HOST}:8082"
UI_FEDERATED_PRINCIPAL_ID = "principal-ui-federated-reviewer"


class AuthGuardWebVerifier(BaseVerifier):
    """Exercise browser APIs and user controls, not bundle strings or HTTP mocks."""

    scenario_id = "30"
    title = "Web: real Chromium authentication and control-plane journeys"

    def __init__(self, context: RunContext) -> None:
        super().__init__(context)
        self.page: Page | None = None
        self.authenticator_id = ""
        self.standalone_login = (
            f"ui-r{context.round_number}-{os.urandom(5).hex()}@example.net"
        )
        self.standalone_password = "browser passkey verification password"
        self.standalone_display_name = f"Browser E2E {self.standalone_login}"
        self.policy_action = f"ui.browser.verify.{os.urandom(4).hex()}"

    def run(self) -> VerificationResult:
        return self.execute(self._run_scenario)

    def _run_scenario(self) -> None:
        mock_host = (
            f"{self.mock_idp_service}.{self.namespace}.svc.cluster.local"
        )
        with (
            self._forward_service(
                self._envoy_proxy_service(), 8082, local_port=8082
            ),
            self._forward_service(self.mock_idp_service, 8080, local_port=8080),
            sync_playwright() as playwright,
        ):
            browser = self._launch_browser(playwright, mock_host)
            try:
                context = browser.new_context(locale="en-US")
                context.expose_function("authguardE2ESign", self._sign_personal_message)
                context.add_init_script(self._injected_wallet_script())
                self.page = context.new_page()
                cdp = context.new_cdp_session(self.page)
                cdp.send("WebAuthn.enable")
                self.authenticator_id = cdp.send(
                    "WebAuthn.addVirtualAuthenticator",
                    {
                        "options": {
                            "protocol": "ctap2",
                            "transport": "internal",
                            "hasResidentKey": True,
                            "hasUserVerification": True,
                            "isUserVerified": True,
                            "automaticPresenceSimulation": True,
                        }
                    },
                )["authenticatorId"]
                self.step(
                    "Web UI-01..03: metadata controls seven login choices, locale, and theme",
                    self._capabilities_and_preferences,
                )
                self.step(
                    "Web UI-04..07: GitHub/Google/WeChat/QQ popup journeys issue unified JWTs",
                    self._oauth_journeys,
                )
                self.step(
                    "Web UI-08..10: administrator creates standalone and federated Principals",
                    self._principal_journeys,
                )
                self.step(
                    "Web UI-11..13: policy Action create/update/delete honors revisioned APIs",
                    self._policy_journey,
                )
                self.step(
                    "Web UI-14: password form authenticates the created standalone Principal",
                    self._password_journey,
                )
                self.step(
                    "Web UI-15..17: Chromium WebAuthn create/get use a CTAP2 virtual authenticator",
                    lambda: self._webauthn_journey(cdp),
                )
                self.step(
                    "Web UI-18: injected EIP-1193 wallet signs SIWX and verifies EOA offline",
                    self._wallet_journey,
                )
                self.step(
                    "Web UI-19..22: Principal status update and delete complete UI CRUD",
                    self._principal_update_delete_journey,
                )
            finally:
                browser.close()

    @staticmethod
    def _launch_browser(playwright: Playwright, mock_host: str):
        resolver = f"MAP {mock_host} 127.0.0.1"
        try:
            return playwright.chromium.launch(
                headless=True,
                args=[
                    "--proxy-server=direct://",
                    "--proxy-bypass-list=*",
                    "--disable-features=AsyncDns,UseDnsHttpsSvcbAlpn",
                    f"--host-resolver-rules={resolver}",
                ],
            )
        except Exception as error:
            raise RuntimeError(
                "Playwright Chromium is unavailable; run `python -m playwright install chromium`"
            ) from error

    @property
    def browser_page(self) -> Page:
        if self.page is None:
            raise RuntimeError("Chromium page was not initialized")
        return self.page

    def _capabilities_and_preferences(self) -> None:
        page = self.browser_page
        page.goto(f"{UI_ORIGIN}/login", wait_until="domcontentloaded")
        browser_security = page.evaluate(
            "({ secure: isSecureContext, credentials: typeof navigator.credentials, "
            "publicKey: typeof PublicKeyCredential })"
        )
        if browser_security != {
            "secure": True,
            "credentials": "object",
            "publicKey": "function",
        }:
            raise RuntimeError(
                f"WebAuthn browser security context is unavailable: {browser_security}"
            )
        required = [
            "login-password-submit",
            "login-webauthn",
            "register-webauthn",
            "login-wallet",
            "login-provider-github",
            "login-provider-google",
            "login-provider-wechat",
            "login-provider-qq",
        ]
        for test_id in required:
            expect(page.get_by_test_id(test_id)).to_be_visible()
        self._checkpoint("UI-01", "metadata-driven authentication choices")
        page.get_by_test_id("locale-select").select_option("zh_CN")
        expect(page.get_by_role("heading", name="登录", exact=True)).to_be_visible()
        self._checkpoint("UI-02", "zh_CN locale")
        page.get_by_test_id("theme-select").select_option("dark")
        expect(page.locator("html")).to_have_attribute("data-theme", "dark")
        page.get_by_test_id("theme-select").select_option("light")
        expect(page.locator("html")).to_have_attribute("data-theme", "light")
        page.emulate_media(color_scheme="dark")
        page.get_by_test_id("theme-select").select_option("system")
        expect(page.locator("html")).to_have_attribute("data-theme", "dark")
        page.emulate_media(color_scheme="light")
        expect(page.locator("html")).to_have_attribute("data-theme", "light")
        self._checkpoint("UI-03", "dark light and system themes")
        page.get_by_test_id("locale-select").select_option("en_US")
        self.details.append(
            "Chromium rendered metadata-driven OAuth2, password, WebAuthn, and CAIP controls in zh_CN/en_US and dark/light/system themes"
        )

    def _oauth_journeys(self) -> None:
        page = self.browser_page
        for case_id, provider in zip(
            ("UI-04", "UI-05", "UI-06", "UI-07"),
            ("github", "google", "wechat", "qq"),
            strict=True,
        ):
            page.goto(f"{UI_ORIGIN}/login", wait_until="domcontentloaded")
            with page.expect_popup(timeout=20_000):
                page.get_by_test_id(f"login-provider-{provider}").click()
            page.wait_for_url(re.compile(rf"^{re.escape(UI_ORIGIN)}/?$"), timeout=25_000)
            expect(page.get_by_test_id("authentication-amr")).to_have_text("oauth2")
            expect(page.get_by_test_id("authenticated-principal")).not_to_have_text("")
            self._checkpoint(case_id, f"{provider} OAuth popup login")
            if provider != "qq":
                page.get_by_test_id("sign-out").click()
                page.wait_for_url(f"{UI_ORIGIN}/login")
        self.details.append(
            "four real browser popup/redirect/callback journeys converged on AuthGuard JWT amr=oauth2"
        )

    def _principal_journeys(self) -> None:
        page = self.browser_page
        page.get_by_test_id("control-token").fill(AUTHGUARD_API_TOKEN)
        page.get_by_test_id("control-token-submit").click()
        page.get_by_test_id("nav-principals").click()
        page.wait_for_url(f"{UI_ORIGIN}/principals")

        page.get_by_test_id("principal-local-open").click()
        page.get_by_test_id("principal-local-login").fill(self.standalone_login)
        page.get_by_test_id("principal-local-display-name").fill(
            self.standalone_display_name
        )
        page.get_by_test_id("principal-local-password").fill(
            self.standalone_password
        )
        page.get_by_test_id("principal-local-submit").click()
        expect(page.get_by_test_id("principal-list")).to_contain_text(
            self.standalone_display_name
        )
        self._checkpoint("UI-08", "standalone Principal creation")

        page.get_by_test_id("principal-federated-open").click()
        page.get_by_test_id("principal-federated-query").fill(
            "ui-federated-reviewer"
        )
        page.get_by_test_id("principal-federated-search").click()
        candidate = page.get_by_test_id("principal-federated-results").get_by_text(
            "UI Federated Reviewer", exact=True
        )
        expect(candidate).to_be_visible()
        self._checkpoint("UI-09", "federated Principal search")
        candidate.click()
        page.get_by_test_id("principal-federated-id").fill(
            UI_FEDERATED_PRINCIPAL_ID
        )
        page.get_by_test_id("principal-federated-materialize").click()
        expect(page.get_by_test_id("principal-list")).to_contain_text(
            "UI Federated Reviewer"
        )
        self._checkpoint("UI-10", "federated Principal materialization")
        self.details.append(
            "Principal UI created only a standalone local account and explicitly materialized a searched federation identity"
        )

    def _policy_journey(self) -> None:
        page = self.browser_page
        page.get_by_test_id("nav-policy").click()
        page.wait_for_url(f"{UI_ORIGIN}/policy")
        page.get_by_test_id("policy-tab-actions").click()
        page.get_by_test_id("policy-create").click()
        page.get_by_test_id("policy-json").fill(
            json.dumps(
                {
                    "identifier": self.policy_action,
                    "description": "real Chromium E2E action",
                    "route_matchers": [],
                }
            )
        )
        page.get_by_test_id("policy-save").click()
        action = page.locator("article").filter(has_text=self.policy_action)
        expect(action).to_have_count(1)
        self._checkpoint("UI-11", "policy Action creation")
        action.locator(".row-actions button").first.click()
        page.get_by_test_id("policy-json").fill(
            json.dumps(
                {
                    "identifier": self.policy_action,
                    "description": "real Chromium E2E action updated",
                    "route_matchers": [],
                }
            )
        )
        page.get_by_test_id("policy-save").click()
        action = page.locator("article").filter(has_text=self.policy_action)
        expect(action).to_contain_text("real Chromium E2E action updated")
        self._checkpoint("UI-12", "policy Action update")
        page.once("dialog", lambda dialog: dialog.accept())
        action.locator("button.danger").click()
        expect(page.locator("article").filter(has_text=self.policy_action)).to_have_count(0)
        self._checkpoint("UI-13", "policy Action deletion")
        self.details.append(
            "Policy UI performed revision-aware Action create, update, and delete through the AuthZ management route"
        )

    def _password_journey(self) -> None:
        page = self.browser_page
        page.get_by_test_id("sign-out").click()
        page.wait_for_url(f"{UI_ORIGIN}/login")
        self._fill_standalone_credentials()
        page.get_by_test_id("login-password-submit").click()
        page.wait_for_url(re.compile(rf"^{re.escape(UI_ORIGIN)}/?$"))
        expect(page.get_by_test_id("authentication-amr")).to_have_text("pwd")
        self._checkpoint("UI-14", "password authentication")

    def _webauthn_journey(self, cdp) -> None:
        page = self.browser_page
        password_principal = page.get_by_test_id("authenticated-principal").inner_text()
        page.get_by_test_id("sign-out").click()
        page.wait_for_url(f"{UI_ORIGIN}/login")
        self._fill_standalone_credentials()
        page.get_by_test_id("register-webauthn").click()
        try:
            page.wait_for_url(re.compile(rf"^{re.escape(UI_ORIGIN)}/?$"), timeout=20_000)
        except PlaywrightTimeoutError as error:
            banner = page.locator(".error-banner")
            detail = banner.inner_text() if banner.count() else "no UI error banner"
            raise RuntimeError(f"WebAuthn registration did not complete: {detail}") from error
        expect(page.get_by_test_id("authentication-amr")).to_have_text(
            "pwd + webauthn"
        )
        self._checkpoint("UI-15", "WebAuthn credential registration")
        credentials = cdp.send(
            "WebAuthn.getCredentials", {"authenticatorId": self.authenticator_id}
        )["credentials"]
        if len(credentials) != 1:
            raise RuntimeError(
                f"Chromium virtual authenticator stored {len(credentials)} credentials"
            )
        self._checkpoint("UI-16", "CTAP2 authenticator credential persistence")

        page.get_by_test_id("sign-out").click()
        page.wait_for_url(f"{UI_ORIGIN}/login")
        page.get_by_test_id("login-id").fill(self.standalone_login)
        page.get_by_test_id("login-webauthn").click()
        page.wait_for_url(re.compile(rf"^{re.escape(UI_ORIGIN)}/?$"), timeout=20_000)
        expect(page.get_by_test_id("authentication-amr")).to_have_text("webauthn")
        expect(page.get_by_test_id("authenticated-principal")).to_have_text(
            password_principal
        )
        self._checkpoint("UI-17", "WebAuthn assertion authentication")
        self.details.append(
            "navigator.credentials.create/get completed in Chromium against a CTAP2 platform virtual authenticator and reused the canonical Principal"
        )

    def _wallet_journey(self) -> None:
        page = self.browser_page
        page.get_by_test_id("sign-out").click()
        page.wait_for_url(f"{UI_ORIGIN}/login")
        page.get_by_test_id("login-wallet").click()
        page.wait_for_url(re.compile(rf"^{re.escape(UI_ORIGIN)}/?$"), timeout=20_000)
        expect(page.get_by_test_id("authentication-amr")).to_have_text(
            "wallet + siwx + eoa"
        )
        self._checkpoint("UI-18", "EIP-1193 SIWX wallet authentication")
        self.details.append(
            "the UI used a standard injected EIP-1193 wallet transport; AuthGuard authored SIWX and verified EIP-191 locally"
        )

    def _principal_update_delete_journey(self) -> None:
        page = self.browser_page
        page.get_by_test_id("nav-principals").click()
        page.wait_for_url(f"{UI_ORIGIN}/principals")

        standalone = page.locator(".principal-table .table-row").filter(
            has_text=self.standalone_display_name
        )
        expect(standalone).to_have_count(1)
        standalone.locator(".row-actions button").first.click()
        expect(standalone.locator(".status")).to_have_text("DISABLED")
        self._checkpoint("UI-19", "Principal disable")
        standalone.locator(".row-actions button").first.click()
        expect(standalone.locator(".status")).to_have_text("ACTIVE")
        self._checkpoint("UI-20", "Principal enable")

        for case_id, display_name in (
            ("UI-21", self.standalone_display_name),
            ("UI-22", "UI Federated Reviewer"),
        ):
            row = page.locator(".principal-table .table-row").filter(
                has_text=display_name
            )
            expect(row).to_have_count(1)
            page.once("dialog", lambda dialog: dialog.accept())
            row.locator(".row-actions .danger").click()
            expect(row).to_have_count(0)
            self._checkpoint(case_id, f"Principal deletion: {display_name}")
        self.details.append(
            "Principal UI toggled ACTIVE/DISABLED and deleted both scenario-owned Principals, completing CRUD without residual identities or credentials"
        )

    def _fill_standalone_credentials(self) -> None:
        page = self.browser_page
        page.get_by_test_id("login-id").fill(self.standalone_login)
        page.get_by_test_id("login-password").fill(self.standalone_password)

    def _checkpoint(self, case_id: str, title: str) -> None:
        path = self.evidence_path(case_id, title, "png")
        self.browser_page.screenshot(path=str(path), full_page=True, animations="disabled")
        self.record_evidence(case_id, title, "image/png", path)

    @staticmethod
    def _sign_personal_message(encoded_message: str) -> str:
        if not isinstance(encoded_message, str) or not encoded_message.startswith("0x"):
            raise RuntimeError("EIP-1193 personal_sign payload was not hexadecimal")
        try:
            message = bytes.fromhex(encoded_message[2:]).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise RuntimeError("EIP-1193 personal_sign payload was invalid UTF-8") from error
        return EvmWallet.sign(message)

    @staticmethod
    def _injected_wallet_script() -> str:
        return f"""
        (() => {{
          const account = {json.dumps(ANVIL_ACCOUNT_0_ADDRESS)};
          const chainId = '0x{int(EVM_OFFLINE_EOA_CHAIN_REFERENCE):x}';
          const wallet = {{
            isMetaMask: true,
            on() {{}},
            removeListener() {{}},
            async request({{ method, params = [] }}) {{
              if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [account];
              if (method === 'eth_chainId') return chainId;
              if (method === 'net_version') return String(parseInt(chainId, 16));
              if (method === 'wallet_getPermissions') return [];
              if (method === 'personal_sign') return window.authguardE2ESign(params[0]);
              throw new Error(`Unsupported E2E wallet method: ${{method}}`);
            }}
          }};
          Object.defineProperty(window, 'ethereum', {{ value: wallet, configurable: false }});
        }})();
        """


def verify(context: RunContext) -> VerificationResult:
    return AuthGuardWebVerifier(context).run()
