"""Real production ESM/browser checks with deterministic HTTP API fixtures.

The standard verifier builds web/ and authguard_host/. This suite does not claim backend E2E.
Run through runner.py --scenario 32; all evidence uses BaseVerifier/report conventions.
"""
from __future__ import annotations
import json
import mimetypes
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import time
from contextlib import ExitStack
from verifier.context import BaseVerifier, VerificationContext, VerificationResult
from util.process import E2EProcessHelper
from urllib.parse import urlparse
from playwright.sync_api import expect, sync_playwright
authguard_root = Path(__file__).resolve().parents[4]
authguard_host_dist = Path(__file__).parent / 'authguard_host/dist'
authguard_web_dist = authguard_root / 'web/dist'

class authguard_fixture_server(ThreadingHTTPServer):
    request_queue_size = 128

class authguard_fixture_handler(BaseHTTPRequestHandler):

    def log_message(self, *_authguard_args):
        pass

    def do_GET(self):
        authguard_path = urlparse(self.path).path
        authguard_json = None
        if authguard_path == '/auth/session':
            authguard_json = {'principal': {'principalId': 'authguard-browser-reviewer', 'kind': 'USER', 'stableGroupIds': [], 'trustedClaims': {}, 'amr': ['pwd']}}
        elif authguard_path == '/.well-known/authn.json':
            authguard_json = {'version': '1', 'standalone': {'enabled': True, 'password': True, 'totp': False, 'webauthn': True}, 'ldap': {'enabled': False}, 'wallet': {'enabled': False}, 'oauth2': {'providers': []}, 'methods': {'password': True}}
        elif authguard_path.startswith('/auth/management/api/'):
            authguard_kind = authguard_path.rsplit('/', 1)[-1]
            authguard_items = {
                'actions': [{'identifier': 'fixture.read'}, {'identifier': 'fixture.write'}],
                'roles': [{'id': 'fixture-reader'}, {'id': 'fixture-writer'}],
                'role-bindings': [{'id': 'fixture-binding-a'}, {'id': 'fixture-binding-b'}],
            }.get(authguard_kind, [])
            if 'policy_fixture' not in self.headers.get('Referer', ''):
                authguard_items = []
            authguard_json = {'items': authguard_items, 'total': len(authguard_items), 'policy_revision': 1}
        if authguard_json is not None:
            authguard_data = json.dumps(authguard_json).encode()
            authguard_type = 'application/json'
        else:
            if authguard_path.startswith('/auth/assets/'):
                authguard_file = authguard_web_dist / 'assets' / authguard_path.removeprefix('/auth/assets/')
            else:
                authguard_dist = authguard_web_dist if self.server.authguard_standalone else authguard_host_dist
                authguard_file = authguard_dist / authguard_path.lstrip('/')
                if not authguard_file.is_file() and (not Path(authguard_path).suffix):
                    authguard_file = authguard_dist / 'index.html'
            if not authguard_file.is_file():
                self.send_error(404)
                return
            authguard_data = authguard_file.read_bytes()
            authguard_type = mimetypes.guess_type(authguard_file)[0] or 'application/octet-stream'
        self.send_response(200)
        self.send_header('Content-Type', authguard_type)
        self.send_header('Content-Length', str(len(authguard_data)))
        self.end_headers()
        try:
            self.wfile.write(authguard_data)
        except (BrokenPipeError, ConnectionResetError):
            pass  # Browser navigation may cancel an in-flight fixture response.

class E2ES32ModuleFederationVerifier(BaseVerifier):
    scenario_id = '32'
    title = 'Web: Module Federation, localization and UI isolation (API fixtures)'
    requires_deployer = False

    def deploy(self, context: VerificationContext) -> None:
        """Own only local browser fixture servers; no cluster deployment."""

    def init(self, context: VerificationContext) -> None:
        """Each browser journey uses a fresh context."""

    def verifier(self, context: VerificationContext) -> VerificationResult:
        return self.execute(self.authguard_run)

    def authguard_build(self):
        for authguard_directory in (authguard_web_dist.parent, authguard_host_dist.parent):
            if not (authguard_directory / 'node_modules').exists():
                self.authguard_command(('npm', 'ci'), authguard_directory)
            self.authguard_command(('npm', 'run', 'build'), authguard_directory)
        self.details.append('Production ESM remote and host built from current sources; HTTP APIs use deterministic fixtures, not a deployed AuthN/AuthZ backend.')

    def authguard_command(self, authguard_command, authguard_directory):
        authguard_result = E2EProcessHelper.run_command(authguard_command, cwd=authguard_directory, timeout_seconds=self.context.timeout_seconds, stream=False)
        self.commands.append(authguard_result)
        if not authguard_result.passed:
            raise RuntimeError(authguard_result.output[-8000:])

    def authguard_run(self):
        self.step('Build production remote and business React host', self.authguard_build)
        with ExitStack() as authguard_stack:
            self.authguard_servers = []
            for authguard_standalone in (False, True):
                authguard_server = authguard_fixture_server(('127.0.0.1', 0), authguard_fixture_handler)
                authguard_server.authguard_standalone = authguard_standalone
                authguard_stack.callback(authguard_server.server_close)
                authguard_stack.callback(authguard_server.shutdown)
                Thread(target=authguard_server.serve_forever, daemon=True).start()
                self.authguard_servers.append(authguard_server)
            self.authguard_origin = f'http://127.0.0.1:{self.authguard_servers[0].server_port}'
            self.authguard_standalone_origin = f'http://127.0.0.1:{self.authguard_servers[1].server_port}'
            authguard_playwright = authguard_stack.enter_context(sync_playwright())
            self.authguard_browser = authguard_playwright.chromium.launch(executable_path=os.getenv('AUTHGUARD_BROWSER_EXECUTABLE'), channel=os.getenv('AUTHGUARD_BROWSER_CHANNEL') or None, headless=True, args=['--proxy-server=direct://', '--proxy-bypass-list=*'])
            authguard_stack.callback(self.authguard_browser.close)
            for authguard_name in sorted((authguard_name for authguard_name in dir(type(self)) if authguard_name.startswith('authguard_check_'))):
                authguard_number, authguard_title = authguard_name.removeprefix('authguard_check_').split('_', 1)
                self.step(f"MF-{authguard_number}: {authguard_title.replace('_', ' ')}", lambda authguard_name=authguard_name: self.authguard_case(authguard_name))

    def authguard_case(self, authguard_name):
        self.authguard_context = self.authguard_browser.new_context(viewport={'width': 1440, 'height': 1000})
        self.authguard_page = self.authguard_context.new_page()
        self.authguard_errors = []
        self.authguard_console_errors = []
        self.authguard_requests = []
        self.authguard_page.on('console', lambda authguard_message: self.authguard_console_errors.append(authguard_message.text) if authguard_message.type == 'error' else None)
        self.authguard_page.on('pageerror', lambda authguard_error: self.authguard_errors.append(str(authguard_error)))
        self.authguard_page.on('request', lambda authguard_request: self.authguard_requests.append(authguard_request.url))
        try:
            getattr(self, authguard_name)()
            if self.authguard_page.url != 'about:blank':
                self.authguard_screenshot(authguard_name.removeprefix('authguard_check_'))
            self.details.append(f'{authguard_name}: browser assertions passed')
        except Exception:
            self.authguard_screenshot('failure_' + authguard_name)
            self.details.extend(self.authguard_console_errors[:3])
            raise
        finally:
            self.authguard_context.close()

    def authguard_screenshot(self, authguard_title, authguard_full_page=True):
        authguard_case_id = self._active_case_id
        authguard_path = self.evidence_path(authguard_case_id, authguard_title, 'png')
        self.authguard_page.screenshot(path=str(authguard_path), full_page=authguard_full_page, animations='disabled')
        self.record_evidence(authguard_case_id, authguard_title, 'image/png', authguard_path)

    def authguard_preferences(self):
        authguard_trigger = self.authguard_page.get_by_test_id('authguard-host-profile')
        if authguard_trigger.get_attribute('aria-expanded') != 'true':
            authguard_trigger.click()
        expect(self.authguard_page.locator('#authguard-business-menu')).to_be_visible()

    def authguard_enter(self, authguard_dropdown=True):
        if authguard_dropdown:
            self.authguard_preferences()
            self.authguard_page.get_by_test_id('authguard-host-access').click()
            assert urlparse(self.authguard_page.url).path == '/access-management', "self.assertEqual(urlparse(self.authguard_page.url).path, '/access-management')"
        else:
            self.authguard_page.get_by_test_id('authguard-left-access').click()
        expect(self.authguard_page.get_by_test_id('authguard-management')).to_be_visible()
        expect(self.authguard_page.get_by_test_id('authguard-business-sidebar')).to_have_count(0)
        expect(self.authguard_page.get_by_test_id('authguard-host-header')).to_have_count(1)
        expect(self.authguard_page.locator('.authguard-management-sidebar')).to_have_count(1)
        expect(self.authguard_page.get_by_test_id('authguard-profile-trigger')).to_have_count(0)

    def authguard_wait_page(self, authguard_module):
        authguard_headings = {'overview': 'Control plane ready', 'policy': 'Policy', 'principals': 'Principals', 'accountSecurity': 'Manage your credentials'}
        expect(self.authguard_page.get_by_role('heading', name=authguard_headings[authguard_module], exact=True)).to_be_visible()
        if authguard_module == 'accountSecurity':
            expect(self.authguard_page.get_by_test_id('account-register-webauthn')).to_be_enabled()

    def authguard_no_overflow(self):
        assert self.authguard_page.evaluate('document.documentElement.scrollWidth <= innerWidth'), "self.assertTrue(self.authguard_page.evaluate('document.documentElement.scrollWidth <= innerWidth'))"
        assert self.authguard_page.locator('.authguard-management').evaluate('authguard_element => authguard_element.scrollWidth <= authguard_element.clientWidth'), "self.assertTrue(self.authguard_page.locator('.authguard-management').evaluate('authguard_element => authguard_element.scrollWidth <= authguard_element.clientWidth'))"

    def authguard_check_01_lazy_loading_round_trips_and_isolation(self):
        authguard_page = self.authguard_page
        authguard_page.goto(self.authguard_origin + '/jobs')
        expect(authguard_page.get_by_test_id('authguard-host-sentinel')).to_be_visible()
        assert not any(('authguard-remoteEntry' in authguard_url for authguard_url in self.authguard_requests)), "self.assertFalse(any(('authguard-remoteEntry' in authguard_url for authguard_url in self.authguard_requests)))"
        authguard_measure = 'authguard_element => ({background:getComputedStyle(authguard_element).backgroundColor,height:authguard_element.getBoundingClientRect().height,font:getComputedStyle(authguard_element).fontFamily})'
        authguard_page.get_by_test_id('authguard-business-draft').fill('Keep this draft')
        authguard_snapshot = authguard_page.get_by_test_id('authguard-host-header').evaluate(authguard_measure)
        authguard_document_script = "({html:document.documentElement.outerHTML.split('>')[0],body:document.body.getAttribute('style'),sheets:document.styleSheets.length})"
        authguard_document = authguard_page.evaluate(authguard_document_script)
        authguard_latencies = []
        for authguard_iteration in range(12):
            authguard_start = time.monotonic()
            self.authguard_enter(authguard_iteration % 2 == 0)
            authguard_latencies.append(round((time.monotonic() - authguard_start) * 1000))
            for authguard_module in [('policy', 'principals', 'accountSecurity', 'overview')[authguard_iteration % 4]]:
                authguard_page.get_by_test_id(f'authguard-nav-{authguard_module}').click()
                expect(authguard_page.get_by_test_id(f'authguard-nav-{authguard_module}')).to_have_attribute('aria-current', 'page')
                self.authguard_wait_page(authguard_module)
                self.authguard_no_overflow()
            authguard_page.get_by_test_id('authguard-return').click()
            expect(authguard_page.get_by_test_id('authguard-business-sidebar')).to_be_visible()
            assert authguard_page.url == self.authguard_origin + '/jobs', "self.assertEqual(authguard_page.url, self.authguard_origin + '/jobs')"
            expect(authguard_page.get_by_test_id('authguard-business-draft')).to_have_value('Keep this draft')
            assert authguard_snapshot == authguard_page.get_by_test_id('authguard-host-header').evaluate(authguard_measure), "self.assertEqual(authguard_snapshot, authguard_page.get_by_test_id('authguard-host-header').evaluate(authguard_measure))"
            assert authguard_document == authguard_page.evaluate(authguard_document_script), 'self.assertEqual(authguard_document, authguard_page.evaluate(authguard_document_script))'
        self.details.append(f'AuthGuard switch latency ms (cold + warm): {authguard_latencies}')
        assert max(authguard_latencies[1:]) < 1500, 'self.assertLess(max(authguard_latencies[1:]), 1500)'
        assert self.authguard_errors == [], 'self.assertEqual(self.authguard_errors, [])'

    def authguard_check_02_host_preferences_and_history(self):
        authguard_page = self.authguard_page
        authguard_page.goto(self.authguard_origin + '/jobs')
        self.authguard_preferences()
        authguard_page.get_by_test_id('authguard-host-locale-zh_CN').click()
        self.authguard_preferences()
        authguard_page.get_by_test_id('authguard-host-theme-dark').click()
        self.authguard_enter()
        expect(authguard_page.get_by_test_id('authguard-nav-policy')).to_have_text('策略管理')
        expect(authguard_page.locator('.authguard-root')).to_have_attribute('data-authguard-theme', 'dark')
        self.authguard_preferences()
        authguard_page.get_by_test_id('authguard-host-locale-en_US').click()
        self.authguard_preferences()
        authguard_page.get_by_test_id('authguard-host-theme-light').click()
        expect(authguard_page.get_by_test_id('authguard-nav-policy')).to_have_text('Policy')
        authguard_page.emulate_media(color_scheme='dark')
        expect(authguard_page.locator('.authguard-root')).to_have_attribute('data-authguard-theme', 'light')
        expect(authguard_page.get_by_test_id('authguard-host-theme-light')).to_have_attribute('aria-pressed', 'true')
        authguard_page.emulate_media(color_scheme='light')
        authguard_page.go_back()
        expect(authguard_page.get_by_test_id('authguard-business-sidebar')).to_be_visible()
        authguard_page.go_forward()
        expect(authguard_page.get_by_test_id('authguard-management')).to_be_visible()
        authguard_page.reload()
        expect(authguard_page.get_by_test_id('authguard-management')).to_be_visible()
        self.authguard_preferences()
        authguard_page.get_by_test_id('authguard-workspace').click()
        expect(authguard_page.get_by_test_id('authguard-business-sidebar')).to_be_visible()
        assert self.authguard_errors == [], 'self.assertEqual(self.authguard_errors, [])'

    def authguard_check_03_selected_individual_modules_and_names(self):
        authguard_page = self.authguard_page
        authguard_page.goto(self.authguard_origin + '/access-management?modules=policy,principals')
        expect(authguard_page.get_by_test_id('authguard-nav-policy')).to_be_visible()
        expect(authguard_page.get_by_test_id('authguard-nav-overview')).to_have_count(0)
        expect(authguard_page.get_by_test_id('authguard-nav-accountSecurity')).to_have_count(0)
        for authguard_module in ('overview', 'policy', 'principals', 'accountSecurity'):
            authguard_page.goto(self.authguard_origin + '/access-management?page=' + authguard_module)
            expect(authguard_page.get_by_test_id('authguard-return')).to_be_visible()
            self.authguard_wait_page(authguard_module)
            expect(authguard_page.get_by_test_id('authguard-host-header')).to_have_count(1)
            expect(authguard_page.locator('.authguard-management-sidebar')).to_have_count(0)
            assert authguard_page.locator('.authguard-remote-host').evaluate("authguard_host => Array.from(authguard_host.shadowRoot.querySelectorAll('[class]')).flatMap(authguard_element => Array.from(authguard_element.classList)).filter(authguard_name => !/^authguard[-_]/.test(authguard_name))") == [], 'self.assertEqual(authguard_page.locator(\'.authguard-remote-host\').evaluate("authguard_host => Array.from(authguard_host.shadowRoot.querySelectorAll(\'[class]\')).flatMap(authguard_element => Array.from(authguard_element.classList)).filter(authguard_name => !/^authguard[-_]/.test(authguard_name))"), [])'
            authguard_page.get_by_test_id('authguard-return').click()
            expect(authguard_page.get_by_test_id('authguard-business-sidebar')).to_be_visible()
        assert self.authguard_errors == [], 'self.assertEqual(self.authguard_errors, [])'

    def authguard_check_04_responsive_layout_and_modal(self):
        authguard_page = self.authguard_page
        for authguard_width in (1440, 900, 640, 390):
            authguard_page.set_viewport_size({'width': authguard_width, 'height': 900})
            authguard_page.goto(self.authguard_origin + '/access-management')
            expect(authguard_page.get_by_test_id('authguard-management')).to_be_visible()
            for authguard_module in ('overview', 'policy', 'principals', 'accountSecurity'):
                authguard_page.get_by_test_id(f'authguard-nav-{authguard_module}').click()
                self.authguard_wait_page(authguard_module)
                self.authguard_no_overflow()
                authguard_return_box = authguard_page.get_by_test_id('authguard-return').bounding_box()
                assert authguard_return_box['y'] + authguard_return_box['height'] <= 900, "self.assertLessEqual(authguard_return_box['y'] + authguard_return_box['height'], 900)"
            self.authguard_screenshot(f'authguard-management-{authguard_width}')
            self.authguard_preferences()
            expect(authguard_page.locator('#authguard-business-menu select')).to_have_count(0)
            for authguard_choice in ('locale-zh_CN', 'locale-en_US', 'theme-light', 'theme-dark'):
                expect(authguard_page.get_by_test_id('authguard-host-' + authguard_choice)).to_be_visible()
            authguard_menu_box = authguard_page.locator('#authguard-business-menu').bounding_box()
            assert authguard_menu_box['x'] >= 0, "self.assertGreaterEqual(authguard_menu_box['x'], 0)"
            assert authguard_menu_box['x'] + authguard_menu_box['width'] <= authguard_width, "self.assertLessEqual(authguard_menu_box['x'] + authguard_menu_box['width'], authguard_width)"
            self.authguard_screenshot(f'authguard-menu-{authguard_width}')
            authguard_page.keyboard.press('Escape')
            authguard_page.get_by_test_id('authguard-nav-principals').click()
            authguard_page.get_by_test_id('principal-local-open').click()
            expect(authguard_page.locator('.authguard-modal')).to_be_visible()
            self.authguard_no_overflow()
            self.authguard_screenshot(f'authguard-modal-{authguard_width}')
        assert self.authguard_errors == [], 'self.assertEqual(self.authguard_errors, [])'

    def authguard_check_05_load_failure_and_expired_session(self):
        authguard_page = self.authguard_page
        authguard_page.route('**/auth/assets/authguard-remoteEntry.js', lambda authguard_route: authguard_route.abort())
        authguard_page.goto(self.authguard_origin + '/jobs')
        authguard_page.get_by_test_id('authguard-left-access').click()
        expect(authguard_page.get_by_role('alert')).to_be_visible()
        expect(authguard_page.get_by_test_id('authguard-host-header')).to_be_visible()
        authguard_page.get_by_role('button', name='Back to workspace').click()
        expect(authguard_page.get_by_test_id('authguard-business-sidebar')).to_be_visible()
        authguard_page.unroute('**/auth/assets/authguard-remoteEntry.js')
        authguard_page.route('**/auth/session', lambda authguard_route: authguard_route.fulfill(status=401, json={'message': 'Expired session'}))
        authguard_page.goto(self.authguard_origin + '/access-management')
        expect(authguard_page.get_by_role('link', name='Sign in to manage access')).to_be_visible()
        expect(authguard_page.get_by_test_id('authguard-host-header')).to_be_visible()
        expect(authguard_page.get_by_test_id('authguard-nav-policy')).to_have_count(0)
        authguard_page.unroute('**/auth/session')
        authguard_page.reload()
        expect(authguard_page.get_by_test_id('authguard-management')).to_be_visible()

    def authguard_check_06_standalone_settings(self):
        authguard_page = self.authguard_page
        authguard_page.goto(self.authguard_standalone_origin)
        expect(authguard_page.get_by_test_id('authguard-profile-trigger')).to_be_visible()
        expect(authguard_page.get_by_test_id('api-token')).to_have_count(0)
        expect(authguard_page.get_by_test_id('locale-switch')).to_have_count(0)
        authguard_page.get_by_test_id('authguard-profile-trigger').click()
        expect(authguard_page.locator('#authguard-system-settings select')).to_have_count(0)
        authguard_page.get_by_test_id('locale-zh_CN').click()
        authguard_page.get_by_test_id('theme-dark').click()
        expect(authguard_page.locator('.authguard-root')).to_have_attribute('data-authguard-theme', 'dark')
        expect(authguard_page.get_by_role('region', name='系统设置')).to_be_visible()
        authguard_page.get_by_test_id('api-token').fill('authguard-browser-fixture-token')
        authguard_page.get_by_test_id('api-token-submit').click()
        authguard_page.keyboard.press('Escape')
        expect(authguard_page.get_by_test_id('locale-switch')).to_have_count(0)
        authguard_page.get_by_test_id('nav-policy').click()
        expect(authguard_page.get_by_role('heading', name='策略管理')).to_be_visible()
        expect(authguard_page.get_by_test_id('policy-create')).to_be_enabled()
        self.authguard_screenshot('authguard-standalone')
        assert self.authguard_errors == [], 'self.assertEqual(self.authguard_errors, [])'

    def authguard_check_07_public_settings_functions(self):
        authguard_page = self.authguard_page
        authguard_page.goto(self.authguard_origin + '/access-management?settings=functions')
        expect(authguard_page.get_by_test_id('authguard-management')).to_be_visible()
        self.authguard_preferences()
        authguard_page.get_by_test_id('authguard-host-locale-zh_CN').click()
        self.authguard_preferences()
        authguard_page.get_by_test_id('authguard-host-theme-dark').click()
        expect(authguard_page.get_by_test_id('authguard-nav-policy')).to_have_text('策略管理')
        expect(authguard_page.locator('.authguard-root')).to_have_attribute('data-authguard-theme', 'dark')
        authguard_page.get_by_test_id('authguard-return').click()
        self.authguard_preferences()
        authguard_page.get_by_test_id('authguard-host-locale-en_US').click()
        self.authguard_preferences()
        authguard_page.get_by_test_id('authguard-host-theme-light').click()
        self.authguard_enter()
        expect(authguard_page.get_by_test_id('authguard-nav-policy')).to_have_text('Policy')
        expect(authguard_page.locator('.authguard-root')).to_have_attribute('data-authguard-theme', 'light')
        assert authguard_page.locator('html').get_attribute('data-authguard-theme') is None, "self.assertIsNone(authguard_page.locator('html').get_attribute('data-authguard-theme'))"
        authguard_page.emulate_media(color_scheme='dark')
        authguard_page.evaluate("async () => { const authguard_remote = await import('/auth/assets/authguard-remoteEntry.js'); const authguard_settings = (await authguard_remote.get('./settings'))(); authguard_settings.authguard_set_theme('system'); }")
        expect(authguard_page.locator('.authguard-root')).to_have_attribute('data-authguard-theme', 'dark')
        authguard_page.emulate_media(color_scheme='light')
        expect(authguard_page.locator('.authguard-root')).to_have_attribute('data-authguard-theme', 'light')
        assert self.authguard_errors == [], 'self.assertEqual(self.authguard_errors, [])'

    def authguard_check_08_desktop_presentation(self):
        authguard_page = self.authguard_page
        for authguard_width, authguard_height in ((1440, 1000), (1920, 1080)):
            authguard_page.set_viewport_size({'width': authguard_width, 'height': authguard_height})
            authguard_page.goto(self.authguard_origin + '/access-management')
            self.authguard_wait_page('overview')
            expect(authguard_page.get_by_test_id('authguard-host-locale')).to_have_count(0)
            expect(authguard_page.get_by_test_id('authguard-host-theme')).to_have_count(0)
            self.authguard_screenshot(f'authguard-desktop-{authguard_width}-light')
            self.authguard_preferences()
            expect(authguard_page.locator('#authguard-business-menu select')).to_have_count(0)
            for authguard_choice in ('locale-zh_CN', 'locale-en_US', 'theme-light', 'theme-dark'):
                expect(authguard_page.get_by_test_id('authguard-host-' + authguard_choice)).to_be_visible()
            authguard_menu_box = authguard_page.locator('#authguard-business-menu').bounding_box()
            assert authguard_menu_box['y'] >= 64, "self.assertGreaterEqual(authguard_menu_box['y'], 64)"
            assert authguard_menu_box['x'] + authguard_menu_box['width'] <= authguard_width, "self.assertLessEqual(authguard_menu_box['x'] + authguard_menu_box['width'], authguard_width)"
            self.authguard_screenshot(f'authguard-desktop-{authguard_width}-menu-light')
            authguard_page.get_by_test_id('authguard-host-locale-zh_CN').click()
            authguard_page.get_by_test_id('authguard-host-theme-dark').click()
            expect(authguard_page.locator('.authguard-business-shell')).to_have_attribute('data-authguard-host-theme', 'dark')
            expect(authguard_page.locator('.authguard-root')).to_have_attribute('data-authguard-theme', 'dark')
            expect(authguard_page.get_by_test_id('authguard-host-locale-zh_CN')).to_have_attribute('aria-pressed', 'true')
            expect(authguard_page.get_by_test_id('authguard-host-locale-en_US')).to_have_attribute('aria-pressed', 'false')
            expect(authguard_page.get_by_test_id('authguard-host-theme-dark')).to_have_attribute('aria-pressed', 'true')
            expect(authguard_page.get_by_test_id('authguard-host-theme-light')).to_have_attribute('aria-pressed', 'false')
            expect(authguard_page.get_by_test_id('authguard-nav-policy')).to_have_text('策略管理')
            self.authguard_screenshot(f'authguard-desktop-{authguard_width}-menu-dark')
            authguard_page.keyboard.press('Escape')
            expect(authguard_page.get_by_test_id('authguard-host-profile')).to_be_focused()
            expect(authguard_page.get_by_test_id('authguard-host-theme')).to_have_count(0)
            self.authguard_no_overflow()
            self.authguard_screenshot(f'authguard-desktop-{authguard_width}-dark')
            self.authguard_preferences()
            authguard_page.get_by_test_id('authguard-nav-policy').click()
            expect(authguard_page.locator('#authguard-business-menu')).to_have_count(0)
        assert self.authguard_errors == [], 'self.assertEqual(self.authguard_errors, [])'
    def authguard_check_09_seven_languages(self):
        authguard_page = self.authguard_page
        authguard_languages = (
            ('en_US', 'EN', 'Policy', 'Principals', 'Manage your credentials'),
            ('zh_CN', '中', '策略管理', '身份主体', '管理认证凭据'),
            ('zh_TW', '繁', '原則管理', '身分主體', '管理認證憑證'),
            ('ja_JP', '日語', 'ポリシー', 'プリンシパル', '認証情報の管理'),
            ('ko_KR', '한글', '정책', '보안 주체', '인증 정보 관리'),
            ('de_DE', 'DE', 'Richtlinien', 'Prinzipale', 'Anmeldedaten verwalten'),
            ('fr_FR', 'FR', 'Politiques', 'Principaux', 'Gérer les identifiants'),
        )
        for authguard_functions in (False, True):
            authguard_page.goto(self.authguard_origin + '/access-management' + ('?settings=functions' if authguard_functions else ''))
            expect(authguard_page.get_by_test_id('authguard-management')).to_be_visible()
            for authguard_width in (1440, 390):
                authguard_page.set_viewport_size({'width': authguard_width, 'height': 1000})
                for authguard_locale, authguard_label, authguard_policy, authguard_principals, authguard_security in authguard_languages:
                    self.authguard_preferences()
                    expect(authguard_page.get_by_test_id('authguard-host-locale').get_by_role('button')).to_have_text([authguard_language[1] for authguard_language in authguard_languages])
                    authguard_page.get_by_test_id('authguard-host-locale-' + authguard_locale).click()
                    expect(authguard_page.get_by_test_id('authguard-nav-policy')).to_have_text(authguard_policy)
                    expect(authguard_page.locator('.authguard-root')).to_have_attribute('lang', authguard_locale.replace('_', '-'))
                    expect(authguard_page.get_by_test_id('authguard-host-locale-' + authguard_locale)).to_have_attribute('aria-pressed', 'true')
                    authguard_menu = authguard_page.locator('#authguard-business-menu').bounding_box()
                    assert authguard_menu['width'] <= 300 and authguard_menu['x'] >= 0 and authguard_menu['x'] + authguard_menu['width'] <= authguard_width
                    authguard_bar = authguard_page.get_by_test_id('authguard-host-locale').bounding_box()
                    authguard_row = authguard_page.locator('.authguard-business-language-row').bounding_box()
                    assert abs(authguard_bar['width'] - authguard_row['width']) < 1
                    authguard_boxes = authguard_page.get_by_test_id('authguard-host-locale').get_by_role('button').evaluate_all('authguard_buttons => authguard_buttons.map(authguard_button => ({y: authguard_button.getBoundingClientRect().y, width: authguard_button.getBoundingClientRect().width, fits: authguard_button.scrollWidth <= authguard_button.clientWidth}))')
                    assert len({authguard_box['y'] for authguard_box in authguard_boxes}) == 1
                    assert max(authguard_box['width'] for authguard_box in authguard_boxes) - min(authguard_box['width'] for authguard_box in authguard_boxes) < 1
                    assert all(authguard_box['fits'] for authguard_box in authguard_boxes)
                    self.authguard_screenshot(f'language_{authguard_locale}_{authguard_width}_functions_{authguard_functions}')
                    authguard_page.keyboard.press('Escape')
                    for authguard_module, authguard_heading in (('policy', authguard_policy), ('principals', authguard_principals), ('accountSecurity', authguard_security)):
                        authguard_page.get_by_test_id('authguard-nav-' + authguard_module).click()
                        expect(authguard_page.get_by_role('heading', name=authguard_heading, exact=True)).to_be_visible()
                        self.authguard_no_overflow()
                    self.details.append(f'{authguard_locale} ({authguard_label}) at {authguard_width}px via {"functions" if authguard_functions else "props"}: translated pages and compact aligned menu passed')
        assert not self.authguard_errors, self.authguard_errors

    def authguard_check_10_locale_detection_and_persistence(self):
        for authguard_browser_locale, authguard_expected in (('zh-Hant-HK', 'zh_TW'), ('ja-JP', 'ja_JP'), ('ko-KR', 'ko_KR'), ('de-AT', 'de_DE'), ('fr-CA', 'fr_FR')):
            with self.authguard_browser.new_context(locale=authguard_browser_locale, viewport={'width': 390, 'height': 900}) as authguard_context:
                authguard_page = authguard_context.new_page()
                authguard_page.goto(self.authguard_standalone_origin + '/login')
                expect(authguard_page.get_by_test_id('locale-' + authguard_expected)).to_have_attribute('aria-pressed', 'true')
                authguard_page.get_by_test_id('locale-fr_FR').click()
                authguard_page.reload()
                expect(authguard_page.get_by_test_id('locale-fr_FR')).to_have_attribute('aria-pressed', 'true')
                assert authguard_page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                assert authguard_page.locator('html').get_attribute('lang') == 'en'
                authguard_path = self.evidence_path(self._active_case_id, 'login_' + authguard_browser_locale, 'png')
                authguard_page.screenshot(path=str(authguard_path), full_page=True, animations='disabled')
                self.record_evidence(self._active_case_id, 'Login language ' + authguard_browser_locale, 'image/png', authguard_path)
                self.details.append(f'Browser {authguard_browser_locale} resolves to {authguard_expected}; explicit fr_FR selection persists on reload without host HTML changes')

    def authguard_policy_open(self, authguard_embedded):
        if authguard_embedded:
            self.authguard_page.goto(self.authguard_origin + '/access-management?policy_fixture=1')
            expect(self.authguard_page.get_by_test_id('authguard-management')).to_be_visible()
            self.authguard_page.get_by_test_id('authguard-nav-policy').click()
        else:
            self.authguard_page.add_init_script("sessionStorage.setItem('authguard.api-token', 'authguard-browser-fixture-token')")
            self.authguard_page.goto(self.authguard_standalone_origin + '/policy?policy_fixture=1')
        self.authguard_policy_rows(['fixture.read', 'fixture.write'])

    def authguard_policy_rows(self, authguard_expected):
        authguard_rows = self.authguard_page.locator('.authguard-resource-list > article')
        expect(authguard_rows).to_have_count(len(authguard_expected))
        expect(authguard_rows.locator('strong')).to_have_text(authguard_expected)
        expect(authguard_rows.get_by_text('undefined', exact=True)).to_have_count(0)

    def authguard_policy_hold(self, authguard_resource, authguard_method='GET'):
        authguard_routes = []
        def authguard_capture(authguard_route):
            if authguard_route.request.method == authguard_method:
                authguard_routes.append(authguard_route)
            else:
                authguard_route.continue_()
        authguard_pattern = '**/auth/management/api/v1/' + authguard_resource
        self.authguard_page.route(authguard_pattern, authguard_capture)
        return authguard_routes, authguard_pattern

    def authguard_policy_release(self, authguard_route, authguard_status=200, authguard_items=None, authguard_payload=None):
        # A 204 has no body to finish; Chromium 151 may omit requestfinished.
        authguard_event = 'response' if authguard_status == 204 else 'requestfinished'
        with self.authguard_page.expect_event(authguard_event, predicate=lambda authguard_result: (authguard_result.request if authguard_status == 204 else authguard_result) == authguard_route.request):
            if authguard_status == 204:
                authguard_route.fulfill(status=204)
            elif authguard_status != 200:
                authguard_route.fulfill(status=authguard_status, json={'message': 'policy fixture request failed'})
            elif authguard_payload is not None:
                authguard_route.fulfill(status=200, json=authguard_payload)
            elif authguard_items is not None:
                authguard_route.fulfill(status=200, json={'items': authguard_items, 'total': len(authguard_items), 'policy_revision': 1})
            else:
                authguard_route.fulfill(response=authguard_route.fetch())
        # Flush fetch callbacks and React commits without relying on a fixed delay.
        self.authguard_page.evaluate('() => new Promise(authguard_resolve => requestAnimationFrame(() => requestAnimationFrame(authguard_resolve)))')

    def authguard_policy_no_errors(self):
        assert not self.authguard_errors, self.authguard_errors
        assert not [authguard_error for authguard_error in self.authguard_console_errors if 'same key' in authguard_error or 'unique "key"' in authguard_error], self.authguard_console_errors

    def authguard_check_11_policy_resource_switch_isolation(self):
        for authguard_embedded in (False, True):
            self.authguard_policy_open(authguard_embedded)
            for authguard_kind, authguard_expected in (
                ('roles', ['fixture-reader', 'fixture-writer']),
                ('role-bindings', ['fixture-binding-a', 'fixture-binding-b']),
                ('actions', ['fixture.read', 'fixture.write']),
            ):
                self.authguard_page.get_by_test_id('policy-tab-' + authguard_kind).click()
                self.authguard_policy_rows(authguard_expected)
            authguard_roles, authguard_pattern = self.authguard_policy_hold('roles')
            self.authguard_page.get_by_test_id('policy-tab-roles').click()
            self.authguard_policy_rows([])
            assert len(authguard_roles) == 1, 'The role request must be pending before checking the empty list'
            self.authguard_policy_release(authguard_roles[0])
            self.authguard_policy_rows(['fixture-reader', 'fixture-writer'])
            self.authguard_page.unroute(authguard_pattern)
            self.authguard_screenshot(f'policy-resource-isolation-embedded-{authguard_embedded}')
        self.authguard_policy_no_errors()
        self.details.append('Standalone and embedded Actions/Roles/Bindings switches show exact rows; old rows are empty while the next type is pending.')

    def authguard_check_12_policy_response_ordering(self):
        for authguard_embedded in (False, True):
            for authguard_status in (200, 500):
                self.authguard_policy_open(authguard_embedded)
                authguard_actions, authguard_action_pattern = self.authguard_policy_hold('actions')
                authguard_roles, authguard_role_pattern = self.authguard_policy_hold('roles')
                authguard_refresh = self.authguard_page.locator('.authguard-page-heading .authguard-icon-button')
                authguard_refresh.click()
                expect(authguard_refresh.locator('.authguard-spin')).to_be_visible()
                self.authguard_page.get_by_test_id('policy-tab-roles').click()
                self.authguard_policy_rows([])
                assert len(authguard_actions) == len(authguard_roles) == 1
                self.authguard_policy_release(authguard_actions[0], authguard_status)
                self.authguard_policy_rows([])
                expect(self.authguard_page.locator('.authguard-error-banner')).to_have_count(0)
                expect(authguard_refresh.locator('.authguard-spin')).to_be_visible()
                self.authguard_policy_release(authguard_roles[0])
                self.authguard_policy_rows(['fixture-reader', 'fixture-writer'])
                expect(authguard_refresh.locator('.authguard-spin')).to_have_count(0)
                # A current failure is visible, then a successful retry recovers.
                authguard_refresh.click()
                expect(authguard_refresh.locator('.authguard-spin')).to_be_visible()
                assert len(authguard_roles) == 2
                self.authguard_policy_release(authguard_roles[-1], 500)
                expect(self.authguard_page.locator('.authguard-error-banner')).to_have_text('policy fixture request failed')
                expect(authguard_refresh.locator('.authguard-spin')).to_have_count(0)
                authguard_refresh.click()
                expect(authguard_refresh.locator('.authguard-spin')).to_be_visible()
                assert len(authguard_roles) == 3
                self.authguard_policy_release(authguard_roles[-1])
                expect(self.authguard_page.locator('.authguard-error-banner')).to_have_count(0)
                # Two refreshes for the same type must also obey response order.
                authguard_refresh.click()
                expect(authguard_refresh.locator('.authguard-spin')).to_be_visible()
                authguard_refresh.click()
                assert len(authguard_roles) == 5
                self.authguard_policy_release(authguard_roles[-1], authguard_items=[{'id': 'fixture-latest-role'}])
                self.authguard_policy_release(authguard_roles[-2], authguard_status, [{'id': 'fixture-obsolete-role'}])
                self.authguard_policy_rows(['fixture-latest-role'])
                expect(self.authguard_page.locator('.authguard-error-banner')).to_have_count(0)
                expect(authguard_refresh.locator('.authguard-spin')).to_have_count(0)
                self.authguard_page.unroute(authguard_action_pattern)
                self.authguard_page.unroute(authguard_role_pattern)
        self.authguard_policy_no_errors()
        self.details.append('Explicitly released out-of-order successes/errors cannot replace the current type, rows, loading or errors; same-type refresh and failure recovery also pass in both modes.')

    def authguard_check_13_policy_delayed_mutations(self):
        for authguard_embedded in (False, True):
            for authguard_leave_page, authguard_status in ((False, 204), (False, 500), (True, 204), (True, 500)):
                self.authguard_policy_open(authguard_embedded)
                authguard_deletes, authguard_pattern = self.authguard_policy_hold('actions/*', 'DELETE')
                self.authguard_page.once('dialog', lambda authguard_dialog: authguard_dialog.accept())
                self.authguard_page.locator('.authguard-resource-list > article').first.locator('.authguard-danger').click()
                if authguard_leave_page:
                    self.authguard_page.get_by_test_id('authguard-nav-principals' if authguard_embedded else 'nav-principals').click()
                    expect(self.authguard_page.get_by_role('heading', name='Principals', exact=True)).to_be_visible()
                else:
                    self.authguard_page.get_by_test_id('policy-tab-roles').click()
                    self.authguard_policy_rows(['fixture-reader', 'fixture-writer'])
                assert len(authguard_deletes) == 1
                authguard_action_requests = sum(authguard_url.endswith('/api/v1/actions') for authguard_url in self.authguard_requests)
                self.authguard_policy_release(authguard_deletes[0], authguard_status)
                assert sum(authguard_url.endswith('/api/v1/actions') for authguard_url in self.authguard_requests) == authguard_action_requests, 'A delayed mutation must not start an obsolete type reload after a switch or unmount'
                if not authguard_leave_page:
                    self.authguard_policy_rows(['fixture-reader', 'fixture-writer'])
                    expect(self.authguard_page.locator('.authguard-error-banner')).to_have_count(0)
                else:
                    expect(self.authguard_page.get_by_role('heading', name='Principals', exact=True)).to_be_visible()
                self.authguard_page.unroute(authguard_pattern)
        self.authguard_policy_no_errors()
        self.details.append('Delayed DELETE success/error cannot restart an Actions load or set an obsolete error after switching to Roles or leaving Policy, in standalone and embedded modes.')

    def authguard_check_14_policy_token_reset(self):
        self.authguard_policy_open(False)
        authguard_actions, authguard_pattern = self.authguard_policy_hold('actions')
        authguard_refresh = self.authguard_page.locator('.authguard-page-heading .authguard-icon-button')
        authguard_refresh.click()
        expect(authguard_refresh.locator('.authguard-spin')).to_be_visible()
        self.authguard_page.get_by_test_id('authguard-profile-trigger').click()
        self.authguard_page.get_by_test_id('api-token').fill('')
        self.authguard_page.get_by_test_id('api-token-submit').click()
        self.authguard_page.get_by_test_id('authguard-profile-trigger').click()
        self.authguard_policy_rows([])
        expect(authguard_refresh.locator('.authguard-spin')).to_have_count(0)
        expect(self.authguard_page.get_by_test_id('policy-create')).to_be_disabled()
        assert len(authguard_actions) == 1
        self.authguard_policy_release(authguard_actions[0])
        self.authguard_policy_rows([])
        self.authguard_page.get_by_test_id('authguard-profile-trigger').click()
        self.authguard_page.get_by_test_id('api-token').fill('authguard-browser-fixture-token')
        self.authguard_page.get_by_test_id('api-token-submit').click()
        self.authguard_page.get_by_test_id('authguard-profile-trigger').click()
        expect(authguard_refresh.locator('.authguard-spin')).to_be_visible()
        assert len(authguard_actions) == 2
        self.authguard_policy_release(authguard_actions[-1])
        self.authguard_policy_rows(['fixture.read', 'fixture.write'])
        expect(authguard_refresh.locator('.authguard-spin')).to_have_count(0)
        expect(self.authguard_page.get_by_test_id('policy-create')).to_be_enabled()
        self.authguard_page.unroute(authguard_pattern)
        self.authguard_policy_no_errors()
        self.details.append('Removing a credential while a load is pending clears rows/loading and ignores its late reply; restoring the credential recovers normally.')

    def authguard_check_15_policy_delayed_saves(self):
        for authguard_embedded in (False, True):
            for authguard_leave_page in (False, True):
                self.authguard_policy_open(authguard_embedded)
                authguard_saves, authguard_pattern = self.authguard_policy_hold('actions/*', 'PUT')
                self.authguard_page.locator('.authguard-resource-list > article').first.locator('.authguard-row-actions button').first.click()
                expect(self.authguard_page.get_by_test_id('policy-json')).to_be_visible()
                self.authguard_page.get_by_test_id('policy-save').click()
                self.authguard_page.get_by_role('button', name='Cancel', exact=True).click()
                if authguard_leave_page:
                    self.authguard_page.get_by_test_id('authguard-nav-principals' if authguard_embedded else 'nav-principals').click()
                    expect(self.authguard_page.get_by_role('heading', name='Principals', exact=True)).to_be_visible()
                else:
                    self.authguard_page.get_by_test_id('policy-tab-roles').click()
                    self.authguard_policy_rows(['fixture-reader', 'fixture-writer'])
                    self.authguard_page.get_by_test_id('policy-create').click()
                    expect(self.authguard_page.get_by_test_id('policy-json')).to_be_visible()
                    authguard_role_draft = self.authguard_page.get_by_test_id('policy-json').input_value()
                assert len(authguard_saves) == 1
                authguard_action_requests = sum(authguard_url.endswith('/api/v1/actions') for authguard_url in self.authguard_requests)
                self.authguard_policy_release(authguard_saves[0], authguard_payload={'policy_revision': 2})
                assert sum(authguard_url.endswith('/api/v1/actions') for authguard_url in self.authguard_requests) == authguard_action_requests, 'An obsolete save must not restart the Actions loader'
                if authguard_leave_page:
                    expect(self.authguard_page.get_by_role('heading', name='Principals', exact=True)).to_be_visible()
                else:
                    expect(self.authguard_page.get_by_test_id('policy-json')).to_have_value(authguard_role_draft)
                    self.authguard_policy_rows(['fixture-reader', 'fixture-writer'])
                    self.authguard_page.get_by_role('button', name='Cancel', exact=True).click()
                self.authguard_page.unroute(authguard_pattern)
        self.authguard_policy_no_errors()
        self.details.append('A delayed Action save cannot close a new Role editor or issue an obsolete reload after switching types or leaving Policy in either mode.')
