"""Reusable real-browser test data for AuthGuard Web authentication journeys."""
from __future__ import annotations
import json
from verifier.authn.s15_wallet import (
    ANVIL_ACCOUNT_0_ADDRESS,
    EVM_OFFLINE_EOA_CHAIN_REFERENCE,
    EvmWallet,
)


class BrowserWallet:
    """A deterministic EIP-1193 transport backed by a real EIP-191 signer."""

    @staticmethod
    def sign_personal_message(encoded_message: str) -> str:
        if not isinstance(encoded_message, str) or not encoded_message.startswith("0x"):
            raise RuntimeError("EIP-1193 personal_sign payload was not hexadecimal")
        try:
            message = bytes.fromhex(encoded_message[2:]).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise RuntimeError(
                "EIP-1193 personal_sign payload was invalid UTF-8"
            ) from error
        return EvmWallet.sign(message)

    @staticmethod
    def injected_script() -> str:
        return f"\n        (() => {{\n          const account = {json.dumps(ANVIL_ACCOUNT_0_ADDRESS)};\n          const chainId = '0x{int(EVM_OFFLINE_EOA_CHAIN_REFERENCE):x}';\n          const wallet = {{\n            isMetaMask: true,\n            on() {{}},\n            removeListener() {{}},\n            async request({{ method, params = [] }}) {{\n              if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [account];\n              if (method === 'eth_chainId') return chainId;\n              if (method === 'net_version') return String(parseInt(chainId, 16));\n              if (method === 'wallet_getPermissions') return [];\n              if (method === 'personal_sign') return window.authguardE2ESign(params[0]);\n              throw new Error(`Unsupported E2E wallet method: ${{method}}`);\n            }}\n          }};\n          Object.defineProperty(window, 'ethereum', {{ value: wallet, configurable: false }});\n        }})();\n        "


class Ctap2BrowserAuthenticator:
    """Installs Chromium's CTAP2 platform authenticator for real WebAuthn APIs."""

    @staticmethod
    def install(context, page) -> tuple[object, str]:
        cdp = context.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        authenticator_id = cdp.send(
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
        return (cdp, authenticator_id)
