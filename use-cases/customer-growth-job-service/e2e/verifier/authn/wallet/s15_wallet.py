"""AuthN s15 CAIP-10 / CAIP-122 SIWX wallet authentication verifier."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import subprocess
import time
from typing import Any
from urllib import request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from common.config import PROJECT_ROOT
from common.kubernetes import AUTHN_HOST
from verifier.authn.other.protocol import AuthenticatedLogin, AuthnProtocolVerifier
from verifier.authn.password.s13_password_totp import StandaloneFixture


WALLET_ACR = "urn:authguard:acr:wallet-possession"
# Anvil deterministic account #0. EOA tests use it on an RPC-free CAIP chain,
# proving that ordinary EIP-191 verification has no node dependency.
ANVIL_ACCOUNT_0_PRIVATE_KEY = (
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)
ANVIL_ACCOUNT_1_PRIVATE_KEY = (
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
)
ANVIL_ACCOUNT_0_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
EVM_OFFLINE_EOA_CHAIN_REFERENCE = "31336"
EVM_ANVIL_CONTRACT_CHAIN_REFERENCE = "31337"
EVM_TIMEOUT_FAULT_CHAIN_REFERENCE = "31338"
ERC1271_VALIDATOR_CONTRACT_ADDRESS = "0x0000000000000000000000000000000000001271"
ERC1271_EMPTY_ACCOUNT_ADDRESS = "0x0000000000000000000000000000000000001272"
ERC6492_COUNTERFACTUAL_ACCOUNT_ADDRESS = "0x0000000000000000000000000000000000006492"

# CAIP-2 bip122 mainnet reference is the first 32 characters of Bitcoin's
# genesis block hash. The fixed WIF controls the matching P2WPKH test address.
BITCOIN_MAINNET_CAIP2_REFERENCE = "000000000019d6689c085ae165831e93"
BITCOIN_BIP322_P2WPKH_ADDRESS = "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l"
BITCOIN_BIP322_TEST_WIF = "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(value: bytes) -> str:
    leading = len(value) - len(value.lstrip(b"\0"))
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    return "1" * leading + encoded


def _base58_decode(value: str) -> bytes:
    number = 0
    for char in value:
        number = number * 58 + BASE58_ALPHABET.index(char)
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + decoded


def _compact_size(value: int) -> bytes:
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    return b"\xfe" + value.to_bytes(4, "little")


def _double_sha256(value: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()


@dataclass(frozen=True)
class EvmWallet:
    """EIP-191 signer equivalent to a browser wallet personal_sign action."""

    account_id: str = (
        f"eip155:{EVM_OFFLINE_EOA_CHAIN_REFERENCE}:{ANVIL_ACCOUNT_0_ADDRESS}"
    )

    @staticmethod
    def sign(message: str, private_key: str = ANVIL_ACCOUNT_0_PRIVATE_KEY) -> str:
        script = (
            "import {privateKeyToAccount} from 'viem/accounts';"
            "const account=privateKeyToAccount(process.argv[1]);"
            "console.log(await account.signMessage({message:process.argv[2]}));"
        )
        completed = subprocess.run(
            ("node", "--input-type=module", "-e", script, private_key, message),
            cwd=PROJECT_ROOT / "web",
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        signature = completed.stdout.strip()
        if len(signature) != 132 or not signature.startswith("0x"):
            raise RuntimeError("viem returned a malformed EIP-191 signature")
        return signature

    @staticmethod
    def message_hash(message: str) -> str:
        script = (
            "import {hashMessage} from 'viem';"
            "console.log(hashMessage(process.argv[1]));"
        )
        completed = subprocess.run(
            ("node", "--input-type=module", "-e", script, message),
            cwd=PROJECT_ROOT / "web",
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        digest = completed.stdout.strip()
        if len(digest) != 66 or not digest.startswith("0x"):
            raise RuntimeError("viem returned a malformed EIP-191 message hash")
        return digest


@dataclass(frozen=True)
class SolanaWallet:
    """Ed25519 SIWX signer representing a Solana wallet keypair."""

    private_key: ed25519.Ed25519PrivateKey
    chain_reference: str

    @classmethod
    def create(cls, chain_reference: str) -> "SolanaWallet":
        return cls(ed25519.Ed25519PrivateKey.generate(), chain_reference)

    @property
    def address(self) -> str:
        return _base58_encode(self.private_key.public_key().public_bytes_raw())

    @property
    def account_id(self) -> str:
        return f"solana:{self.chain_reference}:{self.address}"

    def sign(self, message: str) -> str:
        return _base58_encode(self.private_key.sign(message.encode()))


class BitcoinWallet:
    """P2WPKH BIP-322 signer used as an independent protocol oracle."""

    account_id = (
        f"bip122:{BITCOIN_MAINNET_CAIP2_REFERENCE}:{BITCOIN_BIP322_P2WPKH_ADDRESS}"
    )

    def __init__(self) -> None:
        decoded = _base58_decode(BITCOIN_BIP322_TEST_WIF)
        if len(decoded) != 38 or decoded[0] != 0x80 or decoded[33] != 0x01:
            raise RuntimeError("invalid BIP-322 fixture WIF")
        if _double_sha256(decoded[:-4])[:4] != decoded[-4:]:
            raise RuntimeError("BIP-322 fixture WIF checksum mismatch")
        self.private_key = ec.derive_private_key(
            int.from_bytes(decoded[1:33], "big"), ec.SECP256K1()
        )
        numbers = self.private_key.public_key().public_numbers()
        self.public_key = bytes([2 + (numbers.y & 1)]) + numbers.x.to_bytes(32, "big")
        self.public_key_hash = hashlib.new(
            "ripemd160", hashlib.sha256(self.public_key).digest()
        ).digest()

    def sign(self, message: str, *, full: bool) -> str:
        tagged = hashlib.sha256(b"BIP0322-signed-message").digest()
        message_hash = hashlib.sha256(tagged + tagged + message.encode()).digest()
        challenge_script = b"\x00\x14" + self.public_key_hash
        script_sig = b"\x00\x20" + message_hash
        to_spend = self._transaction(
            previous_txid=bytes(32),
            previous_index=0xFFFFFFFF,
            script_sig=script_sig,
            output_script=challenge_script,
            witness=None,
        )
        previous_txid = _double_sha256(to_spend)
        outpoint = previous_txid + bytes(4)
        sequence = bytes(4)
        output = bytes(8) + b"\x01\x6a"
        script_code = b"\x19\x76\xa9\x14" + self.public_key_hash + b"\x88\xac"
        preimage = (
            bytes(4)
            + _double_sha256(outpoint)
            + _double_sha256(sequence)
            + outpoint
            + script_code
            + bytes(8)
            + sequence
            + _double_sha256(output)
            + bytes(4)
            + (1).to_bytes(4, "little")
        )
        digest = _double_sha256(preimage)
        der = self.private_key.sign(
            digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        r, s = utils.decode_dss_signature(der)
        curve_order = int(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
        )
        der = utils.encode_dss_signature(r, min(s, curve_order - s))
        witness = self._witness((der + b"\x01", self.public_key))
        if not full:
            return "smp" + base64.b64encode(witness).decode()
        to_sign = self._transaction(
            previous_txid=previous_txid,
            previous_index=0,
            script_sig=b"",
            output_script=b"\x6a",
            witness=witness,
        )
        return "ful" + base64.b64encode(to_sign).decode()

    @staticmethod
    def _witness(items: tuple[bytes, ...]) -> bytes:
        return _compact_size(len(items)) + b"".join(
            _compact_size(len(item)) + item for item in items
        )

    @staticmethod
    def _transaction(
        *,
        previous_txid: bytes,
        previous_index: int,
        script_sig: bytes,
        output_script: bytes,
        witness: bytes | None,
    ) -> bytes:
        return b"".join(
            (
                bytes(4),
                b"\x00\x01" if witness is not None else b"",
                b"\x01",
                previous_txid,
                previous_index.to_bytes(4, "little"),
                _compact_size(len(script_sig)),
                script_sig,
                bytes(4),
                b"\x01",
                bytes(8),
                _compact_size(len(output_script)),
                output_script,
                witness or b"",
                bytes(4),
            )
        )


class WalletAuthenticationVerifier(AuthnProtocolVerifier):
    """Exercise offline SIWX signers separately from contract-wallet RPC."""

    def verify(self, standalone: StandaloneFixture) -> None:
        evm = EvmWallet()
        bitcoin = BitcoinWallet()
        with self._forward_service(self._envoy_proxy_service(), 8082) as authn_port:
            self.scenario.step(
                "Wallet WL-01..04: challenge is canonical CAIP/SIWX server state",
                lambda: self._challenge_contract(authn_port, evm.account_id),
            )
            evm_login = self.scenario.step(
                "Wallet WL-05..10: EOA stays offline and unsupported contract proofs return 501",
                lambda: self._evm_eoa(authn_port, evm),
            )
            # The test process contacts the real validator only to anchor and
            # fund its fixture. The AuthGuard configuration carries no Solana
            # RPC, and signature verification remains local to the AuthN Pod.
            with self._forward_service(self.solana_service, 8899) as solana_rpc_port:
                solana_reference = self._solana_reference(solana_rpc_port)
                solana = SolanaWallet.create(solana_reference)
                solana_login = self.scenario.step(
                    "Wallet WL-11..12: local-validator account verifies Ed25519 offline",
                    lambda: self._solana(authn_port, solana_rpc_port, solana),
                )
            bitcoin_login = self.scenario.step(
                "Wallet WL-13..15: Bitcoin BIP-322 simple/full verify offline",
                lambda: self._bitcoin(authn_port, bitcoin),
            )
            self.scenario.step(
                "Wallet WL-16..18: invalid signatures burn challenges and concurrent replay loses",
                lambda: self._replay_contract(authn_port, evm, evm_login.principal_id),
            )
            # Contract-wallet verification is the only successful account path
            # in this scenario that requires an EVM node connection.
            with self._forward_service(self.anvil_service, 8545) as anvil_rpc_port:
                self.scenario.step(
                    "Wallet WL-19..22: ERC-1271 uses real Anvil; extension/fault paths fail closed",
                    lambda: self._contract_wallets(authn_port, anvil_rpc_port),
                )
            self.scenario.step(
                "Wallet WL-23..25: explicit link requires bearer plus fresh possession proof",
                lambda: self._link_contract(
                    authn_port, standalone, evm, solana_reference
                ),
            )
            self.scenario.step(
                "Wallet WL-26..28: identities remain CAIP-10 and no wallet state is persisted",
                lambda: self._persistence_boundaries(
                    evm_login, solana_login, bitcoin_login, solana.account_id
                ),
            )

    def _challenge_contract(self, port: int, account_id: str) -> None:
        challenge = self._challenge(port, account_id)
        message = challenge["message"]
        expires_at = datetime.fromisoformat(challenge["expiresAt"].replace("Z", "+00:00"))
        remaining = (expires_at - datetime.now(timezone.utc)).total_seconds()
        markers = (
            f"{AUTHN_HOST}:8082",
            ANVIL_ACCOUNT_0_ADDRESS,
            "URI: http://e2e-authguard-authn.customer-growth.local:8082",
            "Version: 1",
            f"Chain ID: {EVM_OFFLINE_EOA_CHAIN_REFERENCE}",
            "Nonce:",
            "Issued At:",
            "Expiration Time:",
            f"Request ID: {challenge['challengeId']}",
        )
        if (
            challenge.get("accountId") != account_id
            or challenge.get("signatureEncoding") != "hex"
            or challenge.get("verificationMethods") != ["eoa"]
            or not 60 <= remaining <= 125
            or any(marker not in message for marker in markers)
        ):
            raise RuntimeError("wallet challenge lacks canonical SIWX authority fields")

        invalid_accounts = (
            "0xdeadbeef",
            f"cosmos:cosmoshub-4:{ANVIL_ACCOUNT_0_ADDRESS}",
            f"eip155:1:{ANVIL_ACCOUNT_0_ADDRESS}",
        )
        for invalid in invalid_accounts:
            status, payload = self.post(
                port, "/auth/wallet/challenge", {"accountId": invalid}
            )
            self.expect_error(status, payload, 400, "invalid_request")
        status, _ = self.post(
            port,
            "/auth/wallet/challenge",
            {
                "accountId": account_id,
                "rpcUrl": "https://attacker.invalid",
                "signatureValid": True,
            },
        )
        if status != 422:
            raise RuntimeError("client RPC/signatureValid injection was not rejected")

    def _evm_eoa(self, port: int, wallet: EvmWallet) -> AuthenticatedLogin:
        first = self._authenticate(
            port, wallet.account_id, wallet.sign, ["wallet", "siwx", "eoa"]
        )
        repeated = self._authenticate(
            port,
            wallet.account_id,
            wallet.sign,
            ["wallet", "siwx", "eoa"],
            expected_principal=first.principal_id,
        )
        if repeated.principal_id != first.principal_id:
            raise RuntimeError("repeated EVM possession proof created a second Principal")

        # A plain ERC-1271 signature is not self-describing. A wallet SDK may
        # provide this routing hint; it can only select a stricter verifier and
        # is never accepted as proof. Missing trusted RPC is therefore a
        # deterministic capability error, while auto mode remains fail-closed.
        offline_contract = self._challenge(
            port,
            f"eip155:{EVM_OFFLINE_EOA_CHAIN_REFERENCE}:"
            f"{ERC1271_VALIDATOR_CONTRACT_ADDRESS}",
        )
        status, payload = self._verify(
            port,
            offline_contract,
            "0x01",
            verification_method="erc1271",
        )
        self.expect_error(status, payload, 501, "contract_wallet_not_supported")
        replay_status, replay = self._verify(
            port,
            offline_contract,
            "0x01",
            verification_method="erc1271",
        )
        self.expect_error(replay_status, replay, 400, "invalid_request")

        # ERC-6492 is self-identifying through its magic suffix, so auto mode
        # can return the same precise capability error without trusting a hint.
        counterfactual = self._challenge(
            port,
            f"eip155:{EVM_OFFLINE_EOA_CHAIN_REFERENCE}:"
            f"{ERC6492_COUNTERFACTUAL_ACCOUNT_ADDRESS}",
        )
        status, payload = self._verify(
            port,
            counterfactual,
            "0x00" + "6492" * 16,
        )
        self.expect_error(status, payload, 501, "contract_wallet_not_supported")

        ambiguous = self._challenge(
            port,
            f"eip155:{EVM_OFFLINE_EOA_CHAIN_REFERENCE}:"
            f"{ERC1271_EMPTY_ACCOUNT_ADDRESS}",
        )
        status, payload = self._verify(port, ambiguous, "0x01")
        self.expect_error(status, payload, 401, "authentication_failed")

        # A trusted RPC mapping may exist for contract-wallet fallback, but a
        # valid EOA proof must return before that deliberately slow endpoint is
        # touched. This proves classification is local-first rather than
        # eth_getCode-first.
        rpc_configured_wallet = EvmWallet(
            f"eip155:{EVM_TIMEOUT_FAULT_CHAIN_REFERENCE}:{ANVIL_ACCOUNT_0_ADDRESS}"
        )
        challenge = self._challenge(port, rpc_configured_wallet.account_id)
        signature = rpc_configured_wallet.sign(challenge["message"])
        started = time.monotonic()
        status, payload = self._verify(port, challenge, signature)
        elapsed = time.monotonic() - started
        self.canonical_login(
            status,
            payload,
            expected_amr=["wallet", "siwx", "eoa"],
            expected_acr=WALLET_ACR,
        )
        if elapsed >= 1.5:
            raise RuntimeError(
                f"valid EOA verification appears to have called contract RPC ({elapsed:.2f}s)"
            )
        return first

    def _solana(
        self, authn_port: int, solana_rpc_port: int, wallet: SolanaWallet
    ) -> AuthenticatedLogin:
        # The validator anchors the account/reference fixture. AuthGuard itself
        # receives no Solana RPC and verifies the Ed25519 proof locally.
        if self._json_rpc(solana_rpc_port, "getHealth") != "ok":
            raise RuntimeError("local Solana validator is not healthy")
        airdrop = self._json_rpc(
            solana_rpc_port, "requestAirdrop", [wallet.address, 1_000_000]
        )
        if not isinstance(airdrop, str) or not airdrop:
            raise RuntimeError("local Solana validator rejected the test airdrop")
        deadline = time.monotonic() + 20
        balance = 0
        while time.monotonic() < deadline:
            response = self._json_rpc(
                solana_rpc_port,
                "getBalance",
                [wallet.address, {"commitment": "processed"}],
            )
            balance = response.get("value", 0) if isinstance(response, dict) else 0
            if isinstance(balance, int) and balance > 0:
                break
            time.sleep(0.25)
        if not isinstance(balance, int) or balance <= 0:
            raise RuntimeError("local Solana validator did not fund the test account")
        return self._authenticate(
            authn_port,
            wallet.account_id,
            wallet.sign,
            ["wallet", "siwx", "solana"],
        )

    def _bitcoin(self, port: int, wallet: BitcoinWallet) -> AuthenticatedLogin:
        simple = self._authenticate(
            port,
            wallet.account_id,
            lambda message: wallet.sign(message, full=False),
            ["wallet", "siwx", "bitcoin"],
        )
        full = self._authenticate(
            port,
            wallet.account_id,
            lambda message: wallet.sign(message, full=True),
            ["wallet", "siwx", "bitcoin"],
            expected_principal=simple.principal_id,
        )
        challenge = self._challenge(port, wallet.account_id)
        status, payload = self.post(
            port,
            "/auth/wallet/verify",
            {"challengeId": challenge["challengeId"], "signature": "pof-not-a-psbt"},
        )
        self.expect_error(status, payload, 401, "authentication_failed")
        return full

    def _replay_contract(
        self, port: int, wallet: EvmWallet, principal_id: str
    ) -> None:
        invalid = self._challenge(port, wallet.account_id)
        wrong_signature = wallet.sign(
            invalid["message"], ANVIL_ACCOUNT_1_PRIVATE_KEY
        )
        status, payload = self._verify(port, invalid, wrong_signature)
        self.expect_error(status, payload, 401, "authentication_failed")
        status, payload = self._verify(port, invalid, wallet.sign(invalid["message"]))
        self.expect_error(status, payload, 400, "invalid_request")

        concurrent = self._challenge(port, wallet.account_id)
        signature = wallet.sign(concurrent["message"])
        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = list(
                executor.map(lambda _: self._verify(port, concurrent, signature), range(2))
            )
        successes = [(status, body) for status, body in responses if status == 200]
        failures = [(status, body) for status, body in responses if status != 200]
        if len(successes) != 1 or len(failures) != 1:
            raise RuntimeError(f"wallet challenge was not atomically consumed: {responses}")
        self.canonical_login(
            *successes[0],
            expected_amr=["wallet", "siwx", "eoa"],
            expected_acr=WALLET_ACR,
            expected_principal_id=principal_id,
        )
        self.expect_error(failures[0][0], failures[0][1], 400, "invalid_request")

        malformed = self._challenge(port, wallet.account_id)
        status, payload = self._verify(port, malformed, "0xnot-hex")
        self.expect_error(status, payload, 400, "invalid_request")
        oversized = self._challenge(port, wallet.account_id)
        status, payload = self._verify(port, oversized, "0" * 262_145)
        self.expect_error(status, payload, 400, "invalid_request")

    def _contract_wallets(self, authn_port: int, anvil_rpc_port: int) -> None:
        chain_id = self._json_rpc(anvil_rpc_port, "eth_chainId")
        if chain_id != hex(int(EVM_ANVIL_CONTRACT_CHAIN_REFERENCE)):
            raise RuntimeError(f"unexpected Anvil chain id: {chain_id!r}")

        erc1271 = (
            f"eip155:{EVM_ANVIL_CONTRACT_CHAIN_REFERENCE}:"
            f"{ERC1271_VALIDATOR_CONTRACT_ADDRESS}"
        )
        challenge = self._challenge(authn_port, erc1271)
        if challenge["verificationMethods"] != ["eoa", "erc1271", "erc6492"]:
            raise RuntimeError("RPC-backed chain did not advertise contract verification")
        self._install_erc1271_validator(
            anvil_rpc_port, EvmWallet.message_hash(challenge["message"])
        )
        code = self._json_rpc(
            anvil_rpc_port,
            "eth_getCode",
            [ERC1271_VALIDATOR_CONTRACT_ADDRESS, "latest"],
        )
        if not isinstance(code, str) or code == "0x":
            raise RuntimeError("real ERC-1271 validator bytecode was not installed on Anvil")
        status, payload = self._verify(
            authn_port, challenge, "0x01", verification_method="erc1271"
        )
        contract_login = self.canonical_login(
            status,
            payload,
            expected_amr=["wallet", "siwx", "erc1271"],
            expected_acr=WALLET_ACR,
        )
        replay_status, replay = self._verify(authn_port, challenge, "0x01")
        self.expect_error(replay_status, replay, 400, "invalid_request")

        # Acceptance binds the exact server-authored SIWX hash rather than
        # returning the ERC-1271 magic value for arbitrary input.
        tampered = self._challenge(authn_port, erc1271)
        self._install_erc1271_validator(
            anvil_rpc_port, EvmWallet.message_hash(tampered["message"] + "tampered")
        )
        status, payload = self._verify(authn_port, tampered, "0x01")
        self.expect_error(status, payload, 401, "authentication_failed")

        rejected = self._challenge(
            authn_port,
            f"eip155:{EVM_ANVIL_CONTRACT_CHAIN_REFERENCE}:"
            f"{ERC1271_EMPTY_ACCOUNT_ADDRESS}",
        )
        status, payload = self._verify(authn_port, rejected, "0x01")
        self.expect_error(status, payload, 401, "authentication_failed")

        # ERC-6492 remains an extension point: a tagged but invalid
        # counterfactual proof must reach trusted Anvil and fail closed.
        counterfactual = self._challenge(
            authn_port,
            f"eip155:{EVM_ANVIL_CONTRACT_CHAIN_REFERENCE}:"
            f"{ERC6492_COUNTERFACTUAL_ACCOUNT_ADDRESS}",
        )
        status, payload = self._verify(
            authn_port, counterfactual, "0x00" + "6492" * 16
        )
        self.expect_error(status, payload, 401, "authentication_failed")

        timeout = self._challenge(
            authn_port,
            f"eip155:{EVM_TIMEOUT_FAULT_CHAIN_REFERENCE}:"
            f"{ERC1271_VALIDATOR_CONTRACT_ADDRESS}",
        )
        status, payload = self._verify(authn_port, timeout, "0x01")
        self.expect_error(status, payload, 503, "service_unavailable")
        if not contract_login.principal_id:
            raise RuntimeError("ERC-1271 login did not resolve a canonical Principal")

    def _install_erc1271_validator(self, rpc_port: int, message_hash: str) -> None:
        digest = message_hash.removeprefix("0x")
        if len(digest) != 64:
            raise RuntimeError(f"invalid EIP-191 digest: {message_hash!r}")
        # Runtime implements isValidSignature(bytes32,bytes): accept only this
        # digest plus one-byte fixture signature 0x01.
        runtime = (
            "0x6004357f"
            + digest
            + "1460643560f81c60011416604257"
            + "63ffffffff60e01b60005260206000f3"
            + "5b631626ba7e60e01b60005260206000f3"
        )
        result = self._json_rpc(
            rpc_port,
            "anvil_setCode",
            [ERC1271_VALIDATOR_CONTRACT_ADDRESS, runtime],
        )
        # Anvil 1.7 returns JSON null; older releases returned true.
        if result is not None and result is not True:
            raise RuntimeError(f"Anvil rejected ERC-1271 fixture bytecode: {result!r}")

    def _link_contract(
        self,
        port: int,
        standalone: StandaloneFixture,
        evm: EvmWallet,
        solana_reference: str,
    ) -> None:
        candidate = SolanaWallet.create(solana_reference)
        challenge = self._challenge(port, candidate.account_id)
        proof = candidate.sign(challenge["message"])
        status, payload = self._verify(port, challenge, proof, link=True)
        self.expect_error(status, payload, 401, "authentication_failed")
        challenge = self._challenge(port, candidate.account_id)
        proof = candidate.sign(challenge["message"])
        status, payload = self._verify(
            port, challenge, proof, link=True, bearer=standalone.access_token
        )
        linked = self.canonical_login(
            status,
            payload,
            expected_amr=["wallet", "siwx", "solana"],
            expected_acr=WALLET_ACR,
            expected_principal_id=standalone.principal_id,
        )
        login = self._authenticate(
            port,
            candidate.account_id,
            candidate.sign,
            ["wallet", "siwx", "solana"],
            expected_principal=linked.principal_id,
        )
        if login.principal_id != standalone.principal_id:
            raise RuntimeError("linked wallet did not resolve to the canonical Principal")

        conflicting = self._challenge(port, evm.account_id)
        status, payload = self._verify(
            port,
            conflicting,
            evm.sign(conflicting["message"]),
            link=True,
            bearer=standalone.access_token,
        )
        self.expect_error(status, payload, 409, "conflict")

    def _persistence_boundaries(
        self,
        evm: AuthenticatedLogin,
        solana: AuthenticatedLogin,
        bitcoin: AuthenticatedLogin,
        solana_account_id: str,
    ) -> None:
        if len({evm.principal_id, solana.principal_id, bitcoin.principal_id}) != 3:
            raise RuntimeError("unlinked CAIP accounts auto-merged across chain namespaces")
        rows = self.postgres_scalar(
            "SELECT provider || '|' || issuer || '|' || subject || '|' || claims::text "
            "FROM iam_principal_identity WHERE provider='wallet' ORDER BY subject;"
        ).splitlines()
        if not rows or any(not row.startswith("wallet|caip-122|") for row in rows):
            raise RuntimeError(f"wallet ExternalIdentity persistence is non-canonical: {rows}")
        subjects = [row.split("|", 3)[2] for row in rows]
        if EvmWallet().account_id not in subjects or BitcoinWallet.account_id not in subjects:
            raise RuntimeError("CAIP-10 EVM/Bitcoin subjects were not stored verbatim")
        if solana_account_id not in subjects:
            raise RuntimeError("CAIP-10 Solana subject was not stored verbatim")
        if any(row.rsplit("|", 1)[-1] != "{}" for row in rows):
            raise RuntimeError("wallet signature or transport metadata leaked into identity claims")
        if self.postgres_scalar(
            "SELECT COUNT(*) FROM iam_standalone_credential c JOIN iam_principal_identity i "
            "ON (i.provider,i.issuer,i.subject)=(c.identity_provider,c.identity_issuer,c.identity_subject) "
            "WHERE i.provider='wallet';"
        ) != "0":
            raise RuntimeError("wallet possession was incorrectly persisted as a credential")
        if self.postgres_scalar(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='authguard' "
            "AND (table_name LIKE '%wallet%' OR table_name LIKE '%challenge%');"
        ) != "0":
            raise RuntimeError("wallet/challenge state created a forbidden long-lived table")

    def _challenge(self, port: int, account_id: str) -> dict[str, Any]:
        status, challenge = self.post(
            port, "/auth/wallet/challenge", {"accountId": account_id}
        )
        if status != 200:
            raise RuntimeError(f"wallet challenge failed: HTTP {status}/{challenge}")
        required = {
            "challengeId",
            "accountId",
            "message",
            "expiresAt",
            "signatureEncoding",
            "verificationMethods",
        }
        if set(challenge) != required or challenge["accountId"] != account_id:
            raise RuntimeError(f"wallet challenge schema mismatch: {challenge}")
        return challenge

    def _authenticate(
        self,
        port: int,
        account_id: str,
        signer,
        expected_amr: list[str],
        *,
        expected_principal: str | None = None,
    ) -> AuthenticatedLogin:
        challenge = self._challenge(port, account_id)
        status, payload = self._verify(port, challenge, signer(challenge["message"]))
        authenticated = self.canonical_login(
            status,
            payload,
            expected_amr=expected_amr,
            expected_acr=WALLET_ACR,
            expected_principal_id=expected_principal,
        )
        replay_status, replay = self._verify(
            port, challenge, signer(challenge["message"])
        )
        self.expect_error(replay_status, replay, 400, "invalid_request")
        return authenticated

    def _verify(
        self,
        port: int,
        challenge: dict[str, Any],
        signature: str,
        *,
        link: bool = False,
        bearer: str | None = None,
        verification_method: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        body = {"challengeId": challenge["challengeId"], "signature": signature}
        if verification_method is not None:
            body["verificationMethod"] = verification_method
        return self.post(
            port,
            "/auth/wallet/link" if link else "/auth/wallet/verify",
            body,
            bearer=bearer,
        )

    def _solana_reference(self, rpc_port: int) -> str:
        genesis_hash = self._json_rpc(rpc_port, "getGenesisHash")
        if not isinstance(genesis_hash, str) or len(genesis_hash) < 32:
            raise RuntimeError(f"invalid local Solana genesis hash: {genesis_hash!r}")
        return genesis_hash[:32]

    @staticmethod
    def _json_rpc(port: int, method: str, params: list[Any] | None = None) -> Any:
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
        ).encode()
        outgoing = request.Request(
            f"http://127.0.0.1:{port}",
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with request.urlopen(outgoing, timeout=15) as response:
            body = json.loads(response.read())
        if not isinstance(body, dict) or "error" in body or "result" not in body:
            raise RuntimeError(f"JSON-RPC {method} failed: {body}")
        return body["result"]
