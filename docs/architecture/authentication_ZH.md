# 统一认证架构

AuthGuard AuthN 的协议实现彼此隔离，统一点只有已验证的瞬态结果：

```text
OAuth/OIDC ───────────────┐
Password/TOTP/WebAuthn ───┼─> AuthenticationResult
CAIP/SIWX wallet ─────────┘          |
                              Account Linking
                                    |
                          Canonical Principal
                                    |
                         Unified AuthGuard JWT
                                    |
                         Envoy PEP -> AuthZ PDP
```

`AuthenticationResult` 记录本次证明方式（`amr`、`acr`、`authenticated_at`）；
`ExternalIdentity` 只记录被证明的身份；`Principal` 是协议无关的内部主体；AuthZ 只使用
canonical `principal_id`，不接收密码、OTP、email login、上游 token、WebAuthn assertion、
wallet signature 或 CAIP account。

## 存储

本次只增加一张长期表 `iam_standalone_credential`：

- `password`：`credential_key` 是可变 login identifier，`secret_data` 是 Argon2id PHC；
- `totp`：RFC 6238 secret 以 AES-256-GCM 加密，JSON 数据保存原子递增的
  `lastCounter`；
- `webauthn`：Passkey、安全密钥、平台认证器均为同一种 WebAuthn credential，保存
  credential ID、public key、counter 与标准元数据。

OAuth state、TOTP enrollment、WebAuthn registration/authentication 和 SIWX nonce 均在
Redis 中使用短 TTL，并通过 `GETDEL` 原子单次消费。`AuthenticationResult` 不持久化。
Wallet 只形成 `provider=wallet`、`subject=<CAIP-10>` 的 ExternalIdentity，不增加表。

## HTTP API

OAuth/OIDC：

- `GET /auth/oauth2/{provider}/authorize`
- `POST /auth/oauth2/{provider}/link`
- `GET /auth/oauth2/{provider}/callback`
- `POST /auth/oauth2/{provider}/token-exchange`

Standalone canonical 路径为 `/auth/standalone/...`；同时注册面向客户端的短路径：

- register/login：`/auth/standalone/register`、`/auth/standalone/login`，以及
  `/auth/register`、`/auth/login`；
- TOTP：`/auth/standalone/totp/{challenge|verify}`，以及
  `/auth/totp/{challenge|verify}`；
- WebAuthn：`/auth/standalone/webauthn/{register|authenticate}/{challenge|verify}`，以及
  `/auth/webauthn/{register|authenticate}/{challenge|verify}`。

Wallet：

- `POST /auth/wallet/challenge`
- `POST /auth/wallet/verify`
- `POST /auth/wallet/link`

显式 link 先验证当前 AuthGuard JWT；待绑定的 OAuth 或 wallet 身份仍必须独立完成
OAuth callback 或 SIWX 签名，不能依赖 email、ENS、display name、NFT metadata 或客户端
返回的 `signatureValid`。

## CAIP/SIWX 与链 verifier

CAIP-2/CAIP-10 统一链与账户命名，CAIP-122/SIWX 统一 message、domain、URI、nonce、
issued-at、expiry 和 account/chain binding；它不统一各链密码学。因此 verifier 仍保持
高内聚：

- EVM：EIP-191 EOA，以及通过服务器可信 RPC mapping 验证 ERC-1271/6492；RPC 有超时并
  fail closed，客户端不能提交 RPC URL；
- Solana：Ed25519 public-key signature；
- Bitcoin：Bitcoin Signed Message/address/network 逻辑。当前实现支持 recoverable
  P2PKH message signature；BIP-322 地址类型扩展保留在 Bitcoin verifier 内。

这些差异不会进入 Account Linking、Principal、JWT 或 AuthZ。WalletConnect/Reown 只可
作为客户端 discovery/transport/signing UX，服务端不保存 session topic、relay metadata、
wallet brand，且从不接触私钥或 seed。

## 可选 Web3 构建

Wallet 及其所有 Web3 依赖位于 Cargo feature `web3` 下。基础构建默认不包含该 feature，因而不会编译 Bitcoin、EVM、Solana 或 SIWX 相关 crate 和源码模块：

```bash
cargo build -p authguard-cmd --features web3

# 构建包含 wallet verifier 的镜像；不传 build-arg 时仍是无 Web3 基础镜像。
docker build -f deploy/docker/Dockerfile \
  --build-arg AUTHGUARD_CARGO_FEATURES=web3 .
```

基础构建保持 Rust 1.88+；当前 `web3` 依赖链要求 Rust 1.91+。

受限制的传统金融构建可直接使用默认 feature 集合，完全排除 Web3 crates 和源码模块：

```bash
cargo build -p authguard-cmd
```

若无 `web3` feature 的二进制收到 `authn.wallet.enabled=true`，进程会在启动时明确失败，
不会静默暴露未实现的 wallet route。
