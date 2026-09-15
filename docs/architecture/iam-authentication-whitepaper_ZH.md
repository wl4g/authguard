# AuthGuard IAM 认证白皮书

## 1. 目标与边界

AuthGuard AuthN 将多种身份协议收敛为同一个认证结果、Principal 和 JWT，同时保持：

```text
Authentication != ExternalIdentity != Principal != Authorization
```

AuthN 是认证 authority 和 token issuer；Envoy 是请求路径 PEP；AuthGuard AuthZ 是 PDP。
AuthN 不充当 reverse proxy，AuthZ 不解析 OAuth、密码、WebAuthn、SIWX 或钱包地址。

## 2. 统一抽象

```rust
struct AuthenticationResult {
    external_identity: ExternalIdentity,
    amr: Vec<String>,
    acr: Option<String>,
    authenticated_at: DateTime<Utc>,
}
```

`ExternalIdentity` 只描述“是谁”；`AuthenticationResult` 描述“本次如何证明”；
`Principal` 是内部稳定主体；Authorization 只使用 `principal_id/resource/action/context`。

```text
OAuth/OIDC ───────────────┐
Password/TOTP/WebAuthn ───┼─> AuthenticationResult
CAIP/SIWX Wallet ─────────┘           |
                                Account Linking
                                      |
                              Canonical Principal
                                      |
                              Unified AuthGuard JWT
                                      |
                              Envoy PEP -> AuthZ PDP
```

所有协议只在 `AuthenticationResult` 之后统一。JWT 的 `sub` 永远是 canonical
`principal_id`，并统一包含 `amr`、`acr`、`auth_time`、`iat`、`exp`。

## 3. Provider 体系

- OAuth/OIDC：配置化 adapter 负责上游 token 和身份规范化。
- Standalone：Argon2id password、RFC 6238 TOTP、WebAuthn/Passkey 各自封装；email 只是
  login identifier，稳定 subject 是随机 `local_*` ID。
- Wallet：CAIP-2/CAIP-10 规范身份，CAIP-122/SIWX 规范 challenge；EVM、Solana、Bitcoin
  verifier 仅处理各自密码学。

AMR 由实际证明方式产生：`["pwd"]`、`["pwd","otp"]`、`["webauthn"]`、
`["wallet","siwx","eoa|erc1271|erc6492|solana|bitcoin"]`。

CAIP 无法消除底层密码学差异：EVM 支持 EIP-191、ERC-1271/6492；Solana 使用
Ed25519；Bitcoin 支持 BIP-322 simple/full/proof-of-funds 及受限 P2PKH legacy fallback。
链逻辑不会进入 linking、Principal、JWT 或 AuthZ。

## 4. 状态、凭据与账号绑定

长期新增表仅有 `iam_standalone_credential`：

- `password`：Argon2id PHC hash；
- `totp`：AES-256-GCM 加密 secret 和原子递增 `lastCounter`；
- `webauthn`：credential ID、public key、counter 与标准元数据。

OAuth state、TOTP enrollment、WebAuthn ceremony 和 SIWX nonce 都通过通用 `ICache`
保存，使用短 TTL、`put-if-absent` 和原子 `take`。AuthN 不依赖 Redis API；Redis 只是
当前生产 cache adapter。`AuthenticationResult`、wallet proof 和 challenge 均不入库。

Account Linking 仅接受已验证的 `ExternalIdentity`，支持 first-login 和 explicit-link；
禁止按 email、ENS、display name、NFT metadata 或 WalletConnect accounts 自动合并。

## 5. HTTP 契约

```text
GET  /auth/oauth2/{provider}/authorize
POST /auth/oauth2/{provider}/link
GET  /auth/oauth2/{provider}/callback
POST /auth/oauth2/{provider}/token-exchange

POST /auth/standalone/register       POST /auth/register
POST /auth/standalone/login          POST /auth/login
POST /auth/standalone/totp/...       POST /auth/totp/...
POST /auth/standalone/webauthn/...   POST /auth/webauthn/...

POST /auth/wallet/challenge
POST /auth/wallet/verify
POST /auth/wallet/link
GET  /.well-known/authn.json
```

公开 metadata 只暴露已启用能力、provider ID、CAIP chain 与 endpoint，不暴露 secret 或
RPC URL。WalletConnect/Reown 仅用于浏览器 discovery/transport/signing UX；服务端不保存
其 session、relay 或 wallet brand，也不信任客户端 `signatureValid`。

EVM challenge 返回 `verificationMethods`；`/verify` 接受可选的
`verificationMethod=auto|eoa|erc1271|erc6492` 路由提示，但该提示绝不作为身份证明。
有效 EIP-191 始终本地验签；ERC-6492 可通过 magic suffix 离线识别；普通 ERC-1271
proof 不具备自描述性，已知账号类型的钱包客户端应在 chain 宣告支持时提交 `erc1271`。
可识别/显式请求的合约 proof 若未配置 RPC 返回 `501 contract_wallet_not_supported`；
已配置但不可用返回 `503`；无效或无法分类的 proof 仍返回 `401`。

## 6. 配置

```yaml
authn:
  challengeTtl: 5m
  token:
    issuer: authguard
    audience: authguard-services
    ttl: 1h
    privateKey: ${AUTHGUARD_TOKEN_PRIVATE_KEY}
  standalone:
    enabled: true
    issuer: authguard:standalone
    credentialEncryptionKey: ${AUTHGUARD_CREDENTIAL_KEY}
    totp: { enabled: true, issuer: AuthGuard }
    webauthn:
      enabled: true
      rpId: auth.example.com
      rpOrigin: https://auth.example.com
      rpName: AuthGuard
  wallet:
    enabled: true
    domain: auth.example.com
    uri: https://auth.example.com
    chains:
      eip155:
        "1": {} # EOA 本地验签，无节点依赖
        "31337": { rpc: "${EVM_CONTRACT_RPC}" } # 仅合约钱包
      solana: [mainnet]
      bip122:
        000000000019d6689c085ae165831e93: { network: bitcoin-mainnet }

cache:
  provider: Redis
  redis:
    nodes: [redis://redis-0:6379]
```

EOA、Solana、Bitcoin 均本地验签且不连接节点；只有 ERC-1271/后续 ERC-6492 合约验证
使用服务器受信 RPC mapping。Wallet 及其依赖位于 Cargo `web3` feature；默认构建完全
排除 Web3 crates，配置启用 wallet 但二进制未编译 `web3` 时启动失败。

## 7. 模块边界与扩展

```text
src/authn/src/
  authentication/     通用 challenge 序列化与统一 JWT
  provider/
    base/              OAuth2-like normalization/base adapter
    standalone/        password、TOTP、WebAuthn 协议实现
    wallet/            CAIP/SIWX 与 EVM/Solana/Bitcoin verifier
  handler/             HTTP orchestration、repository 与 runtime
  principal/           JIT、identity linking 与 canonical Principal 解析
  route/               稳定 URI 映射
  lib.rs, server.rs    公共导出与进程生命周期
```

新增协议应实现独立、高内聚 provider，验证成功后返回 `AuthenticationResult`；不得新增
平行 linking/token pipeline。WebAuthn authenticator、同步 Passkey 和安全密钥继续使用
`kind=webauthn`；ERC-6492 和后续链 verifier 通过 wallet provider 内部扩展。
