# AuthGuard IAM Authentication Whitepaper

## 1. Goals and boundaries

AuthGuard AuthN converges multiple identity protocols on one authentication result, Principal,
and JWT while preserving:

```text
Authentication != ExternalIdentity != Principal != Authorization
```

AuthN is the authentication authority and token issuer, Envoy is the request-path PEP, and
AuthGuard AuthZ is the PDP. AuthN is not a reverse proxy, and AuthZ never parses OAuth,
password, WebAuthn, SIWX, or wallet identifiers.

## 2. Unified abstraction

```rust
struct AuthenticationResult {
    external_identity: ExternalIdentity,
    amr: Vec<String>,
    acr: Option<String>,
    authenticated_at: DateTime<Utc>,
}
```

`ExternalIdentity` identifies who was proven; `AuthenticationResult` records how it was proven;
`Principal` is the stable internal subject; Authorization consumes only
`principal_id/resource/action/context`.

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

Protocols converge only after `AuthenticationResult`. JWT `sub` is always the canonical
`principal_id`, with common `amr`, `acr`, `auth_time`, `iat`, and `exp` claims.

## 3. Provider system

- OAuth/OIDC adapters validate upstream tokens and normalize identities.
- Standalone providers isolate Argon2id password, RFC 6238 TOTP, and WebAuthn/Passkey. Email is
  only a login identifier; a random `local_*` value is the stable subject.
- Wallet uses CAIP-2/CAIP-10 for identity and CAIP-122/SIWX for challenges, while EVM, Solana,
  and Bitcoin verifiers own their cryptographic differences.

AMR reflects the proof actually used: `["pwd"]`, `["pwd","otp"]`, `["webauthn"]`, or
`["wallet","siwx","eoa|erc1271|erc6492|solana|bitcoin"]`.

CAIP cannot remove cryptographic differences. EVM supports EIP-191 and ERC-1271/6492, Solana
uses Ed25519, and Bitcoin supports BIP-322 simple/full/proof-of-funds plus a restricted P2PKH
legacy fallback. Chain logic never reaches linking, Principal, JWT, or AuthZ.

## 4. State, credentials, and linking

The only added durable table is `iam_standalone_credential`:

- `password`: Argon2id PHC hash;
- `totp`: AES-256-GCM encrypted secret and atomically increasing `lastCounter`;
- `webauthn`: credential ID, public key, counter, and standard metadata.

OAuth state, TOTP enrollment, WebAuthn ceremonies, and SIWX nonces use the generic `ICache`
contract with short TTL, put-if-absent, and atomic take. AuthN does not depend on Redis APIs;
Redis is the current production cache adapter. `AuthenticationResult`, wallet proofs, and
challenges are never persisted.

Account Linking accepts only verified `ExternalIdentity` values and supports first-login and
explicit-link. Email, ENS, display names, NFT metadata, and WalletConnect accounts are never
automatic merge keys.

Canonical Principal IDs remain bounded opaque strings because they cross JWT `sub`, SCIM, HTTP,
SDK, and AuthZ boundaries. PostgreSQL stores `TEXT` and unconstrained `VARCHAR` with the same
varlena representation and B-tree behavior; SQLite gives both TEXT affinity. At million-Principal
scale, the primary/unique indexes on Principal ID, `(provider, issuer, subject)`, and credential
keys determine login lookup performance, not changing `TEXT` to `VARCHAR`.

## 5. HTTP contract

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

### Hosted Login

`GET /auth/login`, authenticated `GET /auth/account/security`, and
`GET /auth/assets/*` are the only AuthGuard Web routes that a relying application
needs. `/.well-known/*` and the remaining `/auth/*` remain AuthN
routes. A trusted `authn.applications` entry resolves the Gateway-preserved
Host to an `application_id`, display name, logo, static Theme Pack, and HTTPS
`returnUris` allow list. The Hosted Login reads `/.well-known/authn.json`, renders that brand, and
submits the existing Password/TOTP, WebAuthn, OAuth, and Wallet endpoints.

Theme Packs are same-origin CSS and static assets under `/auth/assets/themes/`.
They can override presentation variables and layout selectors but cannot inject
HTML or JavaScript. A business umbrella Chart may package its local asset
directory into a ConfigMap while the AuthGuard tgz and Web image remain
immutable. An Application without `logo` or `theme` still receives its
Host-resolved display name and falls back to the built-in AuthGuard mark and
cyan trust-fabric CSS without an asset mount. WebAuthn enrollment is absent from the unauthenticated login
page: Account Security requires a canonical Principal cookie plus password/TOTP
step-up and verifies both proofs resolve to the same Principal.

`return_to` accepts a configured same-host URI or a safe relative path. AuthN
normalizes successful values to a path, stores the unified JWT in an
`HttpOnly; Secure; SameSite=Lax` cookie, and redirects (OAuth) or returns the
safe path (browser API flows). No SDK, iframe, token localStorage, or business
copy of wallet/WebAuthn/OAuth logic is required. The AuthGuard Console is a
separate UI route and always uses the AuthGuard brand.

Gateway uses one listener for the relying application and AuthGuard public
paths. Its SecurityPolicy targets only business `HTTPRoute` objects labelled
`authguard.io/protected: "true"`; route specificity keeps `/auth/login`,
`/auth/assets/*`, `/.well-known/*`, and `/auth/*` public without a second
origin or listener.

Public metadata exposes enabled capabilities, provider IDs, CAIP chains, and endpoints only;
it never exposes secrets or RPC URLs. WalletConnect/Reown is browser-side discovery,
transport, and signing UX. The server stores no vendor session, relay metadata, or wallet
brand and never trusts client-side `signatureValid`.

An EVM challenge returns `verificationMethods`. `/verify` accepts an optional
`verificationMethod=auto|eoa|erc1271|erc6492` routing hint; the hint never proves identity.
A valid EIP-191 proof is always verified locally. ERC-6492 is recognized by its magic suffix.
Plain ERC-1271 is not self-describing, so an informed wallet client should send `erc1271` when
the chain advertises it. A recognizable/requested contract proof without configured RPC returns
`501 contract_wallet_not_supported`; a configured but unavailable RPC returns `503`, and an
invalid or ambiguous proof remains `401`.

## 6. Configuration

```yaml
authn:
  challengeTtl: 5m
  applications:
    example-app:
      hosts: [app.example.com]
      displayName: Example App
      logo: /auth/assets/branding/example-app.svg
      theme:
        id: example-app
        stylesheet: /auth/assets/themes/custom/example-app.css
      returnUris: [https://app.example.com/**]
  token:
    issuer: authguard
    audience: authguard-services
    ttl: 1h
    privateKeyB64: "${AUTHGUARD__AUTHN__TOKEN__PRIVATE_KEY_B64}"
  standalone:
    enabled: true
    issuer: authguard:standalone
    credentialEncryptionKey: "${AUTHGUARD__AUTHN__STANDALONE__CREDENTIAL_ENCRYPTION_KEY}"
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
        "1": {} # offline EOA verification; no node dependency
        "31337": { rpc: "${EVM_CONTRACT_RPC}" } # contract wallets only
      solana: [mainnet]
      bip122:
        000000000019d6689c085ae165831e93: { network: bitcoin-mainnet }

cache:
  provider: Redis
  redis:
    nodes: [redis://redis-0:6379]
```

EOA, Solana, and Bitcoin signatures verify locally without a node. Only ERC-1271 and future
ERC-6492 contract verification uses a server-trusted RPC mapping. Wallet code and dependencies
are behind the Cargo `web3` feature; default builds exclude all Web3 crates. Enabling wallet
configuration in a binary built without `web3` fails during startup.

## 7. Module boundaries and extension

```text
src/authn/src/
  authentication/     shared challenge serialization and unified JWT
  provider/
    base/              OAuth2-like normalization and base adapter
    standalone/        password, TOTP, and WebAuthn protocols
    wallet/            CAIP/SIWX and EVM/Solana/Bitcoin verifiers
  handler/             HTTP orchestration, repositories, and runtime
  principal/           JIT, identity linking, and canonical Principal resolution
  route/               stable URI mappings
  lib.rs, server.rs    public exports and process lifecycle
```

New protocols add cohesive providers that return `AuthenticationResult`; they must not add a
parallel linking or token pipeline. Platform authenticators, synced passkeys, and security keys
remain `kind=webauthn`. ERC-6492 and future chain verifiers extend only the wallet provider.
