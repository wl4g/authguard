# AuthGuard：统一认证与资源级鉴权架构白皮书

## 1. 产品定位

AuthGuard 是一个独立、统一、通用、高性能的企业级/互联网认证鉴权产品，内置集成 Envoy Gateway。产品正式收敛为两个核心模块：

- `authguard-authn`：认证、外部身份规范化、账号绑定；
- `authguard-authz`：稳定 Principal 上的资源级授权。

默认部署拓扑只有：

```text
Envoy Gateway
authguard-authn
authguard-authz
```

Keycloak、Entra、Okta、GitHub、WeChat、Corporate DSP 等都属于外部身份系统或外部认证平台。AuthGuard 可以集成它们，但不把其中任何一个变成运行时依赖。

产品边界可概括为：

> Envoy owns the edge. AuthGuard AuthN authenticates and normalizes external identities, including account linking. AuthGuard AuthZ authorizes one stable canonical Principal. External IdPs remain external.

## 2. 明确不做什么

本设计不引入：

- Keycloak 默认部署或运行时依赖；
- AuthGuard Kubernetes CRD、Controller 或 Operator；
- Lua/Wasm 实现 OAuth 登录协议；
- 为 GitHub、WeChat 等 Provider patch Envoy；
- 复杂认证 DSL；
- AuthZ 中的 Provider-specific 登录逻辑；
- 基于 email 相同的自动账号绑定。

AuthGuard 不重新实现 API Gateway，也不把业务资源复制进 IAM 核心。

## 3. 组件职责

### 3.1 Envoy Gateway：统一入口与 PEP

Envoy Gateway 负责：

- 所有 Biz UI 登录请求、callback 与业务请求的统一入口；
- 路由、TLS、流量策略和请求边界；
- 标准 OIDC/JWT 的原生能力；
- 热路径中的 `jwt_authn → ext_authz(authguard-authz)`；
- 删除客户端伪造的 AuthGuard 内部身份头。

对于已经由 AuthN 签发 canonical session/token 的请求，Envoy 验证签名、issuer、audience 与有效期，再把受信 token 交给 AuthZ。AuthZ 不重复实现 OAuth 或 Provider 协议。

对于标准 OIDC，Envoy Gateway 原生 OIDC/JWT 能力优先处理标准重定向和 token 验证；AuthN 只负责把已验证的外部身份映射成 canonical Principal。对于 GitHub、WeChat、DSP 等非标准或 OAuth2-like Provider，Envoy 仍然拥有入口，协议差异集中在 AuthN。

### 3.2 authguard-authn：Authentication / Identity Provider Adapter Engine

AuthN 负责：

- `authorize` 请求构造；
- callback 与 state/PKCE/session 边界；
- authorization code 的 token exchange；
- 可选 identity/userinfo 查询；
- stable subject 提取；
- claims normalization；
- `ExternalIdentity` 生成；
- identity binding lookup；
- Account Linking；
- canonical Principal Context 输出。

不同 Provider 可以有以下差异：

- token exchange 使用 GET 或 POST；
- client credential 位于 header、body 或 query；
- token response 是不同 JSON 结构；
- subject 是 `sub`、GitHub `id`、WeChat `unionid/openid` 或企业工号；
- 需要额外 userinfo/identity API；
- 企业 DSP 需要 token translation；
- 特殊错误码、签名或参数约定。

这些差异优先通过有限、直观的 YAML 配置表达；无法优雅配置的企业协议通过最小 Provider SPI 实现。

### 3.3 authguard-authz：纯授权内核

AuthZ 负责：

- canonical Principal 的授权侧物化；
- `USER`、`WORKLOAD`、`GROUP`；
- `RoleBinding`、`Role`、`Action`；
- Resource URN 与父资源；
- Conditions；
- `ALLOW` / `DENY`，且显式 `DENY` 优先；
- Authorization Scope 与业务访问上下文；
- 可选 Principal federation/discovery 的管理面集成。

AuthZ 不处理：

- OAuth callback 或 token exchange；
- password、LDAP bind 登录；
- GitHub `/user`；
- WeChat userinfo；
- DSP AMTOKEN/token translation；
- 登录 session；
- account linking；
- Provider access token 或 authorization code。

Keycloak/LDAP/SCIM discovery 可以继续作为 AuthZ 管理面集成能力，用于搜索和物化授权对象，但物化请求必须携带 AuthN 已解析的 `principal_id`。这些 connector 不参与 AuthZ 热路径，也不把 `(issuer, subject)` 重新定义成 Principal。

SCIM 采用 HTTP push 边界。SCIM 定义的是 HTTP 资源供应协议，并未定义 WebSocket 或 long-poll 推送通道。若上游 IdP 无法主动推送，应由独立 connector/reconciliation agent 轮询 IdP，再把标准化的 SCIM event 推送给 AuthGuard；AuthZ 不承担通用 discovery 定时刷新任务。

## 4. Principal 与 ExternalIdentity

### 4.1 两个模型必须分离

```text
ExternalIdentity
----------------
provider
issuer
subject
claims
        │
        │ account linking / identity binding
        ▼
Principal
---------
internal stable principal_id
USER / WORKLOAD / GROUP
status
authorization state
```

`ExternalIdentity` 是 Provider 认证结果；`Principal` 是 AuthGuard 内部稳定授权主体。二者不是同一个对象。

一个 Principal 可以绑定多个登录身份：

```text
                 Principal P123
                       ▲
             ┌─────────┴─────────┐
             │                   │
Corporate DSP identity      GitHub identity
sub=EMP00123               id=987654
```

AuthZ 的 `RoleBinding.principal_id` 永远引用 `P123`，绝不引用 GitHub ID、WeChat openid/unionid 或 DSP subject。

### 4.2 数据模型

核心关系为：

```sql
iam_principal
  id                    -- AuthGuard-owned stable ID
  kind                  -- USER / WORKLOAD / GROUP
  display_name
  status                -- ACTIVE / DISABLED
  authorization_state

iam_principal_identity
  principal_id
  provider
  issuer
  subject
  claims
```

数据库必须保证：

```text
UNIQUE(provider, issuer, subject)
```

因此同一个外部身份不能绑定到两个 Principal；同一个 Principal 可以绑定多个外部身份。`iam_principal_identity` 属于 AuthN 所有，AuthZ 只消费或投影 `iam_principal.id`。

### 4.3 Canonical AuthN 输出

所有登录来源最终必须规范化为：

```text
AuthenticatedPrincipalContext {
    principalId
    kind
    stableGroupIds
    trustedClaims
    acr
    amr
}
```

`stableGroupIds` 必须是 AuthGuard 内部稳定的 Group Principal IDs，而不是 Provider group name。`trustedClaims` 只能包含经过 AuthN 信任策略筛选的业务 claims。

以下信息不得进入 AuthZ：

- GitHub ID；
- WeChat openid/unionid；
- DSP AMTOKEN；
- OAuth authorization code；
- Provider access/refresh token；
- Provider token response 原文。

## 5. Provider 配置模型

`authguard-authn` 与 `authguard-authz` 共同读取唯一一份 `authguard.yaml`。
根节点 `authn` 由 AuthN 管理，其余授权和运行配置由 AuthZ 管理；两个进程只反序列化自己
拥有的边界，因此共享文件不会形成 crate 依赖，也不再创建第二份 AuthN YAML。

Provider 配置只回答两个问题：

1. How do I authenticate?
2. How do I get a stable external identity?

示例：

```yaml
authn:
  providers:
    github:
      type: oauth2
      issuer: https://github.com
      authorization:
        endpoint: https://github.com/login/oauth/authorize
        scopes: [read:user, user:email]
      token:
        endpoint: https://github.com/login/oauth/access_token
        method: POST
      identity:
        endpoint: https://api.github.com/user
        subject: $.id
        username: $.login
        email: $.email

    wechat:
      type: oauth2-like
      issuer: https://open.weixin.qq.com
      authorization:
        endpoint: https://open.weixin.qq.com/connect/qrconnect
        scopes: [snsapi_login]
      token:
        endpoint: https://api.weixin.qq.com/sns/oauth2/access_token
        method: GET
        query:
          appid: ${clientId}
          secret: ${clientSecret}
          code: ${authorizationCode}
          grant_type: authorization_code
      identity:
        subject: $.unionid
        fallbackSubject: $.openid

    corporate-dsp:
      type: custom
      adapter: corporate-dsp
      issuer: https://dsp.example.com

  accountLinking:
    strategy: explicit
    authoritativeProviders: [corporate-dsp]
    allowLink:
      corporate-dsp: [github, wechat]
```

简单 JSON path 只支持类似 `$.data.user.id` 的字段访问，不扩展成带条件、函数和脚本的 DSL。

Provider 节点禁止声明 `authoritative`、`secondary`、`canCreatePrincipal` 或 `canLink`。这些账号治理语义统一放在 `accountLinking`。

### 5.1 最小 Provider SPI

SPI 只要求实现一个核心能力：

```rust
async fn authenticate(callback: ProviderCallback) -> Result<ExternalIdentity, ProviderError>;
```

自定义 Adapter 可以实现企业 DSP 的签名、token translation 或专有接口，但输出仍必须是 `ExternalIdentity`。SPI 不允许直接写 RoleBinding，也不允许把 Provider token 传给 AuthZ。

## 6. Account Linking

### 6.1 默认安全策略

默认配置：

```yaml
accountLinking:
  strategy: explicit
```

禁止仅因为 email 相同而自动合并账号。email 可作为展示或人工核验信息，不能作为 identity binding key。

企业推荐流程：

```text
首次 Corporate DSP 登录
  -> ExternalIdentity(corporate-dsp, EMP00123)
  -> create Principal P123
  -> bind DSP identity -> P123

P123 authenticated session
  -> 用户主动 Link GitHub
  -> GitHub authentication
  -> bind GitHub identity -> P123

以后 GitHub login
  -> GitHub ExternalIdentity
  -> identity binding lookup
  -> P123
  -> AuthZ
```

如果 GitHub 是 secondary provider，且第一次直接登录时没有 binding，AuthN 必须要求先通过 authoritative provider 确认身份，不得创建第二个 Principal。

`accountLinking.strategy` 支持 `explicit`（安全默认值）与 `first-login`。互联网产品可显式使用 `first-login`：任意尚未绑定的 `(provider, issuer, subject)` 首次登录时创建一个 Principal 和 binding，适合 2C 注册。但它不会推断不同 Provider 身份属于同一个人，也绝不按 email 自动合并；新增登录方式仍通过已认证会话执行 explicit link。

### 6.2 并发与一致性

创建 Principal 与首次 identity binding 必须在一个事务中完成。绑定操作依赖 `UNIQUE(provider, issuer, subject)` 防止并发双绑；冲突必须 fail closed，不得覆盖已有绑定。

## 7. 协议语义必须准确

### 7.1 GitHub OAuth 不是 OIDC

GitHub OAuth 登录通常返回 access token，并通过 GitHub user API 获取用户身份；不能假设存在 OIDC ID Token，也不能从 access token 中按 OIDC `sub` 解析用户。

### 7.2 ID Token 不等于 UserInfo

- ID Token：OIDC Authentication Event 的声明载体，面向 OIDC Client；
- Access Token：调用资源 API 的凭证；
- UserInfo：使用 access token 调用的可选 OIDC endpoint；
- Provider-specific identity API：例如 GitHub `/user`，不因此变成 OIDC UserInfo。

AuthN 根据 Provider 配置选择正确来源，提取 stable subject 后立即规范化。AuthZ 不感知这些差异。

## 8. 典型链路

### 8.1 标准 OIDC

```text
Enterprise OIDC / Keycloak / Entra
  -> Envoy Gateway native OIDC/JWT
  -> AuthN identity normalization / binding lookup
  -> canonical session/token
  -> Envoy jwt_authn
  -> authguard-authz ext_authz
  -> Biz Service
```

标准协议优先由 Envoy 处理；AuthN 不重复验证已经由可信 Envoy 验证的 token，但必须完成 canonical Principal 映射。

### 8.2 GitHub / WeChat

```text
GitHub / WeChat
  -> Envoy Gateway
  -> authguard-authn callback
  -> token exchange
  -> optional identity API
  -> ExternalIdentity
  -> Account Linking
  -> Canonical Principal Context
  -> Envoy jwt_authn -> authguard-authz
```

### 8.3 Corporate DSP

```text
Corporate DSP
  -> Envoy Gateway
  -> authguard-authn DSP Provider Adapter
  -> ExternalIdentity
  -> Account Linking
  -> Canonical Principal Context
  -> authguard-authz
```

## 9. AuthZ 授权模型

授权请求最小形式：

```text
AuthorizationRequest {
  principal_id
  group_principal_ids
  action
  resource_urn
  parent_urns
  conditions
}
```

判定顺序：

1. AuthZ 验证 canonical Principal 已物化且为 `ACTIVE`；
2. HTTP route 映射为 Action 与 Resource URN；
3. 匹配用户和 Group Principal 的 RoleBinding；
4. 匹配 resource、action 与 conditions；
5. 任一显式 `DENY` 命中则拒绝；
6. 至少一个 `ALLOW` 且无 `DENY` 才允许；
7. 默认拒绝。

如果 JWT 中的 `principal_id` 在 `iam_principal` 中不存在，AuthZ 返回 `UNAUTHENTICATED`；AuthZ 不创建 Principal，也不提供 allow-unknown 绕过。只需认证的 2C 路由不应挂载 `ext_authz`；需要订阅、租户、权益或数据资源权限的 2C 路由先由 AuthN `first-login` 物化 canonical Principal，再进入 AuthZ。

Authorization Scope 继续通过签名直接上下文或短期 opaque scope token 交付给业务 SDK，用于资源列表和 SQL 行级过滤。

## 10. Keycloak 定位

Keycloak 是可选 external enterprise IdP integration，不是 AuthGuard runtime dependency。

大型企业通常已有 Keycloak、Entra、Okta、Corporate DSP、SAML/Kerberos Federation Platform 或其他 Corporate IdP。AuthGuard 必须直接适配这些既有平台，而不是要求客户再部署 Keycloak。

保留的 Keycloak Principal discovery/federation 属于管理面 integration capability。默认 Helm 拓扑不部署 Keycloak。

> Keycloak is supported, never required.

## 11. 模块与依赖边界

```text
src/authn                       authguard-authn crate
  provider/                     configurable adapter + minimal SPI
  principal/jit.rs              linking policy 门控的账号绑定/JIT materialization
  route/authentication.rs       OAuth/OAuth-like HTTP 入口
  handler/authentication.rs     认证流程编排
  server.rs                     进程初始化与 listener 生命周期

src/common                      authguard-common crate
  config/config.rs              唯一 AppConfig 模型/单例及任意层级 ENV 覆盖
  model/{principal,identity,role,policy}.rs
                                高内聚 IAM 契约与持久化投影
  storage/base_{sqlite,postgres}.rs
                                实体无关连接池与 schema 初始化
  storage/principal_{sqlite,postgres}.rs
                                共用 canonical Principal 与 identity binding 持久化
  storage/authn/flow_{sqlite,postgres}.rs
                                AuthN flow 持久化
  storage/authz/role_{sqlite,postgres}.rs
                                AuthZ role 与授权目录持久化
  principal/{mod,custom}.rs     公共 discovery 契约与自定义 HTTP 目录连接器
  route/management.rs           health、metrics、运行时诊断
  apm/cache/utils               真正复用的基础设施

src/authz                        authguard-authz crate
  route/mod.rs                  AuthGuard APIs 认证与统一汇聚
  route/{policy,principal}.rs   仅负责传输适配的控制面 APIs
  route/authorization.rs        Envoy ext_authz/access-context gRPC 入口
  handler/{authorization,principal}.rs
                                授权目录与 Principal 管理用例
  handler/envoy_authz.rs        ext_authz evaluation and scope delivery
  principal/{ldap,keycloak,scim}/
                                可选 2B 控制面 federation connectors
  server.rs                     进程初始化与 listener 生命周期

migrations/                     唯一权威 IAM schema
```

依赖规则：

- AuthN 不依赖 AuthZ 的策略实现；
- AuthZ 不依赖 AuthN 的 Provider 实现；
- AuthN、AuthZ 和 Rust 业务 SDK 只向内依赖 `authguard-common`，SDK 不再依赖
  AuthZ 服务端 crate；
- 两者只通过 versioned canonical Principal Context 或等价 wire contract 协作；
- Provider-specific 类型不得出现在 AuthZ public API；
- 业务服务只依赖 AuthGuard access context，不依赖具体 IdP SDK。

AuthN 与 AuthZ 默认使用同一个逻辑 IAM 数据库和同一个 schema，不要求拆成两个 DB。
`iam_principal` 只定义一次，作为共享 aggregate root；AuthN 拥有
`iam_principal_identity` 和临时 `iam_authn_flow`，AuthZ 拥有 policy/action/role/binding
表。唯一顶层 migration 在启动时串行执行。该表所有权边界既消除了重复 DDL，也保留了
未来确有需要时物理拆库的可能。

配置初始化遵循 Spring Boot-like 优先级：`内置默认值 < authguard.yaml < 环境变量`。
任意层级属性都可用 `AUTHGUARD__<SECTION>__<...>` 动态覆盖，配置结构新增字段时无需再维护
一份手工环境变量映射。

两个服务都为关键链路发布 Prometheus 指标和结构化 tracing 事件。业务 SDK 不自行初始化
全局 exporter：Rust 直接产生可接入 OTel 的 `tracing` events；Go/Python/Java 暴露由宿主
应用配置的 logger 与 telemetry observer bridge，从而复用业务服务已有的 OTel
Meter/Tracer provider，避免重复全局实例。

## 12. Flowgent / Sigbot 集成目标

Flowgent、Sigbot 等业务项目只部署或复用：

```text
Envoy Gateway
authguard-authn
authguard-authz
```

企业通过 AuthN YAML 配置 GitHub、WeChat、Corporate DSP、Keycloak、Entra 等 Provider。业务项目不知道底层登录平台，不处理 callback、token exchange 或账号绑定，只消费稳定 `principal_id` 与 AuthZ 输出的访问上下文。

## 13. 最终原则

- Envoy owns the edge；
- AuthN owns external authentication normalization and account linking；
- AuthZ owns authorization for one stable canonical Principal；
- Principal 不等于 `(issuer, subject)`；
- Provider 配置描述协议，不描述账号治理；
- 默认显式绑定，禁止 email 自动合并；
- Keycloak supported, never required；
- External IdPs remain external。
