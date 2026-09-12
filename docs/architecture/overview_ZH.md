# AuthGuard 架构总览

AuthGuard 是一个深度集成 Envoy Gateway 的独立、统一认证鉴权产品。默认部署由三个组件组成：

```text
Envoy Gateway
authguard-authn
authguard-authz
```

AuthN 与 AuthZ 挂载并读取同一份 `authguard.yaml`，通过根节点划分所有权，不拆成两份配置。

核心职责边界：

- Envoy Gateway 负责统一入口、TLS、路由、标准 OIDC/JWT 能力和 PEP；
- `authguard-authn` 负责 Provider 协议适配、`ExternalIdentity` 规范化和 Account Linking；
- `authguard-authz` 只围绕内部稳定 `principal_id` 执行资源级授权。

> Envoy owns the edge. AuthGuard owns identity normalization and authorization.

## 身份与 Principal

外部身份与授权主体严格分离：

```text
(provider, issuer, subject)
          │
          │ iam_principal_identity / Account Linking
          ▼
internal stable principal_id
```

一个 Principal 可以绑定 Corporate DSP、GitHub、WeChat 等多个登录身份。AuthZ 不接收 GitHub ID、openid/unionid、DSP token、authorization code 或 Provider access token。

AuthN 的统一输出为：

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

AuthZ 热路径只按 canonical Principal IDs 批量读取本地 Principal 状态；未知或 disabled Principal fail closed，不再按 `iss/sub` 做 JIT 创建。

## Provider 与账号绑定

Provider YAML 只描述授权端点、token exchange、可选 identity API、stable subject 和简单 claims mapping。GET/POST、header/body/query credential、WeChat `unionid/openid`、GitHub `/user`、DSP token translation 等差异全部停留在 AuthN。

默认 Account Linking 策略是 `explicit`。相同 email 不会触发自动绑定。企业可把 Corporate DSP 声明为 authoritative provider，并允许用户在已认证 Principal session 中主动绑定 GitHub/WeChat。互联网产品可显式选择 `first-login`。

## AuthZ 授权模型

AuthZ 保留：

- `USER` / `WORKLOAD` / `GROUP`；
- Action、Role、RoleBinding；
- Resource URN、parent URNs、Conditions；
- explicit DENY precedence 与 default deny；
- 签名 access context / opaque scope token；
- Keycloak、LDAP、SCIM 等可选管理面 Principal federation/materialization。

管理面 discovery connector 不参与登录或热路径。物化外部候选时必须同时提供 AuthN 已解析的 canonical `principal_id`。

## 协议边界

- GitHub OAuth 不是 OIDC；通常使用 access token 调用 GitHub `/user` 获取身份；
- ID Token 不等于 UserInfo；Access Token 也不等于用户身份；
- 标准 OIDC 优先使用 Envoy Gateway 原生能力；
- GitHub/WeChat/DSP 的协议差异由 AuthN 处理，不 patch Envoy，不使用 Lua/Wasm；
- AuthGuard 不引入 Kubernetes CRD/Controller。

## Keycloak

Keycloak 是可选 external enterprise IdP integration，不是运行时依赖。已有 Keycloak Principal discovery/federation 能力继续作为管理面 integration capability；默认 Helm 拓扑不部署 Keycloak。

> Keycloak is supported, never required.

## 代码结构

```text
src/authn/       authguard-authn：Provider、ExternalIdentity、Account Linking、identity binding
src/authz/        authguard-authz：Principal、policy、ext_authz、Authorization Scope
src/adapters/    业务服务 access-context SDK
deploy/          Envoy Gateway + AuthN + AuthZ 默认部署
```

完整模型与典型链路见 [IAM 认证鉴权白皮书](iam-authorization-whitepaper_ZH.md)。
