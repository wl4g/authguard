# Authguard 架构总览

Authguard 是深度集成 Envoy Gateway 的独立 Resource URN 授权系统，不重复实现
通用 API Gateway。Envoy Gateway 负责入口、OIDC/JWT 认证、路由和流量治理；
Authguard 负责 Envoy extAuth gRPC 请求到 action/Resource URN 的映射、授权决策、策略控制面，
以及向业务服务返回可用于行级查询的受信访问上下文。

它更适合 2B / 2B2C 场景中多账号、多角色、多资源的访问控制管理。适用边界是
多人或多个系统主体是否需要在同一团队、租户或资源集合内协作，且权限范围不同。
2C 也可以使用，但简单消费者自有资源过滤通常无需完整 IAM 平面。

`iam_principal` 是外部系统已完成认证身份在授权侧的稀疏投影。`USER`、`WORKLOAD`、
`GROUP` 使用同一个 Principal 抽象；Authguard 不保存 password 或 session。对 OIDC，
唯一稳定身份键是已验证的 `(issuer, external_id)`，其中 `external_id` 为 `sub`；
禁止使用裸 `sub`、email 或 username 作为身份唯一键。

Principal 通过统一的泛型 `IPrincipalDiscovery<Input>` 边界进入 Authguard：可信 JIT 投影处理首次
合法访问，控制面联邦搜索支持管理员在首次登录前授权，SCIM 子集 ingestion 接收可选的
企业生命周期变化。随服务发布的联邦 connector 支持 Keycloak Admin API（包括由
Keycloak 从 LDAP/AD 联邦而来的身份）、直接 RFC 4511 LDAP 搜索，以及配置化
HTTP + bearer-JWT connector 集成企业内部自研身份系统。当前 SCIM 实现是
RFC 7643 User/Group 子集的增量 ingestion adapter，
不是完整 RFC 7644 SCIM Server。三种方式都规范化并幂等写入同一张
`iam_principal`，不会建立协议专属账号表。
SCIM source 的 `issuer` 必须与对应 OIDC token 的精确 `iss` 相同；SCIM User
`externalId` 应等于 OIDC `sub`，SCIM Group `externalId` 应等于 provider 的稳定 group
ID（Keycloak 为 group UUID）。这样 SCIM、JIT 与联邦搜索才会收敛到同一 Principal。
亿级互联网场景默认以 JIT + 联邦搜索为主，只投影真正访问或被授权的 Principal；启用 SCIM
也应使用增量 provisioning，而不是要求全量预加载。
SCIM 是 push-oriented：IdP/provisioning agent 作为 Client 主动提交变化，Authguard 负责
应用；`refresh` 不是轮询 IdP。必须 pull 的来源应使用独立、来源专属的控制面 connector。

Keycloak 可以搜索其 LDAP/AD federation 用户，但这是 Keycloak 管理能力，不是 OIDC
协议能力。Keycloak group、realm/client role 与 OIDC scope 仍可作为粗粒度身份 claims，
但不会被导入为 Authguard 的资源策略。数据面绝不实时搜索 Keycloak、LDAP、SCIM 或云 IAM。每次鉴权按
`issuer + external_id` 从本地 repository 批量读取主 Principal 与 Group Principal，确保
禁用或撤销立即 fail closed。`IAuthorizationCache` 只保存短期 opaque scope-token
context；已编译 policy 是按 repository revision 刷新的进程内不可变快照。Principal 与
policy 都不进入 Memory/Redis cache。

默认 `auth.identity.groups_claim` 为 `authguard_group_ids`。该 claim 必须携带 issuer-local
稳定 group ID；Keycloak 对应 group UUID。JIT 与 Keycloak 联邦 discovery 都将它规范化为
`group:<UUID>`。group name、display name 和 path 只作展示，不能成为稳定授权键。

```text
用户或 workload
  -> 企业 IdP / Keycloak 签发短期 Access Token
  -> Envoy Gateway 以 issuer、audience 和本地/远程 JWKS 严格验证 JWT
  -> Envoy 只转发已验证的 JWT token；Authguard 从该 token 解析 issuer + external_id(sub)
  -> Authguard :8080 envoy.service.auth.v3.Authorization/Check (仅 Envoy gRPC ext_authz)
  -> Authguard 从 repository 解析 active Principal，并以 L1 编译策略快照求值
       （策略按 durable repository revision 刷新；Redis 只保存 scope-token context）
  -> Envoy 删除客户端 x-authguard-* 头并注入以下二者之一：
       x-authguard-context       HMAC-SHA256 签名的短期 allow/deny URN context
       x-authguard-scope-token   大授权范围，仅携带短期 opaque token
  -> 若启用 auth.resign_jwt，Authguard 另以 RS256 重签短期 JWT
       （携带 authguardOrigin: true）并替换 authorization 头；业务微服务只
       配置公钥验签
  -> workload adapter 的 IAccessContextResolver
       HeaderAccessContextResolver 直接解码 Envoy 注入的 context
       GrpcAccessContextResolver   通过 Authguard :8081 gRPC ResolveScope 解析 token
  -> repository 将 action 对应的 allow/deny URN 编译为 SQL scope

IAM administrator
  -> IPrincipalDiscovery<Input>
       JitPrincipalDiscovery        受信身份首次访问
       KeycloakPrincipalDiscovery   管理面联邦搜索（Keycloak Admin API）
       LdapPrincipalDiscovery       管理面联邦搜索（直接 RFC 4511 LDAP）
       CustomPrincipalDiscovery     管理面联邦搜索（配置化 HTTP + JWT）
       ScimPrincipalDiscovery       RFC 7643 User/Group 子集 ingestion
  -> 幂等物化 iam_principal
  -> Authguard /adm/v1/** (policy 与 role-binding control plane)
```

登录 JWT 只承载身份、租户、组和 MFA 等稳定 claims，不承载大量资源 URN。资源范围由
Authguard 根据每次请求的 principal、action、Resource URN 与 IP/TLS/MFA 等条件实时计算。
JWT 模式只接受 Envoy 验证后转发的 `Authorization: Bearer ...`，OIDC 模式只接受 Envoy
转发的已验证 ID token；Authguard 不接受独立的 issuer、subject、group 或 MFA claim
headers。Authguard 解析已由 Envoy 验证的 token claims，本身不重复执行 JWT 签名验证。
`auth.scope_delivery.direct_urn_limit` 决定直接上下文与 scope token 的切换点；两种结果均有
短 TTL、策略 revision 和目标 action，adapter 缺失、过期或动作不匹配时必须 fail closed。
可选的 `auth.resign_jwt` 会在每个 ALLOW 上重签 RS256 JWT：`iss: authguard`、
`sub: external_id`、`principal_id`、`authguard_group_ids`、`authguardOrigin: true`、
`iat`/`exp`（TTL 沿用 `scope_token_ttl`），并复制原 token 的标量 claims。稳定身份保持
不变——重签者重发 `iss`/`sub` 并追加 `authguardOrigin: true` 标记 claim——业务微服务
验证此签名即可证明请求经过了 Envoy Gateway，从而拒绝客户端直连微服务 API。RSA 私钥仅存于
Authguard；Envoy 对原始 JWT 的标准验证不变，禁用时维持仅移除身份 token 的现状。
两个 gRPC 服务使用独立 listener：Envoy Check 为 `8080`，SDK ResolveScope 为 `8081`。
默认 NetworkPolicy 按 Envoy 与 `authguard.io/scope-client` 分别限制两个端口，避免将
context 签发能力暴露给 workload SDK。

直接上下文格式为 `agctx1.<payload>.<signature>`，SDK 必须先用 HMAC-SHA256 验签再解析
Base64URL v3 payload。Authguard 与 workload 通过
`AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY` 使用同一个至少 32 bytes 的高熵密钥；未签名、被篡改
或密钥不匹配全部 fail closed。Helm 可通过 `authguard.accessContext.existingSecret` 与
`authguard.accessContext.key` 引用已有 Secret；未引用且未显式提供 signing key 时会生成并
复用 64 字符密钥。集群外或独立部署的 workload 必须自行挂载同一 Secret/env。

规范化授权 schema 只包含六张表：`iam_policy`、`iam_principal`、`iam_action`、
`iam_role`、`iam_role_action`、`iam_role_binding`。业务资源和外部账号目录仍由各自
所属系统维护唯一真相。

规范依据：[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
规定 OIDC End-User 的稳定键必须组合 `iss + sub`；[Keycloak 管理指南](https://www.keycloak.org/docs/latest/server_admin/)
说明 LDAP/AD user federation；[SCIM Core Schema RFC 7643](https://www.rfc-editor.org/rfc/rfc7643.html)
与 [SCIM Protocol RFC 7644](https://www.rfc-editor.org/rfc/rfc7644.html) 定义标准化身份 provisioning。

当前实现结构：

authorization route 只依赖 `IAuthorizationHandler`；
`DefaultAuthorizationHandler` 内聚 ACL 求值与 request-access 交付，`PolicyHandler`
编排 CRUD 和 durable synchronization，`PolicyRuntime` 只持有已编译的不可变快照。
源码不再保留重复的授权 service package。

```text
src/core/src
  server.rs     单进程 API/mgmt listener 与优雅停机
  route/        Envoy gRPC 与管理面 HTTP 协议适配
  handler/
    authorization.rs  ACL 求值与 request-access 交付
    policy.rs    policy 编译、不可变 runtime 与策略 CRUD
    principal.rs Principal 投影/discovery 用例
    management.rs health、readiness、status 与 metrics 用例
  config/       authguard.yaml 加载、环境覆盖与校验
  model/        与存储无关的授权模型、SQL-scope 语义及 HTTP/gRPC DTO
  principal/
    mod.rs       discovery 公共模型、trait 与 error
    jit.rs       受信 OIDC JIT 投影
    keycloak.rs  Keycloak Admin API 搜索 connector
    ldap.rs      直接 RFC 4511 LDAP connector
    custom.rs    配置化 HTTP/JWT 自研身份 API connector
    scim.rs      RFC 7643 User/Group 子集 ingestion
  storage/      SQLite/PostgreSQL repository 与私有 row record
  cache/        Memory/Redis opaque scope-token context cache
  utils/        identity 解析、HTTP 多元组映射、OTel 与 metrics
src/core/migrations
  001_init.ddl.sql 可移植授权 schema DDL
  001_init.dml.sql singleton policy 初始 DML
src/adapters    Rust、Go、Python、Java SDK
use-cases       企业客户增长分析任务业务服务 E2E 示例
deploy          单 Authguard image、Envoy Gateway Helm 与 Grafana dashboard
```

Rust model 不是持久化 entity：扁平的 `model/` 统一承载与存储无关的授权语义和边界
DTO，数据库行结构只收敛在 `storage/record.rs`。SQLite 与 PostgreSQL 共用同一组编号
一致的 DDL/DML migration。

正式模型见 [IAM 授权白皮书](iam-authorization-whitepaper_ZH.md)，当前落地方案见
[Envoy Gateway 集成实施方案](../plans/envoy-gateway-integration-implementation-plan_ZH.md)。
