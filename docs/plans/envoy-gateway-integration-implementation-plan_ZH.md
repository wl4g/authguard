# Authguard 与 Envoy Gateway 集成实施方案

- 状态：当前已落地契约
- 范围：`authguard-authn`、`authguard-authz`、Envoy Gateway、Helm、四语言 adapters 与可观测性
- 原则：Envoy owns the edge；AuthN 认证、归一化并绑定外部身份；AuthZ 只授权 canonical Principal

## 1. 产品与运行边界

Authguard 是内置集成 Envoy Gateway 的独立认证鉴权产品，不重复实现通用 API Gateway。
默认部署 Envoy Gateway、`authguard-authn` 与 `authguard-authz`；两个 Rust 服务可由同一镜像
提供不同入口，并共同读取一份 `authguard.yaml`：

- AuthN 面：`:8082` 承载非标准 OAuth2/OAuth2-like/企业协议的 authorize、callback、
  token exchange、可选 identity lookup、ExternalIdentity normalization 与 account linking。
- AuthZ Envoy 授权面：`:8080` 只提供
  `envoy.service.auth.v3.Authorization/Check`，只允许 Envoy 数据面访问。
- AuthZ workload scope 面：`:8081` 只提供
  `authguard.access.v1.AccessContextService/ResolveScope`，只允许选中的 SDK workload 访问。
- AuthZ 控制面：独立 management HTTP 端口承载 `/api/v1/**`、health、readiness 与 metrics。

```text
Client
  -> Envoy Proxy
       -> standard OIDC/JWT authentication, or route provider flow to authguard-authn
            -> ExternalIdentity -> account linking -> canonical Principal
       -> jwt_authn -> SecurityPolicy extAuth gRPC
            -> authguard-authz Authorization/Check
                 -> resolve verified canonical principal_id
                 -> map HTTP tuple to action + Resource URN
                 -> evaluate compiled authorization catalog
                 -> inject direct context or opaque scope token
       -> business service adapter
            -> ResolveScope when token-backed
            -> compile action-aware allow/deny URNs into SQL scope

Administrator
  -> /api/v1/**
       -> canonical Principal federation/materialization
       -> action, role, and role-binding CRUD
       -> transactional action/role/role-binding catalog replacement
```

当前源码边界：

```text
src/common/src/config/config.rs  统一强类型配置、简单 Provider 与集中式 Account Linking 模型
src/authn/src/provider/       配置化 Provider engine 与最小特殊协议 SPI
src/authn/src/principal/jit.rs identity binding、JIT 与 canonical Principal 解析
src/common/src/model/identity.rs ExternalIdentity 与 canonical authentication context
src/common/src            AuthN/AuthZ/SDK 共享的稳定模型、配置、协议、存储连接与 telemetry
src/authz/src/route       Envoy gRPC 与 management HTTP 协议适配
src/authz/src/handler/authorization.rs  授权目录编译、CRUD、ACL 求值与管理面授权用例
src/authz/src/handler/principal.rs  Principal 投影/discovery 用例
src/common/src/route/management.rs   health、readiness、metrics 与运行时诊断入口
src/common/src/principal/mod.rs  discovery 公共 trait、查询模型与 error
src/authz/src/principal/keycloak/  Keycloak Admin API 搜索 connector
src/authz/src/principal/ldap/      直接 RFC 4511 LDAP connector
src/common/src/principal/custom.rs 配置化 HTTP/JWT 自研身份 API connector
src/authz/src/principal/scim/      RFC 7643 User/Group 子集 ingestion
src/common/src/model/{principal,identity,role,policy}.rs 与存储无关的 IAM 实体模型
src/common/src/storage/       底层按 SQLite/PostgreSQL、上层按 IAM 主实体拆分 repository
src/common/src/cache          Memory/Redis IAuthorizationCache（仅 opaque scope-token context）
src/common/src/utils      AuthN/AuthZ 共用的 HTTP 匹配、JWT 等工具
src/common/src/apm        AuthN/AuthZ 共用的 OTel、Prometheus 与运行时诊断
migrations                单一 IAM datastore 的顶层 DDL/DML（含 AuthN identity binding 与 AuthZ policy）
src/adapters             Java、Go、Python、Rust workload SDK
```

`model/` 只保存协议无关的 IAM 实体模型；HTTP DTO 与业务流程归属 AuthZ handler，SQL
行映射只封装在对应的 `*_sqlite.rs` / `*_postgres.rs`，不得泄漏到 handler。AuthN 与 AuthZ
共用顶层、单份、编号一致的 DDL/DML migration；表的写入所有权仍由
模块边界约束，不因共用 datastore 而互相调用内部 repository。

## 2. 配置与存储

AuthN 与 AuthZ 共用的唯一主配置为 `etc/authguard.yaml`，容器使用
`AUTHGUARD__<SECTION>__<KEY>` 环境变量覆盖。当前可配置边界为：

- `authn.providers`：只描述如何认证并获得稳定 ExternalIdentity；
- `authn.accountLinking`：集中定义 explicit/first-login 策略、authoritative provider 与允许绑定关系；
- `server`：Envoy Check 与 workload ResolveScope 两个 gRPC listener、request/response
  大小、timeout、并发和 worker 数。
- `mgmt`：management 监听、health、Prometheus 与 OTLP tracing。
- `authz.identity`：受信 token/header claim 映射。
- `authz.scope_delivery`：direct context 与 opaque token 的 TTL/阈值。
- `authz.principal_discovery`：可选 Keycloak/LDAP/custom 联邦 discovery 和 SCIM 子集 ingestion；
  只用于 AuthZ 管理面物化，不参与登录或数据面身份解析。
- `storage`：SQLite 或 PostgreSQL；本地默认 SQLite，生产多副本使用 PostgreSQL。
- `cache`：Memory 或 Redis Cluster；本地默认 Memory，Helm 默认 Redis Cluster。

AuthN/AuthZ schema 初始化统一使用仓库根目录 `migrations/001_init.ddl.sql` 与 `001_init.dml.sql`；
两者共用配置文件、migration 和 datastore，但数据库职责和 crate 依赖不耦合。

持久化 schema 不包含 `iam_policy`：授权目录由 `iam_principal`、`iam_action`、`iam_role`、
`iam_role_action`、`iam_role_binding` 五表共同表达。目录修改执行完整校验和单一数据库事务，
成功后发布当前进程的编译目录；revision 只用于当前进程管理 API 的并发写保护，不承担跨副本
状态同步。生产管理面应落到单一 AuthZ writer，数据面副本通过滚动发布加载一致目录。

AuthN 维护 `iam_authn_flow` 和
`iam_principal_identity(principal_id, provider, issuer, subject)`；
`(provider, issuer, subject)` 全局唯一。绑定只由 Account Linking 用例修改，AuthZ 不查询
provider identity，也不以 email 自动合并账号。

## 3. 数据面契约

| RPC | 调用方 | 当前语义 |
|---|---|---|
| `envoy.service.auth.v3.Authorization/Check` (`:8080`) | Envoy Gateway extAuth | 从标准 `CheckRequest` 读取 method、host、path、headers、source peer 与 scheme，完成身份解析、route mapping 和授权 |
| `authguard.access.v1.AccessContextService/ResolveScope` (`:8081`) | workload SDK | 用短期 opaque token 解析完整 v3 request access context |

放行时 Authguard 删除客户端提供的 `authorization`、身份传递头、
`x-authguard-context` 与 `x-authguard-scope-token`，随后只注入以下二者之一：

- `x-authguard-context`：Base64URL 编码的 v3 JSON，包含 `principal_id`、`action`、
  `resource_urn`、allow/deny Resource URNs、`policy_revision` 与有效期。
- `x-authguard-scope-token`：不可预测的短期 opaque token；完整上下文保存在
  `IAuthorizationCache`，SDK 通过 `ResolveScope` 获取。

登录 JWT 只承载身份和有界 claims，不承载大量资源 URN。Authguard 不把 JWT payload
解码等同于验签；生产信任边界是 Envoy 的 issuer/audience/JWKS 验证以及集群网络隔离。
标准 OIDC authorization-code flow 优先由 Envoy Gateway 原生能力处理。GitHub 不因使用
OAuth2 就被视为 OIDC，Access Token 也不等于 ID Token；GitHub `/user`、WeChat
openid/unionid、DSP token translation 等只由 AuthN Provider Adapter 处理。AuthZ 不管理
callback、provider token 或登录 session。

## 4. 控制面契约

`/api/v1/**` 使用独立 `AUTHGUARD__AUTHZ__API_TOKEN` Bearer 凭证，不复用 workload
OIDC/JWT。当前真实 API 为：

| API | 语义 |
|---|---|
| `GET /api/v1/policy` | 读取由 action/role/role-binding 组成的授权目录 |
| `PUT /api/v1/policy` | 校验并在单一数据库事务中替换完整授权目录 |
| `GET|POST /api/v1/actions` | 列出或创建 action |
| `GET|PUT|DELETE /api/v1/actions/{action_id}` | action resource CRUD |
| `GET|POST /api/v1/roles` | 列出或创建 role |
| `GET|PUT|DELETE /api/v1/roles/{role_id}` | role resource CRUD |
| `GET|POST /api/v1/role-bindings` | 列出或创建 role binding |
| `GET|PUT|DELETE /api/v1/role-bindings/{binding_id}` | role-binding resource CRUD |
| `GET /api/v1/principals` | 搜索本地 Principal 投影 |
| `GET|PATCH|DELETE /api/v1/principals/{principal_id}` | 读取、更新状态或安全删除投影 |
| `POST /api/v1/principal-discovery/search` | 对已配置 source 执行联邦搜索 |
| `POST /api/v1/principal-discovery/materialize` | 服务端重新 resolve 并物化候选 Principal |
| `POST /api/v1/principal-discovery/scim/events` | ingestion 一条 RFC 7643 User/Group 子集变化 |
| `POST /api/v1/authorize` | 运维/调试用显式 URN 决策 |
| `GET /api/v1/status` | 查询 policy revision 与资源计数 |

当前随 AuthZ 发布的可选联邦 connector 为 Keycloak、直接 RFC 4511 LDAP，以及配置化
HTTP + bearer-JWT 的 custom connector（集成企业自研身份系统）；LDAP/AD 用户也可
通过 Keycloak federation 间接搜索。SCIM 路径是 RFC 7643 User/Group 子集的增量
ingestion adapter，不是完整 RFC 7644 SCIM Server，也不提供 `/scim/v2/Users` 或
`/scim/v2/Groups`。

Keycloak 是可支持的 external enterprise IdP integration，不是 Authguard runtime dependency，
也不进入默认 Helm 部署。

## 5. HTTP tuple 到 URN

`iam_action.route_matchers` 中的每个 `HttpRouteMatcher` 只包含：

```json
{
  "id": "customer-growth-job-read",
  "methods": ["GET"],
  "hosts": ["growth.example.com"],
  "path": "/api/v1/customer-growth/jobs/{job_id}",
  "resource_urn": "urn:iam:prod:customer-growth:global:{tenant_id}:workspace/customer-insights/project/retention-analytics/job/{job_id}",
  "parent_urns": [
    "urn:iam:prod:customer-growth:global:{tenant_id}:workspace/customer-insights/project/retention-analytics",
    "urn:iam:prod:customer-growth:global:{tenant_id}:workspace/customer-insights"
  ]
}
```

Action 由 matcher 所属的 `iam_action` 提供，不在 matcher 中重复保存。`path` 支持字面量、
`{variable}`、单段 `*` 和末尾 `**`；URN template 可引用路径变量、`method`、`host` 与
已配置的受信 identity claims。无匹配、多个匹配、缺失模板值或非法 URN 均 fail closed。

## 6. 条件与 Principal discovery

当前 role-binding `conditions` 支持：

- `sourceIp.inCidr` / `sourceIp.notInCidr`；
- `request.methods` / `request.secureTransport`；
- `subject.mfa` / `subject.claims`。

所需上下文缺失时条件不匹配。当前不声称支持 time window 或 resource-tag condition。

`IPrincipalDiscovery<Input>` 统一 AuthZ 管理面的可选目录发现路径：

- `KeycloakPrincipalDiscovery`：Keycloak Admin API 有界并发搜索（`FED_KEYCLOAK`）；
- `LdapPrincipalDiscovery`：直接 RFC 4511 LDAP 搜索（`FED_LDAP`）；
- `CustomPrincipalDiscovery`：配置化 URL/请求/响应映射 + bearer JWT 的企业自研系统搜索（provider code 为 `FED_CUSTOM`）；
- `ScimPrincipalDiscovery`：RFC 7643 User/Group 子集 upsert/delete normalization。

联邦搜索和 SCIM ingestion 只在控制面运行；物化请求必须携带 AuthN 已解析的 canonical
`principal_id`。extAuth 热路径只按 `principal_id` 读取本地 Principal repository 与已编译
授权目录，不进入 `IAuthorizationCache`，因此禁用或撤销不会等待 cache TTL。canonical
context 的 `stable_group_ids` 只能包含稳定内部 group Principal IDs；Keycloak group UUID
可以在集成边界映射，但 provider-specific ID 不得直接泄漏到 AuthZ 热路径。

## 7. Helm 与可观测性

`deploy/helm/authguard` 默认安装 Envoy Gateway、AuthN 与 AuthZ，并可安装 Redis Cluster。
AuthN/AuthZ Deployment 挂载同一个 ConfigMap 中的 `authguard.yaml`。已有兼容 Envoy Gateway 的集群可设置
`envoy_gateway.enabled=false`，同时保持 `envoy_gateway.ext_authz.enabled=true` 应用 gRPC
extAuth `SecurityPolicy`。运行镜像使用项目约定的阿里云 registry 地址。
默认 NetworkPolicy 分别允许 Envoy 访问 `8080`，以及带
`authguard.io/scope-client` 选择器的 workload 访问 `8081`；两个服务不得复用 listener。

management `GET /metrics` 当前暴露：

- `authguard_authorization_decisions_total{decision,reason}`；
- `authguard_authorization_duration_seconds`；
- `authguard_http_requests_total{route,method,status}`；
- `authguard_policy_reloads_total{outcome}`；
- `authguard_policy_revision`；
- scope delivery/resolve 计数与 resolve latency。

OTel 支持 OTLP gRPC exporter 与 W3C trace context；未启用 exporter 时保留本地 tracing。
`deploy/apm/grafana/authguard-overview.json` 当前展示 authorization decision/latency、
management HTTP、policy reload 与 `authguard_policy_revision`；scope 指标仍可由
Prometheus 查询。

## 8. Adapter 与验收

四种语言 SDK 均只保留 `access/filter/model/util` 职责，并提供 direct-header 与
gRPC scope-token 两个 `IAccessContextResolver` 实现。`AUTHGUARD_GRPC_TARGET` 是 gRPC
target，不是 HTTP base URL；`AUTHGUARD_GRPC_TLS` 控制 channel TLS。filter/interceptor
只管理 request 生命周期，repository 使用 action-aware SQL scope 并 fail closed。

每种 SDK 的统一契约是 **46 个测试：22 个 access/filter/resolver + 24 个
codec/URN/SQL**。客户增长业务用例另有一份跨五种实现共享的 53-case CRUD/条件/URN
契约。

验收入口：

```bash
make test
make e2e
make e2e-k3s
```

`make test` 覆盖 Rust workspace、四语言 SDK、五个业务实现与 Helm lint/template；
`make e2e` 在本地数据库执行共享业务契约；`make e2e-k3s` 负责完整清理、重新部署并通过
Envoy Gateway 校验真实 HTTP 结果。
