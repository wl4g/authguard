# Authguard 与 Envoy Gateway 集成实施方案

- 状态：当前已落地契约
- 范围：Authguard core、Envoy Gateway、Helm、四语言 adapters 与可观测性
- 原则：Envoy 负责入口与认证，Authguard 负责授权；默认拒绝；持久化成功后才发布新 revision

## 1. 产品与运行边界

Authguard 是深度集成 Envoy Gateway、基于 Resource URN 的独立授权系统，不重复实现
通用 API Gateway。项目发布一个 Rust 服务镜像，监听两个逻辑平面：

- Envoy 授权面：`:8080` 只提供
  `envoy.service.auth.v3.Authorization/Check`，只允许 Envoy 数据面访问。
- workload scope 面：`:8081` 只提供
  `authguard.access.v1.AccessContextService/ResolveScope`，只允许选中的 SDK workload 访问。
- 控制面：独立 management HTTP 端口承载 `/adm/v1/**`、health、readiness 与 metrics。

```text
Client
  -> Envoy Proxy
       -> OIDC/JWT authentication
       -> SecurityPolicy extAuth gRPC
            -> Authguard Authorization/Check
                 -> resolve verified issuer + external_id
                 -> map HTTP tuple to action + Resource URN
                 -> evaluate immutable policy snapshot
                 -> inject direct context or opaque scope token
       -> business service adapter
            -> ResolveScope when token-backed
            -> compile action-aware allow/deny URNs into SQL scope

Administrator
  -> /adm/v1/**
       -> Principal discovery/projection
       -> action, role, and role-binding CRUD
       -> singleton policy aggregate CAS replacement
```

当前源码边界：

```text
src/core/src/route       Envoy gRPC 与 management HTTP 协议适配
src/core/src/handler/authorization.rs  ACL 求值与 request-access 交付
src/core/src/handler/policy.rs  policy 编译、不可变 runtime 与策略 CRUD
src/core/src/handler/principal.rs  Principal 投影/discovery 用例
src/core/src/handler/management.rs  health、readiness、status 与 metrics 用例
src/core/src/principal/mod.rs  discovery 公共模型、trait 与 error
src/core/src/principal/jit.rs  受信 OIDC JIT 投影
src/core/src/principal/keycloak.rs  Keycloak Admin API 搜索 connector
src/core/src/principal/ldap.rs      直接 RFC 4511 LDAP connector
src/core/src/principal/custom.rs    配置化 HTTP/JWT 自研身份 API connector
src/core/src/principal/scim.rs  RFC 7643 User/Group 子集 ingestion
src/core/src/model       与存储无关的授权模型、SQL-scope 语义及 HTTP/gRPC DTO
src/core/src/storage     SQLite/PostgreSQL repository；row record 收敛在 record.rs
src/core/src/cache       Memory/Redis IAuthorizationCache（仅 opaque scope-token context）
src/core/src/utils       HTTP tuple 映射、身份解析、OTel 与 Prometheus
src/core/migrations      001_init.ddl.sql 与 001_init.dml.sql
src/adapters             Java、Go、Python、Rust workload SDK
```

扁平的 `model/` 不承载数据库 entity；它统一保存授权语义和 route/handler 边界的
HTTP/gRPC DTO。SQLite/PostgreSQL 的持久化行结构只封装在 `storage/record.rs`，不得泄漏到
handler。两种 repository 共用编号一致的 DDL/DML migration。

## 2. 配置与存储

单一主配置为 `etc/authguard.yaml`，容器使用
`AUTHGUARD__<SECTION>__<KEY>` 环境变量覆盖。当前可配置边界为：

- `server`：Envoy Check 与 workload ResolveScope 两个 gRPC listener、request/response
  大小、timeout、并发和 worker 数。
- `mgmt`：management 监听、health、Prometheus 与 OTLP tracing。
- `auth.identity`：受信 token/header claim 映射。
- `auth.scope_delivery`：direct context 与 opaque token 的 TTL/阈值。
- `auth.principal_discovery`：JIT、Keycloak 联邦 discovery 和 SCIM 子集 ingestion。
- `storage`：SQLite 或 PostgreSQL；本地默认 SQLite，生产多副本使用 PostgreSQL。
- `cache`：Memory 或 Redis Cluster；本地默认 Memory，Helm 默认 Redis Cluster。

schema 初始化固定使用 `migrations/001_init.ddl.sql` 与 `001_init.dml.sql`：前者只定义
六表结构、约束和索引，后者只写入 singleton policy 初始数据，不再维护 provider 专属
初始化脚本。

持久化 schema 固定为六表：`iam_policy`、`iam_principal`、`iam_action`、
`iam_role`、`iam_role_action`、`iam_role_binding`。v1 的 `iam_policy` 是 singleton
aggregate。策略修改使用 revision CAS：完整校验 -> durable storage transaction ->
当前进程 `PolicyRuntime` 原子发布不可变编译快照。其他副本按 repository revision
刷新；policy 与 Principal 均不通过 cache 传播状态。

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
OIDC authorization-code callback 由 Envoy Gateway 原生能力处理，Authguard 不管理登录
session 或 token 生命周期。

## 4. 控制面契约

`/adm/v1/**` 使用独立 `AUTHGUARD__AUTH__ADMIN_TOKEN` Bearer 凭证，不复用 workload
OIDC/JWT。当前真实 API 为：

| API | 语义 |
|---|---|
| `GET /adm/v1/policy` | 读取 singleton policy aggregate |
| `PUT /adm/v1/policy` | 校验并按 revision CAS 原子替换完整 aggregate |
| `GET|POST /adm/v1/actions` | 列出或创建 action |
| `GET|PUT|DELETE /adm/v1/actions/{action_id}` | action resource CRUD |
| `GET|POST /adm/v1/roles` | 列出或创建 role |
| `GET|PUT|DELETE /adm/v1/roles/{role_id}` | role resource CRUD |
| `GET|POST /adm/v1/role-bindings` | 列出或创建 role binding |
| `GET|PUT|DELETE /adm/v1/role-bindings/{binding_id}` | role-binding resource CRUD |
| `GET /adm/v1/principals` | 搜索本地 Principal 投影 |
| `GET|PATCH|DELETE /adm/v1/principals/{principal_id}` | 读取、更新状态或安全删除投影 |
| `POST /adm/v1/principal-discovery/search` | 对已配置 source 执行联邦搜索 |
| `POST /adm/v1/principal-discovery/materialize` | 服务端重新 resolve 并物化候选 Principal |
| `POST /adm/v1/principal-discovery/scim/refresh` | ingestion 一条 RFC 7643 User/Group 子集变化 |
| `POST /adm/v1/authorize` | 运维/调试用显式 URN 决策 |
| `GET /adm/v1/status` | 查询 policy revision 与资源计数 |

当前随服务发布的联邦 connector 为 Keycloak、直接 RFC 4511 LDAP，以及配置化
HTTP + bearer-JWT 的 custom connector（集成企业自研身份系统）；LDAP/AD 用户也可
通过 Keycloak federation 间接搜索。SCIM 路径是 RFC 7643 User/Group 子集的增量
ingestion adapter，不是完整 RFC 7644 SCIM Server，也不提供 `/scim/v2/Users` 或
`/scim/v2/Groups`。

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

`IPrincipalDiscovery<Input>` 统一这些路径：

- `JitPrincipalDiscovery`：已验证 OIDC `(iss, sub)` 的按需本地投影；
- `KeycloakPrincipalDiscovery`：Keycloak Admin API 有界并发搜索（`FED_KEYCLOAK`）；
- `LdapPrincipalDiscovery`：直接 RFC 4511 LDAP 搜索（`FED_LDAP`）；
- `CustomPrincipalDiscovery`：配置化 URL/请求/响应映射 + bearer JWT 的企业自研系统搜索（`FED_CUSTOM`）；
- `ScimPrincipalDiscovery`：RFC 7643 User/Group 子集 upsert/delete normalization。

联邦搜索和 SCIM ingestion 只在控制面运行；extAuth 热路径只读取本地 Principal
repository 与 policy snapshot。Principal 每次按 `issuer + external_id` 批量读取，不进入
`IAuthorizationCache`，因此禁用或撤销不会等待 cache TTL。默认 `groups_claim` 为
`authguard_group_ids`；Keycloak 必须提供稳定 group UUID，name/path 只作展示。

## 7. Helm 与可观测性

`deploy/helm/authguard` vendored Envoy Gateway `v1.9.0` 和 Redis Cluster chart。默认安装
Envoy Gateway 与 Redis；已有兼容 Envoy Gateway 的集群可设置
`envoy-gateway.enabled=false`，同时保持 `envoy_gateway.ext_authz.enabled=true` 应用 gRPC
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
