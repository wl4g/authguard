# Authguard IAM 当前能力边界与后续缺口

- 状态：Open Plan
- 更新日期：2026-11-15
- 基准：当前 `src/authz`、四语言 SDK、Helm 与 customer-growth E2E

本文只记录尚未实现或仍需产品决策的能力，不重复把已落地功能列为缺口。现行正式模型见
[统一 AuthN/AuthZ 设计规范](../architecture/Authguard-AuthN-AuthZ-Whitepaper_ZH.md)。
企业准入、成员关系与策略一致性的源码证据及优先级统一见该规范的
[R1–R7 审查](../architecture/Authguard-AuthN-AuthZ-Whitepaper_ZH.md#reference-implementation)。

## 1. 当前已落地基线

- AuthZ 五表 schema：`iam_principal`、`iam_action`、`iam_role`、`iam_role_action`、
  `iam_role_binding`；不持久化冗余的 `iam_policy` aggregate。
- SQLite 单机/开发 repository 与 PostgreSQL 共享持久化 repository；策略跨副本一致性尚未完成。
- `model/` 只承载协议无关的 IAM 实体，HTTP DTO 归属 handler，SQL 行映射封装在
  对应 `*_sqlite.rs` / `*_postgres.rs`；两种数据库实现分别加载
  `migration/20260904195419/{sqlite,postgres}/` 下的 `init.ddl.sql`/`init.dml.sql`。
- Memory/Redis Cluster `IAuthorizationCache` 仅保存 opaque scope-token context；
  `PolicyRuntime` 独立持有进程内编译授权目录。
- Envoy v3 extAuth gRPC、HTTP tuple-to-URN matcher、显式 DENY 优先与默认拒绝。
- source IP CIDR、method、secure transport、MFA、subject claims 条件。
- AuthN Provider engine、ExternalIdentity normalization、显式 Account Linking 与
  `iam_principal_identity` binding；Keycloak 联邦搜索/materialization、SCIM 子集 ingestion
  保留为 AuthZ 可选管理面集成。
- AuthN `LdapRoutes`/`LdapHandler` 的独立密码登录，支持 LDAPS/StartTLS、稳定 subject、
  JIT 与预授权绑定复用；查询 SA bind 与用户 bind 分开，失败不回退到 standalone。
- AuthZ 每次按 canonical `principal_id` 从 repository 批量读取，不进入 cache；
  `stable_group_ids` 使用内部稳定的 GROUP Principal ID，不直接使用 provider-local ID。
- actions、roles、role bindings 完整 CRUD；Principal 本地查询、状态更新与安全删除；
  授权目录的读取和完整事务替换。
- Java、Go、Python、Rust adapters 的 direct-header 与 gRPC token resolver；每语言
  46 个同构 SDK 场景以及五实现共享的 53 个业务授权场景。

## 2. Principal discovery 与 provisioning 缺口

### 2.1 SCIM 不是完整 RFC 7644 Server

当前 `/scim/v2/Users` 与 `/scim/v2/Groups` 实现 RFC 7643 User/Group 有界字段的
GET/POST/PUT/PATCH/DELETE。尚未实现：

- ServiceProviderConfig、ResourceTypes 与 Schemas discovery；
- 复杂 SCIM filter/PATCH path、排序与 Bulk；
- provisioning client 独立 scope/mTLS 认证模型。

是否演进为完整 SCIM Server 应由明确的企业 provisioning 需求驱动；在此之前文档和 API
只称其为 SCIM subset ingestion。

### 2.2 联邦 connector 覆盖范围

当前实际发布的 AuthZ 管理面 federated connector 为：Keycloak（可间接搜索其 LDAP/AD federation
用户）、直接 RFC 4511 LDAP，以及配置化 HTTP + bearer-JWT 的
  `CustomPrincipalDiscovery`（覆盖企业内部自研系统，如 DSP 目录）。尚未发布
AWS/GCP 等云 IAM connector。扩展实现应继续遵循 `IPrincipalDiscovery<Input>` 统一
契约（`provider()` 标识协议、`discover` 执行搜索、`resolve_principal` 服务端重新
解析）。管理面可使用预分配或已有的 canonical `principal_id` 物化从未登录的用户，
登录时按相同 identity key 复用；来源协议不进入 AuthZ 数据面。

## 3. 条件与策略能力缺口

当前 `conditions` 尚未支持：

- time window、日期或工作时段；
- business resource tags/attributes；
- 数值比较、集合操作和可扩展 operator registry；
- 独立的 condition schema/version 迁移策略。

新增条件必须保持缺少可信属性时 fail closed，并避免让 Authguard 数据面同步查询业务表。

## 4. 审计与控制面缺口

- 目前有 Prometheus/OTel 运行观测，但没有 append-only 授权审计 event store。
- 当前控制面使用单一独立 Bearer token；尚未实现细粒度 admin Principal/action 授权、
  key rotation workflow 或 mTLS 管理入口。
- v1 没有 policy revision 历史、回滚 API 或差异审阅 UI。
- 当前 policy revision 只存在于进程内，repository 读取固定返回 revision 1；需要持久化 CAS、
  跨副本发布/失效与重启版本连续性。schema 的 RoleBinding 主键为 `id`，没有 `policy_id`。

## 5. 企业场景新增要求

- 集团批准的登录/模块准入必须成为本地细粒度授权的上限，不能被普通 ALLOW 覆盖。
- SCIM `members` 持久化尚未参与请求中的成员关系判定，需要稳定 ID crosswalk、
  可撤销的成员/准入投影和明确的新鲜度预算。
- 直接 LDAP 用户登录已完成，R5 已关闭；AuthZ discovery 继续只使用查询 SA，分别配置。
- `type: custom` 当前在 Provider 组装时报错；专有 DSP Adapter 注册与直接 SPNEGO 未实现。
- workload → 业务 API 的身份类型、DSP 联邦与用户委托需要明确契约；该链路必须接入 AuthGuard。
- workload → 原生资源的认证鉴权由产品执行。自建资源走 DBA 工单，云权限走
  `workload-iam-sot` 项目 IAM policy PR → Terraform，不属于 AuthGuard 的功能缺口。

## 6. 明确不属于当前缺口的边界

- AuthZ 不实现 password、session、OAuth callback、token exchange、LDAP bind 或通用 API
  Gateway；这些认证协议能力属于 AuthN Provider Adapter，入口仍由 Envoy 统一承载。
- 不新增 `iam_resource` 作为授权正确性的依赖；业务资源继续由业务数据库维护。
- 不支持任意 regex Resource URN，`**` 只允许作为 resource path 的最后一段。
- Group Principal 与用户属于该组的 membership 是两个概念；核心是否使用独立表可按实现决定，
  但不能再以“不维护 membership”为由排除企业场景所需的可撤销可信成员关系投影。
