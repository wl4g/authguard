# Authguard IAM 当前能力边界与后续缺口

- 状态：Open Plan
- 更新日期：2026-09-03
- 基准：当前 `src/core`、四语言 SDK、Helm 与 customer-growth E2E

本文只记录尚未实现或仍需产品决策的能力，不重复把已落地功能列为缺口。现行正式模型见
[IAM 授权白皮书](../architecture/iam-authorization-whitepaper_ZH.md)。

## 1. 当前已落地基线

- 六表 schema：`iam_policy`、`iam_principal`、`iam_action`、`iam_role`、
  `iam_role_action`、`iam_role_binding`。
- v1 使用 singleton `iam_policy` aggregate 与 revision CAS，不提供多 policy collection。
- SQLite 单机/开发 repository 与 PostgreSQL 多副本 repository。
- 扁平的 `model/` 统一承载与存储无关的授权业务模型和 HTTP/gRPC DTO，并与
  `storage/record.rs` 持久化行记录隔离；两种 repository 共用
  `001_init.ddl.sql`/`001_init.dml.sql` migration。
- Memory/Redis Cluster `IAuthorizationCache` 仅保存 opaque scope-token context；
  `PolicyRuntime` 独立持有不可变进程内编译快照。
- Envoy v3 extAuth gRPC、HTTP tuple-to-URN matcher、显式 DENY 优先与默认拒绝。
- source IP CIDR、method、secure transport、MFA、subject claims 条件。
- Principal JIT projection、Keycloak 联邦搜索/materialization、SCIM 子集 ingestion。
- Principal 每次按 `issuer + external_id` 从 repository 批量读取，不进入 cache；默认
  `authguard_group_ids` 使用 issuer-local 稳定 group ID（Keycloak UUID）。
- actions、roles、role bindings 完整 CRUD；Principal 本地查询、状态更新与安全删除；
  singleton policy 的读取和完整原子替换。
- Java、Go、Python、Rust adapters 的 direct-header 与 gRPC token resolver；每语言
  46 个同构 SDK 场景以及五实现共享的 53 个业务授权场景。

## 2. Principal discovery 与 provisioning 缺口

### 2.1 SCIM 不是完整 RFC 7644 Server

当前 `POST /adm/v1/principal-discovery/scim/refresh` 只接收 RFC 7643 User/Group 有界字段
的 upsert/delete 变化。尚未实现：

- `/scim/v2/Users`、`/scim/v2/Groups` 标准资源端点；
- ServiceProviderConfig、ResourceTypes 与 Schemas discovery；
- SCIM filter、pagination、PATCH/Bulk 与标准错误响应；
- provisioning client 独立 scope/mTLS 认证模型。

是否演进为完整 SCIM Server 应由明确的企业 provisioning 需求驱动；在此之前文档和 API
只称其为 SCIM subset ingestion。

### 2.2 联邦 connector 覆盖范围

当前实际发布的 federated connector 是 Keycloak；Keycloak 可间接搜索其 LDAP/AD
federation 用户。尚未发布直接 LDAP、AWS/GCP IAM 或自研 IdP connector。扩展实现应继续
遵循 `IPrincipalDiscovery<Input>` 与 `IPrincipalResolver`，不得把来源协议泄漏到 handler
或 storage。

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
- `iam_role_binding` 当前只以 `(policy_id, id)` 保证唯一，不做内容级重复 binding 去重。

## 5. 明确不属于当前缺口的边界

- Authguard 不实现 password、session、OAuth login、LDAP bind 或通用 API Gateway。
- 不新增 `iam_resource` 作为授权正确性的依赖；业务资源继续由业务数据库维护。
- 不支持任意 regex Resource URN，`**` 只允许作为 resource path 的最后一段。
- 不在六表核心内维护本地 group membership；group 由受信认证上下文/discovery 投影为
  `GROUP` Principal。
