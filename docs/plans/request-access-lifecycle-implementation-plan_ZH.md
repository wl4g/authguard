# 请求级访问上下文完整生命周期实施计划

- 状态：当前已落地契约
- 范围：`authguard-authn`、`authguard-authz`、四语言 adapters、Envoy Gateway Helm、Redis Cluster、
  `use-cases/customer-growth-job-service`
- 原则：认证与授权解耦；默认拒绝；Principal 状态每次从 repository 校验；请求头不可由客户端伪造；
  direct/token 两种交付使用同一版本化访问上下文。

## 1. 目标链路

```text
External IdP -> Envoy Gateway native OIDC/JWT or authguard-authn Provider Adapter
  -> AuthenticatedPrincipalContext (canonical principal_id)
  -> authguard-authz gRPC Authorization/Check
  -> repository batch lookup for active Principal IDs
  -> L1 compiled policy evaluation (durable policy repository is source of truth)
  -> x-authguard-context OR x-authguard-scope-token
  -> SDK IAccessContextResolver
  -> action-aware SQL scope
  -> business repository CRUD
```

登录 JWT 不保存资源 URN。Authguard 根据当前 principal、groups、action、Resource URN
和 IP/TLS/MFA/claims 条件实时生成 allow/deny URN expressions。

## 2. 数据契约

1. 访问上下文当前版本为 v3，canonical 字段固定为：
   `principal_id`、`action`、`resource_urn`、allow/deny URNs、`policy_revision`、
   `issued_at_epoch_seconds`、`expires_at_epoch_seconds`。
   四语言 decoder 仅为 v3 过渡接受 `subject_id`/`policy_version` 别名；新编码结果只输出
   canonical 字段，v2 版本会被拒绝。
2. `authguard.access.v1.AccessContextService/ResolveScope` 独占 `:8081` gRPC listener；
   请求携带短期 opaque scope token，响应携带同一编码访问上下文。Envoy
   `Authorization/Check` 独占 `:8080`，workload SDK 不得访问该 listener。
3. 固定受信头：`x-authguard-context` 与 `x-authguard-scope-token`。二者同时出现或
   均缺失均拒绝；adapter 不再解析业务请求的 `Authorization`。
4. token 使用至少 256 bit CSPRNG，Redis key 只保存 token SHA-256，值设置 TTL；
   token 不写日志、不进入 metrics label。

## 3. AuthZ 与缓存

Core 分层中，扁平的 `model/` 统一保存与存储无关的授权业务模型、SQL-scope 语义和
HTTP/gRPC DTO；SQLite/PostgreSQL 行映射只存在于对应 `*_sqlite.rs` / `*_postgres.rs`，route/handler
不依赖持久化行结构。

1. `authz.scope_delivery` 新增：
   - `direct_urn_limit`：allow + deny 数量小于或等于该值时候选 direct；
   - `max_direct_header_bytes`：头大小的第二道上限；
   - `context_ttl`、`scope_token_ttl`。
2. 顶层 `cache` 提供 Memory/Redis 多实现与 Redis nodes、用户名、密码、连接/
   响应超时和 key prefix；`IAuthorizationCache` 只保存 opaque scope-token context。
3. 热路径始终读取 `PolicyRuntime` 的进程内不可变编译快照。后台从 durable repository
   按 revision 刷新各副本。policy 与 Principal 均不进入 Memory/Redis；
   每次鉴权按 canonical `principal_id` 批量读取 repository，确保禁用/撤销立即 fail closed。
4. control-plane 更新顺序：编译校验 -> SQLite/PostgreSQL 原子写 -> 当前进程
   `PolicyRuntime` 原子发布。其他副本继续按 revision 从 repository 刷新。
5. direct 交付不要求 Redis；token 交付和 `ResolveScope` 必须成功访问 token store，
   否则 fail closed。
6. Prometheus 已记录 direct/token delivery、scope resolve 的 hit/miss/invalid/error 与
   resolution latency；Grafana 当前面板覆盖 decision、latency、management HTTP、policy
   reload/revision。

## 4. Envoy Gateway 与 Helm

1. `SecurityPolicy.jwt` 支持两种互斥配置：
   - `localJWKS`：values 提供 IdP 公钥对应的标准 JWKS JSON，模板生成 ConfigMap；
   - `remoteJWKS`：配置 issuer、audience 与 JWKS URI。
2. JWT 验证与 gRPC `extAuth` 合并到同一个 SecurityPolicy；`failOpen=false`。
3. Authguard `OkHttpResponse.headers_to_remove` 删除 `authorization`、
   `x-authguard-context`、`x-authguard-scope-token`，随后只覆盖注入一种访问上下文。
4. Redis Cluster 作为 Authguard 边界下的可选内建工作负载；生产也可引用外部 Secret
   和节点列表。默认外部镜像全部使用：
   - `registry.cn-shenzhen.aliyuncs.com/wl4g/envoyproxy_envoy:distroless-v1.36.4`
   - `registry.cn-shenzhen.aliyuncs.com/wl4g/envoyproxy_gateway:v1.9.0`
   - `registry.cn-shenzhen.aliyuncs.com/wl4g-k8s/bitnami_redis-cluster:7.0.14`
5. Keycloak 只属于 use-case E2E，使用
   `registry.cn-shenzhen.aliyuncs.com/wl4g/keycloak:26.7.0`，不进入 Authguard 生产 chart。
6. 默认 NetworkPolicy 将 `:8080` 限制给 Envoy，将 `:8081` 限制给
   `authguard.io/scope-client` workload，避免 SDK 调用 context 签发 RPC。

## 5. 四语言 SDK

Java、Go、Python、Rust 统一保留 `access/filter/model/util` 边界，并提供：

- `IAccessContextResolver`；
- `HeaderAccessContextResolver`：读取并校验 Envoy 注入的 v3 direct context；
- `GrpcAccessContextResolver`：读取 token，通过复用连接的 gRPC client 调
  `ResolveScope`；
- `AUTHGUARD_GRPC_TARGET` 初始化复用 channel；该值是 gRPC target（例如
  `authguard.authguard.svc.cluster.local:8081` 或
  `dns:///authguard.authguard.svc.cluster.local:8081`），不是 REST base URL；
- `AUTHGUARD_GRPC_TLS` 控制传输安全，默认关闭以适配集群内受保护的明文 HTTP/2；
- resolver chain：拒绝歧义头，direct 与 token 二选一；
- filter/interceptor：设置当前 request access，异常与请求结束后可靠清理；
- action-aware SQL scope：缺失、过期、动作不匹配全部 fail closed。

四种 SDK 的 resolver、过期、防伪、gRPC error 与 SQL 场景名称和数量保持一致。

## 6. customer-growth-job-service E2E

1. 保留五实现 CRUD/SQL 共享场景；fixture 使用 canonical v3 context。
2. Go/sqlx、Rust/sqlx、Python/SQLAlchemy、Spring JDBC、Spring JPA 五个项目都提供
   可实际启动的 HTTP workload，完整使用 middleware/interceptor、resolver chain 和
   repository SQL scope，不允许测试绕过入口直接写请求上下文。
3. 增加隔离 namespace 的完整部署 verifier：每轮清理并重新部署 Keycloak、Redis
   Cluster、Envoy Gateway、Authguard、共享 PostgreSQL 和五个 workload。
4. Keycloak realm 包含 direct-reader 与 token-editor；runner 从 token endpoint 登录并
   获取真实签名 Access Token。
5. 至少验证：无 JWT、坏签名、错误 issuer/audience、客户端伪造两个 Authguard 头、
   direct context、scope token、token miss/过期、Redis 暂时不可用、IP/TLS/MFA 条件、
   allow/deny、`*`/`**`、action mismatch 以及 CRUD SQL scope。
6. E2E 不依赖外部 IdP、数据库或 SaaS；所需组件全部由本地 Helm/Kubernetes 启动。
   五个服务共享 `e2e_customer_growth` PostgreSQL database，但使用五个独立 `e2e_` schema
   和登录角色，支持开发机和 CI，报告继续归档到 `e2e/reports/`。

## 7. 验收门槛

- `cargo fmt --check` 与 `cargo clippy --workspace --all-targets -- -D warnings`；
- Rust workspace、Java、Go、Python 全量 UT；
- 四语言 resolver/SQL 契约严格同构且每种 46 个场景（22 access/filter/resolver +
  24 codec/URN/SQL）；
- `make e2e` 现有 portable 53 场景全部通过；
- 完整 lifecycle E2E 同时覆盖 direct 与 scope-token 两条链路；
- Helm 默认/local-JWKS/remote-JWKS/外部 Redis 四种 values 渲染通过；
- `git diff --check`、旧 Bearer 资源授权范围 resolver/非 canonical context 输出扫描无残留；
- 构建产物清理，宿主机 CPU、内存和 I/O 回落正常。
