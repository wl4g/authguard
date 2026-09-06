# Authguard - 企业级统一 IAM 认证+资源级鉴权系统设计

- **状态：** Architecture Baseline
- **日期：** 2026-09-03
- **适用范围：** Authguard / Envoy Gateway external authorization / 通用企业 IAM / 多语言业务服务
- **当前落地：** 单 Authguard Rust 服务、Envoy Gateway 集成、adapters 与 use-cases

## 1. 摘要

- 本文定义一套通用、独立、企业级的资源授权架构。它不绑定任何具体业务系统；业务微服务只需要把自身对象抽象成受保护资源，通过统一 Resource URN、action、role、role binding、condition 与业务端 adapter SDK 完成权限控制。

- Authguard 是深度集成 Envoy Gateway 的独立授权平面。Envoy Gateway 负责入口、OIDC/JWT 认证、路由和流量治理；Authguard 把传统企业 RBAC 与面向资源的 URN 授权合并为同一套模型，使 external authorization 数据面和业务 adapter 可以用同一套 policy 回答两个问题：

  1. 当前 Principal 是否能对某个具体资源执行某个 action？
  2. 当前 Principal 在业务服务数据库查询中能看到哪些资源行？

- 从 B2B / B2C 场景的多账号、多角色、多资源访问控制管理角度看，Authguard 更适合 2B 与 2B2C 系统。核心边界不是业务标签，而是系统是否存在多人或多个系统主体协作，且不同主体在同一团队、租户或资源集合内承担不同角色、拥有不同资源访问范围。企业客户增长分析任务、企业 SaaS、云资源平台、数据平台、供应链/采购、企业资金管理等场景通常具备这些特征。2C 系统也可以使用同一 URN 模型，尤其是商家后台、平台运营、客服、风控、审计等复杂后台；但如果只是“消费者只能访问自己的订单”这类简单所有权过滤，直接字段条件通常足够，完整 IAM 授权平面会偏重。

- 核心结论：

  - 认证只回答“调用方是谁”。
  - 授权只回答“调用方能对哪个资源执行什么动作”。
  - `iam_principal` 是外部系统已认证身份在授权侧的投影，不保存认证凭据。
  - `USER`、`WORKLOAD`、`GROUP` 统一为 Principal；OIDC 身份必须以
    `(issuer, external_id)` 唯一识别，其中 `external_id` 为 `sub`。禁止使用裸
    `sub`、email 或 username 作为身份唯一键。
  - 权限动作使用 `iam_action`，角色使用 `iam_role`，角色动作关系使用
    `iam_role_action`，授权关系使用 `iam_role_binding`。
  - `IPrincipalDiscovery<Input>` 统一可信 JIT (Just-In-Time) 投影、管理面联邦搜索和 RFC 7643
    User/Group 子集 ingestion。
    三条路径都规范化并幂等物化同一条 `iam_principal`；数据面仅可对已验证身份执行本地
    JIT，联邦搜索和 SCIM ingestion 不进入数据面鉴权依赖链。
  - 资源身份使用基于 RFC 8141 URN 语法风格的 `urn:iam:...` 统一资源名称。
  - IAM 核心不维护 `iam_resource` 资源表；资源真相由业务系统自己的表维护。
  - request 四元组只用于 route/resource matcher，不作为资源权限模型本身。
  - 资源列表查询由业务 Resource Adapter 将 action 对应的 `AuthorizationScope` 编译成
    业务 SQL scope。

- 标准部署由 Envoy Gateway controller、其管理的 Envoy Proxy 数据面和单 Authguard 镜像组成。Authguard 不重复实现通用 API Gateway，也不在业务服务内复制 evaluator；业务服务只通过 adapter 消费 Envoy 转发的受信访问上下文。

### 1.1 全局物理调用视图

- 控制面（e.g, B2B 场景预授权）：管理员给新员工 Bob 或新微服务 workload 预授权，此时 Bob/Workload 可能从未访问过应用：

```text
Admin UI/API: "search Bob/Workload"
  │  POST /adm/v1/principal-discovery/search          (parallel pull)
  ▼
federation fan-out:
  KeycloakPrincipalDiscovery  ─▶ Keycloak Admin API
  LdapPrincipalDiscovery      ─▶ LDAP (RFC-4511)
  CustomPrincipalDiscovery    ─▶ HTTP + pre-issued bearer JWT
  │  candidates: (issuer, external_id) + display metadata, not materialized yet
  ▼
POST /adm/v1/principal-discovery/materialize
  └─▶ server-side re-resolve (anti-spoofing) ─▶ upsert iam_principal
POST /adm/v1/role-bindings
  └─▶ iam_role_binding(effect + resource URN + conditions)

converge on the same iam_principal:
  SCIM push (RFC 7643/7644)   ─▶ IdP lifecycle events (pre-provision / disable)
  JIT projection (data plane) ─▶ first verified request
```

- 数据面（e.g, Bob/Workload 的一次业务请求）：

```text
User(Bob) ─ (e.g, on Windows/macOS AD login with Kerberos TGT ─▶ SSO(WWW-Authenticate: Negotiate) ─▶ IdP/DSP/Keycloak get access token)
Workload(Service Account)  ─ (e.g, on GKE internal google-flavor auth ─▶ GCP IAM get access token)
  │
  ▼
Envoy Gateway: verify JWT (iss, aud, JWKS)
  │
  ▼ gRPC ext_authz
Authguard:
  · db: load policies from iam_principal projection + iam_role/binding
  · route_matchers: validate method / path / query params / path params
  · conditions: validate headers / MFA / trusted claims
  │
  ▼ ALLOW
  ├─▶ small lists: x-authguard-context header (direct allow/deny URNs)
  └─▶ large lists: x-authguard-scope-token ─▶ Redis IAuthorizationCache
  └─▶ optional business JWT: Authguard 重签 RS256 JWT（携带
      `authguardOrigin: true`）并覆盖 authorization 头
  │
  ▼
Envoy forwards the request
  │
  ▼
Business Microservice
  │  adapter SDK: IAccessContextResolver
  │    HeaderAccessContextResolver ─▶ Local Read from headers directly. (short lists)
  │    GrpcAccessContextResolver   ─▶ Remote Read from Authguard. (large lists)
  │  optional: 以 Authguard 公钥验证 business JWT
  ▼
SQL WHERE scope ─▶ row-level fine-grained data permissions
```

两侧收敛到同一个 `iam_principal`：控制面预授权与数据面 JIT 投影都只物化受信身份的稳定
标识与展示元数据；数据面热路径绝不回调 IdP / LDAP / SCIM，adapter 解析或编译失败即
fail closed。

### 1.2 最小模型

```text
principal(USER / WORKLOAD / GROUP)
  ─ role binding(effect, resource URN, conditions)
  ─ role
  ─ role action
  ─ action
```

role binding 的资源目标是 Resource URN：

```text
urn:iam:<partition>:<service>:<region>:<tenant>:<resource-path>
```

示例：

```text
urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score
urn:iam:prod:github:global:octo-org:repo/payment-service
urn:iam:prod:s3:us-east-1:123456789012:bucket/audit-logs/object/2026/08/**
```

Wildcard 规则必须保持小而可预测：

- `*` 匹配一个 segment。
- `**` 只允许作为 resource-path 的最后一个 segment。
- 不支持 `pay*` 这类 segment 内部分 wildcard。

这个限制是 Resource Adapter 能把 role binding 安全编译成 SQL predicate 的前提。

### 1.3 一个最小授权故事

Alice 通过 OIDC Provider 登录。Provider 只证明“这是 Alice”，不决定 Alice
能访问哪些业务资源。Envoy 验证 token 后，Authguard 对受信外部身份执行 JIT 投影：

```text
issuer      = https://idp.example.com/realms/company
external_id = 00u123                    # 已验证的 OIDC sub
kind        = USER
  -> iam_principal:alice
```

Alice 首次访问前，管理员也可以通过联邦搜索得到同一个 Principal。管理员把该
Principal 绑定到 `reader`：

```text
iam_principal:alice
  -> iam_role_binding
       effect       = ALLOW
       resource_urn = urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*
  -> iam_role:reader
  -> iam_role_action
  -> iam_action:customer-growth.job.read
  -> iam_action:customer-growth.job.run.read
```

当 Alice 请求查看某个客户增长分析任务的执行结果：

```text
GET /customer-growth/workspaces/customer-insights/projects/retention-analytics/jobs/daily-churn-risk-score/runs/run-123
```

route matcher 生成：

```text
action       = customer-growth.job.run.read
resource_urn = urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score/run/run-123
parent_urns  = [
  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score,
  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics,
  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights
]
```

授权器发现 Alice 的 active role binding，`reader` role 包含
`customer-growth.job.run.read`，且 binding pattern 覆盖该任务，于是允许请求。

## 2. 设计目标

### 2.1 功能目标

- 接收 Envoy Gateway 已验证的 OIDC/JWT user、service account 与 workload identity。
- 支持 principal、role、role binding、action catalog、condition 与 route/resource matcher。
- 通过可信 JIT (Just-In-Time) 投影、管理面联邦搜索和 RFC 7643 User/Group 子集 ingestion 发现 Principal，
  无需预加载 IdP 全量账号。
- 支持平台级、租户/组织/域级、资源级授权。
- 支持 GitHub 风格的 organization/repository 授权体验，但不绑定 GitHub 领域模型。
- 支持任意业务资源类型，例如 repository、customer-growth job、bot、workflow、dataset、channel。
- 支持资源层级继承，例如 workspace owner 可继承访问其下 customer-growth job。
- 通过 Envoy Gateway external authorization 强制拦截。
- 支持 UI 读取 auth context 用于菜单、按钮、无权限状态控制。
- 通过 Prometheus/OTel 观测授权判定和管理请求；认证审计由 Envoy/IdP 负责，持久化
  授权审计 event store 尚未实现。

### 2.2 工程目标

- 高内聚：protocol route、authorization evaluator、policy runtime、identity resolver、
  persistence 与 observability 各自职责明确，并通过窄接口协作。
- 低耦合：IAM 核心不依赖具体业务表结构。
- 无重复：identity 不拆表重复字段，route matcher 不拆多张半结构化表，资源目录不在 IAM 核心重复维护。
- 可跨语言实现：Java、Go、Python、Rust 共享数据语义、授权算法和测试契约。
- 单一部署形态：Authguard 是 Envoy Gateway 的独立外部授权服务，adapter 只负责业务访问上下文和 SQL scope。

### 2.3 非目标

- 不把 UI 权限隐藏当作安全边界。
- 不镜像外部身份系统中的所有账号。
- 核心鉴权链路不要求 SCIM 全量镜像或预加载；RFC 7643 User/Group 子集 ingestion
  是已实现但按需启用的增量生命周期集成，不是完整 RFC 7644 Server。
- 不实现通用 API Gateway、OIDC session、登录页面或 IdP。
- 不把 request method/path/query 当作资源权限模型。
- 不在 IAM 核心维护业务资源生命周期。
- 不支持任意 regex 资源授权 pattern；v1 只支持可下推查询的有限 wildcard。
- 不保留旧兼容模型。

### 2.4 与其他策略引擎的关系与边界

| 维度 | OPA / SpiceDB / Cerbos | Authguard |
|---|---|---|
| 身份获取闭环 | 无身份管道，身份数据全靠外部自喂 | 内置联邦搜索（Keycloak/LDAP/custom）+ SCIM + JIT，管理员搜人 → 绑定 → 未登录即生效 |
| 行级数据过滤 | OPA 仅 partial-evaluation 社区玩法；Cerbos 只有查询计划 | 同一条 role binding 经 adapter SDK 编译为 SQL WHERE |
| 模型可下推性 | Rego 图灵完备，任意策略无法保证编译成 SQL 谓词 | 收敛 URN + 有限 wildcard（`*`/`**`），正是安全下推的前提 |
| 决策交付语义 | OPA-Envoy 允许后按 Rego 自定义 headers | 双模：小列表直携 `x-authguard-context`，大列表 scope-token → Redis + gRPC |
| 主战场 | OPA = K8s admission / 任意领域规则 | Authguard = 2B/2B2C 企业资源授权闭环 |

两类定位互补而非替代：K8s admission 等通用领域是 OPA 主场、属 Authguard 非目标；
若未来需超出 `conditions` 的任意 ABAC，可在 `ConditionsMatch` 求值点内嵌
Rego/Cedar，主模型不变。

## 3. 总体模型

统一授权链路：

```text
external identity
  -> iam_principal
  -> iam_role_binding(effect + resource URN + conditions)
  -> iam_role
  -> iam_role_action
  -> iam_action
  -> authorization decision
```

单请求判定链路：

```text
HTTP request
  -> Envoy Gateway authn filter
  -> route/resource matcher
  -> action identifier
  -> resource URN + parent resource URNs
  -> effective role bindings
  -> role/action check
  -> condition check
  -> ALLOW / DENY
```

资源列表查询链路：

```text
current principal
  -> requested action 对应的 role-binding 求值
  -> AuthorizationScope(allow Resource URNs, deny Resource URNs)
  -> business Resource Adapter
  -> SQL predicate / query scope
  -> business DB
```

### 3.1 核心关系图

```text
verified identity ─────▶ iam_principal
                              │
                              ▼
                     iam_role_binding
                   effect + resource_urn
                         + conditions
                              │
                              ▼
                          iam_role
                              │
                              ▼
                       iam_role_action
                              │
request ── matcher ─────▶ iam_action
                              │
                              ▼
                     decision: ALLOW / DENY
```

其中只有业务系统知道资源表结构。IAM 只看 Resource URN 和 action；业务 Resource Adapter 负责把 binding pattern 翻译成业务查询条件。

## 4. 核心概念

### 4.1 Principal

Principal 是唯一的授权主体抽象。通过 `kind` 区分 `USER`、`WORKLOAD`、`GROUP`，
使人工用户、service account、微服务 workload 与外部管理的组使用同一套 role binding，
无需增加 Principal 子类型表。

`iam_principal` 是稀疏的授权侧投影，不是身份真相源。它只保存已经经过可信认证流程
访问过系统，或被管理员选择进行授权的 Principal；不保存密码、session、MFA secret
或外部系统的完整用户画像。

### 4.2 外部身份引用

每个投影 Principal 都使用来源系统的稳定引用：

```text
issuer + external_id
```

对 OIDC 而言，`issuer` 是精确规范化的 `iss` claim，`external_id` 是已验证的
`sub` claim。OpenID Connect 只保证 `iss + sub` 组合是 issuer 范围内唯一且不会
重新分配的 End-User 标识。裸 `sub` 在不同 issuer 之间可能冲突；email、username、
display name 都可能变化或被重新分配，禁止作为身份唯一键。

Group 同样必须使用 issuer-local 稳定 ID。默认 `auth.identity.groups_claim` 为
`authguard_group_ids`；Keycloak 集成要求 claim 值为 group UUID，并将它规范化为
`external_id = group:<UUID>`。JIT 与 Keycloak 联邦 discovery 使用同一 UUID，避免按
group name/path 与 UUID 物化出两个 Principal。group name、display name 与 path 只作
展示元数据，禁止作为 role-binding 的稳定授权键。

LDAP、SCIM、云 IAM 或企业自研 IdP 由 `IPrincipalDiscovery<Input>` 将来源系统的稳定账号
ID 规范化为同一个二元组。`issuer` 使用该来源配置的 canonical authority URI；如果
来源系统不能保证不同 Principal kind 的 ID 全局唯一，对应实现必须先给
`external_id` 增加类型命名空间再投影。人类可读的 profile 字段只作为展示元数据。

### 4.3 Principal 发现与投影

Authguard 在统一的 `IPrincipalDiscovery<Input>` 公共边界后实现三条互补的身份进入路径：

1. **可信 JIT (Just-In-Time) 投影：** Envoy 验证 user/workload token 后，Authguard 以
   `(issuer, external_id)` 幂等 upsert。只记录真正访问过受保护应用的身份。
2. **管理面联邦搜索：** 管理员在 Authguard UI/API 为员工账号、机器/service account
   或其他 workload 账号配置权限策略时，通常不知道外部认证标识符（OIDC `sub`、
   LDAP `entryUUID` 等）。管理员从已配置的 discovery source 搜索候选人；随服务发布的
   connector 包括 Keycloak Admin API（也可看到由 Keycloak 从 LDAP/AD 联邦而来的身份）
   和直接 RFC 4511 LDAP。选中后由服务端按稳定引用重新 resolve，再物化 Principal 并
   创建 role binding。
3. **SCIM 子集 ingestion：** 已实现 adapter 接收 RFC 7643 User/Group 的有界字段，
   并将 user/group upsert 或 delete 事件规范化为相同 Principal 投影。delete 会将
   已投影 Principal 标记为 `DISABLED`。

联邦搜索需要覆盖账号标识符；`GROUP` 同样被搜索，但目的只是取回 group name/path
等展示元数据，供管理员在绑定 UI 中辨认候选者。稳定授权键始终是不可变的
`issuer + external_id`（如 `group:<UUID>`），绝不使用搜索结果里的展示名称。
搜索发现并展示外部 group，绝不把 Keycloak group、realm role 等外部对象复制成
Authguard 的第二套授权策略权威源。

三种模式适用不同授权场景，差异是结构性的。**JIT 投影**天然适配 2C 互联网平台的
个人用户授权：2C 场景天然是单所有者模型——用户之间不存在多人协作与不同权限的
共享数据，每个用户只拥有自己的数据，也不存在管理员为每个用户预先逐一授权的
过程。所有用户请求都经过同一个网关，因此首次注册/登录的已验证请求就是
Authguard 第一次观察到该身份的时机，JIT 当即物化 Principal，无需 provisioning
管道，也无需全量预加载目录。物化后的 Principal 同时支撑网关之后的纵深防御：
后端业务微服务可基于 Authguard 注入的 access context 做二次鉴权，将其编译为
SQL scope，使消费者只能 CRUD 自己的数据行。**SCIM ingestion 与联邦搜索**适配
2B 企业内部场景，结构正好相反：员工与 workload/service account 在不同权限下
协作，由管理员预先授权（往往早于账号首次登录），账号生命周期由 IdP/HR 系统
集中管理——联邦搜索负责找到外部标识符，SCIM 负责应用推送来的生命周期变化。

JIT + 联邦搜索是互联网平台的默认主路径，即使外部身份达到亿级，Authguard 也只保存
真正访问受保护应用或获得 binding 的 Principal。SCIM 子集 ingestion 按需启用，
且以增量事件为主；启用它不等于必须全量预加载。当前接口不是完整
RFC 7644 SCIM Server：没有 `/scim/v2/Users`/`Groups`、SCIM discovery、filtering 或
bulk protocol endpoints。SCIM delete ingestion 会将投影标记为 disabled，不级联删除 role binding。

SCIM provisioning 是 push-oriented：IdP 或 provisioning agent 作为 SCIM Client，主动把
账号生命周期变化发送给 Service Provider。adapter 的 `refresh` 含义是“应用这条已提交的
变化”，不是轮询 IdP。若特定来源必须 pull，应实现为独立的控制面 connector 或定时 bridge，
不能称为 SCIM；pull connector 与 SCIM Client 各自使用独立、最小权限的机器身份，且都不
进入数据面鉴权链路。

JIT 表示“首次观察且不存在时插入”，不是“每个请求都写数据库”。为避免 Principal
禁用或撤销受 TTL 影响，每次鉴权都按 `issuer + external_id` 批量查询本地 repository，
校验主 Principal 与 Group Principal 状态。认证账号禁用仍由 IdP/Gateway 与短期 Access
Token 约束；Authguard 本地 Principal 禁用和 role-binding 撤销立即 fail closed。

Keycloak 可以通过自身管理能力搜索已配置 LDAP/Active Directory federation 中的用户；
这是 Keycloak 能力，而不是 OIDC 标准能力。OIDC 定义认证与 claims，不定义对 issuer
全量用户执行管理搜索的 API。
Keycloak group、realm/client role、client scope 与 protocol mapper 仍可产生粗粒度身份
claims；Authguard 只发现稳定 Principal 标识和有界展示元数据，不把这些对象复制成第二套
授权策略权威源。

联邦搜索与 SCIM ingestion 严格属于控制面/provisioning 平面。数据面只根据受信身份引用
读取本地 Principal repository 和不可变策略快照；每次鉴权禁止实时请求 Keycloak、LDAP、
SCIM server 或云 IAM。`IAuthorizationCache` 只保存短期 opaque scope-token context，
不缓存 policy 或 Principal。策略求值使用进程内不可变 `PolicyRuntime`，后台按 revision
直接从 durable storage 刷新。

协议无关公共边界命名为 `IPrincipalDiscovery<Input>`，而不是
`IPrincipalDirectory` 或 `IPrincipalSearcher`：directory 只是来源类型之一，而
discovery 同时覆盖受信 JIT 身份、联邦搜索和 SCIM 子集生命周期事件。该泛型契约使用强类型
输入/输出，不设计一个带 unsupported mode 的 tagged 大请求：

```text
IPrincipalDiscovery<Input>
  provider() -> 'static str              -- JIT / SCIM / FED_KEYCLOAK / FED_LDAP / FED_CUSTOM
  provider_id() -> &str                  -- 配置的 discovery_id，写入每条投影
  Discover(input: Input) -> Output
  ResolvePrincipal(reference) -> Option<PrincipalProjection>

JitPrincipalDiscovery
  IPrincipalDiscovery<VerifiedOidcPrincipal> -> PrincipalProjection

KeycloakPrincipalDiscovery
  IPrincipalDiscovery<PrincipalSearchQuery> -> PrincipalSearchPage
  Keycloak Admin API connector, provider = FED_KEYCLOAK

LdapPrincipalDiscovery
  IPrincipalDiscovery<PrincipalSearchQuery> -> PrincipalSearchPage
  RFC 4511 connector, provider = FED_LDAP

CustomPrincipalDiscovery
  IPrincipalDiscovery<PrincipalSearchQuery> -> PrincipalSearchPage
  配置化 HTTP + bearer-JWT connector, provider = FED_CUSTOM
  以配置映射 request/response schema，集成企业内部自研系统

ScimPrincipalDiscovery
  IPrincipalDiscovery<ScimRefreshRequest> -> ScimProjectionEvent
  Refresh(input: ScimRefreshRequest) -> ScimProjectionEvent
```

每种实现只验证自己的强类型输入，并产出包含 canonical `issuer`、`external_id`、`kind`、
来源标识和有界元数据的强类型结果，用于统一 upsert `iam_principal`。storage 和
authorization handler 只消费规范化投影，不感知 OIDC、Keycloak、LDAP、custom HTTP、
云 IAM 或 SCIM 原始 payload。控制面流程为：

源码 API 注释链接当前实现的规范依据：JIT identity projection 链接 OpenID
Connect Core，Keycloak connector 链接 Keycloak Admin/User Storage 文档，LDAP
connector 链接 RFC 4511（协议）与 RFC 4515（过滤器）、RFC 2696（分页），SCIM 数据
规范化链接 RFC 7643 与 RFC 7644。custom connector 没有外部标准可引用：它是
企业内部自研系统（如企业 DSP 目录）的逃生通道——其 vendor API 没有公开协议，
通过配置化的 URL/请求/响应绑定加预签发 bearer JWT 完成映射。这些链接用于界定
协议责任，不表示 Authguard 已提供完整 RFC 7644 Server，也不是数据面运行依赖。

```text
GET  /adm/v1/principals
     -> 搜索本地投影
POST /adm/v1/principal-discovery/search
     -> 对请求选中的已配置来源执行联邦搜索
POST /adm/v1/principal-discovery/materialize
     -> 服务端重新 resolve 后物化候选 Principal
POST /adm/v1/principal-discovery/scim/refresh
     -> 接收一条 RFC 7643 User/Group 子集 upsert/delete 变化
POST /adm/v1/role-bindings
     -> 绑定内部 principal_id
```

外部 candidate 不能直接成为 binding target。物化后得到稳定的内部 `principal_id`，
由 `iam_role_binding` 引用。

每种协议最多允许**一个 active connector**（`FED_KEYCLOAK` / `FED_LDAP` /
`FED_CUSTOM`），配置校验在启动时拒绝重复条目，保证每个搜索结果候选无歧义：
每条结果携带来源 `provider_id` + `issuer`，其中 `provider_id` 是该
connector 配置的 `discovery_id`（协议标签只标识 connector 类型，例如用于
搜索过滤）。由于每种协议只配置一个 connector，该 discovery id 仍然唯一
对应一个 source，物化（materialize）时在同一 source 重新 resolve 后才
允许授予 role binding。管理员搜索仍会并行扇出到不同协议并合并分页结果，
但每条候选都能归因到唯一的来源。

Action 表示“要做什么”，使用点分隔命名，如：

```text
resource.read
resource.write
resource.delete
resource.access.manage
resource.run.trigger
resource.trace.read
domain.member.manage
platform.admin
```

底层表名使用 `iam_action`，不使用 `iam_permission`。原因是 permission 是最终授权结果，action 是可被 role 组合的原子动作。

资源目标不进入 action 字符串，而由 route/resource matcher 和 role binding 解析。

### 4.5 Role

Role 是 action 集合。常规授权应通过 binding 授 role，不直接给 Principal 散粒度 action。

通用内置角色建议：

| Role | Scope | 能力 |
|---|---|---|
| owner | resource/domain | 完整管理，包括 access |
| maintainer | resource/domain | 管理资源，不管理 access owner |
| writer | resource | 修改资源和触发执行 |
| operator | resource | 执行、取消、审批，不修改定义 |
| reader | resource/domain | 只读 |
| auditor | platform/domain | 只读审计与证据 |

### 4.6 Role Binding

Role Binding 是一条明确的授权关系：

```text
principal
  has one role
  on resource_urn
  with effect ALLOW or DENY
  under optional conditions
```

每行只绑定一个 Principal 与一个 Role。需要多个角色时创建多行，使撤销、唯一约束、
求值和审计保持简单。

### 4.7 Resource URN

受保护资源是任意业务对象。IAM 使用 Resource URN 表达资源身份。

本文采用基于 RFC 8141 URN 语法风格的内部统一资源名称：

```text
urn:iam:<partition>:<service>:<region>:<tenant>:<resource-path>
```

字段含义：

| Segment | 含义 |
|---|---|
| `iam` | 内部 URN namespace identifier |
| `partition` | 管理分区或环境，例如 `prod`、`staging`、`corp` |
| `service` | 业务系统或微服务，例如 `customer-growth`、`collaboration` |
| `region` | 区域；无区域资源使用 `global` |
| `tenant` | 租户、组织、namespace、account 等稳定隔离边界 |
| `resource-path` | 业务资源路径，格式由业务系统定义，建议 `<type>/<id>[/<subtype>/<id>]` |

示例：

```text
urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights
urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics
urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score
urn:iam:prod:collaboration:global:acme:channel/customer-support
urn:iam:prod:collaboration:global:acme:dataset/customer-faq
```

Wildcard pattern 示例：

```text
urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*
urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/**
urn:iam:prod:collaboration:global:acme:channel/*
urn:iam:prod:*:global:*:**
```

v1 wildcard 规则必须可预测、可编译、可下推：

- exact segment：精确匹配。
- `*`：匹配一个 colon segment 或一个 resource-path segment。
- `**`：只允许出现在 resource-path 末尾，表示匹配子树。
- 不支持任意 regex。
- 不支持 segment 中间的模糊匹配，例如 `foo*bar`。

### 4.8 URN、ARN 与 request 四元组

ARN（Amazon Resource Name）是 AWS 的资源命名约定。本文借鉴 ARN 的资源定位思想，但不复用 `arn:` 前缀，避免被误解为 AWS ARN 兼容。

RFC 8141 定义了标准 URN 的外层形式 `urn:<NID>:<NSS>`。本文使用 `iam` 作为内部 NID，并在 NSS 中定义固定分段。若未来需要公开跨组织互操作，应注册正式 NID 或提供明确的 namespace 兼容声明。

request 四元组，例如 method、uri/path、query params、path params，只用于 route/resource matcher：

```text
request tuple
  -> action
  -> resource URN
  -> parent resource URNs
```

它不替代 Resource URN。当前 IP、method、TLS、MFA 和受信 claims 不进入
URN，而进入 role binding 的 `conditions`。

### 4.9 为什么需要 `parent_urns`

一个请求通常命中叶子资源，但授权经常授在父级范围。

示例：

```text
GitHub:      repo 继承 org 授权
客户增长任务: job 继承 project 与 workspace 授权
S3:          object 继承 bucket 或 access point 授权
```

如果 matcher 只返回叶子 Resource URN，那么 org/namespace/bucket 级授权只能走两种坏设计：

- 把父级 binding 物化复制到所有子资源；
- 让 evaluator 查询业务表，临时推导父资源。

前者会产生海量 binding 与一致性问题，后者会让 IAM core 依赖业务表结构。本文采用更收敛的方式：route/resource matcher 返回确定的父资源链。

```text
resource_urn = 具体叶子资源
parent_urns  = 具体父资源，按从近到远排序
```

示例：

```text
resource_urn = urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score
parent_urns  = [
  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics,
  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights
]
```

`parent_urns` 必须是 concrete URN，不能是 wildcard pattern。wildcard 只允许出现在 `iam_role_binding.resource_urn`。evaluator 使用 binding pattern 去匹配 `[resource_urn] + parent_urns`。

这样既能表达继承授权，又不需要展开 binding，也不需要 IAM core 理解业务表。

### 4.10 为什么 IAM 核心不需要资源表

IAM 核心不维护 `iam_resource` 表。资源是否存在、资源属性、资源生命周期应由业务系统自己的表维护，例如客户增长分析系统的 workspace/project/job 表、协作平台的 channel/dataset 表。

原因：

- 避免 IAM 资源目录与业务资源表双写不一致。
- 避免 IAM 核心绑定具体业务 schema。
- 避免资源删除后 IAM 表残留导致列表越权。
- 允许不同业务系统用同一套 IAM 模型保护不同资源类型。

IAM 只保存授权目标：

```text
iam_role_binding.resource_urn
```

资源搜索、授权选择器、跨服务资源清单和离线审计 index 应保留为所属业务服务或
observability 系统的投影，不进入 Authguard 授权 schema；投影失效不得影响授权正确性。

## 5. 数据模型

标准化授权 schema 只包含六张表：

```text
iam_policy
iam_principal
iam_action
iam_role
iam_role_action
iam_role_binding
```

schema 由一组编号相同的 migration 初始化：`migrations/001_init.ddl.sql` 只包含结构
DDL，`migrations/001_init.dml.sql` 只包含 singleton policy 初始数据；SQLite 与
PostgreSQL 消费同一套逻辑 migration。扁平的 `model/` 统一承载与存储无关的授权业务
模型和 HTTP/gRPC DTO，持久化行映射只存在于 `storage/record.rs`。数据库行使用 record
命名，不与业务模型混称 entity。

外部账号目录、业务资源、session、credential、资源 inventory 与审计 pipeline 均不进入
这六张核心表。

### 5.1 `iam_policy`

```text
id
name
description
revision
created_at
updated_at
```

v1 使用数据库唯一索引约束单行 `iam_policy`；它是当前整个授权目录的 singleton
聚合根，不是多 policy 集合，也不是序列化 snapshot 表。它不重复保存
已经规范化的 role/action/binding 数据。`revision` 是控制面更新和不可变
`PolicyRuntime` 发布使用的
乐观并发版本号。未来如需保留历史版本，应写入 append-only audit/event store，而不是在
鉴权热路径中再增加 snapshot 表。

### 5.2 `iam_principal`

```text
id
kind             -- USER / WORKLOAD / GROUP
issuer
external_id      -- OIDC sub 或其他 provider 稳定标识
display_name
status
attributes
last_seen_at
created_at
updated_at
```

约束与边界：

- `unique(issuer, external_id)` 是 Authguard 全局外部身份唯一键。
- OIDC 必须使用已验证的 `iss + sub`；禁止按裸 `sub`、email、username 或 display name 去重。
- 该行只是授权侧投影，不保存 password、token、session、MFA secret 或本地认证凭据。
- `attributes` 只保存受信 discovery source 返回的有界展示/授权元数据；
  PostgreSQL 使用 JSONB，SQLite 使用受 `JSON_VALID` 约束的 TEXT。
- JIT 投影、服务端重新 resolve 的联邦候选人和 SCIM 子集 ingestion 变化统一执行相同的幂等
  upsert。
- 未启用 SCIM 时，从未访问 Authguard、也从未被分配权限的外部账号不会被物化。启用
  SCIM 时，只投影配置的 provisioning scope 接受的变化，不要求完整镜像外部账号库。

### 5.3 `iam_action`

`iam_action` 保存动作标识符和 HTTP route/resource matcher。

```text
policy_id
identifier      -- 例如 customer-growth.job.read
description
route_matchers  -- PostgreSQL JSONB array / SQLite validated JSON TEXT
```

`matchers` 元素格式：

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

规则：

- `(policy_id, identifier)` 是主键，在 singleton policy 内唯一标识 action。
- `route_matchers` 包含该 action 保护的所有 HTTP tuple-to-resource matcher。
- matcher 真实字段为 `id`、`methods`、`hosts`、`path`、`resource_urn`、`parent_urns`。
- `path` 是分段模板：`{name}` 捕获一个路径段，`*` 匹配一段，末尾 `**` 匹配剩余路径。
- `resource_urn` 与 `parent_urns` 可引用路径变量、`method`、`host` 以及受信 identity
  claims；缺失变量或生成非法 URN 时 fail closed。
- `parent_urns` 列出 concrete parent Resource URNs，用于继承授权判定。
- `route_matchers=[]` 表示该 action 只用于内部逻辑或角色组合，不直接匹配 HTTP。

### 5.4 `iam_role`

```text
id
policy_id
name
description
```

`(policy_id, id)` 是主键，`(policy_id, name)` 唯一。当前 Role 不保存状态或内置标记。

### 5.5 `iam_role_action`

```text
policy_id
role_id
action_identifier
```

约束：

```text
primary key (policy_id, role_id, action_identifier)
```

### 5.6 `iam_role_binding`

```text
policy_id
id
principal_id
role_id
effect                       -- ALLOW / DENY
resource_urn                 -- exact URN 或有限 wildcard expression
conditions                   -- PostgreSQL JSONB object / SQLite validated JSON TEXT
```

约束：

- 被引用 Role 必须属于 `policy_id`；Principal 是可跨 policy 复用的全局外部身份投影。
- 每条 binding 只引用一个 Principal 与一个 Role。
- `resource_urn` 可以是 exact URN，或仅使用受支持的 `*`/尾部 `**` wildcard grammar。
- `(policy_id, id)` 是当前数据库中 binding 的唯一约束；实现不声称按整个
  binding 内容去重。
- 显式 DENY binding 优先于 ALLOW binding。

v1 不单独保存 group membership。可信认证上下文或 `IPrincipalDiscovery` 实现可把外部
group 解析成 `GROUP` Principal，再通过同一张表授予 role。未来如确需 Authguard 管理本地
group membership，应作为单独版本化能力设计，而不是向六表核心增加
nullable/self-reference 字段。

## 6. 授权判定

### 6.1 请求判定算法

```text
1. Authn middleware 验证调用方。
2. Identity resolver 得到精确 issuer + external_id。
3. 按 issuer + external_id 从 repository 批量解析 active iam_principal，包括可信外部
   group ID 对应的 GROUP Principal；Principal 不进入 cache。
4. Route matcher 从 `iam_action.route_matchers` 得到 action/resource_urn/parent_urns。
5. Evaluator 加载这些 Principal 的 active iam_role_binding。
6. 通过 iam_role_action 展开每个 binding 对应 role 的 actions。
7. 检查 action match。
8. 检查 binding `resource_urn` 是否匹配请求 `resource_urn` 或 `parent_urns`。
9. 检查 `conditions`。
10. explicit DENY 优先。
11. 默认拒绝。
12. 记录有界 decision metrics 与 tracing event。
```

### 6.2 核心伪代码

单请求授权逻辑可以压缩为如下伪代码：

```text
function Authorize(request):
    identity = Authenticate(request)
    if identity is None:
        return DENY("unauthenticated")

    principals = ResolveRepositoryPrincipals(identity.issuer, identity.externalId,
                                             identity.stableGroupExternalIds)

    match = MatchAction(request.method, request.path, request.query)
    if match is None:
        return DENY("no matching protected action")

    resource_urns = [match.resource_urn] + match.parent_urns
    bindings = LoadActiveRoleBindings(principals)

    decision = DENY("default deny")

    for binding in bindings:
        if not AnyPatternMatches(binding.resource_urn, resource_urns):
            continue

        role_actions = ActionsOfRole(binding.role_id)
        if match.action not in role_actions:
            continue

        if not ConditionsMatch(binding.conditions, request, principals, match.resource_urn):
            continue

        if binding.effect == "DENY":
            return DENY("explicit deny", binding.id)

        decision = ALLOW("matched role binding", binding.id)

    return decision
```

这段伪代码刻意不访问业务资源表。业务资源是否存在由业务 handler 或 Resource Adapter 判断；授权器只判断“如果该资源存在，当前主体是否有权访问这个 URN”。

### 6.3 Effective role bindings

一次请求的有效授权来自：

```text
direct Principal role bindings
+ trusted GROUP Principal role bindings
```

resource inheritance 不通过额外 binding 派生，而通过 matcher 返回的 `parent_urns` 与 binding pattern 匹配完成。

### 6.4 Conditions

`conditions` 表达 ABAC 条件，不表达资源身份。

示例：

```json
{
  "sourceIp": {
    "inCidr": ["10.0.0.0/8"],
    "notInCidr": ["10.20.0.0/16"]
  },
  "request": {
    "methods": ["GET", "POST"],
    "secureTransport": true
  },
  "subject": {
    "mfa": true,
    "claims": {"department": "growth"}
  }
}
```

条件属性来源：

- source IP、request method 和 TLS scheme：来自 Envoy `CheckRequest`。
- MFA 与 subject claims：来自已验证 identity token 以及配置的受信 claim 映射。

如果 condition 依赖的属性无法可靠获取，默认条件不满足。当前未实现 time
window 或 resource-tag/resource-attribute condition。

## 7. 资源列表查询与 Resource Adapter

单请求拦截只解决“这个请求能不能执行”。企业系统还必须解决“当前用户能看到哪些资源”。

IAM 不直接列资源。业务服务负责列资源，但必须把 IAM 返回的授权范围编译进业务查询条件。

### 7.1 当前 SDK 资源映射契约

业务服务为自己的表定义 `ResourceSqlMapping`，将 URN 分段对应到数据库列。
当前四语言 SDK 负责验证 request action，并将 allow/deny URN expressions 编译为
参数化 SQL scope：

```text
ResourceSqlMapping + RequestAccess(action, allow_urns, deny_urns)
  -> parameterized SQL predicate + arguments
```

职责划分：

- IAM core：对当前 Principal 集合的 active `RoleBinding` 求值，并输出 action 对应的
  `AuthorizationScope`。
- Resource Adapter：理解业务表结构，将 `urn` 编译成 SQL predicate。
- Business DB：作为资源存在性、资源属性、资源生命周期的唯一真相。

资源列表查询伪代码：

```text
function ListResources(principal, action, resourceType, filters):
    principals = ResolveLocalPrincipals(principal)
    bindings = LoadActiveRoleBindings(principals)

    allowed_patterns = []
    denied_patterns = []

    for binding in bindings:
        if action not in ActionsOfRole(binding.role_id):
            continue

        if not ConditionsMatchForList(binding.conditions, principals):
            continue

        if binding.effect == "DENY":
            denied_patterns.append(binding.resource_urn)
        else:
            allowed_patterns.append(binding.resource_urn)

    scope = ResourceAdapter(resourceType).CompileListScope(
        allow = allowed_patterns,
        deny  = denied_patterns,
        filters = filters
    )

    return BusinessDB.Query(resourceType, scope)
```

关键点是：IAM 输出包含 allow/deny Resource URN expressions 的
`AuthorizationScope`，业务 adapter 输出 SQL predicate。不能反过来让 IAM 直接扫描业务表。

### 7.2 企业客户增长分析任务查询示例

由 effective role bindings 得到的 action-specific `AuthorizationScope`：

```text
allow urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/**
allow urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/lifetime-value-forecasting/job/daily-customer-lifetime-value-forecast
deny  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit
```

客户增长 Job Resource Adapter 可将该 scope 编译为：

```sql
WHERE
  tenant_id = 'example-corp'
  AND workspace_id = 'customer-insights'
  AND (
    project_id = 'retention-analytics'
    OR (
      project_id = 'lifetime-value-forecasting'
      AND job_id = 'daily-customer-lifetime-value-forecast'
    )
  )
  AND NOT (
    project_id = 'retention-analytics'
    AND job_id = 'vip-retention-risk-audit'
  )
```

该查询展示同一团队成员如何在一个列表请求中同时合并项目级读取、单 Job 直接 binding 和敏感 Job 显式拒绝。

### 7.3 Pattern 下推限制

为了支持稳定 SQL 下推，v1 role-binding `resource_urn` pattern 只支持有限 wildcard：

```text
exact
*
trailing /*
trailing /**
```

不支持任意 regex。否则只能全表扫描后过滤，无法满足企业级性能、审计和稳定性要求。

### 7.4 一致性策略

资源真相由业务表维护，因此不会出现 IAM 资源目录与业务资源表双写不一致。

Role Binding 创建时可选两种策略：

- 强校验：同服务内 binding 创建前调用业务 Resource Adapter 确认资源存在。
- 弱校验：允许预授权未来资源；资源不存在时 list 不返回，请求时业务服务返回 not found。

资源删除后，binding 可以异步清理。由于列表查询来自业务表，已删除资源不会因为 binding 残留被展示；请求也会由业务服务返回 not found。

## 8. 授权场景示例

### 8.1 场景一：增长分析团队读取一个 workspace 子树

授权关系：

```text
iam_principal:growth-analysts (GROUP)
  -> bind reader
  -> urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/**
```

请求：

```text
GET /customer-growth/jobs
```

matcher：

```text
action      = customer-growth.job.read
resource_urn = urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics
```

结果：

```text
ALLOW
```

原因：binding pattern 覆盖该 job，reader role 包含 `customer-growth.job.read`。

### 8.2 场景二：用户只被授权一个客户留存 job

授权关系：

```text
iam_principal:revenue-analyst (USER)
  -> bind reader
  -> urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score
```

查询列表时，业务 repository 将资源授权与业务条件同时下推：

```sql
WHERE tenant_id = 'example-corp'
  AND workspace_id = 'customer-insights'
  AND project_id = 'retention-analytics'
  AND job_id = 'daily-churn-risk-score'
```

结果：列表中只出现 `daily-churn-risk-score`，不会因为同属一个 workspace
而泄漏其他 job。

### 8.3 场景三：读权限不能修改 job

授权关系：

```text
iam_principal:growth-auditors (GROUP)
  -> bind reader
  -> urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/**
```

请求：

```text
PUT /customer-growth/jobs/1
```

matcher：

```text
action = customer-growth.job.update
```

结果：

```text
DENY
```

原因：reader role 不包含 `customer-growth.job.update`，即使 Resource URN 匹配也不能放行。

### 8.4 场景四：显式 DENY 优先

授权关系：

```text
iam_principal:growth-editors (GROUP)
  -> bind writer
  -> urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*

iam_principal:external-analyst (USER)
  -> bind DENY writer
  -> urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit
```

结果：该主体可以更新 retention project 下其他 job，但不能更新
`vip-retention-risk-audit`。

### 8.5 场景五：Workload Principal 使用独立资源范围

自动化 workload 在 `iam_principal` 中使用 `WORKLOAD` kind，并通过独立 role binding
获得精确的读取范围：

```text
allowed_actions = [customer-growth.job.read]
allowed_urns = [
  urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/lifetime-value-forecasting/job/daily-customer-lifetime-value-forecast
]
```

该 workload 只能读取这一个 job，不会继承某个人类 Principal 的额外权限。
凭据签发与 secret storage 仍由 IdP 负责。

### 8.6 场景六：资源已删除但 role binding 残留

授权关系中仍有一条 binding：

```text
bind reader on urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/retired-cohort-job
```

但业务 job 表中 `retired-cohort-job` 已删除。

结果：

- list jobs 不展示 `retired-cohort-job`，因为列表来自业务表。
- 直接请求 `retired-cohort-job` 返回 not found。
- binding 可由异步清理任务删除，但残留 binding 不会导致越权。

### 8.7 场景七：GitHub 风格 organization / repository 授权

GitHub org/repo 是典型层级资源授权：organization 拥有 repository，team 或 user 被授予 repository role，organization 级设置可提供更宽的默认授权。它可以直接映射到本文模型：

```text
GitHub org       -> tenant/domain
GitHub team      -> iam_principal(kind=GROUP)
GitHub repo      -> Resource URN
GitHub repo role -> iam_role
```

示例 URN：

```text
urn:iam:prod:github:global:analytics-labs:org/analytics-labs
urn:iam:prod:github:global:analytics-labs:repo/analytics
urn:iam:prod:github:global:analytics-labs:repo/analytics-ui
```

给某个 team 授权单个 repo：

```text
iam_principal:platform-team (GROUP)
  -> bind maintainer
  -> urn:iam:prod:github:global:analytics-labs:repo/analytics
```

给某个 team 授权 org 下所有 repo 只读：

```text
iam_principal:security-reviewers (GROUP)
  -> bind reader
  -> urn:iam:prod:github:global:analytics-labs:repo/*
```

list repositories 可编译为：

```sql
WHERE org = 'analytics-labs'
  AND (
    repo = 'analytics'
    OR :has_all_org_repo_read = true
  )
```

这与客户增长分析 workspace/job 是同一个模型。资源名称不同，但 Principal/Role/RoleBinding/Action 语义不变。

### 8.8 场景八：AWS S3 风格跨地域资源授权

S3 与 GitHub 的资源形态不同：bucket name 是全局命名，object key 是路径，access point 可以带 region，Multi-Region Access Point 是跨多个 region bucket 的全局入口。本文模型仍能统一表达，因为 region 和 resource-path 都是 Resource URN 的一等分段。

Bucket 与 object：

```text
urn:iam:prod:s3:global:111122223333:bucket/company-audit-logs
urn:iam:prod:s3:global:111122223333:bucket/company-audit-logs/object/2026/08/22/report.json
```

Regional access point：

```text
urn:iam:prod:s3:us-west-2:111122223333:access-point/audit-reader
urn:iam:prod:s3:us-west-2:111122223333:access-point/audit-reader/object/*
```

Multi-region access point：

```text
urn:iam:prod:s3:global:111122223333:multi-region-access-point/audit-global/object/*
```

授权：

```text
iam_principal:global-auditors (GROUP)
  -> bind reader
  -> urn:iam:prod:s3:*:111122223333:access-point/audit-reader/object/**
```

条件：

```json
{
  "sourceIp": {"inCidr": ["10.0.0.0/8"]},
  "request": {"tls": true}
}
```

关键点：region 只是 URN 的一个 segment。GitHub 这类全局资源可使用 `global`，S3 这类资源可使用具体 region 或 `global` 表达全局入口。授权 evaluator 不需要变化。

## 9. 认证边界与身份输入

Authguard 不实现 OAuth/OIDC session、Cookie、LDAP bind 或登录页面。浏览器 OIDC
authorization-code callback 由 Envoy Gateway 原生 OIDC filter 处理；Helm 中的
`redirectURL` 是对外回调地址。LDAP、password 或其他认证源应先由企业 IdP 转换为
Envoy 可验证的 OIDC/JWT 身份。

```text
登录或 workload identity
  -> 企业 IdP / Keycloak 签发 audience 受限的 Access Token
  -> Envoy Gateway 使用 issuer、audience 与本地/远程 JWKS 严格验签
  -> 将已验证 JWT 交给 Authguard gRPC ext_authz
  -> Authguard 提取 issuer + external_id(sub)、groups 与受信 claims
  -> 解析本地 Principal 投影，并映射 action + Resource URN
  -> 结合 source IP、TLS、HTTP method、MFA 与 claims 求值
```

Authguard 对受信 token 只做 claim 解码，不把 payload decode 描述为验签。生产信任
边界必须同时包含 Envoy 认证策略、Authguard Service 网络隔离，并禁止业务服务绕过
Gateway。登录 Access Token 只携带稳定身份与粗粒度 claims，不携带大量 allow/deny URN；
资源权限由 Authguard 针对当前请求实时计算，避免 JWT 过大、权限撤销延迟和 audience 越界。

进入该边界的有两条完全不同的客户端流程，不能混用：

- **浏览器用户（人）**——例如运营人员用 GitHub 登录 flowgent UI。Envoy Gateway 的
  OIDC filter 负责整个 authorization-code 流程：重定向到 IdP、处理 callback
  重定向、用 code 换取 token 并维护会话；用户在 IdP UI 上完成登录，应用自身不再
  实现或保存任何 OAuth callback 逻辑。Envoy 将已验证的 ID token 转发给 Authguard
  （`x-authguard-id-token`，OIDC 模式）。
- **Workload（机器）**——作业服务、同步代理、CI runner。不存在浏览器重定向；
  workload 以自身业务 SA 账号走 OAuth2/OIDC **client_credentials** 获取短期
  audience 受限的 access token，并以 `Authorization: Bearer` 发送；Envoy JWT
  provider 验证该 token（JWT 模式）。Workload 绝不使用浏览器流程，也绝不冒充用户。

在该边界下游，Authguard 可重签自己的内部业务 JWT（见 §10）：原始凭据仍由 Envoy 按
标准验证，只有 ALLOW 响应会改写转发给业务服务的 token。因此 Authguard 始终是“验签
无关的重签者”——绝不接受未验证 token，也绝不要求 Envoy 放宽其 JWT/OIDC 策略。

OIDC Core 要求需要稳定用户标识时使用 `iss + sub` 组合；`sub` 只在单个 issuer 内局部
唯一。因此 Authguard 把已验证 `iss` 写入 `iam_principal.issuer`，把已验证 `sub`
写入 `iam_principal.external_id`；email 与 username 只作为可变展示元数据。

Principal 按需进入 Authguard：

- 可信 JIT 投影在 Principal 第一次合法请求后幂等记录它。互联网场景无需导入几千万乃至
  上亿个从未被授权、也从未访问应用的账号。
- 联邦搜索支持管理员给尚未访问应用的 user、workload 或 group 提前授权。协议无关的
  `KeycloakPrincipalDiscovery` / `LdapPrincipalDiscovery` /
  `CustomPrincipalDiscovery` 归一化来源候选结果，Authguard 在写入前由服务端重新
  resolve；custom connector 用配置化的 URL/请求/响应绑定加预签发 bearer JWT 集成
  企业内部自研系统（如 DSP 目录）。
- SCIM 子集 ingestion 通过 `ScimPrincipalDiscovery` 接收规范化的 RFC 7643 User/Group
  upsert/delete 变化，用于企业预开户和快速停用，同时保持按需启用和增量处理；它不是
  RFC 7644 Server。

JIT 对应 2C 互联网个人用户的按需授权；联邦搜索与 SCIM 对应 2B 企业内员工与
workload/service account 的集中预授权与生命周期集成。

Keycloak 可以联邦 LDAP/Active Directory，并通过自身管理搜索暴露这些用户；这不是
OIDC 标准能力。通用 OIDC 不定义“管理员搜索 issuer 全量用户”的协议。Authguard 同时
提供直接 LDAP connector 与配置化 HTTP/JWT custom connector（覆盖企业内部自研
系统），未来云 IAM connector 也复用同一边界；它们均只用于控制面。
运行时鉴权始终从 repository 读取本地
`iam_principal`，并使用不可变策略快照与受信 token claims；IdP/LDAP 故障不得进入
数据面依赖链。Principal 不写入 `IAuthorizationCache`。

三个实现统一遵循泛型 `IPrincipalDiscovery<Input>` 契约，并收敛到同一个
`iam_principal` upsert。JIT + 联邦搜索仍是互联网场景最小/default 部署；启用已实现的
SCIM adapter 也不会把 SCIM 或外部目录加入运行时鉴权依赖链。

## 10. 业务访问上下文

允许判定会生成短期、带 `policy_revision` 且绑定 Principal/action/resource 的访问上下文。Authguard
依据 `auth.scope_delivery.direct_urn_limit` 选择唯一一种交付方式：

- allow + deny 数量小于等于阈值：gRPC `CheckResponse` 覆盖注入 `x-authguard-context`，其值为 Base64URL
  版本化 JSON，直接包含 allow/deny URN expressions。
- 超过阈值或 direct header 超过大小上限：完整上下文写入配置的
  `IAuthorizationCache` 并设置短 TTL，只注入不可预测的
  `x-authguard-scope-token`；业务 adapter 再通过 Authguard `:8081` gRPC `ResolveScope` 解析。

每次允许响应都先通过 gRPC `headers_to_remove` 删除客户端可能伪造的
`x-authguard-context` 与 `x-authguard-scope-token`，再覆盖写入唯一结果。两个头都出现、
上下文过期、token 不存在、action 不匹配或 resolver 失败时，adapter 必须 fail closed。

四种 SDK 使用同一入口抽象 `IAccessContextResolver`：
`HeaderAccessContextResolver` 解析 Envoy 注入的直接上下文，`GrpcAccessContextResolver` 通过内部
gRPC 解析 scope token；filter/interceptor 只负责请求生命周期与框架胶水。repository
使用 action-aware Resource SQL mapping，将授权 scope 与业务条件共同写入 list/get/update/
delete 的 SQL WHERE；create 则先对候选 Resource URN 求值。

Envoy `Authorization/Check` 独占 `:8080`，workload `ResolveScope` 独占 `:8081`。
默认 NetworkPolicy 分别以 Envoy 与 `authguard.io/scope-client` 选择器限制这两个端口；
workload 不能调用签发 direct context/scope token 的 Envoy Check listener。

每个 Authguard 实例以 `PolicyRuntime` 持有的进程内不可变编译快照完成 policy 求值；
后台按 revision 直接从 durable repository 刷新。Redis Cluster 只作为跨副本
scope-token store；scope-token miss 或 cache 故障时 fail closed。policy 与 Principal
均不进入 Memory/Redis cache。

### 10.1 业务 JWT 重签（resign）

可选（`auth.resign_jwt.enabled`）开启后，每个 ALLOW 都为业务微服务重签一枚短期
JWT 并替换 `authorization` 头（Envoy 先移除原始身份 token）。格式为 RS256
compact JWT（`RSASSA-PKCS1-v1_5` + SHA-256，RFC 8017 § 8.2）：

- `iss: "authguard"` 标记重签者，`authguardOrigin: true` 标记重签来源——客户端原始
  token 绝不携带该 claim。
- `sub` 复制已验证的 external_id，`principal_id` 对应本地 Principal，微服务可直接
  映射进 Authguard 模型。
- `authguard_group_ids` 携带 issuer-local 稳定 group ID。
- `iat`/`exp` 沿用 `scope_token_ttl`，并复制原 token 的标量身份 claims（如
  tenant_id、MFA 状态）；`iss`/`sub`/`authguard_group_ids` 不会被客户端值覆盖。
- **稳定身份保持不变，并追加 `authguardOrigin: true` 标记 claim**。业务
  微服务验证该签名即可证明请求经过了 Envoy Gateway，从而拒绝客户端直连微服务
  API。
- RSA 私钥（≥ 2048 bits，PKCS#8 PEM）仅存于 Authguard，经
  `AUTHGUARD__AUTH__RESIGN_JWT__PRIVATE_KEY` 注入。业务 workload 只持有配对公钥
  （PKCS#1 PEM，供引导工具使用），用任意标准 JWT 库验签，无需调用 Authguard SDK。
- 禁用（默认）时维持仅移除身份 token 的现状。Envoy 自身的 JWT/OIDC 验证（§9）不变。

业务 JWT 只是给 workload 的身份便利，不是授权判定：权限强制仍由 action 绑定且 fail
closed 的 `x-authguard-context` / `x-authguard-scope-token` 完成。

## 11. 控制面凭证与初始策略

`/adm/v1/**` 使用独立 Bearer 凭证，通过 Kubernetes Secret 注入
`AUTHGUARD__AUTH__ADMIN_TOKEN`。未配置时控制面默认关闭。`GET|PUT
/adm/v1/policy` 读取或原子替换 singleton policy 聚合；actions、roles 和 role bindings
提供 collection/resource CRUD。Principal 控制面提供本地投影列表、读取、状态更新
与安全删除，并通过独立 Principal discovery API 完成联邦搜索、物化与 SCIM 子集
ingestion。
策略变更先校验完整聚合，再写入 SQLite 或 PostgreSQL repository，然后原子发布
不可变内存 revision。多副本定期按 repository revision 同步；任一实例
的鉴权热路径始终只读不可变 L1 快照。多副本生产部署使用 PostgreSQL 与 Redis Cluster，
业务 OIDC/JWT 不得复用为控制面凭证。

## 12. [Sigbot](https://github.com/flowgent-labs/flowgent) 集成示例

| Flowgent 概念 | 通用 IAM 概念 |
|---|---|
| namespace | tenant / resource domain |
| agent flow | protected resource |
| flow run / task / trace | agent-flow 的子资源或执行证据 |
| LLM provider / MCP / skill / notification channel | 其他 protected resource |

示例 route matcher：

```json
{
  "id": "flow-run-trace-read",
  "methods": ["GET"],
  "hosts": [],
  "path": "/api/v1/{namespace}/flows/{flow}/runs/{run}/trace",
  "resource_urn": "urn:iam:prod:flowgent:global:{namespace}:agent-flow/{flow}/run/{run}",
  "parent_urns": [
    "urn:iam:prod:flowgent:global:{namespace}:agent-flow/{flow}",
    "urn:iam:prod:flowgent:global:{namespace}:namespace/{namespace}",
    "urn:iam:prod:flowgent:global:platform:platform/root"
  ]
}
```

这里 `agent-flow` 只是受保护资源示例，不是 IAM 模型内置概念。

## 13. [Sigbot](https://github.com/sigbot-projects/sigbot-core) 集成示例

| Sigbot 概念 | 通用 IAM 概念 |
|---|---|
| organization / team | tenant / resource domain |
| bot | protected resource |
| skill / tool / channel / memory | protected resource 或 bot 子资源 |
| conversation / evidence | bot 或 channel 的证据资源 |

示例：

```text
urn:iam:prod:sigbot:global:strategy:bot/customer-support
urn:iam:prod:sigbot:global:strategy:bot/customer-support/memory/customer-faq
urn:iam:prod:sigbot:global:strategy:channel/slack-main
```

## 14. 模块边界

### 14.1 Authguard Rust workspace

`route/authorization.rs` 只依赖窄接口 `IAuthorizationHandler`。
`DefaultAuthorizationHandler` 负责 ACL 求值与 access-context 交付；`PolicyHandler`
负责策略用例和 durable synchronization，`PolicyRuntime` 只持有已编译的不可变快照。
源码不再保留重复的授权 service 层。

```text
core/route   -- Envoy authorization gRPC 与 management HTTP 协议适配
core/handler/authorization.rs -- ACL 求值与 request-access 交付
core/handler/policy.rs        -- policy 编译、不可变 runtime 与策略 CRUD
core/handler/principal.rs     -- Principal 投影/discovery 用例
core/handler/management.rs    -- health、readiness、status 与 metrics 用例
core/storage -- SQLite/PostgreSQL 策略持久化
core/cache   -- Memory/Redis opaque scope-token context 缓存
core/config  -- authguard.yaml 加载、环境覆盖和校验
core/model        -- 与存储无关的授权模型、SQL-scope 语义及 HTTP/gRPC DTO
core/principal/mod.rs        -- discovery 公共模型、trait 与 error
core/principal/jit.rs        -- 受信 OIDC JIT (Just-In-Time) 投影
core/principal/keycloak.rs   -- Keycloak Admin API 搜索 connector
core/principal/ldap.rs       -- 直接 RFC 4511 LDAP connector
core/principal/custom.rs     -- 配置化 HTTP/JWT 自研身份 API connector
core/principal/scim.rs       -- RFC 7643 User/Group 子集 ingestion
core/storage/record.rs       -- SQLite/PostgreSQL 私有 row record
core/utils        -- identity 解析、HTTP tuple-to-URN 映射、OTel 与 metrics
core/migrations/001_init.ddl.sql -- 授权 schema DDL
core/migrations/001_init.dml.sql -- singleton policy 初始 DML
```

### 14.2 Language adapters

```text
adapters/rust    -- Rust SDK and SQL scope helpers
adapters/golang  -- Go SDK and SQL scope helpers
adapters/python  -- Python SDK and SQL scope helpers
adapters/java    -- Java/Spring SDK and SQL scope helpers
```

### 14.3 Business service use cases

```text
use-cases/customer-growth-job-service/e2e/deploy/rust-sqlx-service
use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service
use-cases/customer-growth-job-service/e2e/deploy/python-sqlalchemy-service
use-cases/customer-growth-job-service/e2e/deploy/springboot-jdbc-service
use-cases/customer-growth-job-service/e2e/deploy/springboot-jpa-service
```

跨语言必须共享：

- Resource URN grammar。
- action identifier 命名规范。
- `iam_action.route_matchers` JSON schema。
- role-binding evaluation algorithm。
- auth context API contract。
- golden test fixtures。

## 15. 安全原则

1. 默认拒绝。
2. DENY 优先于 ALLOW。
3. 第三方 identity 只能通过本地 Principal 投影参与授权。
4. 浏览器不读取 HttpOnly JWT。
5. OIDC 身份必须使用已验证 `iss + sub`，不得使用可变 profile 字段作为唯一键。
6. Principal 状态每次从 repository 校验，不得因 cache TTL 延迟禁用或撤销。
7. Secret 不进入 IAM audit metadata。
8. Role Binding 只能通过具备 revision 并发保护的控制面 API 创建、更新或删除。
9. 联邦身份搜索与 SCIM 子集 ingestion 不得参与数据面鉴权。
10. UI 权限控制只是体验，middleware / gateway 才是安全边界。
11. 资源真相由业务表维护，IAM 不维护核心资源目录。
12. 当前授权判定记录有界 metrics 与 tracing；持久化审计 event store 属于后续能力。

## 16. 参考

- RFC 8141: Uniform Resource Names (URNs): <https://www.rfc-editor.org/rfc/rfc8141.html>
- OpenID Connect Core 1.0，`iss` 与 `sub`: <https://openid.net/specs/openid-connect-core-1_0.html>
- Keycloak Server Administration Guide，用户联邦: <https://www.keycloak.org/docs/latest/server_admin/>
- Keycloak Admin REST API，用户搜索: <https://www.keycloak.org/docs-api/latest/rest-api/index.html>
- Keycloak Server Developer Guide，User Storage SPI: <https://www.keycloak.org/docs/latest/server_development/index.html>
- RFC 4511: Lightweight Directory Access Protocol (LDAP): <https://www.rfc-editor.org/rfc/rfc4511.html>
- RFC 7643: SCIM Core Schema: <https://www.rfc-editor.org/rfc/rfc7643.html>
- RFC 7644: SCIM Protocol: <https://www.rfc-editor.org/rfc/rfc7644.html>
- AWS IAM Amazon Resource Names (ARNs): <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html>
- GitHub organization repository roles: <https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization>
- Amazon S3 IAM resource types and policy resources: <https://docs.aws.amazon.com/AmazonS3/latest/userguide/security_iam_service-with-iam.html>
