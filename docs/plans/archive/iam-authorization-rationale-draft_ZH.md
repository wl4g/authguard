# 企业级 IAM 授权模型疑问与决策记录草稿

> **历史文档 / Superseded：** 本草稿记录早期 `iam_subject` / `iam_group` /
> `iam_grant` 候选模型，已被当前六表 singleton policy 模型取代。现行契约以
> [IAM 授权白皮书](../../architecture/iam-authorization-whitepaper_ZH.md#5-数据模型)为准。

**状态：** Historical / Superseded
**日期：** 2026-08-21
**用途：** 复盘为什么采用当前 IAM 设计，不作为正式架构规范。正式规范见 `authguard/docs/architecture/iam-authorization-whitepaper_ZH.md`。

## 1. 为什么不直接用 request 四元组做权限控制？

request 四元组适合判断“这个 HTTP 请求是否能被访问”，但不适合作为资源权限模型。

原因：

- 它能较容易控制某个写请求，例如 `POST /flows/{flow}/runs`。
- 但它很难回答“当前登录用户拥有哪些资源列表”。
- 资源列表必须落到业务 SQL 查询，request pattern 不能自然映射到业务表列。
- 如果把 method/path/query 当资源，会导致权限与路由强绑定，业务重构 route 时权限语义被破坏。

最终决策：

```text
request tuple -> route/resource matcher -> action + resource URN
```

request 四元组只负责识别 action 和生成资源 URN，不作为最终授权目标。

## 2. 为什么使用 Resource URN？

需要一个稳定、可读、可比较、可做 wildcard 的统一资源命名方式。AWS ARN 已证明这种模式适合大规模资源授权，但 ARN 是 AWS 生态固定语义，不能直接复用。

最终决策：

```text
urn:iam:<partition>:<service>:<region>:<tenant>:<resource-path>
```

示例：

```text
urn:iam:prod:flowgent:global:default:agent-flow/security-autonomy-fixer
urn:iam:prod:sigbot:global:strategy:bot/customer-support
```

这是基于 RFC 8141 URN 语法风格的内部统一资源名称。URN 只表达资源身份，不表达 IP、method、query、MFA、时间等条件。

## 3. 为什么不用 IRN？

IRN 表达“内部资源名称”也可行，但不是通用标准术语，看起来不够自然。

最终决策：

- 放弃 IRN。
- 使用 URN。
- 明确这是 `urn:iam:...` 内部 namespace，而不是 AWS ARN。

## 4. RFC 8141 URN 是否能满足 ARN 的资源定位语义？

基本能满足，但语义边界要说清楚。

RFC 8141 定义了 URN 外层语法：

```text
urn:<NID>:<NSS>
```

NSS 内部结构由具体 namespace 自己定义。因此可以在 `iam` namespace 下定义：

```text
<partition>:<service>:<region>:<tenant>:<resource-path>
```

这能满足多级资源定位。条件能力不属于 URN，应该进入 `conditions_json`。

## 5. 为什么不建立核心 `iam_resource` 表？

这是关键决策。

建立核心资源表会带来一致性问题：

- 业务资源表一份，IAM 资源表一份，容易双写不一致。
- 资源删除、重命名、迁移后，IAM 资源表可能残留脏数据。
- IAM 核心会被迫理解各业务系统资源生命周期。
- 多微服务场景下，中心 IAM 很难实时维护所有业务资源真相。

最终决策：

- IAM 核心不建 `iam_resource` 表。
- 资源真相由业务系统自己的表维护。
- IAM 只保存 `iam_grant.urn`。
- 如需资源搜索/授权选择器/离线审计加速，可建可选 `iam_resource_projection`，但它只是 cache/index，不参与授权正确性。

## 6. 没有资源表，如何做资源列表查询？

资源列表查询由业务 Resource Adapter 负责。

链路：

```text
current subject
  -> effective grants
  -> urns for action
  -> business Resource Adapter
  -> SQL predicate / query scope
  -> business DB
```

例如用户拥有：

```text
reader on urn:iam:prod:flowgent:global:default:agent-flow/security-autonomy-fixer
reader on urn:iam:prod:flowgent:global:security:agent-flow/*
```

Flowgent adapter 可编译为：

```sql
WHERE
  (namespace = 'default' AND name = 'security-autonomy-fixer')
  OR
  (namespace = 'security')
```

这样既能做精细授权，又能下推到业务 SQL。

## 7. Resource Adapter 的职责是什么？

每个业务资源类型实现一个薄 adapter：

```text
BuildURN(row) -> resource_urn
BuildParentURNs(row) -> []resource_urn
CompileListScope(action, effective_grants) -> SQL predicate / query scope
LoadResourceAttributes(resource_urn) -> attributes
```

IAM core 不知道 flow/bot/dataset 的表结构。业务 adapter 知道自己的表结构，并负责将授权范围编译成可执行查询。

## 8. 为什么限制 wildcard，不支持任意 regex？

任意 regex 表达力强，但无法稳定下推 SQL。最终会退化为：

```text
全表扫描 -> 应用层过滤
```

这在企业级系统里不可接受。

最终决策：v1 只支持有限 wildcard：

```text
exact
*
trailing /*
trailing /**
```

这样可以安全编译成 SQL 条件。

## 9. IP、method、query、MFA、时间应放在哪里？

它们不是资源身份，不应放进 URN。

最终决策：

- method/path/query/path params：用于 `iam_action.matchers` 识别 action 与生成 resource URN。
- source IP、time、MFA、request attributes、subject/resource attributes：进入 `iam_grant.conditions_json`。

示例：

```json
{
  "sourceIp": {"inCidr": ["10.0.0.0/8"]},
  "request": {"methods": ["GET"]},
  "time": {"before": "2026-12-31T23:59:59Z"},
  "subject": {"mfa": true}
}
```

## 10. user 和 group 是否应该统一成 subject 表？

不建议。

原因：

- subject 是可认证实体。
- group 是集合实体。
- subject 有 identities/email/service-account/workload 约束。
- group 有 scope/name/membership 约束。
- 合并后字段大量 nullable，membership 会变成自引用关系，审计与约束更复杂。

最终决策：

```text
iam_subject
iam_group
iam_group_member
```

运行时统一为：

```text
PrincipalSet = authenticated subject + groups
```

即“实现时统一对象”，不是“数据库强行合表”。

v1 不考虑也不支持 group 嵌套。membership 只表达 `iam_subject -> iam_group`，避免在第一版引入递归展开、循环检测、最大深度、审计链压缩等复杂度。

## 11. 为什么 user 表改叫 subject？

因为授权主体不只有 human user，还包括：

- service account
- workload identity
- system subject
- break-glass/admin subject

`iam_subject` 比 `iam_user` 更通用、专业，也更适合跨 Flowgent 和 Sigbot Core 复用。

## 12. 为什么 permission 表改叫 action？

permission 容易混淆“动作”和“授权结果”。

最终模型中：

- action：要做什么，例如 `flow.run.trigger`。
- role：action 集合。
- grant：谁在什么资源上拥有某些 role。
- permission：运行时判定结果，不作为核心表名。

因此底层表名使用：

```text
iam_action
iam_role
iam_role_action
iam_grant
iam_grant_role
```

## 13. 为什么 grant 支持多个 role？

用户期望模型是：

```text
subject/group
  -> grant
  -> one or multiple roles
  -> resource
```

如果每个 grant 只能有一个 role，UI 上批量授权会生成多条 grant，审计和撤销不够自然。

最终决策：

```text
iam_grant
iam_grant_role
```

一个 grant 可绑定多个 role。grant 仍然 append-only，不做 update；角色集合变更通过撤销旧 grant、新增新 grant 完成。

## 14. 为什么 action matcher 与 resource grant 分开？

它们回答的问题不同：

- `iam_action.matchers`：这个请求对应哪个 action 和哪个 resource URN？
- `iam_grant.urn`：某主体/组在什么资源范围上被授予角色？

分开后，route 重构只影响 matcher，业务授权语义仍由 Resource URN 保持稳定。

## 15. 如何处理资源删除后一致性？

资源删除后，业务表是唯一真相：

- list 查询来自业务表，因此 deleted resource 不会展示。
- request 查询由业务 handler 判断 resource not found。
- IAM grant 可异步清理，但残留 grant 不应导致越权。

授权创建时可选：

- 强校验：创建 grant 前调用业务 adapter 验证资源存在。
- 弱校验：允许预授权未来资源。

## 16. 最终统一总结

最终模型：

```text
iam_subject(user / service_account / workload / system)
iam_group
iam_group_member

iam_action
iam_role
iam_role_action

iam_grant
iam_grant_role

iam_api_key
iam_audit_event
```

最终链路：

```text
HTTP request
  -> iam_action.matchers
  -> action + resource URN + parent URNs
  -> PrincipalSet(subject + groups)
  -> iam_grant.urn
  -> iam_grant_role -> iam_role -> iam_role_action
  -> conditions_json
  -> decision
```

资源列表链路：

```text
effective grants
  -> Resource Adapter
  -> SQL predicate
  -> business DB
```

这个设计同时解决：

- 单请求权限判断。
- 资源列表可见性。
- 资源层级继承。
- 精细化资源授权。
- 多微服务资源一致性。
- IAM 核心不绑定具体业务表结构。

## 17. 为什么 GitHub org/repo 和 AWS S3 跨地域资源能统一？

它们看起来差异很大：

- GitHub 是组织/团队/仓库的层级授权。
- S3 是 bucket/object/access point 的资源授权，其中 access point 可带 region，Multi-Region Access Point 又是 global endpoint。

但授权系统真正需要统一的是四件事：

```text
who       = subject/group
can do    = action/role
on what   = Resource URN / pattern
when      = conditions
```

GitHub 映射：

```text
org       -> tenant/domain
team      -> iam_group
repo      -> urn:iam:prod:github:global:{org}:repo/{repo}
repo role -> iam_role
```

S3 映射：

```text
bucket                    -> urn:iam:prod:s3:global:{account}:bucket/{bucket}
object                    -> urn:iam:prod:s3:global:{account}:bucket/{bucket}/object/{key}
regional access point     -> urn:iam:prod:s3:{region}:{account}:access-point/{name}
multi-region access point -> urn:iam:prod:s3:global:{account}:multi-region-access-point/{name}
```

因此差异被限制在 Resource Adapter 和 URN 生成规则里；IAM evaluator 不需要知道它正在处理 GitHub repo 还是 S3 object。

## 18. 为什么需要 parentUrns？

一个请求通常命中叶子资源，但企业授权经常授在父级范围。

示例：

```text
GitHub:     repo 继承 org 授权
Flowgent:   flow run 继承 flow 与 namespace 授权
S3:         object 继承 bucket 或 access point 授权
```

如果 matcher 只返回叶子资源，例如：

```text
urn:iam:prod:flowgent:global:security:agent-flow/fixer/run/run-123
```

那么 namespace 级授权只能通过两种方式实现：

- 把 namespace grant 展开复制到所有 flow/run；
- 让 IAM evaluator 查询 Flowgent 的业务表，临时推导 namespace。

前者会产生一致性和规模问题，后者会让 IAM core 绑定业务 schema。

最终决策：matcher 返回当前资源和父资源链。

```text
resourceUrn = concrete leaf resource
parentUrns  = concrete parent resources, nearest first
```

然后 evaluator 用 `iam_grant.urn` 去匹配：

```text
[resourceUrn] + parentUrns
```

`parentUrns` 必须是 concrete URN，不能是 wildcard pattern。wildcard 只属于 grant 的 `urn`。

## 19. 为什么 `iam_grant` 的授权目标列直接叫 `urn`？

`resource_urn_pattern` 更显式，但过长，而且会在 DML、代码模型、API response 中反复出现。

最终决策：列名叫 `urn`。

语义约束写在文档和类型里：

```text
iam_grant.urn = exact Resource URN 或有限 Resource URN pattern
```

这样字段短，但不丢失语义。因为表名已经是 `iam_grant`，`urn` 在该上下文中就是“该 grant 的授权资源目标”。
