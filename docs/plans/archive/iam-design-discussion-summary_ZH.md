# Authguard IAM 设计历史讨论总结

> **历史文档 / Superseded：** 文中早期 subject/group/grant 表结构已被当前
> `iam_policy` / `iam_principal` / `iam_action` / `iam_role` / `iam_role_action` /
> `iam_role_binding` 六表模型取代。现行契约以
> [IAM 授权白皮书](../../architecture/iam-authorization-whitepaper_ZH.md#5-数据模型)为准。

**状态：** Historical Summary
**日期：** 2026-08-22
**用途：** 记录 Authguard 独立化前的关键讨论、取舍与最终结论，便于后续独立 session 继续实现。

## 1. 背景

最初 IAM 设计来自 Flowgent 的企业级 RBAC 需求：不同团队维护不同 agent flow，既要支持类似 GitHub org/repo 的团队授权体验，也要支持后端真实拦截、UI 权限上下文、资源列表可见性过滤和审计。

讨论过程中发现，这套模型并不应绑定 Flowgent。它本质上是一个通用认证与授权平面，可用于 Flowgent、Sigbot Core 或其他业务微服务。因此最终决定抽成独立项目 Authguard。

## 2. 关键问题与结论

### 2.1 RBAC 与 ARN/URN 资源授权是否冲突？

不冲突。RBAC 解决“主体通过角色拥有哪些动作”，URN 解决“动作作用在哪些资源范围”。最终模型是互补关系：

```text
subject/group -> grant -> role -> action
                      \
                       -> urn / conditions
```

### 2.2 为什么使用 `urn:iam:...` 而不是 ARN 或 IRN？

ARN 是 AWS 专有语义，直接使用 `arn:` 会造成兼容性误解。IRN 不够标准。RFC 8141 URN 提供了稳定外层语法，因此采用：

```text
urn:iam:<partition>:<service>:<region>:<tenant>:<resource-path>
```

其中 `iam` 是内部 namespace identifier。

### 2.3 为什么不建核心资源表？

业务资源真相应由业务系统自己的表维护。IAM 只保存 grant 的 `urn`，不复制业务资源。

这样避免：

- IAM resource 表与业务表双写不一致；
- 资源删除后投影残留导致列表越权；
- IAM core 绑定具体业务 schema；
- 多业务服务集成时中心 IAM 变成资源生命周期耦合点。

### 2.4 没有资源表，如何查询“我能看到哪些资源”？

通过 Resource Adapter 做 SQL pushdown：

```text
effective grants -> urn patterns -> Resource Adapter -> SQL predicate -> business DB
```

IAM core 计算授权范围，业务 adapter 理解业务表列并生成查询条件。

### 2.5 为什么限制 wildcard？

任意 regex 无法稳定下推 SQL，会退化成全表扫描再应用层过滤。v1 只支持：

```text
exact
*
trailing /**
```

这能被确定地翻译成 `=`、`OR`、prefix `LIKE` 等查询条件。

### 2.6 为什么需要 `parentUrns`？

请求通常命中叶子资源，但授权经常授在父级范围。例如 repo 继承 org、object 继承 bucket、flow run 继承 flow/namespace。

最终决定由 route/resource matcher 返回：

```text
resourceUrn = concrete leaf resource
parentUrns  = concrete parent resources, nearest first
```

evaluator 用 grant pattern 匹配 `[resourceUrn] + parentUrns`。这样无需展开 grant，也无需 IAM 查询业务表推导父级。

### 2.7 为什么 user/group 不合并成 subject 表？

`iam_subject` 是可认证实体，`iam_group` 是集合实体。合表会造成大量 nullable 字段和复杂自引用 membership。最终保留：

```text
iam_subject
iam_group
iam_group_member
```

运行时统一为：

```text
PrincipalSet = authenticated subject + direct groups
```

v1 不支持 group 嵌套。

### 2.8 为什么 permission 改叫 action？

permission 容易混淆“动作定义”和“授权结果”。最终表名采用：

```text
iam_action
iam_role
iam_role_action
iam_grant
iam_grant_role
```

action 表示“要做什么”，role 是 action 集合，grant 是授权事实。

### 2.9 GitHub org/repo 与 S3 跨地域资源如何统一？

它们资源形态不同，但授权四元组一致：

```text
who       = subject/group
can do    = action/role
on what   = Resource URN / pattern
when      = conditions
```

差异被限制在 Resource Adapter 和 URN 生成规则中。Evaluator 不需要知道资源来自 GitHub、S3、Flowgent 还是 Sigbot。

## 3. 最终收敛

Authguard 被定义为独立系统：

```text
authguard/
  src/common
  src/core
  src/gateway
  src/adapters/{rust,golang,python,java}
  use-cases/customer-growth-job-service/e2e/deploy/{rust-sqlx-service,golang-sqlx-service,python-sqlalchemy-service,springboot-jdbc-service,springboot-jpa-service}
```

正式设计文档：

- `docs/architecture/iam-authorization-whitepaper_ZH.md`
- `docs/architecture/iam-authorization-whitepaper.md`

设计决策草稿：

- `docs/plans/archive/iam-authorization-rationale-draft_ZH.md`

实现差异与待办：

- `docs/plans/iam-implementation-gaps_ZH.md`
