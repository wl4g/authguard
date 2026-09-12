# Authguard 文档

Authguard 是一个深度集成 Envoy Gateway 的通用、独立、高性能 IAM 授权项目。它以标准化 URN 作为资源标识和授权边界，既能表达类似 S3 bucket/object/path 的层级授权，也能覆盖类似 GitHub org/repo/team 的企业协作授权。Envoy Gateway 负责入口、OIDC/JWT 认证、路由和流量治理；Authguard 以独立 Rust 微服务提供 external authorization 数据面和 IAM 控制面。

它尤其适合多人或多个系统主体协作、但角色和资源范围不同的 2B/2B2C 场景。2C 也能使用同一模型，只是简单的“用户只能访问自己的数据”通常直接使用所有权字段即可，无需完整 IAM。业务服务通过 adapter 接收受信访问上下文，并把 allow/deny Resource URN 安全编译为数据库查询范围。

以下索引按文档用途组织。正式架构以白皮书为准，计划和归档文档用于记录设计演进、实现差异和后续任务。

## 子文档索引

### 架构

- [架构总览](architecture/overview_ZH.md)：项目边界、核心组件和集成入口。
- [IAM 授权白皮书](architecture/iam-authorization-whitepaper_ZH.md)：正式授权模型、URN 规则、Principal/Role/Role Binding/条件、SQL 下推和 adapter 边界。
- [IAM Authorization Whitepaper](architecture/iam-authorization-whitepaper.md)：英文版白皮书。

### 计划

- [IAM 当前能力边界与后续缺口](plans/iam-implementation-gaps_ZH.md)：只记录当前未实现或待决策的能力。
- [Envoy Gateway 集成实施方案](plans/envoy-gateway-integration-implementation-plan_ZH.md)：当前部署定位、API、配置、可观测性、Helm 与 adapter 验收标准。
- [Request Access 生命周期实施方案](plans/request-access-lifecycle-implementation-plan_ZH.md)：v3 直接上下文、opaque scope token 解析、不可变 policy runtime、SDK 与 workload 生命周期。

### 归档

- [IAM 设计历史讨论总结](plans/archive/iam-design-discussion-summary_ZH.md)：早期讨论和决策背景记录。
- [IAM 授权模型早期决策草稿](plans/archive/iam-authorization-rationale-draft_ZH.md)：已被当前 Principal/Action/Role/RoleBinding 模型取代的历史草稿。

### 业务案例

- [客户增长分析任务授权案例](../use-cases/customer-growth-job-service/README.md)：同一企业增长团队业务场景的 Go、Rust、Python、Spring JDBC、Spring JPA 独立服务实现，共享 53 个授权案例并提供完整 k3s 部署验证。
