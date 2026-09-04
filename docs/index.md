# Authguard Documentation

Authguard is a generic, standalone, high-performance IAM authorization project built for deep Envoy Gateway integration. Standards-aligned URNs model both S3-style bucket/object/path permissions and GitHub-style organization/repository/team collaboration. Envoy Gateway owns ingress, OIDC/JWT authentication, routing, and traffic policy; the standalone Rust service provides an external-authorization data plane and an IAM control plane.

It is especially useful in B2B/B2B2C systems where multiple users or workloads collaborate with different roles and resource scopes. B2C systems can use the same model, although simple owner-only filtering rarely needs a complete IAM plane. Business adapters consume trusted access context and safely compile allow/deny Resource URNs into database query scopes.

The index below is organized by document purpose. The whitepaper is the canonical architecture reference; plan and archive documents record design evolution, implementation gaps, and follow-up work.

## Subdocument Index

### Architecture

- [Architecture overview](architecture/overview.md): project boundaries, core components, and integration entry points.
- [IAM authorization whitepaper](architecture/iam-authorization-whitepaper.md): canonical authorization model, URN rules, Principals/Roles/Role Bindings/conditions, SQL pushdown, and adapter boundaries.
- [IAM authorization whitepaper (ZH)](architecture/iam-authorization-whitepaper_ZH.md): Chinese whitepaper.

### Plans

- [Current IAM capability boundaries and gaps (ZH)](plans/iam-implementation-gaps_ZH.md): capabilities not yet implemented or awaiting a product decision.
- [Envoy Gateway integration implementation plan (ZH)](plans/envoy-gateway-integration-implementation-plan_ZH.md): current deployment position, APIs, configuration, observability, Helm, and adapter acceptance criteria.
- [Request-access lifecycle implementation plan (ZH)](plans/request-access-lifecycle-implementation-plan_ZH.md): v3 direct context, opaque scope-token resolution, immutable policy runtime, SDK, and workload lifecycle.

### Archive

- [IAM design discussion summary (ZH)](plans/archive/iam-design-discussion-summary_ZH.md): early discussion and decision background.
- [Early IAM authorization-model rationale draft (ZH)](plans/archive/iam-authorization-rationale-draft_ZH.md): historical draft superseded by the six-table singleton-policy model.

### Use cases

- [Customer growth job authorization](../use-cases/customer-growth-job-service/README.md): one enterprise growth-team scenario implemented as independent Go, Rust, Python, Spring JDBC, and Spring JPA services with a shared 53-case authorization contract and full k3s deployment verifier.
