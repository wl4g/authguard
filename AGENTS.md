# Authguard Development Specifications
All further development must follow this file and the existing architecture and protocol contracts. Keep changes minimal, maintain high cohesion and low coupling, and remove redundancy.

## Core Structure and Source Boundaries
- `Cargo.toml`: Rust workspace containing `src/{cmd,common,authn,authz}` and `src/sdk/rust`.
- `src/cmd/src/{main.rs,console.rs}`: unified CLI, AuthN/AuthZ startup, and administration console.
- `src/common/src/{config,model,storage,cache,apm,utils,principal,route}`: shared contracts and infrastructure.
- `src/common/src/config/config.rs` and `etc/authguard.yaml`: configuration models and defaults; keep changes synchronized.
- `src/authn/src/{server.rs,route,handler,provider,authentication,principal}`: authentication protocols, credentials, tokens, and identity normalization.
- `src/authz/src/{server.rs,route,handler,principal}`: authorization decisions, policies, scopes, principal discovery, and SCIM.
- `src/sdk/{rust,golang,java,python}`: business-side scope validation and SQL/object scope enforcement; preserve protocol parity across languages.
- `web/src/{main.tsx,App.tsx,core}`: React entry points, routing, authentication, and API contexts.
- `web/src/{login,account,dashboard}`: login, credential management, and administration pages; `shared/` owns themes, localization, and isolated styles.
- `web/src/federation/` and `web/vite.config.ts`: standalone/embedded modes, page-level remotes, React singletons, and federation builds.
- `deploy/helm/authguard` and `deploy/docker`: production deployment definitions; business use cases must reuse them without duplicating implementations.
- `use-cases/customer-growth-job-service/{deploy,verifier,util}`: business topology, vertical scenarios, and shared execution/reporting mechanisms.
- `docs/architecture/`: architecture and protocol specifications; `.agents/skills/authguard-chart-integrator/`: Chart and React integration contracts.

## Implementation Requirements
- Follow the existing entry/route -> handler -> domain logic/storage layers; shared layers must not depend on specific authentication providers.
- AuthN produces a canonical Principal; AuthZ consumes protocol-neutral identity. Passwords, wallet proofs, and upstream tokens must not cross into authorization.
- Prefix new internal identifiers with `authguard_`; prefix UI classes, CSS variables, and animations with `authguard-`. Do not pollute host globals.
- Federated modules must reuse existing feature pages, isolate styles and routing, and preserve the host header, environment synchronization, and return-to-workspace behavior.
- Build plugins belong in `devDependencies`; directly used runtime libraries require direct dependencies. Static deployments must contain complete build artifacts.
- Synchronize feature changes with configuration, documentation, translations, deployment templates, and affected integration skills; vendored Chart archives must match their source.

## Mandatory Vertical Scenarios and Unified E2E Entry Point
- Every new or changed feature must have sufficient vertical scenario cases in `use-cases/customer-growth-job-service/verifier/*/sNN_xx.py`.
- Organize cases around complete business flows. Cover all applicable success, failure, boundary, permission, state-transition, persistence, cleanup, and regression branches without omissions.
- UI cases must also cover real interactions, standalone/embedded modes, navigation round trips, language/theme synchronization, responsive layouts, and style isolation.
- Scenarios must implement the `E2ESNNXxVerifier` lifecycle (`deploy/init/verifier`) and register in `util/constant.py`.
- **Every end-to-end test, including browser, federated UI, fixture-based, and focused diagnostic tests, must run through `use-cases/customer-growth-job-service/runner.py`.**
- Never execute `sNN_xx.py` directly, use standalone Playwright/pytest scripts, or add alternative entry points to bypass the runner; Make entry points must ultimately invoke it.
- Use `runner.py --scenario <ids>` for focused verification; let the runner schedule the complete matrix. Never report a partial pass as a complete E2E pass.
- Use `BaseVerifier.step/execute/evidence_path/record_evidence`; the shared reporter owns archival, report generation, and evidence links.
- Follow `reports/00_summary.md`, `reports/round-XX/`, and `reports/round-XX/evidence/NN/`; do not create alternative output roots.
- Explicitly distinguish real-backend verification from API fixtures; never mock federation loading instead of importing and rendering actual remotes.

## Execution and Resource Constraints
- Monitor host CPU, memory, and I/O; investigate processes and Docker/K8s containers during anomalies. Intervene only in confirmed low-priority, resource-heavy tasks threatening host health.
- Check `target/` before every Rust build; run `cargo clean` first if it exceeds 20 GiB. Never remove formally named images.
- For GFW network failures, use `HTTPS_PROXY=http://127.0.0.1:8800`; pull new build images through `~/mirror-pull.sh`.
- Test secrets may be loaded by sourcing `~/.wl4gshrc.sec`; never read, print, or commit secret contents.
- Use standard Git commit prefixes such as `feat:`, `fix:`, `refactor:`, `docs:`, or `chore:`; never include `Co-Authored-By`.
