# AuthGuard workload SDK boundary

The adapters consume only AuthGuard's signed access context. They do not know
the external identity provider, perform authentication, or import an AuthN/AuthZ
server implementation. The Rust adapter depends on `authguard-common` for the
wire model and generated scope-resolution client; it does not depend on
`authguard-authz`.

## Observability

SDKs are libraries inside a business service, so they must not install a second
global OpenTelemetry SDK or exporter. They emit safe, bounded structured events
through the host application's telemetry stack:

- Rust uses `tracing`; the application's `tracing-opentelemetry` layer exports
  the events and their current trace context.
- Go uses `slog` plus `util.ConfigureTelemetryObserver`.
- Python uses `logging` plus `configure_telemetry_observer`.
- Java uses `IAuthguardLogger` plus `configureTelemetryObserver`.

The observer callbacks receive event name, outcome/duration, resolver mode,
allow/deny expression counts, and SQL parameter count. Applications should map
the bounded event/outcome values to counters and `duration_ms` to a histogram.
Callbacks are isolated: observer failures never change fail-closed authorization
behavior. Tokens, HMAC keys, JWTs, SQL arguments, and raw resource URNs are not
logged or passed as metric labels.

Critical event families are consistent across SDKs:

| Flow | Start | Terminal |
|---|---|---|
| signed header resolution | `authguard.access_context.header.started` | `authguard.access_context.verify.succeeded/failed` |
| opaque gRPC resolution | `authguard.scope_token.grpc.started` | `authguard.scope_token.grpc.succeeded/failed` |
| access-context binding | `authguard.access_filter.started` | `authguard.access_filter.authenticated/rejected/unauthenticated` |
| URN expression to SQL WHERE | `authguard.sql_scope.compile.started` | `authguard.sql_scope.compile.succeeded/failed` |

