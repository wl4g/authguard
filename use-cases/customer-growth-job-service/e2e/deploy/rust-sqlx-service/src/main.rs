#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let telemetry = authguard_common::apm::init_telemetry(
        &authguard_common::apm::TelemetryConfig {
            service_name: std::env::var("OTEL_SERVICE_NAME")
                .unwrap_or_else(|_| "e2e-authguard-rust-sqlx".to_string()),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: "e2e".to_string(),
            env_filter: std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "info,authguard_adapter_rust=debug".to_string()),
            json: true,
            otlp_endpoint: std::env::var("AUTHGUARD_OTEL_GRPC_ENDPOINT").ok(),
            export_timeout: std::time::Duration::from_secs(5),
            sample_rate: 1.0,
        },
    )?;
    let result = authguard_customer_growth_job_rust_service::server::run().await;
    telemetry.shutdown();
    result
}
