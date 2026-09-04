use anyhow::Context as _;
use authguard_core::config::AuthguardConfig;
use authguard_core::server::AuthguardServer;

fn main() -> anyhow::Result<()> {
    let config = AuthguardConfig::load()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.server.performance.worker_threads)
        .thread_name("authguard-worker")
        .enable_all()
        .build()
        .context("build Tokio runtime")?;
    runtime.block_on(AuthguardServer::new(config).run())
}
