//! Unified `AuthGuard` executable.

mod api;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context as _;
use authguard_common::config::{AppConfig, DEFAULT_CONFIG};
use clap::{Args, Parser, Subcommand};

use crate::api::ApiOptions;

#[derive(Debug, Parser)]
#[command(
    name = "authguard",
    version,
    about = "Unified authentication, identity normalization, and authorization"
)]
struct Cli {
    #[arg(
        short,
        long,
        global = true,
        default_value = DEFAULT_CONFIG,
        value_name = "FILE"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run unified OAuth, standalone credential, and optional wallet authentication.
    Authn(AuthnOptions),
    /// Run the Envoy `ext_authz`, workload scope, product API, and management listeners.
    Authz,
    /// Call the `AuthGuard` API for canonical Principal and policy operations.
    Api(ApiOptions),
}

#[derive(Debug, Args)]
struct AuthnOptions {
    /// Override the `AuthN` HTTP listen address.
    #[arg(long, default_value = "0.0.0.0:8082", value_name = "HOST:PORT")]
    bind: SocketAddr,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Authn(options) => run_authn(&cli.config, options.bind),
        Command::Authz => run_authz(&cli.config),
        Command::Api(options) => runtime(2)?.block_on(options.run()),
    }
}

fn run_authn(config_file: &std::path::Path, bind: SocketAddr) -> anyhow::Result<()> {
    let config = AppConfig::load_authn(config_file)?;
    runtime(config.server.performance.worker_threads)?.block_on(authguard_authn::server::run(bind))
}

fn run_authz(config_file: &std::path::Path) -> anyhow::Result<()> {
    let config = AppConfig::load(config_file)?;
    runtime(config.server.performance.worker_threads)?
        .block_on(authguard_authz::server::AuthguardServer::new().run())
}

fn runtime(worker_threads: usize) -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads.max(1))
        .enable_all()
        .build()
        .context("build AuthGuard Tokio runtime")
}
