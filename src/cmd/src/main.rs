//! Unified `AuthGuard` executable.

mod console;

use std::path::PathBuf;

use anyhow::Context as _;
use authguard_common::config::{AppConfig, CONFIG_FILE_ENV, DEFAULT_CONFIG};
use clap::{Args, Parser, Subcommand};

use crate::console::ConsoleOptions;

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
        env = CONFIG_FILE_ENV,
        default_value = DEFAULT_CONFIG,
        value_name = "FILE"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the OAuth/OAuth-like authentication and account-linking service.
    Authn(AuthnOptions),
    /// Run the Envoy `ext_authz` and authorization control-plane service.
    Authz,
    /// Manage canonical Principals and authorization resources.
    Console(ConsoleOptions),
}

#[derive(Debug, Args)]
struct AuthnOptions {
    /// Override the `AuthN` HTTP listen address.
    #[arg(long, env = "AUTHGUARD_AUTHN_BIND", value_name = "HOST:PORT")]
    bind: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    std::env::set_var(CONFIG_FILE_ENV, &cli.config);

    match cli.command {
        Command::Authn(options) => run_authn(&cli.config, options),
        Command::Authz => run_authz(),
        Command::Console(options) => runtime(2)?.block_on(options.run()),
    }
}

fn run_authn(config_file: &std::path::Path, options: AuthnOptions) -> anyhow::Result<()> {
    if let Some(bind) = options.bind {
        std::env::set_var("AUTHGUARD_AUTHN_BIND", bind);
    }
    let config = AppConfig::load_authn(config_file)?;
    runtime(config.server.performance.worker_threads)?.block_on(authguard_authn::server::run())
}

fn run_authz() -> anyhow::Result<()> {
    let config = AppConfig::load()?;
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
