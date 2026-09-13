//! `AuthGuard` control-plane API console.

use std::io::{self, BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _};
use clap::{Args, CommandFactory as _, Parser, Subcommand, ValueEnum};
use reqwest::{Method, Response};
use serde_json::Value;

#[derive(Debug, Args)]
pub struct ConsoleOptions {
    /// `AuthZ` management endpoint, including its configured context path.
    #[arg(long, env = "AUTHGUARD_CONSOLE_ENDPOINT", default_value = "http://127.0.0.1:9091")]
    endpoint: String,

    /// Control-plane bearer credential.
    #[arg(long, env = "AUTHGUARD_CONSOLE_TOKEN", hide_env_values = true)]
    token: String,

    #[command(subcommand)]
    operation: Option<ConsoleOperation>,
}

#[derive(Debug, Subcommand)]
enum ConsoleOperation {
    /// List a resource collection.
    List {
        #[arg(value_enum)]
        resource: ListResource,
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long)]
        after_id: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Get one resource by identifier.
    Get {
        #[arg(value_enum)]
        resource: ItemResource,
        id: String,
    },
    /// Create an authorization resource from a JSON document.
    Create {
        #[arg(value_enum)]
        resource: MutableResource,
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Replace an authorization resource from a JSON document.
    Update {
        #[arg(value_enum)]
        resource: MutableResource,
        id: String,
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Delete one resource.
    Delete {
        #[arg(value_enum)]
        resource: DeleteResource,
        id: String,
    },
    /// Activate or disable a canonical Principal.
    PrincipalStatus {
        principal_id: String,
        #[arg(value_enum)]
        status: PrincipalState,
    },
    /// Search configured enterprise Principal-discovery connectors.
    Discover {
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Materialize a discovered external Principal reference.
    Materialize {
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Get, replace, or reset the complete authorization catalog.
    Policy {
        #[command(subcommand)]
        operation: PolicyOperation,
    },
    /// Evaluate one authorization request from a JSON document.
    Authorize {
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Show authorization runtime status and current policy revision.
    Status,
}

#[derive(Debug, Subcommand)]
enum PolicyOperation {
    Get,
    Replace {
        #[arg(short, long)]
        file: PathBuf,
    },
    Reset,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ListResource {
    Principals,
    Actions,
    Roles,
    RoleBindings,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ItemResource {
    Principal,
    Action,
    Role,
    RoleBinding,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum MutableResource {
    Action,
    Role,
    RoleBinding,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DeleteResource {
    Principal,
    Action,
    Role,
    RoleBinding,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PrincipalState {
    Active,
    Disabled,
}

struct ConsoleClient {
    endpoint: String,
    token: String,
    http: reqwest::Client,
}

#[derive(Debug, Parser)]
#[command(no_binary_name = true)]
struct InteractiveCommand {
    #[command(subcommand)]
    operation: ConsoleOperation,
}

impl ConsoleOptions {
    pub async fn run(self) -> anyhow::Result<()> {
        if self.token.trim().is_empty() {
            bail!("--token or AUTHGUARD_CONSOLE_TOKEN is required");
        }
        let client = ConsoleClient::new(&self.endpoint, self.token)?;
        match self.operation {
            Some(operation) => client.execute(operation).await,
            None if io::stdin().is_terminal() => client.repl().await,
            None => bail!("a console operation is required when stdin is not a terminal"),
        }
    }
}

impl ConsoleClient {
    fn new(endpoint: &str, token: String) -> anyhow::Result<Self> {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        reqwest::Url::parse(&endpoint).context("parse AuthZ management endpoint")?;
        Ok(Self { endpoint, token, http: reqwest::Client::new() })
    }

    async fn repl(&self) -> anyhow::Result<()> {
        println!("AuthGuard management console. Type 'help' or 'quit'.");
        let stdin = io::stdin();
        let mut lines = stdin.lock().lines();
        loop {
            print!("authguard> ");
            io::stdout().flush()?;
            let Some(line) = lines.next() else { break };
            let line = line?;
            let words: Vec<_> = line.split_whitespace().collect();
            if words.is_empty() {
                continue;
            }
            if matches!(words[0], "exit" | "quit") {
                break;
            }
            if words[0] == "help" {
                InteractiveCommand::command().print_help()?;
                println!();
                continue;
            }
            match InteractiveCommand::try_parse_from(words) {
                Ok(command) => {
                    if let Err(error) = self.execute(command.operation).await {
                        eprintln!("error: {error:#}");
                    }
                }
                Err(error) => error.print()?,
            }
        }
        Ok(())
    }

    async fn execute(&self, operation: ConsoleOperation) -> anyhow::Result<()> {
        let response = match operation {
            ConsoleOperation::List { resource, query, after_id, limit } => {
                let path = match resource {
                    ListResource::Principals => "/api/v1/principals",
                    ListResource::Actions => "/api/v1/actions",
                    ListResource::Roles => "/api/v1/roles",
                    ListResource::RoleBindings => "/api/v1/role-bindings",
                };
                let mut request = self.request(Method::GET, path);
                if matches!(resource, ListResource::Principals) {
                    request = request.query(&[
                        ("query", query),
                        ("after_id", after_id.unwrap_or_default()),
                        ("limit", limit.to_string()),
                    ]);
                }
                request.send().await?
            }
            ConsoleOperation::Get { resource, id } => {
                self.request(Method::GET, &item_path(resource, &id)).send().await?
            }
            ConsoleOperation::Create { resource, file } => {
                self.mutate(Method::POST, collection_path(resource), Some(&file)).await?
            }
            ConsoleOperation::Update { resource, id, file } => {
                self.mutate(Method::PUT, &mutable_item_path(resource, &id), Some(&file)).await?
            }
            ConsoleOperation::Delete { resource: DeleteResource::Principal, id } => {
                self.request(Method::DELETE, &format!("/api/v1/principals/{id}")).send().await?
            }
            ConsoleOperation::Delete { resource, id } => {
                self.mutate(Method::DELETE, &delete_item_path(resource, &id), None).await?
            }
            ConsoleOperation::PrincipalStatus { principal_id, status } => {
                let status = match status {
                    PrincipalState::Active => "ACTIVE",
                    PrincipalState::Disabled => "DISABLED",
                };
                self.request(Method::PATCH, &format!("/api/v1/principals/{principal_id}"))
                    .json(&serde_json::json!({ "status": status }))
                    .send()
                    .await?
            }
            ConsoleOperation::Discover { file } => {
                self.json_request(Method::POST, "/api/v1/principal-discovery/search", &file).await?
            }
            ConsoleOperation::Materialize { file } => {
                self.json_request(Method::POST, "/api/v1/principal-discovery/materialize", &file)
                    .await?
            }
            ConsoleOperation::Policy { operation: PolicyOperation::Get } => {
                self.request(Method::GET, "/api/v1/policy").send().await?
            }
            ConsoleOperation::Policy { operation: PolicyOperation::Replace { file } } => {
                self.mutate(Method::PUT, "/api/v1/policy", Some(&file)).await?
            }
            ConsoleOperation::Policy { operation: PolicyOperation::Reset } => {
                self.mutate(Method::DELETE, "/api/v1/policy", None).await?
            }
            ConsoleOperation::Authorize { file } => {
                self.json_request(Method::POST, "/api/v1/authorize", &file).await?
            }
            ConsoleOperation::Status => self.request(Method::GET, "/api/v1/status").send().await?,
        };
        print_response(response).await
    }

    async fn mutate(
        &self,
        method: Method,
        path: &str,
        file: Option<&Path>,
    ) -> anyhow::Result<Response> {
        let revision = self.current_revision().await?;
        let mut request = self.request(method, path).header("if-match", revision);
        if let Some(file) = file {
            request = request.json(&read_json(file)?);
        }
        Ok(request.send().await?)
    }

    async fn json_request(
        &self,
        method: Method,
        path: &str,
        file: &Path,
    ) -> anyhow::Result<Response> {
        Ok(self.request(method, path).json(&read_json(file)?).send().await?)
    }

    async fn current_revision(&self) -> anyhow::Result<String> {
        let response = self.request(Method::GET, "/api/v1/status").send().await?;
        if !response.status().is_success() {
            return response_error(response).await;
        }
        response
            .headers()
            .get("x-authguard-policy-revision")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .context("AuthZ status response omitted x-authguard-policy-revision")
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.http.request(method, format!("{}{path}", self.endpoint)).bearer_auth(&self.token)
    }
}

fn collection_path(resource: MutableResource) -> &'static str {
    match resource {
        MutableResource::Action => "/api/v1/actions",
        MutableResource::Role => "/api/v1/roles",
        MutableResource::RoleBinding => "/api/v1/role-bindings",
    }
}

fn mutable_item_path(resource: MutableResource, id: &str) -> String {
    format!("{}/{id}", collection_path(resource))
}

fn item_path(resource: ItemResource, id: &str) -> String {
    match resource {
        ItemResource::Principal => format!("/api/v1/principals/{id}"),
        ItemResource::Action => format!("/api/v1/actions/{id}"),
        ItemResource::Role => format!("/api/v1/roles/{id}"),
        ItemResource::RoleBinding => format!("/api/v1/role-bindings/{id}"),
    }
}

fn delete_item_path(resource: DeleteResource, id: &str) -> String {
    match resource {
        DeleteResource::Principal => format!("/api/v1/principals/{id}"),
        DeleteResource::Action => format!("/api/v1/actions/{id}"),
        DeleteResource::Role => format!("/api/v1/roles/{id}"),
        DeleteResource::RoleBinding => format!("/api/v1/role-bindings/{id}"),
    }
}

fn read_json(path: &Path) -> anyhow::Result<Value> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read JSON document {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("decode JSON document {}", path.display()))
}

async fn print_response(response: Response) -> anyhow::Result<()> {
    if !response.status().is_success() {
        return response_error(response).await;
    }
    let status = response.status();
    let body = response.text().await?;
    if body.trim().is_empty() {
        println!("{status}");
    } else if let Ok(json) = serde_json::from_str::<Value>(&body) {
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!("{body}");
    }
    Ok(())
}

async fn response_error<T>(response: Response) -> anyhow::Result<T> {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    bail!("AuthZ API returned {status}: {body}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_console_resources_to_versioned_api_paths() {
        assert_eq!(collection_path(MutableResource::Role), "/api/v1/roles");
        assert_eq!(item_path(ItemResource::Principal, "P123"), "/api/v1/principals/P123");
        assert_eq!(
            delete_item_path(DeleteResource::RoleBinding, "rb-1"),
            "/api/v1/role-bindings/rb-1"
        );
    }

    #[test]
    fn parses_batch_console_command() {
        let command = InteractiveCommand::try_parse_from(["list", "principals", "--limit", "5"])
            .expect("valid console command");
        assert!(matches!(command.operation, ConsoleOperation::List { limit: 5, .. }));
    }
}
