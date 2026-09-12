#[tokio::main]
async fn main() -> anyhow::Result<()> {
    authguard_authn::server::run().await
}
