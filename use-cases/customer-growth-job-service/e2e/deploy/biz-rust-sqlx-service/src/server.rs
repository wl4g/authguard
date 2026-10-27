use sqlx::any::AnyPoolOptions;

use crate::{
    authorization::resign_token::ResignTokenVerifier,
    config::{access_filter, AppProperties},
    controller::{http, CustomerGrowthJobController},
    repository::CustomerGrowthJobRepository,
    service::CustomerGrowthJobService,
};

/// Starts the Axum business microservice.
///
/// # Errors
///
/// Returns an error when configuration, database initialization, or serving fails.
pub async fn run() -> anyhow::Result<()> {
    let properties = AppProperties::load()?;
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .max_connections(16)
        .min_connections(1)
        .connect(&properties.database_url)
        .await?;
    let repository = CustomerGrowthJobRepository::new(pool);
    repository.ping().await?;
    let controller =
        CustomerGrowthJobController::new(CustomerGrowthJobService::new(repository.clone()));
    let app =
        http::routes(controller, repository, access_filter()?, ResignTokenVerifier::from_env()?);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", properties.port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
