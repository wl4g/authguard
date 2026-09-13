use std::collections::BTreeMap;

use async_trait::async_trait;
use serde_json::Value;

use super::ProviderError;
use crate::config::HttpMethod;

/// Provider token-exchange request after bounded configuration rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenExchangeRequest {
    pub endpoint: String,
    pub method: HttpMethod,
    pub headers: BTreeMap<String, String>,
    pub query: BTreeMap<String, String>,
    pub body: BTreeMap<String, String>,
}

/// Optional identity lookup performed with a Provider access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityLookupRequest {
    pub endpoint: String,
    pub access_token: String,
    pub access_token_query: Option<String>,
}

/// Narrow HTTP seam used by configuration-backed OAuth-like adapters.
#[async_trait]
pub trait ProviderTransport: Send + Sync {
    async fn exchange_token(&self, request: TokenExchangeRequest) -> Result<Value, ProviderError>;
    async fn lookup_identity(&self, request: IdentityLookupRequest)
        -> Result<Value, ProviderError>;
}

/// Redirect-disabled production transport shared by OAuth-like Providers.
#[derive(Debug, Clone)]
pub struct ReqwestProviderTransport {
    client: reqwest::Client,
}

impl ReqwestProviderTransport {
    /// Creates a bounded Provider HTTP client.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP client cannot be constructed.
    pub fn new(timeout: std::time::Duration) -> Result<Self, ProviderError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| ProviderError::Transport(error.to_string()))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl ProviderTransport for ReqwestProviderTransport {
    async fn exchange_token(&self, request: TokenExchangeRequest) -> Result<Value, ProviderError> {
        let mut builder = match request.method {
            HttpMethod::Get => self.client.get(&request.endpoint),
            HttpMethod::Post => self.client.post(&request.endpoint),
        }
        .query(&request.query);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        if request.method == HttpMethod::Post {
            builder = builder.form(&request.body);
        }
        let response =
            builder.send().await.map_err(|error| ProviderError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(ProviderError::ProviderRejected(response.status().as_u16()));
        }
        response.json().await.map_err(|error| ProviderError::Transport(error.to_string()))
    }

    async fn lookup_identity(
        &self,
        request: IdentityLookupRequest,
    ) -> Result<Value, ProviderError> {
        let mut builder = self.client.get(request.endpoint).header("accept", "application/json");
        if let Some(parameter) = request.access_token_query {
            builder = builder.query(&[(parameter, request.access_token)]);
        } else {
            builder = builder.bearer_auth(request.access_token);
        }
        let response =
            builder.send().await.map_err(|error| ProviderError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(ProviderError::ProviderRejected(response.status().as_u16()));
        }
        response.json().await.map_err(|error| ProviderError::Transport(error.to_string()))
    }
}
