use std::collections::BTreeMap;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use reqwest::Url;
use tracing::Instrument as _;

use super::normalization::{normalize_identity, string_at, validate_provider};
use super::transport::{IdentityLookupRequest, ProviderTransport, TokenExchangeRequest};
use super::{IProviderAdapter, OAuthLikeCallback, ProviderError};
use crate::config::{ClientCredentialPlacement, OAuthProviderProperties};
use crate::model::ExternalIdentity;

const OAUTH_CLIENT_ID: &str = "client_id";
const OAUTH_CLIENT_SECRET: &str = "client_secret";

/// Configuration-driven OAuth/OAuth-like provider implementation.
pub struct OAuthLikeProvider<T> {
    provider_id: String,
    config: OAuthProviderProperties,
    transport: T,
}

impl<T> OAuthLikeProvider<T> {
    /// Creates a provider after validating its bounded configuration.
    ///
    /// # Errors
    ///
    /// Rejects missing endpoints, issuer, or unsupported JSON paths.
    pub fn new(
        provider_id: impl Into<String>,
        config: OAuthProviderProperties,
        transport: T,
    ) -> Result<Self, ProviderError> {
        let provider_id = provider_id.into();
        validate_provider(&provider_id, &config)?;
        Ok(Self { provider_id, config, transport })
    }

    /// Builds the provider authorization URL using only standard OAuth
    /// parameters plus the provider's explicit query additions.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid configured endpoint.
    pub fn authorization_url(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
    ) -> Result<Url, ProviderError> {
        self.authorization_url_with_client_id_parameter(
            client_id,
            redirect_uri,
            state,
            OAUTH_CLIENT_ID,
        )
    }

    pub(super) fn authorization_url_with_client_id_parameter(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
        client_id_parameter: &str,
    ) -> Result<Url, ProviderError> {
        self.authorization_url_with_parameters(
            client_id,
            redirect_uri,
            state,
            client_id_parameter,
            " ",
        )
    }

    pub(super) fn authorization_url_with_parameters(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
        client_id_parameter: &str,
        scope_separator: &str,
    ) -> Result<Url, ProviderError> {
        let mut url = Url::parse(&self.config.authorization.endpoint)
            .map_err(|_| ProviderError::InvalidConfiguration("invalid authorization endpoint"))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair(client_id_parameter, client_id);
            query.append_pair("redirect_uri", redirect_uri);
            query.append_pair("state", state);
            if !self.config.authorization.scopes.is_empty() {
                query.append_pair("scope", &self.config.authorization.scopes.join(scope_separator));
            }
            for (name, value) in &self.config.authorization.query {
                query.append_pair(name, value);
            }
        }
        Ok(url)
    }

    fn token_request(
        &self,
        callback: &OAuthLikeCallback,
        client_id_parameter: &str,
        client_secret_parameter: &str,
    ) -> TokenExchangeRequest {
        let variables = BTreeMap::from([
            ("clientId", callback.client_id.as_str()),
            ("clientSecret", callback.client_secret.as_str()),
            ("authorizationCode", callback.authorization_code.as_str()),
            ("redirectUri", callback.redirect_uri.as_str()),
        ]);
        let mut headers = render_map(&self.config.token.headers, &variables);
        let mut query = render_map(&self.config.token.query, &variables);
        let mut body = render_map(&self.config.token.body, &variables);
        if self.config.token.query.is_empty() && self.config.token.body.is_empty() {
            body.extend([
                ("grant_type".to_string(), "authorization_code".to_string()),
                ("code".to_string(), callback.authorization_code.clone()),
                ("redirect_uri".to_string(), callback.redirect_uri.clone()),
            ]);
        }
        if !has_explicit_client_credentials(&self.config.token) {
            match self.config.token.client_credentials {
                ClientCredentialPlacement::Body => {
                    body.insert(client_id_parameter.to_string(), callback.client_id.clone());
                    body.insert(
                        client_secret_parameter.to_string(),
                        callback.client_secret.clone(),
                    );
                }
                ClientCredentialPlacement::Query => {
                    query.insert(client_id_parameter.to_string(), callback.client_id.clone());
                    query.insert(
                        client_secret_parameter.to_string(),
                        callback.client_secret.clone(),
                    );
                }
                ClientCredentialPlacement::Basic => {
                    let credentials = STANDARD
                        .encode(format!("{}:{}", callback.client_id, callback.client_secret));
                    headers.insert("authorization".to_string(), format!("Basic {credentials}"));
                }
                ClientCredentialPlacement::None => {}
            }
        }
        TokenExchangeRequest {
            endpoint: self.config.token.endpoint.clone(),
            method: self.config.token.method,
            headers,
            query,
            body,
        }
    }

    pub(super) async fn authenticate_with_client_credentials(
        &self,
        callback: OAuthLikeCallback,
        client_id_parameter: &str,
        client_secret_parameter: &str,
    ) -> Result<ExternalIdentity, ProviderError>
    where
        T: ProviderTransport,
    {
        self.authenticate_with_parameters(
            callback,
            client_id_parameter,
            client_secret_parameter,
            None,
        )
        .await
    }

    pub(super) async fn authenticate_with_parameters(
        &self,
        callback: OAuthLikeCallback,
        client_id_parameter: &str,
        client_secret_parameter: &str,
        identity_access_token_query: Option<&str>,
    ) -> Result<ExternalIdentity, ProviderError>
    where
        T: ProviderTransport,
    {
        let started = std::time::Instant::now();
        let span = tracing::info_span!(
            "authn.provider.authenticate",
            otel.kind = "client",
            authguard.provider = %self.provider_id,
            authguard.provider.type = "oauth",
            authguard.provider.identity_lookup = self.config.identity.endpoint.is_some(),
        );
        async {
            tracing::info!(
                event = "authguard.authn.provider.started",
                provider = %self.provider_id,
                "provider callback processing started"
            );
            let result = async {
                let token_response = self
                    .transport
                    .exchange_token(self.token_request(
                        &callback,
                        client_id_parameter,
                        client_secret_parameter,
                    ))
                    .await?;
                let access_token = string_at(&token_response, &self.config.token.access_token)
                    .ok_or(ProviderError::MissingAccessToken)?;
                let identity_response = if let Some(endpoint) = &self.config.identity.endpoint {
                    Some(
                        self.transport
                            .lookup_identity(IdentityLookupRequest {
                                endpoint: endpoint.clone(),
                                access_token,
                                access_token_query: identity_access_token_query.map(str::to_owned),
                            })
                            .await?,
                    )
                } else {
                    None
                };
                normalize_identity(
                    &self.provider_id,
                    &self.config.issuer,
                    &self.config.identity,
                    &token_response,
                    identity_response.as_ref(),
                )
            }
            .await;
            match &result {
                Ok(identity) => tracing::info!(
                    event = "authguard.authn.provider.succeeded",
                    provider = %self.provider_id,
                    subject_present = !identity.subject.is_empty(),
                    duration_seconds = started.elapsed().as_secs_f64(),
                    "provider callback processing completed"
                ),
                Err(error) => tracing::warn!(
                    event = "authguard.authn.provider.failed",
                    provider = %self.provider_id,
                    error_category = error.category(),
                    duration_seconds = started.elapsed().as_secs_f64(),
                    "provider callback processing failed"
                ),
            }
            result
        }
        .instrument(span)
        .await
    }
}

#[async_trait]
impl<T> IProviderAdapter for OAuthLikeProvider<T>
where
    T: ProviderTransport,
{
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn authorization_url(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
    ) -> Result<Url, ProviderError> {
        OAuthLikeProvider::authorization_url(self, client_id, redirect_uri, state)
    }

    async fn authenticate(
        &self,
        callback: OAuthLikeCallback,
    ) -> Result<ExternalIdentity, ProviderError> {
        self.authenticate_with_client_credentials(callback, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET)
            .await
    }
}

fn has_explicit_client_credentials(config: &crate::config::TokenEndpointProperties) -> bool {
    config
        .headers
        .values()
        .chain(config.query.values())
        .chain(config.body.values())
        .any(|value| value.contains("${clientId}") || value.contains("${clientSecret}"))
}

fn render_map(
    values: &BTreeMap<String, String>,
    variables: &BTreeMap<&str, &str>,
) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(name, template)| {
            let rendered =
                variables.iter().fold(template.clone(), |value, (variable, replacement)| {
                    value.replace(&format!("${{{variable}}}"), replacement)
                });
            (name.clone(), rendered)
        })
        .collect()
}
