//! Search-and-user-bind authentication; no directory credentials are persisted.

use super::{ApiError, AuthenticationPipeline, AuthnRuntime, LoginResponse};
use crate::{AuthenticationResult, ExternalIdentity, PrincipalKind};
use authguard_common::{
    apm::AuthnMetrics,
    config::{AppConfig, LdapAuthnProperties},
};
use axum::{extract::State, http::HeaderMap, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use ldap3::{ldap_escape, LdapConnAsync, LdapConnSettings, Scope, SearchEntry, SearchOptions};
use serde::Deserialize;
use serde_json::json;
use std::{collections::BTreeMap, sync::Arc, time::Instant};

#[derive(Clone)]
pub(crate) struct LdapHandler {
    config: LdapAuthnProperties,
    pipeline: Arc<AuthenticationPipeline>,
    metrics: AuthnMetrics,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LdapLoginRequest {
    login: String,
    password: String,
    #[serde(default)]
    return_to: String,
}

impl LdapHandler {
    pub(crate) fn open(
        metrics: AuthnMetrics,
        runtime: &AuthnRuntime,
    ) -> anyhow::Result<Option<Self>> {
        let config = AppConfig::get().get_authn().ldap.clone();
        if !config.enabled {
            return Ok(None);
        }
        Self::new(config, runtime.pipeline.clone(), metrics).map(Some)
    }

    fn new(
        mut config: LdapAuthnProperties,
        pipeline: Arc<AuthenticationPipeline>,
        metrics: AuthnMetrics,
    ) -> anyhow::Result<Self> {
        config.validate()?;
        if ldap3::parse_filter(config.user_filter.replace("{login}", "user")).is_err() {
            anyhow::bail!("authn.ldap.userFilter is not a valid LDAP search filter");
        }
        if !config.bind_password_file.is_empty() {
            config.bind_password = std::fs::read_to_string(&config.bind_password_file)
                .map_err(|_| anyhow::anyhow!("authn.ldap bind credential file could not be read"))?
                .trim_end_matches(['\r', '\n'])
                .to_string();
            if config.bind_password.is_empty() {
                anyhow::bail!("authn.ldap bind credential is empty");
            }
        }
        Ok(Self { config, pipeline, metrics })
    }

    pub(crate) async fn login(
        State(handler): State<Self>,
        headers: HeaderMap,
        Json(request): Json<LdapLoginRequest>,
    ) -> Result<LoginResponse, ApiError> {
        let started = Instant::now();
        let result = async {
            let return_to = crate::route::application::ApplicationResolver::new(
                AppConfig::get().get_authn(),
                &headers,
            )
            .validate_return_to(&request.return_to)?;
            let identity = handler.authenticate(&request.login, &request.password).await?;
            let authentication = AuthenticationResult::new(identity, ["pwd"], None, Utc::now());
            let issued = handler
                .pipeline
                .login(authentication, PrincipalKind::User)
                .await
                .map_err(ApiError::pipeline)?;
            if issued.principal.kind != PrincipalKind::User {
                return Err(ApiError::unauthorized("invalid credentials"));
            }
            Ok(LoginResponse::new(issued, return_to))
        }
        .await;
        handler.metrics.record_flow(
            &handler.config.provider_id,
            "ldap_password",
            result.as_ref().err().map_or("success", ApiError::metric_outcome),
            started.elapsed().as_secs_f64(),
        );
        result
    }

    async fn authenticate(
        &self,
        login: &str,
        password: &str,
    ) -> Result<ExternalIdentity, ApiError> {
        let login = login.trim();
        if login.is_empty()
            || login.len() > 256
            || login.chars().any(char::is_control)
            || password.is_empty()
            || password.len() > 4096
        {
            return Err(ApiError::unauthorized("invalid credentials"));
        }
        tokio::time::timeout(self.config.request_timeout, self.bind_user(login, password))
            .await
            .map_err(|_| ApiError::unavailable("LDAP authentication timed out"))?
    }

    async fn bind_user(&self, login: &str, password: &str) -> Result<ExternalIdentity, ApiError> {
        let config = &self.config;
        let settings = LdapConnSettings::new()
            .set_conn_timeout(config.connect_timeout)
            .set_starttls(config.start_tls);
        let (connection, mut ldap) = LdapConnAsync::with_settings(settings, &config.url)
            .await
            .map_err(|_| ApiError::unavailable("LDAP authentication is unavailable"))?;
        ldap3::drive!(connection);
        let result = async {
            ldap.simple_bind(&config.bind_dn, &config.bind_password)
                .await
                .and_then(ldap3::LdapResult::success)
                .map_err(|_| ApiError::unavailable("LDAP directory search is unavailable"))?;
            let filter = config.user_filter.replace("{login}", &ldap_escape(login));
            let attrs = [&config.subject_attribute, &config.display_name_attribute]
                .into_iter()
                .filter(|s| !s.is_empty())
                .map(String::as_str)
                .collect::<Vec<_>>();
            let ldap3::SearchResult(entries, status) = ldap
                .with_search_options(SearchOptions::new().sizelimit(2))
                .search(&config.base_dn, Scope::Subtree, &filter, attrs)
                .await
                .map_err(|_| ApiError::unavailable("LDAP directory search is unavailable"))?;
            if entries.len() != 1 {
                return Err(ApiError::unauthorized("invalid credentials"));
            }
            if !status.refs.is_empty() {
                return Err(ApiError::unavailable("LDAP referrals are not supported"));
            }
            status
                .success()
                .map_err(|_| ApiError::unavailable("LDAP directory search is unavailable"))?;
            let entry = std::panic::catch_unwind(|| {
                SearchEntry::construct(entries.into_iter().next().expect("one LDAP entry"))
            })
            .map_err(|_| ApiError::unavailable("LDAP directory response is invalid"))?;
            if entry.dn.is_empty() {
                return Err(ApiError::unauthorized("invalid credentials"));
            }
            let subject = Self::subject(&entry, &config.subject_attribute)
                .ok_or_else(|| ApiError::unavailable("LDAP stable subject is unavailable"))?;
            ldap.simple_bind(&entry.dn, password)
                .await
                .map_err(|_| ApiError::unavailable("LDAP authentication is unavailable"))?
                .success()
                .map_err(|_| ApiError::unauthorized("invalid credentials"))?;
            let name = Self::attribute(&entry, &config.display_name_attribute).unwrap_or(login);
            Ok(ExternalIdentity {
                provider: config.provider_id.clone(),
                issuer: config.issuer.clone(),
                subject,
                claims: BTreeMap::from([("display_name".to_string(), json!(name))]),
            })
        }
        .await;
        let _ = ldap.unbind().await;
        result
    }

    fn attribute<'a>(entry: &'a SearchEntry, name: &str) -> Option<&'a str> {
        entry
            .attrs
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .and_then(|(_, values)| (values.len() == 1).then(|| values[0].as_str()))
            .filter(|value| !value.trim().is_empty())
    }

    fn subject(entry: &SearchEntry, name: &str) -> Option<String> {
        Self::attribute(entry, name).map(str::to_string).or_else(|| {
            entry.bin_attrs.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).and_then(
                |(_, values)| {
                    (values.len() == 1 && !values[0].is_empty())
                        .then(|| URL_SAFE_NO_PAD.encode(&values[0]))
                },
            )
        })
    }
}

#[cfg(test)]
#[path = "../../tests/handler/ldap.rs"]
mod tests;
