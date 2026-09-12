use std::collections::BTreeMap;

use reqwest::Url;
use serde_json::Value;

use super::ProviderError;
use crate::config::{IdentityMappingProperties, OAuthProviderProperties};
use crate::model::ExternalIdentity;

pub(super) fn validate_provider(
    provider_id: &str,
    config: &OAuthProviderProperties,
) -> Result<(), ProviderError> {
    require_canonical("provider id", provider_id)?;
    require_canonical("issuer", &config.issuer)?;
    parse_http_url("authorization endpoint", &config.authorization.endpoint)?;
    parse_http_url("token endpoint", &config.token.endpoint)?;
    if let Some(endpoint) = &config.identity.endpoint {
        parse_http_url("identity endpoint", endpoint)?;
    }
    validate_json_path(&config.token.access_token)?;
    validate_json_path(&config.identity.subject)?;
    for path in config
        .identity
        .fallback_subject
        .iter()
        .chain(config.identity.username.iter())
        .chain(config.identity.email.iter())
        .chain(config.identity.trusted_claims.values())
    {
        validate_json_path(path)?;
    }
    Ok(())
}

pub(super) fn normalize_identity(
    provider: &str,
    issuer: &str,
    mapping: &IdentityMappingProperties,
    token_response: &Value,
    identity_response: Option<&Value>,
) -> Result<ExternalIdentity, ProviderError> {
    let source = identity_response.unwrap_or(token_response);
    let subject = string_at(source, &mapping.subject)
        .or_else(|| mapping.fallback_subject.as_deref().and_then(|path| string_at(source, path)))
        .ok_or(ProviderError::MissingSubject)?;
    require_canonical("subject", &subject)?;

    let mut claims = BTreeMap::new();
    for (name, path) in &mapping.trusted_claims {
        insert_claim(&mut claims, name, source, path);
    }
    if let Some(path) = mapping.username.as_deref() {
        insert_claim(&mut claims, "username", source, path);
    }
    if let Some(path) = mapping.email.as_deref() {
        // Email remains profile metadata and is never an account-linking key.
        insert_claim(&mut claims, "email", source, path);
    }
    Ok(ExternalIdentity {
        provider: provider.to_string(),
        issuer: issuer.to_string(),
        subject,
        claims,
    })
}

pub(super) fn string_at(value: &Value, path: &str) -> Option<String> {
    match value_at(value, path)? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn insert_claim(claims: &mut BTreeMap<String, Value>, name: &str, source: &Value, path: &str) {
    if let Some(value) = value_at(source, path).filter(|value| !value.is_null()) {
        claims.insert(name.to_string(), value.clone());
    }
}

fn parse_http_url(name: &'static str, input: &str) -> Result<(), ProviderError> {
    let url = Url::parse(input).map_err(|_| ProviderError::InvalidConfiguration(name))?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        return Err(ProviderError::InvalidConfiguration(name));
    }
    Ok(())
}

fn require_canonical(name: &'static str, input: &str) -> Result<(), ProviderError> {
    if input.is_empty() || input.trim() != input || input.len() > 512 {
        return Err(ProviderError::InvalidConfiguration(name));
    }
    Ok(())
}

fn validate_json_path(path: &str) -> Result<(), ProviderError> {
    if path == "$"
        || path
            .strip_prefix("$.")
            .is_some_and(|tail| !tail.is_empty() && tail.split('.').all(valid_path_segment))
    {
        return Ok(());
    }
    Err(ProviderError::InvalidConfiguration(
        "identity mappings support only simple JSON paths like $.data.user.id",
    ))
}

fn valid_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn value_at<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path == "$" {
        return Some(value);
    }
    path.strip_prefix("$.")?
        .split('.')
        .try_fold(value, |current, key| current.as_object()?.get(key))
}

#[cfg(test)]
mod tests {
    use super::validate_json_path;

    #[test]
    fn supports_only_bounded_json_paths() {
        assert!(validate_json_path("$.users[?(@.primary)].id").is_err());
        assert!(validate_json_path("$.data.user.id").is_ok());
    }
}
