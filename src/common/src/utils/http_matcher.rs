use std::collections::HashMap;
use std::str::FromStr;

use thiserror::Error;

use crate::model::{HttpRouteMatcher, ResourceUrn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHttpRoute {
    pub route_id: String,
    pub action: String,
    pub resource_urn: ResourceUrn,
    pub parent_urns: Vec<ResourceUrn>,
}

#[derive(Debug, Error)]
pub enum HttpMappingError {
    #[error("route `{route_id}` path must start with /")]
    PathMustStartWithSlash { route_id: String },
    #[error("route `{route_id}` contains invalid path variable `{variable}`")]
    InvalidVariable { route_id: String, variable: String },
    #[error("route `{route_id}` may use ** only as the final path segment")]
    InvalidGlobStar { route_id: String },
    #[error("multiple HTTP authorization routes matched the request")]
    Ambiguous,
    #[error("no HTTP authorization route matched the request")]
    NotMapped,
    #[error("route template references missing value `{0}`")]
    MissingTemplateValue(String),
    #[error("route generated an invalid Resource URN: {0}")]
    InvalidResourceUrn(String),
}

#[derive(Debug, Clone)]
pub struct CompiledHttpRoute {
    action: String,
    rule: HttpRouteMatcher,
    path: Vec<PathMatcher>,
}

#[derive(Debug, Clone)]
enum PathMatcher {
    Literal(String),
    Variable(String),
    Any,
    Remainder,
}

impl CompiledHttpRoute {
    /// Compiles one bounded HTTP-to-resource mapping.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, variables, or glob placement.
    pub fn compile(action: String, rule: HttpRouteMatcher) -> Result<Self, HttpMappingError> {
        if !rule.path.starts_with('/') {
            return Err(HttpMappingError::PathMustStartWithSlash { route_id: rule.id });
        }
        let raw_segments = split_path(&rule.path);
        let mut path = Vec::with_capacity(raw_segments.len());
        for (index, segment) in raw_segments.iter().enumerate() {
            let matcher = match *segment {
                "*" => PathMatcher::Any,
                "**" if index + 1 == raw_segments.len() => PathMatcher::Remainder,
                "**" => {
                    return Err(HttpMappingError::InvalidGlobStar { route_id: rule.id.clone() });
                }
                value if value.starts_with('{') && value.ends_with('}') => {
                    let variable = &value[1..value.len() - 1];
                    if !valid_variable(variable) {
                        return Err(HttpMappingError::InvalidVariable {
                            route_id: rule.id.clone(),
                            variable: variable.to_string(),
                        });
                    }
                    PathMatcher::Variable(variable.to_string())
                }
                value => PathMatcher::Literal(value.to_string()),
            };
            path.push(matcher);
        }
        Ok(Self { action, rule, path })
    }

    fn resolve<S: std::hash::BuildHasher>(
        &self,
        method: &str,
        host: &str,
        request_path: &str,
        claims: &HashMap<String, String, S>,
    ) -> Result<Option<ResolvedHttpRoute>, HttpMappingError> {
        if !self.rule.methods.is_empty()
            && !self.rule.methods.iter().any(|candidate| candidate.eq_ignore_ascii_case(method))
        {
            return Ok(None);
        }
        if !self.rule.hosts.is_empty()
            && !self.rule.hosts.iter().any(|candidate| host_matches(candidate, host))
        {
            return Ok(None);
        }

        let mut values: HashMap<String, String> =
            claims.iter().map(|(name, value)| (name.clone(), value.clone())).collect();
        values.insert("method".to_string(), method.to_ascii_lowercase());
        values.insert("host".to_string(), host.to_string());
        if !match_path(&self.path, request_path, &mut values) {
            return Ok(None);
        }

        let raw_urn = expand_template(&self.rule.resource_urn, &values)?;
        let resource_urn = ResourceUrn::from_str(&raw_urn)
            .map_err(|err| HttpMappingError::InvalidResourceUrn(err.to_string()))?;
        let parent_urns = self
            .rule
            .parent_urns
            .iter()
            .map(|template| {
                let raw = expand_template(template, &values)?;
                ResourceUrn::from_str(&raw)
                    .map_err(|err| HttpMappingError::InvalidResourceUrn(err.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(ResolvedHttpRoute {
            route_id: self.rule.id.clone(),
            action: self.action.clone(),
            resource_urn,
            parent_urns,
        }))
    }
}

/// Resolves exactly one compiled route for an HTTP request.
///
/// # Errors
///
/// Returns an error when no route or more than one route matches, or when a
/// matched resource template cannot be expanded safely.
pub fn resolve_route<S: std::hash::BuildHasher>(
    routes: &[CompiledHttpRoute],
    method: &str,
    host: &str,
    path: &str,
    claims: &HashMap<String, String, S>,
) -> Result<ResolvedHttpRoute, HttpMappingError> {
    let mut resolved = None;
    for route in routes {
        if let Some(candidate) = route.resolve(method, host, path, claims)? {
            if resolved.is_some() {
                return Err(HttpMappingError::Ambiguous);
            }
            resolved = Some(candidate);
        }
    }
    resolved.ok_or(HttpMappingError::NotMapped)
}

fn match_path(
    pattern: &[PathMatcher],
    request_path: &str,
    values: &mut HashMap<String, String>,
) -> bool {
    let request = split_path(request_path);
    let mut request_index = 0;
    for matcher in pattern {
        match matcher {
            PathMatcher::Remainder => return true,
            PathMatcher::Literal(expected) => {
                if request.get(request_index).copied() != Some(expected.as_str()) {
                    return false;
                }
            }
            PathMatcher::Variable(name) => {
                let Some(value) = request.get(request_index) else {
                    return false;
                };
                values.insert(name.clone(), (*value).to_string());
            }
            PathMatcher::Any => {
                if request.get(request_index).is_none() {
                    return false;
                }
            }
        }
        request_index += 1;
    }
    request_index == request.len()
}

fn split_path(path: &str) -> Vec<&str> {
    path.trim_matches('/').split('/').filter(|segment| !segment.is_empty()).collect()
}

fn expand_template(
    template: &str,
    values: &HashMap<String, String>,
) -> Result<String, HttpMappingError> {
    let mut output = String::with_capacity(template.len());
    let mut remaining = template;
    while let Some(start) = remaining.find('{') {
        output.push_str(&remaining[..start]);
        let after_start = &remaining[start + 1..];
        let Some(end) = after_start.find('}') else {
            return Err(HttpMappingError::MissingTemplateValue(after_start.to_string()));
        };
        let variable = &after_start[..end];
        let value = values
            .get(variable)
            .ok_or_else(|| HttpMappingError::MissingTemplateValue(variable.to_string()))?;
        output.push_str(value);
        remaining = &after_start[end + 1..];
    }
    output.push_str(remaining);
    Ok(output)
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.split(':').next().unwrap_or(host);
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host != suffix && host.ends_with(&format!(".{suffix}"));
    }
    pattern.eq_ignore_ascii_case(host)
}

fn valid_variable(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_path_and_identity_claims_into_resource_urn() {
        let route = CompiledHttpRoute::compile(
            "customer-growth.job.read".to_string(),
            HttpRouteMatcher {
                id: "job-read".to_string(),
                methods: vec!["GET".to_string()],
                hosts: vec!["*.example.com".to_string()],
                path: "/customer-growth/jobs/{job_id}".to_string(),
                resource_urn: "urn:iam:prod:customer-growth:global:{tenant_id}:job/{job_id}"
                    .to_string(),
                parent_urns: Vec::new(),
            },
        )
        .expect("route");
        let claims = HashMap::from([("tenant_id".to_string(), "acme".to_string())]);

        let resolved = resolve_route(
            &[route],
            "GET",
            "api.example.com",
            "/customer-growth/jobs/job-1",
            &claims,
        )
        .expect("resolved");

        assert_eq!(resolved.route_id, "job-read");
        assert_eq!(
            resolved.resource_urn.to_string(),
            "urn:iam:prod:customer-growth:global:acme:job/job-1"
        );
        assert_eq!(resolved.action, "customer-growth.job.read");
    }
}
