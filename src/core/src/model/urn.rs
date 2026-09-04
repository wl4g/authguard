use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UrnError {
    #[error("URN must use format urn:iam:<partition>:<service>:<region>:<tenant>:<resource-path>")]
    InvalidFormat,
    #[error("URN segment `{0}` must not be empty")]
    EmptySegment(&'static str),
    #[error("exact Resource URN must not contain wildcard `{0}`")]
    WildcardInExactUrn(String),
    #[error("wildcard `{0}` is not allowed in this segment")]
    InvalidWildcard(String),
    #[error("globstar ** is only allowed as the final resource path segment")]
    InvalidGlobStar,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceUrn {
    pub partition: String,
    pub service: String,
    pub region: String,
    pub tenant: String,
    pub path: Vec<String>,
}

impl ResourceUrn {
    #[must_use]
    pub fn path_string(&self) -> String {
        self.path.join("/")
    }
}

impl fmt::Display for ResourceUrn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "urn:iam:{}:{}:{}:{}:{}",
            self.partition,
            self.service,
            self.region,
            self.tenant,
            self.path.join("/")
        )
    }
}

impl FromStr for ResourceUrn {
    type Err = UrnError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let parts = split_urn(input)?;
        validate_exact_segment("partition", parts.partition)?;
        validate_exact_segment("service", parts.service)?;
        validate_exact_segment("region", parts.region)?;
        validate_exact_segment("tenant", parts.tenant)?;
        let path = split_path(parts.path)?;
        for segment in &path {
            if segment == "*" || segment == "**" {
                return Err(UrnError::WildcardInExactUrn(segment.clone()));
            }
        }
        Ok(Self {
            partition: parts.partition.to_string(),
            service: parts.service.to_string(),
            region: parts.region.to_string(),
            tenant: parts.tenant.to_string(),
            path,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrnPattern {
    pub partition: SegmentPattern,
    pub service: SegmentPattern,
    pub region: SegmentPattern,
    pub tenant: SegmentPattern,
    pub path: Vec<PathPattern>,
}

impl UrnPattern {
    #[must_use]
    pub fn matches(&self, urn: &ResourceUrn) -> bool {
        self.partition.matches(&urn.partition)
            && self.service.matches(&urn.service)
            && self.region.matches(&urn.region)
            && self.tenant.matches(&urn.tenant)
            && path_matches(&self.path, &urn.path)
    }

    #[must_use]
    pub fn matches_any<'a>(&self, urns: impl IntoIterator<Item = &'a ResourceUrn>) -> bool {
        urns.into_iter().any(|urn| self.matches(urn))
    }
}

impl fmt::Display for UrnPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self.path.iter().map(ToString::to_string).collect::<Vec<_>>().join("/");
        write!(
            f,
            "urn:iam:{}:{}:{}:{}:{}",
            self.partition, self.service, self.region, self.tenant, path
        )
    }
}

impl FromStr for UrnPattern {
    type Err = UrnError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let parts = split_urn(input)?;
        Ok(Self {
            partition: SegmentPattern::parse(parts.partition)?,
            service: SegmentPattern::parse(parts.service)?,
            region: SegmentPattern::parse(parts.region)?,
            tenant: SegmentPattern::parse(parts.tenant)?,
            path: parse_path_pattern(parts.path)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentPattern {
    Exact(String),
    Any,
}

impl SegmentPattern {
    fn parse(input: &str) -> Result<Self, UrnError> {
        if input.is_empty() {
            return Err(UrnError::EmptySegment("segment"));
        }
        match input {
            "*" => Ok(Self::Any),
            "**" => Err(UrnError::InvalidWildcard(input.to_string())),
            _ if input.contains('*') => Err(UrnError::InvalidWildcard(input.to_string())),
            _ => Ok(Self::Exact(input.to_string())),
        }
    }

    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Self::Exact(expected) => expected == value,
            Self::Any => true,
        }
    }
}

impl fmt::Display for SegmentPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(value) => write!(f, "{value}"),
            Self::Any => write!(f, "*"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathPattern {
    Exact(String),
    Any,
    GlobStar,
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(value) => write!(f, "{value}"),
            Self::Any => write!(f, "*"),
            Self::GlobStar => write!(f, "**"),
        }
    }
}

struct UrnParts<'a> {
    partition: &'a str,
    service: &'a str,
    region: &'a str,
    tenant: &'a str,
    path: &'a str,
}

fn split_urn(input: &str) -> Result<UrnParts<'_>, UrnError> {
    let mut parts = input.splitn(7, ':');
    let scheme = parts.next().ok_or(UrnError::InvalidFormat)?;
    let nid = parts.next().ok_or(UrnError::InvalidFormat)?;
    let partition = parts.next().ok_or(UrnError::InvalidFormat)?;
    let service = parts.next().ok_or(UrnError::InvalidFormat)?;
    let region = parts.next().ok_or(UrnError::InvalidFormat)?;
    let tenant = parts.next().ok_or(UrnError::InvalidFormat)?;
    let path = parts.next().ok_or(UrnError::InvalidFormat)?;
    if scheme != "urn" || nid != "iam" || path.contains(':') {
        return Err(UrnError::InvalidFormat);
    }
    Ok(UrnParts { partition, service, region, tenant, path })
}

fn validate_exact_segment(name: &'static str, input: &str) -> Result<(), UrnError> {
    if input.is_empty() {
        return Err(UrnError::EmptySegment(name));
    }
    if input == "*" || input == "**" || input.contains('*') {
        return Err(UrnError::WildcardInExactUrn(input.to_string()));
    }
    Ok(())
}

fn split_path(input: &str) -> Result<Vec<String>, UrnError> {
    if input.is_empty() {
        return Err(UrnError::EmptySegment("resource-path"));
    }
    let segments = input.split('/').map(str::to_string).collect::<Vec<_>>();
    if segments.iter().any(String::is_empty) {
        return Err(UrnError::EmptySegment("resource-path"));
    }
    Ok(segments)
}

fn parse_path_pattern(input: &str) -> Result<Vec<PathPattern>, UrnError> {
    let segments = split_path(input)?;
    let mut result = Vec::with_capacity(segments.len());
    for (idx, segment) in segments.iter().enumerate() {
        let parsed = match segment.as_str() {
            "*" => PathPattern::Any,
            "**" if idx + 1 == segments.len() => PathPattern::GlobStar,
            "**" => return Err(UrnError::InvalidGlobStar),
            _ if segment.contains('*') => return Err(UrnError::InvalidWildcard(segment.clone())),
            _ => PathPattern::Exact(segment.clone()),
        };
        result.push(parsed);
    }
    Ok(result)
}

fn path_matches(pattern: &[PathPattern], path: &[String]) -> bool {
    let mut pidx = 0;
    let mut uidx = 0;
    while pidx < pattern.len() {
        match &pattern[pidx] {
            PathPattern::GlobStar => return pidx + 1 == pattern.len(),
            PathPattern::Any => {
                if uidx >= path.len() {
                    return false;
                }
                pidx += 1;
                uidx += 1;
            }
            PathPattern::Exact(expected) => {
                if path.get(uidx) != Some(expected) {
                    return false;
                }
                pidx += 1;
                uidx += 1;
            }
        }
    }
    uidx == path.len()
}
