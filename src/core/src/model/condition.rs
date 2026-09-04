use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationConditionSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<SourceIpConditionSpec>,
    #[serde(default, skip_serializing_if = "RequestConditionSpec::is_empty")]
    pub request: RequestConditionSpec,
    #[serde(default, skip_serializing_if = "SubjectConditionSpec::is_empty")]
    pub subject: SubjectConditionSpec,
}

impl AuthorizationConditionSpec {
    pub(crate) fn compile(&self) -> Result<AuthorizationConditions, String> {
        let source_ip = self.source_ip.as_ref().map(SourceIpConditionSpec::compile).transpose()?;
        Ok(AuthorizationConditions {
            source_ip,
            request: self.request.clone(),
            subject: self.subject.clone(),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceIpConditionSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub in_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_in_cidr: Vec<String>,
}

impl SourceIpConditionSpec {
    fn compile(&self) -> Result<SourceIpConditions, String> {
        fn parse(values: &[String], field: &str) -> Result<Vec<IpNet>, String> {
            values
                .iter()
                .map(|value| {
                    value.parse::<IpNet>().map_err(|error| {
                        format!("{field} contains invalid CIDR `{value}`: {error}")
                    })
                })
                .collect()
        }

        Ok(SourceIpConditions {
            in_cidr: parse(&self.in_cidr, "sourceIp.inCidr")?,
            not_in_cidr: parse(&self.not_in_cidr, "sourceIp.notInCidr")?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestConditionSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_transport: Option<bool>,
}

impl RequestConditionSpec {
    fn is_empty(&self) -> bool {
        self.methods.is_empty() && self.secure_transport.is_none()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectConditionSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, String>,
}

impl SubjectConditionSpec {
    fn is_empty(&self) -> bool {
        self.mfa.is_none() && self.claims.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluationContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_transport: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationConditions {
    source_ip: Option<SourceIpConditions>,
    request: RequestConditionSpec,
    subject: SubjectConditionSpec,
}

impl AuthorizationConditions {
    #[must_use]
    pub fn matches(&self, context: &EvaluationContext) -> bool {
        self.source_ip.as_ref().is_none_or(|condition| condition.matches(context.source_ip))
            && self.request.matches(context)
            && self.subject.matches(context)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SourceIpConditions {
    in_cidr: Vec<IpNet>,
    not_in_cidr: Vec<IpNet>,
}

impl SourceIpConditions {
    fn matches(&self, source_ip: Option<IpAddr>) -> bool {
        let Some(source_ip) = source_ip else {
            return false;
        };
        (self.in_cidr.is_empty() || self.in_cidr.iter().any(|cidr| cidr.contains(&source_ip)))
            && !self.not_in_cidr.iter().any(|cidr| cidr.contains(&source_ip))
    }
}

impl RequestConditionSpec {
    fn matches(&self, context: &EvaluationContext) -> bool {
        let method_matches = self.methods.is_empty()
            || context.request_method.as_ref().is_some_and(|method| {
                self.methods.iter().any(|allowed| allowed.eq_ignore_ascii_case(method))
            });
        let transport_matches =
            self.secure_transport.is_none_or(|expected| context.secure_transport == Some(expected));
        method_matches && transport_matches
    }
}

impl SubjectConditionSpec {
    fn matches(&self, context: &EvaluationContext) -> bool {
        let mfa_matches = self.mfa.is_none_or(|expected| {
            context.claims.get("mfa").and_then(|value| value.parse::<bool>().ok()) == Some(expected)
        });
        mfa_matches && self.claims.iter().all(|(key, value)| context.claims.get(key) == Some(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combines_network_transport_and_subject_conditions() {
        let conditions = AuthorizationConditionSpec {
            source_ip: Some(SourceIpConditionSpec {
                in_cidr: vec!["10.0.0.0/8".to_string()],
                not_in_cidr: vec!["10.20.0.0/16".to_string()],
            }),
            request: RequestConditionSpec {
                methods: vec!["GET".to_string()],
                secure_transport: Some(true),
            },
            subject: SubjectConditionSpec {
                mfa: Some(true),
                claims: BTreeMap::from([("department".to_string(), "risk".to_string())]),
            },
        }
        .compile()
        .expect("conditions");
        let context = EvaluationContext {
            source_ip: Some("10.10.1.8".parse().expect("ip")),
            request_method: Some("get".to_string()),
            secure_transport: Some(true),
            claims: BTreeMap::from([
                ("mfa".to_string(), "true".to_string()),
                ("department".to_string(), "risk".to_string()),
            ]),
        };
        assert!(conditions.matches(&context));
    }

    #[test]
    fn required_attributes_fail_closed() {
        let conditions = AuthorizationConditionSpec {
            source_ip: Some(SourceIpConditionSpec {
                in_cidr: vec!["10.0.0.0/8".to_string()],
                not_in_cidr: Vec::new(),
            }),
            request: RequestConditionSpec { methods: Vec::new(), secure_transport: Some(true) },
            subject: SubjectConditionSpec { mfa: Some(true), claims: BTreeMap::new() },
        }
        .compile()
        .expect("conditions");
        assert!(!conditions.matches(&EvaluationContext::default()));
    }
}
