//! Request, subject, network-condition, and access-context evaluation.

mod condition {
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
        /// Compiles the serializable condition specification for hot-path evaluation.
        ///
        /// # Errors
        ///
        /// Returns an error when a configured network condition contains an invalid CIDR.
        pub fn compile(&self) -> Result<AuthorizationConditions, String> {
            let source_ip =
                self.source_ip.as_ref().map(SourceIpConditionSpec::compile).transpose()?;
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
            let transport_matches = self
                .secure_transport
                .is_none_or(|expected| context.secure_transport == Some(expected));
            method_matches && transport_matches
        }
    }

    impl SubjectConditionSpec {
        fn matches(&self, context: &EvaluationContext) -> bool {
            let mfa_matches = self.mfa.is_none_or(|expected| {
                context.claims.get("mfa").and_then(|value| value.parse::<bool>().ok())
                    == Some(expected)
            });
            mfa_matches
                && self.claims.iter().all(|(key, value)| context.claims.get(key) == Some(value))
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
}
pub use condition::*;

mod access {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use hmac::{Hmac, Mac as _};
    use serde::{Deserialize, Serialize};
    use sha2::Sha256;
    use thiserror::Error;

    pub const ACCESS_CONTEXT_HEADER: &str = "x-authguard-context";
    pub const SCOPE_TOKEN_HEADER: &str = "x-authguard-scope-token";
    pub const ACCESS_CONTEXT_VERSION: u8 = 3;
    pub const ACCESS_CONTEXT_SIGNING_KEY_ENV: &str = "AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY";
    const SIGNED_CONTEXT_PREFIX: &str = "agctx1";
    const MIN_SIGNING_KEY_BYTES: usize = 32;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AccessContextInput {
        pub principal_id: String,
        pub action: String,
        pub resource_urn: String,
        pub allow_resource_urns: Vec<String>,
        pub deny_resource_urns: Vec<String>,
        pub policy_revision: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct AccessContext {
        pub version: u8,
        pub principal_id: String,
        pub action: String,
        pub resource_urn: String,
        pub allow_resource_urns: Vec<String>,
        pub deny_resource_urns: Vec<String>,
        pub policy_revision: u64,
        pub issued_at_epoch_seconds: u64,
        pub expires_at_epoch_seconds: u64,
    }

    #[derive(Debug, Error)]
    pub enum AccessContextError {
        #[error("invalid base64url access context: {0}")]
        Base64(#[from] base64::DecodeError),
        #[error("invalid access context JSON: {0}")]
        Json(#[from] serde_json::Error),
        #[error("unsupported access context version {0}")]
        UnsupportedVersion(u8),
        #[error("access context has expired")]
        Expired,
        #[error("access context issue time is in the future")]
        IssuedInFuture,
        #[error("access context expiry must be later than issue time")]
        InvalidLifetime,
        #[error("access context signing key must contain at least {MIN_SIGNING_KEY_BYTES} bytes")]
        InvalidSigningKey,
        #[error("invalid signed access context format")]
        InvalidSignedFormat,
        #[error("invalid signed access context signature")]
        InvalidSignature,
    }

    /// HMAC-SHA256 signer/verifier for direct request-access headers.
    #[derive(Clone)]
    pub struct AccessContextSigner {
        key: Vec<u8>,
    }

    impl std::fmt::Debug for AccessContextSigner {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.debug_struct("AccessContextSigner").finish_non_exhaustive()
        }
    }

    impl AccessContextSigner {
        /// Creates a signer from a high-entropy secret containing at least 32 bytes.
        ///
        /// # Errors
        ///
        /// Returns an error when the key is too short.
        pub fn new(key: impl AsRef<[u8]>) -> Result<Self, AccessContextError> {
            let key = key.as_ref();
            if key.len() < MIN_SIGNING_KEY_BYTES {
                return Err(AccessContextError::InvalidSigningKey);
            }
            Ok(Self { key: key.to_vec() })
        }

        /// Reads the direct-context key from `AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY`,
        /// either from the process environment or from the mounted
        /// `AUTHGUARD_ENV_FILE` KEY=VALUE file.
        ///
        /// # Errors
        ///
        /// Returns an error when the variable is absent, non-Unicode, or too short.
        pub fn from_env() -> Result<Self, AccessContextError> {
            let key = crate::config::secret_env(ACCESS_CONTEXT_SIGNING_KEY_ENV)
                .ok_or(AccessContextError::InvalidSigningKey)?;
            Self::new(key)
        }

        /// Signs an encoded context as `agctx1.<payload>.<base64url-hmac-sha256>`.
        ///
        /// # Errors
        ///
        /// Returns an error only if the configured HMAC key is invalid.
        pub fn sign_encoded(&self, encoded: &str) -> Result<String, AccessContextError> {
            let signing_input = format!("{SIGNED_CONTEXT_PREFIX}.{encoded}");
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
                .map_err(|_| AccessContextError::InvalidSigningKey)?;
            mac.update(signing_input.as_bytes());
            let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
            Ok(format!("{signing_input}.{signature}"))
        }

        /// Verifies a direct-context compact token and returns its encoded payload.
        ///
        /// # Errors
        ///
        /// Returns an error for malformed tokens or invalid signatures.
        pub fn verify(&self, signed: &str) -> Result<String, AccessContextError> {
            let mut parts = signed.split('.');
            let prefix = parts.next();
            let payload = parts.next();
            let signature = parts.next();
            if prefix != Some(SIGNED_CONTEXT_PREFIX)
                || payload.is_none_or(str::is_empty)
                || signature.is_none_or(str::is_empty)
                || parts.next().is_some()
            {
                return Err(AccessContextError::InvalidSignedFormat);
            }
            let Some(payload) = payload else {
                return Err(AccessContextError::InvalidSignedFormat);
            };
            let Some(signature) = signature else {
                return Err(AccessContextError::InvalidSignedFormat);
            };
            let signature = URL_SAFE_NO_PAD
                .decode(signature)
                .map_err(|_| AccessContextError::InvalidSignedFormat)?;
            let signing_input = format!("{SIGNED_CONTEXT_PREFIX}.{payload}");
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
                .map_err(|_| AccessContextError::InvalidSigningKey)?;
            mac.update(signing_input.as_bytes());
            mac.verify_slice(&signature).map_err(|_| AccessContextError::InvalidSignature)?;
            Ok(payload.to_string())
        }
    }

    impl AccessContext {
        #[must_use]
        pub fn new(
            input: AccessContextInput,
            issued_at_epoch_seconds: u64,
            ttl: std::time::Duration,
        ) -> Self {
            Self {
                version: ACCESS_CONTEXT_VERSION,
                principal_id: input.principal_id,
                action: input.action,
                resource_urn: input.resource_urn,
                allow_resource_urns: input.allow_resource_urns,
                deny_resource_urns: input.deny_resource_urns,
                policy_revision: input.policy_revision,
                issued_at_epoch_seconds,
                expires_at_epoch_seconds: issued_at_epoch_seconds.saturating_add(ttl.as_secs()),
            }
        }

        /// Serializes the context as unpadded `Base64URL` JSON for a single HTTP header.
        ///
        /// # Errors
        ///
        /// Returns an error if the context cannot be serialized.
        pub fn encode(&self) -> Result<String, serde_json::Error> {
            serde_json::to_vec(self).map(|json| URL_SAFE_NO_PAD.encode(json))
        }

        /// Decodes a versioned access context HTTP header.
        ///
        /// # Errors
        ///
        /// Returns an error for malformed `Base64URL`, invalid JSON, or unknown versions.
        pub fn decode(encoded: &str) -> Result<Self, AccessContextError> {
            let json = URL_SAFE_NO_PAD.decode(encoded)?;
            let context: Self = serde_json::from_slice(&json)?;
            context.validate(epoch_seconds())?;
            Ok(context)
        }

        /// Validates the version and bounded request lifetime at an explicit time.
        ///
        /// # Errors
        ///
        /// Returns an error for unsupported, expired, future-issued, or inverted
        /// lifetimes.
        pub fn validate(&self, now_epoch_seconds: u64) -> Result<(), AccessContextError> {
            if self.version != ACCESS_CONTEXT_VERSION {
                return Err(AccessContextError::UnsupportedVersion(self.version));
            }
            if self.expires_at_epoch_seconds <= self.issued_at_epoch_seconds {
                return Err(AccessContextError::InvalidLifetime);
            }
            if self.issued_at_epoch_seconds > now_epoch_seconds.saturating_add(30) {
                return Err(AccessContextError::IssuedInFuture);
            }
            if self.expires_at_epoch_seconds <= now_epoch_seconds {
                return Err(AccessContextError::Expired);
            }
            Ok(())
        }
    }

    #[must_use]
    pub fn epoch_seconds() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn access_context_round_trips_as_base64url_json() {
            let now = epoch_seconds();
            let expected = AccessContext::new(
                AccessContextInput {
                    principal_id: "principal-user-1".to_string(),
                    action: "job.read".to_string(),
                    resource_urn: "urn:iam:prod:customer-growth:global:example-corp:job/1"
                        .to_string(),
                    allow_resource_urns: vec![
                        "urn:iam:prod:customer-growth:global:example-corp:job/*".to_string(),
                    ],
                    deny_resource_urns: Vec::new(),
                    policy_revision: 7,
                },
                now,
                std::time::Duration::from_secs(30),
            );
            let encoded = expected.encode().expect("encode");
            assert!(!encoded.contains('='));
            assert_eq!(AccessContext::decode(&encoded).expect("decode"), expected);
        }

        #[test]
        fn expired_context_is_rejected() {
            let context = AccessContext::new(
                AccessContextInput {
                    principal_id: "principal-user-1".to_string(),
                    action: "job.read".to_string(),
                    resource_urn: "urn:iam:prod:customer-growth:global:example-corp:job/1"
                        .to_string(),
                    allow_resource_urns: Vec::new(),
                    deny_resource_urns: Vec::new(),
                    policy_revision: 7,
                },
                100,
                std::time::Duration::from_secs(1),
            );
            assert!(matches!(context.validate(101), Err(AccessContextError::Expired)));
        }

        #[test]
        fn direct_context_signature_detects_tampering() {
            let codec = AccessContextSigner::new([7_u8; 32]).expect("signer");
            let compact = codec.sign_encoded("payload").expect("sign");
            assert_eq!(codec.verify(&compact).expect("verify"), "payload");
            assert!(matches!(
                codec.verify(&compact.replace("payload", "tampered")),
                Err(AccessContextError::InvalidSignature)
            ));
        }
    }
}
pub use access::*;
