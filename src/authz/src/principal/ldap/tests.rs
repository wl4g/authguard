use std::collections::BTreeMap;

use tokio::sync::Mutex;

use super::*;
use crate::config::LdapBindAuthProperties;

#[derive(Default)]
struct FakeLdapSearchClient {
    pages: BTreeMap<String, LdapSearchPage>,
    requests: Mutex<Vec<LdapSearchRequest>>,
}

impl FakeLdapSearchClient {
    fn with_pages(pages: impl IntoIterator<Item = (String, LdapSearchPage)>) -> Self {
        Self { pages: pages.into_iter().collect(), requests: Mutex::new(Vec::new()) }
    }
}

#[async_trait]
impl ILdapSearchClient for FakeLdapSearchClient {
    async fn search(
        &self,
        request: LdapSearchRequest,
    ) -> Result<LdapSearchPage, PrincipalDiscoveryError> {
        let page = self.pages.get(&request.base_dn).cloned().unwrap_or_default();
        self.requests.lock().await.push(request);
        Ok(page)
    }
}

fn user_mapping() -> LdapObjectMappingProperties {
    LdapObjectMappingProperties {
        search_base: "ou=people".to_string(),
        object_filter: "(objectClass=inetOrgPerson)".to_string(),
        id_attribute: "entryUUID".to_string(),
        name_attribute: "uid".to_string(),
        display_name_attribute: Some("cn".to_string()),
        email_attribute: Some("mail".to_string()),
        enabled_attribute: Some("accountEnabled".to_string()),
        search_attributes: ["uid", "cn", "mail"].into_iter().map(str::to_string).collect(),
    }
}

fn group_mapping() -> LdapObjectMappingProperties {
    LdapObjectMappingProperties {
        search_base: "ou=groups".to_string(),
        object_filter: "(objectClass=groupOfNames)".to_string(),
        id_attribute: "entryUUID".to_string(),
        name_attribute: "cn".to_string(),
        search_attributes: ["cn"].into_iter().map(str::to_string).collect(),
        ..LdapObjectMappingProperties::default()
    }
}

fn config() -> LdapPrincipalDiscoveryProperties {
    LdapPrincipalDiscoveryProperties {
        discovery_id: "corporate-ldap".to_string(),
        url: "ldaps://ldap.example.com:636".to_string(),
        issuer: "https://identity.example.com/directories/corporate".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        auth: LdapBindAuthProperties {
            bind_dn: "uid=authguard,ou=service-accounts,dc=example,dc=com".to_string(),
            bind_password: "not-logged-secret".to_string(),
            ..LdapBindAuthProperties::default()
        },
        user: user_mapping(),
        group: group_mapping(),
        ..LdapPrincipalDiscoveryProperties::default()
    }
}

fn user_entry(external_id: &str) -> LdapEntry {
    LdapEntry {
        dn: "uid=alice,ou=people,dc=example,dc=com".to_string(),
        attributes: BTreeMap::from([
            ("entryuuid".to_string(), vec![external_id.to_string()]),
            ("uid".to_string(), vec!["alice".to_string()]),
            ("cn".to_string(), vec!["Alice Analyst".to_string()]),
            ("mail".to_string(), vec!["alice@example.com".to_string()]),
            ("accountenabled".to_string(), vec!["TRUE".to_string()]),
        ]),
    }
}

fn group_entry(external_id: &str) -> LdapEntry {
    LdapEntry {
        dn: "cn=growth-analysts,ou=groups,dc=example,dc=com".to_string(),
        attributes: BTreeMap::from([
            ("entryuuid".to_string(), vec![external_id.to_string()]),
            ("cn".to_string(), vec!["growth-analysts".to_string()]),
        ]),
    }
}

#[test]
fn rejects_plain_ldap_by_default_without_exposing_bind_secret() {
    let mut config = config();
    config.url = "ldap://ldap.example.com:389".to_string();

    let error = LdapPrincipalDiscovery::new(&config).err().expect("unsafe LDAP rejected");

    assert!(matches!(error, PrincipalDiscoveryError::InvalidConfiguration(_)));
    assert!(!error.to_string().contains("not-logged-secret"));
}

#[test]
fn accepts_plain_ldap_only_when_explicitly_enabled() {
    let mut config = config();
    config.url = "ldap://127.0.0.1:1389".to_string();
    config.allow_insecure = true;

    assert!(LdapPrincipalDiscovery::new(&config).is_ok());
}

#[test]
fn rejects_malformed_static_filter_and_attribute_description() {
    let mut invalid_filter = config();
    invalid_filter.user.object_filter = "(objectClass=person".to_string();
    assert!(LdapPrincipalDiscovery::new(&invalid_filter).is_err());

    let mut invalid_attribute = config();
    invalid_attribute.user.search_attributes = vec!["uid)(objectClass=*)".to_string()];
    assert!(LdapPrincipalDiscovery::new(&invalid_attribute).is_err());
}

#[tokio::test]
async fn search_maps_user_group_and_independent_paged_cursors() {
    let fake = Arc::new(FakeLdapSearchClient::with_pages([
        (
            "ou=people,dc=example,dc=com".to_string(),
            LdapSearchPage {
                entries: vec![user_entry("user-42")],
                next_cookie: b"user-cookie".to_vec(),
            },
        ),
        (
            "ou=groups,dc=example,dc=com".to_string(),
            LdapSearchPage {
                entries: vec![group_entry("group-7")],
                next_cookie: b"group-cookie".to_vec(),
            },
        ),
    ]));
    let provider = LdapPrincipalDiscovery::with_client(&config(), fake.clone()).expect("provider");

    let page = provider.discover(PrincipalSearchQuery::new("growth")).await.expect("search LDAP");

    assert_eq!(page.principals.len(), 2);
    assert_eq!(page.principals[0].kind, PrincipalKind::User);
    assert_eq!(page.principals[0].display_name, "Alice Analyst");
    assert_eq!(page.principals[0].reference.external_id, "user-42");
    assert_eq!(page.principals[1].kind, PrincipalKind::Group);
    assert_eq!(page.principals[1].reference.external_id, "group:group-7");
    assert_eq!(
        page.next_cursors.get("corporate-ldap:users"),
        Some(&URL_SAFE_NO_PAD.encode(b"user-cookie"))
    );
    assert_eq!(
        page.next_cursors.get("corporate-ldap:groups"),
        Some(&URL_SAFE_NO_PAD.encode(b"group-cookie"))
    );
    assert_eq!(fake.requests.lock().await.len(), 2);
}

#[tokio::test]
async fn search_escapes_untrusted_text_before_building_rfc4515_filter() {
    let fake = Arc::new(FakeLdapSearchClient::default());
    let provider = LdapPrincipalDiscovery::with_client(&config(), fake.clone()).expect("provider");
    let mut query = PrincipalSearchQuery::new("alice*)(uid=*)");
    query.kinds.insert(PrincipalKind::User);

    provider.discover(query).await.expect("safe search");

    let requests = fake.requests.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
            requests[0].filter,
            "(&(objectClass=inetOrgPerson)(|(uid=*alice\\2a\\29\\28uid=\\2a\\29*)(cn=*alice\\2a\\29\\28uid=\\2a\\29*)(mail=*alice\\2a\\29\\28uid=\\2a\\29*)))"
        );
    assert!(ldap3::parse_filter(&requests[0].filter).is_ok());
}

#[tokio::test]
async fn kind_selection_prevents_unnecessary_directory_searches() {
    let fake = Arc::new(FakeLdapSearchClient::default());
    let provider = LdapPrincipalDiscovery::with_client(&config(), fake.clone()).expect("provider");

    let mut workloads = PrincipalSearchQuery::new("job-runner");
    workloads.kinds.insert(PrincipalKind::Workload);
    assert!(provider.discover(workloads).await.expect("unsupported").principals.is_empty());
    assert!(fake.requests.lock().await.is_empty());
}

#[tokio::test]
async fn cursor_is_decoded_and_page_size_is_bounded_by_provider_configuration() {
    let fake = Arc::new(FakeLdapSearchClient::default());
    let mut provider_config = config();
    provider_config.max_page_size = 10;
    let provider =
        LdapPrincipalDiscovery::with_client(&provider_config, fake.clone()).expect("provider");
    let mut query = PrincipalSearchQuery::new("alice");
    query.kinds.insert(PrincipalKind::User);
    query.per_provider_limit = 80;
    query
        .cursors
        .insert("corporate-ldap:users".to_string(), URL_SAFE_NO_PAD.encode(b"opaque-cookie"));

    provider.discover(query).await.expect("paged search");

    let requests = fake.requests.lock().await;
    assert_eq!(requests[0].cookie, b"opaque-cookie");
    assert_eq!(requests[0].page_size, 10);
}

#[tokio::test]
async fn resolve_uses_exact_escaped_filter_and_stable_issuer_key() {
    let fake = Arc::new(FakeLdapSearchClient::with_pages([(
        "ou=people,dc=example,dc=com".to_string(),
        LdapSearchPage { entries: vec![user_entry("user*)(uid=*)")], next_cookie: Vec::new() },
    )]));
    let provider = LdapPrincipalDiscovery::with_client(&config(), fake.clone()).expect("provider");
    let reference = ExternalPrincipalRef {
        provider_id: "corporate-ldap".to_string(),
        issuer: "https://identity.example.com/directories/corporate".to_string(),
        external_id: "user*)(uid=*)".to_string(),
    };

    let projection =
        provider.resolve_principal(&reference).await.expect("resolve").expect("principal");

    assert_eq!(projection.reference, reference);
    let requests = fake.requests.lock().await;
    assert_eq!(
        requests[0].filter,
        "(&(objectClass=inetOrgPerson)(entryUUID=user\\2a\\29\\28uid=\\2a\\29))"
    );
    assert!(ldap3::parse_filter(&requests[0].filter).is_ok());
}

#[tokio::test]
async fn resolve_rejects_non_unique_identity_attribute() {
    let fake = Arc::new(FakeLdapSearchClient::with_pages([(
        "ou=people,dc=example,dc=com".to_string(),
        LdapSearchPage {
            entries: vec![user_entry("duplicate"), user_entry("duplicate")],
            next_cookie: Vec::new(),
        },
    )]));
    let provider = LdapPrincipalDiscovery::with_client(&config(), fake).expect("provider");
    let reference = ExternalPrincipalRef {
        provider_id: "corporate-ldap".to_string(),
        issuer: "https://identity.example.com/directories/corporate".to_string(),
        external_id: "duplicate".to_string(),
    };

    let result = provider.resolve_principal(&reference).await;

    assert!(matches!(result, Err(PrincipalDiscoveryError::InvalidResponse { .. })));
}

#[tokio::test]
async fn resolve_rejects_provider_and_issuer_mismatch_before_directory_access() {
    let fake = Arc::new(FakeLdapSearchClient::default());
    let provider = LdapPrincipalDiscovery::with_client(&config(), fake.clone()).expect("provider");
    let wrong_provider = ExternalPrincipalRef {
        provider_id: "other-ldap".to_string(),
        issuer: "https://identity.example.com/directories/corporate".to_string(),
        external_id: "user-42".to_string(),
    };
    let wrong_issuer = ExternalPrincipalRef {
        provider_id: "corporate-ldap".to_string(),
        issuer: "https://attacker.example/directories/corporate".to_string(),
        external_id: "user-42".to_string(),
    };

    assert!(matches!(
        provider.resolve_principal(&wrong_provider).await,
        Err(PrincipalDiscoveryError::UnknownProvider(_))
    ));
    assert!(matches!(
        provider.resolve_principal(&wrong_issuer).await,
        Err(PrincipalDiscoveryError::InvalidQuery(_))
    ));
    assert!(fake.requests.lock().await.is_empty());
}

#[tokio::test]
async fn unsupported_enabled_value_fails_closed() {
    let mut entry = user_entry("user-42");
    entry.attributes.insert("accountenabled".to_string(), vec!["perhaps".to_string()]);
    let fake = Arc::new(FakeLdapSearchClient::with_pages([(
        "ou=people,dc=example,dc=com".to_string(),
        LdapSearchPage { entries: vec![entry], next_cookie: Vec::new() },
    )]));
    let provider = LdapPrincipalDiscovery::with_client(&config(), fake).expect("provider");
    let mut query = PrincipalSearchQuery::new("alice");
    query.kinds.insert(PrincipalKind::User);

    let result = provider.discover(query).await;

    assert!(matches!(result, Err(PrincipalDiscoveryError::InvalidResponse { .. })));
}
