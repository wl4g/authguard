use std::sync::Mutex;

use super::*;

impl AppConfigProperties {
    fn from_default_yaml() -> anyhow::Result<Self> {
        Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG_YAML, FileFormat::Yaml))
            .build()?
            .try_deserialize::<Self>()
            .context("decode default AuthGuard configuration")
    }
}

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvCleanup(Vec<&'static str>);

impl Drop for EnvCleanup {
    fn drop(&mut self) {
        for name in &self.0 {
            std::env::remove_var(name);
        }
    }
}

fn apply_overrides(yaml: &str, entries: &[(&str, &str)]) -> serde_yaml::Value {
    let mut value = serde_yaml::from_str(yaml).expect("test YAML");
    apply_environment_entries(
        &mut value,
        entries.iter().map(|(name, value)| ((*name).to_string(), (*value).to_string())),
    )
    .expect("environment overrides");
    value
}

#[test]
fn environment_overrides_scalar_types_and_relaxed_names() {
    let value = apply_overrides(
        "server: {service_name: yaml, port: 8080}\nmgmt: {otel: {enabled: false}}\n",
        &[
            ("AUTHGUARD__SERVER__SERVICE_NAME", "env-service"),
            ("AUTHGUARD__SERVER__PORT", "8180"),
            ("AUTHGUARD__MGMT__OTEL__ENABLED", "true"),
        ],
    );
    assert_eq!(value["server"]["service_name"], "env-service");
    assert_eq!(value["server"]["port"], 8180);
    assert_eq!(value["mgmt"]["otel"]["enabled"], true);
}

#[test]
fn environment_overrides_scalar_array_elements() {
    let value = apply_overrides(
        "cache: {redis: {nodes: [redis-0:6379, redis-1:6379]}}\n",
        &[("AUTHGUARD__CACHE__REDIS__NODES[1]", "redis-2:6379")],
    );
    assert_eq!(value["cache"]["redis"]["nodes"][1], "redis-2:6379");
}

#[test]
fn environment_overrides_objects_inside_arrays() {
    let value = apply_overrides(
        "authz: {principal_discovery: {keycloak: [{enabled: false}, {enabled: false}]}}\n",
        &[("AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__KEYCLOAK[1]__ENABLED", "true")],
    );
    assert_eq!(value["authz"]["principal_discovery"]["keycloak"][1]["enabled"], true);
}

#[test]
fn environment_supports_kubernetes_safe_array_indices() {
    let mut config = serde_yaml::Value::Null;
    apply_environment_entries(
        &mut config,
        [(
            "AUTHGUARD__AUTHZ__PRINCIPAL_DISCOVERY__LDAP__INDEX_0__ENABLED".to_string(),
            "true".to_string(),
        )],
    )
    .expect("Kubernetes-safe array override");
    assert_eq!(config["authz"]["principal_discovery"]["ldap"][0]["enabled"], true);
}

#[test]
fn environment_supports_bracket_indices_on_arbitrary_nested_shapes() {
    let value = apply_overrides(
            "authn: {principal_discovery: [{keycloak: {enable: false}}, {keycloak: {enable: false}}]}\n",
            &[(
                "AUTHGUARD__AUTHN__PRINCIPAL_DISCOVERY[1]__KEYCLOAK__ENABLE",
                "true",
            )],
        );
    assert_eq!(value["authn"]["principal_discovery"][1]["keycloak"]["enable"], true);
}

#[test]
fn environment_overrides_dynamic_provider_maps() {
    let value = apply_overrides(
        "authn: {providers: {github: {identity: {subject: '$.id'}}}}\n",
        &[("AUTHGUARD__AUTHN__PROVIDERS__GITHUB__IDENTITY__SUBJECT", "$.node_id")],
    );
    assert_eq!(value["authn"]["providers"]["github"]["identity"]["subject"], "$.node_id");
}

#[test]
fn environment_creates_nested_map_and_array_values() {
    let value = apply_overrides(
        "authn: {accountLinking: {allowLink: {}}}\n",
        &[("AUTHGUARD__AUTHN__ACCOUNT_LINKING__ALLOW_LINK__CORPORATE_DSP[0]", "github")],
    );
    assert_eq!(value["authn"]["accountLinking"]["allowLink"]["corporate_dsp"][0], "github");
}

#[test]
fn provider_runtime_templates_are_not_treated_as_secret_environment_refs() {
    let mut value = serde_yaml::from_str(
            "authn: {providers: {wechat: {token: {query: {appid: '${clientId}', secret: '${clientSecret}', code: '${authorizationCode}', redirect: '${redirectUri}'}}}}}\n",
        )
        .expect("provider YAML");
    expand_authn_owned_env_refs(&mut value, &HashMap::new()).expect("runtime templates");
    let query = &value["authn"]["providers"]["wechat"]["token"]["query"];
    assert_eq!(query["appid"], "${clientId}");
    assert_eq!(query["secret"], "${clientSecret}");
    assert_eq!(query["code"], "${authorizationCode}");
    assert_eq!(query["redirect"], "${redirectUri}");
}

#[test]
fn environment_rejects_malformed_array_indices() {
    let mut value = serde_yaml::from_str("authn: {}\n").expect("test YAML");
    let error = apply_environment_entries(
        &mut value,
        [("AUTHGUARD__AUTHN__PROVIDERS[one]".to_string(), "github".to_string())],
    )
    .expect_err("invalid index must fail");
    assert!(error.to_string().contains("parse environment override"));
}

#[test]
fn arbitrary_nested_environment_values_override_yaml() {
    let _guard = ENV_LOCK.lock().unwrap();
    let cleanup = EnvCleanup(vec![
        "AUTHGUARD__AUTHN__TOKEN__AUDIENCE",
        "AUTHGUARD__AUTHN__CHALLENGE_TTL",
        "AUTHGUARD__STORAGE__POSTGRES__MAX_CONNECTIONS",
        "AUTHGUARD__MGMT__OTEL__ENABLED",
    ]);
    let directory = std::env::temp_dir().join(format!("authguard-config-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let file = directory.join("authguard.yaml");
    std::fs::write(
        &file,
        r"
authn:
  challengeTtl: 1m
  token:
    audience: yaml-audience
storage:
  provider: SQLite
  postgres:
    max_connections: 2
logging: {}
mgmt:
  metrics: {}
  otel:
    enabled: false
",
    )
    .unwrap();
    std::env::set_var("AUTHGUARD__AUTHN__TOKEN__AUDIENCE", "env-audience");
    std::env::set_var("AUTHGUARD__AUTHN__CHALLENGE_TTL", "3m");
    std::env::set_var("AUTHGUARD__STORAGE__POSTGRES__MAX_CONNECTIONS", "17");
    std::env::set_var("AUTHGUARD__MGMT__OTEL__ENABLED", "true");

    let config = AppConfigProperties::load_for_authn(&file).unwrap();
    std::fs::remove_dir_all(&directory).ok();
    drop(cleanup);

    assert_eq!(config.authn.token.audience, "env-audience");
    assert_eq!(config.authn.challenge_ttl, Duration::from_secs(180));
    assert_eq!(config.storage.postgres.max_connections, 17);
    assert!(config.mgmt.otel.enabled);
}

#[test]
fn each_service_resolves_only_its_owned_secret_subtree() {
    let mut authorization_view = serde_yaml::from_str::<serde_yaml::Value>(
        r"
authn:
  token:
    privateKey: ${AUTHN_ONLY_KEY}
authz:
  api:
    token: resolved-authz-secret
",
    )
    .unwrap();
    expand_authz_owned_env_refs(&mut authorization_view, &HashMap::new()).unwrap();
    assert_eq!(
        authorization_view["authn"]["token"]["privateKey"].as_str(),
        Some("${AUTHN_ONLY_KEY}")
    );

    let mut authentication_view = serde_yaml::from_str::<serde_yaml::Value>(
        r"
authn:
  providers: {}
authz:
  api:
    token: ${AUTHZ_ONLY_SECRET}
storage: {}
logging: {}
mgmt: {}
",
    )
    .unwrap();
    expand_authn_owned_env_refs(&mut authentication_view, &HashMap::new()).unwrap();
    assert_eq!(authentication_view["authz"]["api"]["token"].as_str(), Some("${AUTHZ_ONLY_SECRET}"));
}

#[test]
fn provider_yaml_keeps_protocol_and_linking_policy_separate() {
    let config: AuthnProperties = serde_yaml::from_str(
        r"
providers:
  corporate-oidc:
    type: oidc
    issuer: https://sso.example.com/realms/corporate
    clientId: authguard
    clientSecret: test-only-secret
    callbackUrl: https://app.example.com/auth/oauth2/corporate-oidc/callback
    scopes: [openid, profile, email]
    userinfo: true
    tokenIntrospection:
      endpoint: https://sso.example.com/realms/corporate/protocol/openid-connect/token/introspect
      acceptedAudiences: [customer-growth-job-service]
    identity:
      subject: $.sub
      username: $.preferred_username
      email: $.email
  github:
    type: oauth2
    issuer: https://github.com
    authorization:
      endpoint: https://github.com/login/oauth/authorize
      scopes: [read:user, user:email]
    token:
      endpoint: https://github.com/login/oauth/access_token
      method: POST
    identity:
      endpoint: https://api.github.com/user
      subject: $.id
      username: $.login
      email: $.email
accountLinking:
  strategy: explicit
  authoritativeProviders: [corporate-dsp]
  allowLink:
    corporate-dsp: [github, wechat]
",
    )
    .expect("provider configuration");

    let ProviderProperties::Oidc(oidc) = &config.providers["corporate-oidc"] else {
        panic!("corporate-oidc must decode as OIDC");
    };
    assert_eq!(
        oidc.token_introspection.as_ref().expect("introspection").accepted_audiences,
        ["customer-growth-job-service"]
    );
    assert!(matches!(config.providers["github"], ProviderProperties::OAuth2(_)));
    assert_eq!(config.account_linking.strategy, LinkingStrategy::Explicit);
    assert!(config.account_linking.allow_link["corporate-dsp"].contains("github"));
}

#[test]
fn provider_cannot_declare_account_governance_role() {
    let error = serde_yaml::from_str::<AuthnProperties>(
        r"
providers:
  github:
    type: oauth2
    role: secondary
",
    )
    .expect_err("provider governance field must be rejected");
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn annotated_default_configuration_is_valid() {
    let config = AppConfigProperties::from_default_yaml().expect("decode defaults");
    config.validate().expect("valid");
    assert_eq!(config.server.service_name, "authguard-authz");
    assert_eq!(config.mgmt.port, 9091);
    assert_eq!(config.authz.api.port, 9090);
    assert_eq!(config.storage.provider, "SQLite");
    assert_eq!(config.cache.provider, "Memory");
    assert_eq!(config.cache.memory.max_capacity, 65_535);
}

#[test]
fn password_only_standalone_does_not_require_redis_but_mfa_does() {
    let mut authn = AuthnProperties::default();
    authn.standalone.enabled = true;
    let cache = CacheProperties::default();

    validate_authn(&authn, &cache).expect("password-only standalone AuthN");

    authn.standalone.totp.enabled = true;
    assert!(validate_authn(&authn, &cache)
        .expect_err("TOTP must require Redis")
        .to_string()
        .contains("cache.provider=Redis"));
}

#[test]
fn caip_chain_references_use_the_caip_2_bound() {
    validate_caip_reference("mainnet", "solana").expect("valid reference");
    assert!(validate_caip_reference(&"a".repeat(33), "solana").is_err());
    assert!(validate_caip_reference("contains:colon", "bip122").is_err());
}

#[test]
fn evm_eoa_chain_does_not_require_contract_rpc() {
    let authn: AuthnProperties = serde_yaml::from_str(
        r"
wallet:
  enabled: true
  domain: auth.example.com
  uri: https://auth.example.com
  chains:
    eip155:
      '1': {}
      '31337':
        rpc: http://anvil:8545
",
    )
    .expect("wallet configuration");
    let cache = CacheProperties {
        provider: "Redis".to_string(),
        redis: RedisClusterProperties {
            nodes: vec!["redis://127.0.0.1:6379".to_string()],
            ..RedisClusterProperties::default()
        },
        ..CacheProperties::default()
    };

    validate_authn(&authn, &cache).expect("offline EOA plus contract-wallet RPC");
    assert_eq!(authn.wallet.chains.eip155["1"].rpc, None);
    assert_eq!(authn.wallet.chains.eip155["31337"].rpc.as_deref(), Some("http://anvil:8545"));
}

#[test]
fn hosted_login_applications_require_exact_https_origins() {
    let mut authn = AuthnProperties::default();
    authn.applications.insert(
        "example-app".to_string(),
        ApplicationProperties {
            hosts: BTreeSet::from(["app.example.com".to_string()]),
            display_name: "Example App".to_string(),
            logo: "/auth/assets/themes/custom/example-app.svg".to_string(),
            theme: Some(ApplicationThemeProperties {
                id: "example-app".to_string(),
                stylesheet: "/auth/assets/themes/custom/example-app.css".to_string(),
            }),
            return_uris: vec!["https://app.example.com/**".to_string()],
        },
    );
    validate_authn(&authn, &CacheProperties::default()).expect("valid hosted application");

    let mut fallback = authn.clone();
    let fallback_application = fallback.applications.get_mut("example-app").expect("application");
    fallback_application.logo.clear();
    fallback_application.theme = None;
    validate_authn(&fallback, &CacheProperties::default())
        .expect("text branding with the built-in visual fallback");

    authn
        .applications
        .get_mut("example-app")
        .expect("application")
        .theme
        .as_mut()
        .expect("theme")
        .stylesheet = "https://cdn.example.com/theme.css".to_string();
    assert!(validate_authn(&authn, &CacheProperties::default()).is_err());
    authn
        .applications
        .get_mut("example-app")
        .expect("application")
        .theme
        .as_mut()
        .expect("theme")
        .stylesheet = "/auth/assets/themes/custom/example-app.css".to_string();
    authn.applications.get_mut("example-app").expect("application").return_uris =
        vec!["http://app.example.com/**".to_string()];
    assert!(validate_authn(&authn, &CacheProperties::default()).is_err());
}

#[test]
fn hosted_login_host_must_belong_to_one_application() {
    let application = ApplicationProperties {
        hosts: BTreeSet::from(["app.example.com".to_string()]),
        display_name: "Example App".to_string(),
        logo: String::new(),
        theme: None,
        return_uris: vec!["https://app.example.com/**".to_string()],
    };
    let mut authn = AuthnProperties::default();
    authn.applications.insert("first-app".to_string(), application.clone());
    authn.applications.insert("second-app".to_string(), application);

    assert!(validate_authn(&authn, &CacheProperties::default()).is_err());
}

#[test]
fn rejects_unbounded_worker_configuration() {
    let config = AppConfigProperties {
        server: ServerProperties {
            performance: PerformanceProperties {
                worker_threads: 0,
                ..PerformanceProperties::default()
            },
            ..ServerProperties::default()
        },
        ..AppConfigProperties::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn rejects_removed_file_storage_and_cache_providers() {
    let mut file_storage = AppConfigProperties::default();
    file_storage.storage.provider = "file".to_string();
    assert!(file_storage.validate().is_err());

    let mut file_cache = AppConfigProperties::default();
    file_cache.cache.provider = "File".to_string();
    assert!(file_cache.validate().is_err());
}

#[test]
fn rejects_process_local_providers_in_multi_replica_deployments() {
    let mut memory = AppConfigProperties::default();
    memory.storage.provider = "postgres".to_string();
    memory.server.deployment.replica_count = 2;
    assert!(memory.validate_deployment().is_err());

    let mut sqlite = AppConfigProperties::default();
    sqlite.cache.provider = "Redis".to_string();
    sqlite.server.deployment.replica_count = 2;
    assert!(sqlite.validate_deployment().is_err());

    let mut shared = AppConfigProperties::default();
    shared.storage.provider = "postgres".to_string();
    shared.cache.provider = "Redis".to_string();
    shared.server.deployment.replica_count = 2;
    assert!(shared.validate_deployment().is_ok());
    shared.server.deployment.replica_count = 0;
    assert!(shared.validate_deployment().is_err());
}

#[test]
fn rejects_redis_replica_reads_for_scope_tokens() {
    let mut config = AppConfigProperties::default();
    config.cache.provider = "Redis".to_string();
    config.cache.redis.read_from_replica = true;

    assert!(config.validate().is_err());
}

#[test]
fn validates_file_backed_federated_discovery_credentials() {
    let mut config = AppConfigProperties::default();
    config.authz.principal_discovery.keycloak = vec![KeycloakPrincipalDiscoveryProperties {
        enabled: true,
        discovery_id: "corporate-keycloak".to_string(),
        base_url: "https://id.example.com".to_string(),
        issuer: "https://id.example.com/realms/corporate".to_string(),
        realm: "corporate".to_string(),
        auth: OidcClientCredentialsProperties {
            client_id: "authguard-principal-discovery".to_string(),
            client_secret_file: "/run/secrets/keycloak-client-secret".to_string(),
            ..OidcClientCredentialsProperties::default()
        },
        ..KeycloakPrincipalDiscoveryProperties::default()
    }];
    let object_mapping = LdapObjectMappingProperties {
        object_filter: "(objectClass=inetOrgPerson)".to_string(),
        id_attribute: "entryUUID".to_string(),
        name_attribute: "uid".to_string(),
        search_attributes: vec!["uid".to_string(), "mail".to_string()],
        ..LdapObjectMappingProperties::default()
    };
    config.authz.principal_discovery.ldap = vec![LdapPrincipalDiscoveryProperties {
        enabled: true,
        discovery_id: "corporate-ldap".to_string(),
        url: "ldaps://ldap.example.com:636".to_string(),
        issuer: "urn:identity:corporate-ldap".to_string(),
        base_dn: "dc=example,dc=com".to_string(),
        auth: LdapBindAuthProperties {
            bind_dn: "cn=authguard,ou=service-accounts,dc=example,dc=com".to_string(),
            bind_password_file: "/run/secrets/ldap-bind-password".to_string(),
            ..LdapBindAuthProperties::default()
        },
        user: object_mapping.clone(),
        group: LdapObjectMappingProperties {
            object_filter: "(objectClass=groupOfNames)".to_string(),
            name_attribute: "cn".to_string(),
            search_attributes: vec!["cn".to_string()],
            ..object_mapping
        },
        ..LdapPrincipalDiscoveryProperties::default()
    }];
    config.authz.principal_discovery.custom = vec![CustomPrincipalDiscoveryProperties {
        enabled: true,
        discovery_id: "dsp-directory".to_string(),
        url: "https://dsp.example.com/identity".to_string(),
        issuer: "https://dsp.example.com".to_string(),
        jwt_token_file: "/run/secrets/dsp-jwt".to_string(),
        ..CustomPrincipalDiscoveryProperties::default()
    }];

    config.validate().expect("file-backed connector credentials are valid");

    config.authz.principal_discovery.keycloak[0].auth.client_secret =
        "ambiguous-inline-secret".to_string();
    assert!(config.validate().is_err());
}

#[test]
fn skips_disabled_federated_connector_entries() {
    let mut config = AppConfigProperties::default();
    // Incomplete on purpose: a disabled entry must not be validated.
    config.authz.principal_discovery.keycloak =
        vec![KeycloakPrincipalDiscoveryProperties::default()];
    config.authz.principal_discovery.ldap = vec![LdapPrincipalDiscoveryProperties::default()];
    config.authz.principal_discovery.custom = vec![CustomPrincipalDiscoveryProperties::default()];

    config.validate().expect("disabled federated entries are skipped");
}

#[test]
fn rejects_multiple_enabled_connectors_of_one_protocol() {
    let keycloak = |discovery_id: &str| KeycloakPrincipalDiscoveryProperties {
        enabled: true,
        discovery_id: discovery_id.to_string(),
        base_url: "https://sso.example.com".to_string(),
        realm: "example-corp".to_string(),
        auth: OidcClientCredentialsProperties {
            client_id: "authguard-search".to_string(),
            client_secret: "not-logged-secret".to_string(),
            ..OidcClientCredentialsProperties::default()
        },
        ..KeycloakPrincipalDiscoveryProperties::default()
    };

    // Two enabled connectors of the same protocol are ambiguous by
    // definition: search candidates must map to exactly one source.
    let mut config = AppConfigProperties::default();
    config.authz.principal_discovery.keycloak =
        vec![keycloak("corporate-keycloak"), keycloak("partner-keycloak")];
    assert!(config.validate().is_err());

    // One per protocol stays valid and unambiguous.
    config.authz.principal_discovery.keycloak = vec![keycloak("corporate-keycloak")];
    config.validate().expect("one enabled connector per protocol is valid");
}

#[test]
fn validates_resign_configuration() {
    let mut config = AppConfigProperties::default();
    config.validate().expect("resign JWT is disabled by default");

    config.authz.resign.enabled = true;
    config.authz.resign.private_key_b64 = "bm90IGEga2V5".to_string();
    config.authz.resign.max_ttl = Duration::ZERO;
    assert!(config.validate().is_err(), "positive ttl is required");

    config.authz.resign.max_ttl = Duration::from_secs(60);
    config.validate().expect("inline private key is valid");
}
