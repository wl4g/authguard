use authguard_adapter_rust::{
    access::{self, HeaderAccessContextResolver},
    filter::{AccessScope, HttpHeaderAccessFilter},
    model::AccessContext,
    util::{sign_access_context, ACCESS_CONTEXT_HEADER},
};
use authguard_customer_growth_job_rust_service::{
    controller::CustomerGrowthJobController,
    dto::{
        CreateCustomerGrowthJobRequest, CustomerGrowthJobSearchRequest,
        UpdateCustomerGrowthJobRequest,
    },
    repository::CustomerGrowthJobRepository,
    service::CustomerGrowthJobService,
};
use serde::Deserialize;
use sqlx::{any::AnyPoolOptions, AnyPool};
use std::sync::Arc;

const CUSTOMER_GROWTH_JOBS_SQL: &str = include_str!("../../../config/init.sql");
const AUTHORIZATION_SCENARIOS_JSON: &str =
    include_str!("../../../config/authguard-e2e-scenarios.json");
const TEST_SIGNING_KEY: &[u8] = b"test-access-context-hmac-key-32-bytes-minimum";

#[derive(Debug, Deserialize)]
struct AuthorizationFixture {
    version: u8,
    authz: AuthorizationScenarios,
}

#[derive(Debug, Deserialize)]
struct AuthorizationScenarios {
    access_context_version: u8,
    scenarios: Vec<AuthorizationScenario>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationScenario {
    id: String,
    operation: String,
    principal_id: String,
    action: String,
    resource_urn: String,
    allow_resource_urns: Vec<String>,
    deny_resource_urns: Vec<String>,
    #[serde(default)]
    criteria: ScenarioCriteria,
    #[serde(default)]
    target_job_id: i64,
    job: Option<ScenarioJob>,
    update: Option<ScenarioUpdate>,
    gateway_allowed: bool,
    expected_allowed: bool,
    #[serde(default)]
    expected_job_ids: Vec<i64>,
    #[serde(default)]
    expected_status: String,
}

#[derive(Debug, Default, Deserialize)]
struct ScenarioCriteria {
    workspace_id: Option<String>,
    project_id: Option<String>,
    status: Option<String>,
    owner_user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ScenarioJob {
    id: i64,
    region: String,
    tenant_id: String,
    workspace_id: String,
    project_id: String,
    job_id: String,
    display_name: String,
    status: String,
    owner_user_id: String,
}

#[derive(Debug, Deserialize)]
struct ScenarioUpdate {
    display_name: String,
    status: String,
    owner_user_id: String,
}

#[tokio::test]
async fn authorization_scenarios_from_shared_fixture() {
    let fixture: AuthorizationFixture = serde_json::from_str(AUTHORIZATION_SCENARIOS_JSON).unwrap();
    assert_eq!(fixture.version, 4);
    assert!(fixture.authz.scenarios.len() >= 30);
    let access_context_version = fixture.authz.access_context_version;

    for scenario in fixture.authz.scenarios {
        let (controller, pool) = new_customer_growth_job_controller().await;
        let access_scope = enter_access_context(access_context_version, &scenario).await;
        let request_access = access_scope.as_ref().and_then(AccessScope::request_access);
        let (allowed, actual_ids, actual_status) =
            execute_scenario(&controller, &pool, request_access, &scenario).await;
        assert_eq!(allowed, scenario.expected_allowed, "scenario {}", scenario.id);
        if !scenario.expected_allowed {
            assert_denied_mutation_did_not_change_database(&pool, &scenario).await;
        }
        if scenario.operation == "list" && scenario.expected_allowed {
            assert_eq!(actual_ids, scenario.expected_job_ids, "scenario {}", scenario.id);
        }
        if !scenario.expected_status.is_empty() {
            assert_eq!(actual_status, scenario.expected_status, "scenario {}", scenario.id);
        }
        access::clear_current();
    }
}

async fn assert_denied_mutation_did_not_change_database(
    pool: &AnyPool,
    scenario: &AuthorizationScenario,
) {
    match scenario.operation.as_str() {
        "create" => {
            let job = scenario.job.as_ref().expect("create job");
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM customer_growth_jobs WHERE id = $1")
                    .bind(job.id)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(count, 0, "scenario {}", scenario.id);
        }
        "update" => {
            let status: String =
                sqlx::query_scalar("SELECT status FROM customer_growth_jobs WHERE id = $1")
                    .bind(scenario.target_job_id)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(status, "READY", "scenario {}", scenario.id);
        }
        "delete" => {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM customer_growth_jobs WHERE id = $1")
                    .bind(scenario.target_job_id)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            assert_eq!(count, 1, "scenario {}", scenario.id);
        }
        _ => {}
    }
}

async fn enter_access_context(
    version: u8,
    scenario: &AuthorizationScenario,
) -> Option<AccessScope> {
    access::clear_current();
    if !scenario.gateway_allowed {
        return None;
    }
    let mut context = AccessContext::new(
        authguard_adapter_rust::model::AccessContextInput {
            principal_id: scenario.principal_id.clone(),
            action: scenario.action.clone(),
            resource_urn: scenario.resource_urn.clone(),
            allow_resource_urns: scenario.allow_resource_urns.clone(),
            deny_resource_urns: scenario.deny_resource_urns.clone(),
            policy_revision: 1,
        },
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        std::time::Duration::from_secs(30),
    );
    context.version = version;
    let mut headers = http::HeaderMap::new();
    headers.insert(
        ACCESS_CONTEXT_HEADER,
        sign_access_context(&context, TEST_SIGNING_KEY).unwrap().parse().unwrap(),
    );
    let filter = HttpHeaderAccessFilter::new(vec![Arc::new(
        HeaderAccessContextResolver::new(TEST_SIGNING_KEY).unwrap(),
    )]);
    let scope = filter.enter_headers(&headers).await.unwrap();
    assert!(scope.authenticated(), "scenario {}", scenario.id);
    Some(scope)
}

async fn execute_scenario(
    controller: &CustomerGrowthJobController,
    pool: &AnyPool,
    access: Option<&authguard_adapter_rust::RequestAccess>,
    scenario: &AuthorizationScenario,
) -> (bool, Vec<i64>, String) {
    let Some(access) = access else {
        return (false, Vec::new(), String::new());
    };
    match scenario.operation.as_str() {
        "list" => {
            let criteria = &scenario.criteria;
            match controller
                .list_visible_jobs(
                    access,
                    &CustomerGrowthJobSearchRequest {
                        workspace_id: criteria.workspace_id.clone(),
                        project_id: criteria.project_id.clone(),
                        status: criteria.status.clone(),
                        owner_user_id: criteria.owner_user_id.clone(),
                    },
                )
                .await
            {
                Ok(rows) => (true, rows.into_iter().map(|row| row.id).collect(), String::new()),
                Err(_) => (false, Vec::new(), String::new()),
            }
        }
        "get" => match controller.get_job(access, scenario.target_job_id).await {
            Ok(Some(_)) => (true, Vec::new(), String::new()),
            Ok(None) | Err(_) => (false, Vec::new(), String::new()),
        },
        "create" => {
            let job = scenario.job.as_ref().expect("create scenario job");
            let result = controller
                .create_job(
                    access,
                    CreateCustomerGrowthJobRequest {
                        id: job.id,
                        region: job.region.clone(),
                        tenant_id: job.tenant_id.clone(),
                        workspace_id: job.workspace_id.clone(),
                        project_id: job.project_id.clone(),
                        job_id: job.job_id.clone(),
                        display_name: job.display_name.clone(),
                        status: job.status.clone(),
                        owner_user_id: job.owner_user_id.clone(),
                    },
                )
                .await;
            match result {
                Ok(created) => (created.id == job.id, Vec::new(), created.status),
                Err(_) => (false, Vec::new(), String::new()),
            }
        }
        "update" => {
            let update = scenario.update.as_ref().expect("update scenario payload");
            match controller
                .update_job(
                    access,
                    scenario.target_job_id,
                    UpdateCustomerGrowthJobRequest {
                        display_name: update.display_name.clone(),
                        status: update.status.clone(),
                        owner_user_id: update.owner_user_id.clone(),
                    },
                )
                .await
            {
                Ok(updated) => (true, Vec::new(), updated.status),
                Err(_) => (false, Vec::new(), String::new()),
            }
        }
        "delete" => {
            if controller.delete_job(access, scenario.target_job_id).await.is_err() {
                return (false, Vec::new(), String::new());
            }
            let remaining: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM customer_growth_jobs WHERE id = $1")
                    .bind(scenario.target_job_id)
                    .fetch_one(pool)
                    .await
                    .unwrap();
            (remaining == 0, Vec::new(), String::new())
        }
        operation => panic!("unsupported scenario operation: {operation}"),
    }
}

async fn new_customer_growth_job_controller() -> (CustomerGrowthJobController, AnyPool) {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
    seed_customer_growth_jobs(&pool).await;
    let repository = CustomerGrowthJobRepository::new(pool.clone());
    (CustomerGrowthJobController::new(CustomerGrowthJobService::new(repository)), pool)
}

async fn seed_customer_growth_jobs(pool: &AnyPool) {
    for statement in
        CUSTOMER_GROWTH_JOBS_SQL.split(';').map(str::trim).filter(|sql| !sql.is_empty())
    {
        sqlx::query(statement).execute(pool).await.unwrap();
    }
}
