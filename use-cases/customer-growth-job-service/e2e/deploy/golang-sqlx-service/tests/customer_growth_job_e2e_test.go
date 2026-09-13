package tests

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"authguard/adapters/golang/filter"
	"authguard/adapters/golang/model"
	adapterutil "authguard/adapters/golang/util"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/controller"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/dto"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/repository"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/service"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

type authorizationFixture struct {
	Version   int                     `json:"access_context_version"`
	Scenarios []authorizationScenario `json:"scenarios"`
}

type authguardFixture struct {
	Version int                  `json:"version"`
	Authz   authorizationFixture `json:"authz"`
}

const testAccessContextSigningKey = "test-access-context-hmac-key-32-bytes-minimum"

type authorizationScenario struct {
	ID                string           `json:"id"`
	Operation         string           `json:"operation"`
	PrincipalID       string           `json:"principal_id"`
	Action            string           `json:"action"`
	ResourceURN       string           `json:"resource_urn"`
	AllowResourceURNs []string         `json:"allow_resource_urns"`
	DenyResourceURNs  []string         `json:"deny_resource_urns"`
	Criteria          scenarioCriteria `json:"criteria"`
	TargetJobID       int64            `json:"target_job_id"`
	Job               *scenarioJob     `json:"job"`
	Update            *scenarioUpdate  `json:"update"`
	GatewayAllowed    bool             `json:"gateway_allowed"`
	ExpectedAllowed   bool             `json:"expected_allowed"`
	ExpectedJobIDs    []int64          `json:"expected_job_ids"`
	ExpectedStatus    string           `json:"expected_status"`
}

type scenarioCriteria struct {
	WorkspaceID *string `json:"workspace_id"`
	ProjectID   *string `json:"project_id"`
	Status      *string `json:"status"`
	OwnerUserID *string `json:"owner_user_id"`
}

type scenarioJob struct {
	ID          int64  `json:"id"`
	Region      string `json:"region"`
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	ProjectID   string `json:"project_id"`
	JobID       string `json:"job_id"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	OwnerUserID string `json:"owner_user_id"`
}

type scenarioUpdate struct {
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	OwnerUserID string `json:"owner_user_id"`
}

func TestAuthorizationScenariosFromSharedFixture(t *testing.T) {
	fixture := loadAuthorizationFixture(t)
	if len(fixture.Scenarios) < 30 {
		t.Fatalf("expected at least 30 business scenarios, got %d", len(fixture.Scenarios))
	}

	for _, scenario := range fixture.Scenarios {
		scenario := scenario
		t.Run(scenario.ID, func(t *testing.T) {
			db, jobController := newCustomerGrowthJobController(t)
			defer db.Close()
			requestContext := requestContext(t, fixture.Version, scenario)
			allowed, actualIDs, actualStatus := executeScenario(
				t, db, jobController, requestContext, scenario,
			)
			if allowed != scenario.ExpectedAllowed {
				t.Fatalf("allowed=%t want=%t", allowed, scenario.ExpectedAllowed)
			}
			if !scenario.ExpectedAllowed {
				assertDeniedMutationDidNotChangeDatabase(t, db, scenario)
			}
			if scenario.Operation == "list" && scenario.ExpectedAllowed &&
				!reflect.DeepEqual(actualIDs, scenario.ExpectedJobIDs) {
				t.Fatalf("job ids got=%v want=%v", actualIDs, scenario.ExpectedJobIDs)
			}
			if scenario.ExpectedStatus != "" && actualStatus != scenario.ExpectedStatus {
				t.Fatalf("status=%q want=%q", actualStatus, scenario.ExpectedStatus)
			}
			t.Logf("AUTHGUARD_E2E_CASE id=%s", scenario.ID)
		})
	}
}

func assertDeniedMutationDidNotChangeDatabase(
	t *testing.T, db *sqlx.DB, scenario authorizationScenario,
) {
	t.Helper()
	switch scenario.Operation {
	case "create":
		var count int
		if err := db.Get(&count, "SELECT COUNT(*) FROM e2e_authguard_customer_growth_jobs WHERE id = ?", scenario.Job.ID); err != nil || count != 0 {
			t.Fatalf("denied create changed database count=%d err=%v", count, err)
		}
	case "update":
		var status string
		if err := db.Get(&status, "SELECT status FROM e2e_authguard_customer_growth_jobs WHERE id = ?", scenario.TargetJobID); err != nil || status != "READY" {
			t.Fatalf("denied update changed status=%q err=%v", status, err)
		}
	case "delete":
		var count int
		if err := db.Get(&count, "SELECT COUNT(*) FROM e2e_authguard_customer_growth_jobs WHERE id = ?", scenario.TargetJobID); err != nil || count != 1 {
			t.Fatalf("denied delete changed database count=%d err=%v", count, err)
		}
	}
}

func executeScenario(
	t *testing.T,
	db *sqlx.DB,
	jobController *controller.CustomerGrowthJobController,
	ctx context.Context,
	scenario authorizationScenario,
) (bool, []int64, string) {
	t.Helper()
	switch scenario.Operation {
	case "list":
		rows, err := jobController.ListVisibleJobs(ctx, dto.CustomerGrowthJobSearchRequest{
			WorkspaceID: valueOrEmpty(scenario.Criteria.WorkspaceID),
			ProjectID:   valueOrEmpty(scenario.Criteria.ProjectID),
			Status:      valueOrEmpty(scenario.Criteria.Status),
			OwnerUserID: valueOrEmpty(scenario.Criteria.OwnerUserID),
		})
		if err != nil {
			return false, nil, ""
		}
		ids := make([]int64, 0, len(rows))
		for _, row := range rows {
			ids = append(ids, row.ID)
		}
		return true, ids, ""
	case "get":
		_, found, err := jobController.GetJob(ctx, scenario.TargetJobID)
		return err == nil && found, nil, ""
	case "create":
		if scenario.Job == nil {
			t.Fatal("create scenario is missing job")
		}
		job := scenario.Job
		created, err := jobController.CreateJob(ctx, dto.CreateCustomerGrowthJobRequest{
			ID: job.ID, Region: job.Region, TenantID: job.TenantID,
			WorkspaceID: job.WorkspaceID, ProjectID: job.ProjectID, JobID: job.JobID,
			DisplayName: job.DisplayName, Status: job.Status, OwnerUserID: job.OwnerUserID,
		})
		return err == nil && created.ID == job.ID, nil, created.Status
	case "update":
		if scenario.Update == nil {
			t.Fatal("update scenario is missing update")
		}
		updated, err := jobController.UpdateJob(ctx, scenario.TargetJobID, dto.UpdateCustomerGrowthJobRequest{
			DisplayName: scenario.Update.DisplayName,
			Status:      scenario.Update.Status,
			OwnerUserID: scenario.Update.OwnerUserID,
		})
		return err == nil, nil, updated.Status
	case "delete":
		err := jobController.DeleteJob(ctx, scenario.TargetJobID)
		if err != nil {
			return false, nil, ""
		}
		var remaining int
		if queryErr := db.Get(&remaining, "SELECT COUNT(*) FROM e2e_authguard_customer_growth_jobs WHERE id = ?", scenario.TargetJobID); queryErr != nil {
			t.Fatal(queryErr)
		}
		return remaining == 0, nil, ""
	default:
		t.Fatalf("unsupported operation %q", scenario.Operation)
		return false, nil, ""
	}
}

func requestContext(t *testing.T, version int, scenario authorizationScenario) context.Context {
	t.Helper()
	t.Setenv("AUTHGUARD_ACCESS_CONTEXT_HMAC_KEY", testAccessContextSigningKey)
	if !scenario.GatewayAllowed {
		ctx, authenticated, err := filter.NewAccessFilter(nil).Enter(
			context.Background(), filter.HeaderFunc(func(string) string { return "" }),
		)
		if err != nil || authenticated {
			t.Fatalf("unexpected anonymous filter result authenticated=%t err=%v", authenticated, err)
		}
		return ctx
	}
	accessContext := model.NewAccessContext(
		scenario.PrincipalID,
		scenario.Action,
		scenario.ResourceURN,
		scenario.AllowResourceURNs,
		scenario.DenyResourceURNs,
		1,
		30*time.Second,
	)
	accessContext.Version = version
	encodedContext, err := adapterutil.SignAccessContext(accessContext, testAccessContextSigningKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx, authenticated, err := filter.NewAccessFilter(nil).Enter(
		context.Background(),
		filter.HeaderFunc(func(name string) string {
			if name == adapterutil.AccessContextHeader {
				return encodedContext
			}
			return ""
		}),
	)
	if err != nil || !authenticated {
		t.Fatalf("enter Authguard context authenticated=%t err=%v", authenticated, err)
	}
	return ctx
}

func newCustomerGrowthJobController(t *testing.T) (*sqlx.DB, *controller.CustomerGrowthJobController) {
	t.Helper()
	db, err := sqlx.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	seedCustomerGrowthJobs(t, db)
	jobRepository := repository.NewCustomerGrowthJobRepository(db)
	return db, controller.NewCustomerGrowthJobController(service.NewCustomerGrowthJobService(jobRepository))
}

func seedCustomerGrowthJobs(t *testing.T, db *sqlx.DB) {
	t.Helper()
	content, err := os.ReadFile(configPath(t, "init.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range strings.Split(string(content), ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("execute shared SQL fixture: %v", err)
		}
	}
}

func loadAuthorizationFixture(t *testing.T) authorizationFixture {
	t.Helper()
	content, err := os.ReadFile(configPath(t, "authguard-e2e-scenarios.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture authguardFixture
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.Authz
}

func configPath(t *testing.T, name string) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve Go test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "config", name))
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
