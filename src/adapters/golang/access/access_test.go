package access

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"authguard/adapters/golang/model"
)

const jobWildcard = "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*"

func TestCurrentContextCompilesSQLScope(t *testing.T) {
	ctx := WithGrantSet(context.Background(), model.AccessGrantSet{
		AllowResourceURNs: []string{jobWildcard},
	})

	scope, err := CurrentScope(ctx, customerGrowthJobMapping())
	if err != nil {
		t.Fatal(err)
	}
	assertScope(
		t,
		scope,
		"region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?",
		[]any{"global", "example-corp", "customer-insights", "retention-analytics"},
	)
}

func TestCurrentActionScopeCompilesForMatchingAction(t *testing.T) {
	ctx := WithRequestAccess(context.Background(), model.RequestAccess{
		Action: "customer-growth.job.read",
		Grants: model.AccessGrantSet{AllowResourceURNs: []string{jobWildcard}},
	})

	scope, err := CurrentScopeForAction(
		ctx, "customer-growth.job.read", customerGrowthJobMapping(),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertScope(
		t,
		scope,
		"region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?",
		[]any{"global", "example-corp", "customer-insights", "retention-analytics"},
	)
}

func TestCurrentActionScopeRejectsActionMismatch(t *testing.T) {
	ctx := WithRequestAccess(context.Background(), model.RequestAccess{
		Action: "customer-growth.job.read",
		Grants: model.AccessGrantSet{AllowResourceURNs: []string{jobWildcard}},
	})

	_, err := CurrentScopeForAction(
		ctx, "customer-growth.job.update", customerGrowthJobMapping(),
	)
	var mismatch ActionMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected action mismatch, got %v", err)
	}
}

func TestCurrentScopeWithoutAccessContextFailsClosed(t *testing.T) {
	_, err := CurrentScope(context.Background(), customerGrowthJobMapping())
	if !errors.Is(err, ErrAccessContextUnavailable) {
		t.Fatalf("expected missing access context error, got %v", err)
	}
}

func customerGrowthJobMapping() model.ResourceSQLMapping {
	return model.ResourceSQLMapping{
		Partition: model.ConstSegment("prod"),
		Service:   model.ConstSegment("customer-growth"),
		Region:    model.ColumnSegment("region"),
		Tenant:    model.ColumnSegment("tenant_id"),
		Path: []model.PathMap{
			model.LiteralPath("workspace"),
			model.ColumnPath("workspace_id"),
			model.LiteralPath("project"),
			model.ColumnPath("project_id"),
			model.LiteralPath("job"),
			model.ColumnPath("job_id"),
		},
	}
}

func assertScope(t *testing.T, actual model.SqlScope, where string, args []any) {
	t.Helper()
	if actual.Where != where || !reflect.DeepEqual(actual.Args, args) {
		t.Fatalf(
			"scope mismatch:\nwant: %s %#v\n got: %s %#v",
			where,
			args,
			actual.Where,
			actual.Args,
		)
	}
}
