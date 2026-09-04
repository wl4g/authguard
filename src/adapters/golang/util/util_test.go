package util

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"authguard/adapters/golang/model"
)

const exactJob = "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score"
const jobWildcard = "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*"

func TestCompilesExactJobResourceToSQLScope(t *testing.T) {
	scope, err := CompileScope(customerGrowthJobMapping(), []string{exactJob}, nil)
	assertNoError(t, err)
	assertScope(
		t,
		scope,
		"region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?",
		[]any{"global", "example-corp", "customer-insights", "retention-analytics", "daily-churn-risk-score"},
	)
}

func TestCompilesSingleSegmentJobWildcardWithoutJobPredicate(t *testing.T) {
	scope, err := CompileScope(customerGrowthJobMapping(), []string{jobWildcard}, nil)
	assertNoError(t, err)
	assertScope(
		t,
		scope,
		"region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?",
		[]any{"global", "example-corp", "customer-insights", "retention-analytics"},
	)
}

func TestCombinesMultipleAllowScopesBeforeExplicitDeny(t *testing.T) {
	scope, err := CompileScope(
		customerGrowthJobMapping(),
		[]string{
			jobWildcard,
			"urn:iam:prod:customer-growth:global:example-corp:workspace/campaign-analytics/project/campaign-attribution/job/daily-channel-attribution",
		},
		[]string{"urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit"},
	)
	assertNoError(t, err)
	assertScope(
		t,
		scope,
		"((region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?) OR "+
			"(region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?)) "+
			"AND NOT (region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?)",
		[]any{
			"global", "example-corp", "customer-insights", "retention-analytics",
			"global", "example-corp", "campaign-analytics", "campaign-attribution", "daily-channel-attribution",
			"global", "example-corp", "customer-insights", "retention-analytics", "vip-retention-risk-audit",
		},
	)
}

func TestReturnsDenyAllWhenAllowListIsEmpty(t *testing.T) {
	scope, err := CompileScope(
		customerGrowthJobMapping(),
		nil,
		[]string{"urn:iam:prod:customer-growth:global:example-corp:**"},
	)
	assertNoError(t, err)
	assertScope(t, scope, "0=1", nil)
}

func TestCompilesObjectKeyGlobstarToBoundarySafePrefix(t *testing.T) {
	scope, err := CompileScope(
		objectMapping(),
		[]string{"urn:iam:prod:object-store:us-west-2:example-corp:bucket/audit-exports/object/2026/08/**"},
		nil,
	)
	assertNoError(t, err)
	assertScope(
		t,
		scope,
		"region = ? AND account_id = ? AND bucket = ? AND (object_key = ? OR object_key LIKE ?)",
		[]any{"us-west-2", "example-corp", "audit-exports", "2026/08", "2026/08/%"},
	)
}

func TestRejectsSingleSegmentWildcardInsideRemainderColumn(t *testing.T) {
	_, err := CompileScope(
		objectMapping(),
		[]string{"urn:iam:prod:object-store:us-west-2:example-corp:bucket/audit-exports/object/*/report.json"},
		nil,
	)
	if err == nil {
		t.Fatal("expected wildcard inside remainder column to fail")
	}
}

func TestAccessContextCodecRoundTrips(t *testing.T) {
	expected := sampleAccessContext()

	encoded, err := EncodeAccessContext(expected)
	assertNoError(t, err)
	actual, err := DecodeAccessContext(encoded)
	assertNoError(t, err)

	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("access context mismatch:\nwant: %#v\n got: %#v", expected, actual)
	}
}

func TestAccessContextCodecEmitsV3CanonicalFields(t *testing.T) {
	encoded, err := EncodeAccessContext(sampleAccessContext())
	assertNoError(t, err)
	payload := decodeEncodedPayload(t, encoded)

	if payload["version"] != float64(model.AccessContextVersion) {
		t.Fatalf("unexpected access context version: %#v", payload["version"])
	}
	if payload["principal_id"] != "revenue-analyst" || payload["policy_revision"] != float64(1) {
		t.Fatalf("canonical identity/revision fields missing: %#v", payload)
	}
	if _, exists := payload["subject_id"]; exists {
		t.Fatal("encoder must not emit legacy subject_id")
	}
	if _, exists := payload["policy_version"]; exists {
		t.Fatal("encoder must not emit legacy policy_version")
	}
}

func TestAccessContextCodecAcceptsV3LegacyFieldAliases(t *testing.T) {
	encoded, err := EncodeAccessContext(sampleAccessContext())
	assertNoError(t, err)
	payload := decodeEncodedPayload(t, encoded)
	payload["subject_id"] = payload["principal_id"]
	delete(payload, "principal_id")
	payload["policy_version"] = payload["policy_revision"]
	delete(payload, "policy_revision")
	legacyJSON, err := json.Marshal(payload)
	assertNoError(t, err)

	decoded, err := DecodeAccessContext(base64.RawURLEncoding.EncodeToString(legacyJSON))
	assertNoError(t, err)
	if decoded.PrincipalID != "revenue-analyst" || decoded.PolicyRevision != 1 {
		t.Fatalf("legacy aliases were not decoded: %#v", decoded)
	}
}

func TestParsesDescriptiveResourceURNComponents(t *testing.T) {
	pattern, err := ParseURNPattern(exactJob)
	assertNoError(t, err)

	if pattern.Partition != "prod" || pattern.Service != "customer-growth" ||
		pattern.Region != "global" || pattern.Tenant != "example-corp" {
		t.Fatalf("unexpected URN components: %#v", pattern)
	}
	expectedPath := []string{
		"workspace", "customer-insights", "project", "retention-analytics", "job", "daily-churn-risk-score",
	}
	if !reflect.DeepEqual(pattern.Path, expectedPath) {
		t.Fatalf("path mismatch: want=%#v got=%#v", expectedPath, pattern.Path)
	}
}

func TestRejectsNonIamUrnNamespace(t *testing.T) {
	assertParseFails(t, "urn:other:prod:customer-growth:global:example-corp:workspace/customer-insights")
}

func TestRejectsURNWithoutResourcePath(t *testing.T) {
	assertParseFails(t, "urn:iam:prod:customer-growth:global:example-corp:")
}

func TestRejectsEmptyResourcePathSegment(t *testing.T) {
	assertParseFails(t, "urn:iam:prod:customer-growth:global:example-corp:workspace//project/retention-analytics")
}

func TestRejectsPartialSegmentWildcard(t *testing.T) {
	assertParseFails(t, "urn:iam:prod:customer-growth:global:example-corp:workspace/revenue-*/project/retention-analytics")
}

func TestRejectsNonTerminalGlobstar(t *testing.T) {
	assertParseFails(t, "urn:iam:prod:customer-growth:global:example-corp:workspace/**/job/daily-churn-risk-score")
}

func TestIgnoresAllowForDifferentService(t *testing.T) {
	scope, err := CompileScope(
		customerGrowthJobMapping(),
		[]string{"urn:iam:prod:billing:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score"},
		nil,
	)
	assertNoError(t, err)
	assertScope(t, scope, "0=1", nil)
}

func TestIgnoresDenyForDifferentService(t *testing.T) {
	scope, err := CompileScope(
		customerGrowthJobMapping(),
		[]string{exactJob},
		[]string{"urn:iam:prod:billing:global:example-corp:**"},
	)
	assertNoError(t, err)
	assertScope(
		t,
		scope,
		"region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?",
		[]any{"global", "example-corp", "customer-insights", "retention-analytics", "daily-churn-risk-score"},
	)
}

func TestCompilesAllSegmentWildcardsToAllowAll(t *testing.T) {
	scope, err := CompileScope(customerGrowthJobMapping(), []string{"urn:iam:*:*:*:*:**"}, nil)
	assertNoError(t, err)
	assertScope(t, scope, "1=1", nil)
}

func TestGlobalDenyWildcardCollapsesScopeToDenyAll(t *testing.T) {
	scope, err := CompileScope(
		customerGrowthJobMapping(),
		[]string{exactJob},
		[]string{"urn:iam:*:*:*:*:**"},
	)
	assertNoError(t, err)
	assertScope(t, scope, "0=1", nil)
}

func TestCompilesExactObjectKeyIntoSingleEquality(t *testing.T) {
	scope, err := CompileScope(
		objectMapping(),
		[]string{"urn:iam:prod:object-store:us-west-2:example-corp:bucket/audit-exports/object/2026/08/report.json"},
		nil,
	)
	assertNoError(t, err)
	assertScope(
		t,
		scope,
		"region = ? AND account_id = ? AND bucket = ? AND object_key = ?",
		[]any{"us-west-2", "example-corp", "audit-exports", "2026/08/report.json"},
	)
}

func sampleAccessContext() model.AccessContext {
	return model.NewAccessContext(
		"revenue-analyst",
		"customer-growth.job.read",
		exactJob,
		[]string{jobWildcard},
		[]string{
			"urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit",
		},
		1,
		30*time.Second,
	)
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

func objectMapping() model.ResourceSQLMapping {
	return model.ResourceSQLMapping{
		Partition: model.ConstSegment("prod"),
		Service:   model.ConstSegment("object-store"),
		Region:    model.ColumnSegment("region"),
		Tenant:    model.ColumnSegment("account_id"),
		Path: []model.PathMap{
			model.LiteralPath("bucket"),
			model.ColumnPath("bucket"),
			model.LiteralPath("object"),
			model.RemainderColumnPath("object_key"),
		},
	}
}

func assertParseFails(t *testing.T, urn string) {
	t.Helper()
	if _, err := ParseURNPattern(urn); err == nil {
		t.Fatalf("expected URN to be rejected: %s", urn)
	}
}

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func assertScope(t *testing.T, scope model.SqlScope, where string, args []any) {
	t.Helper()
	if scope.Where != where {
		t.Fatalf("where mismatch:\nwant: %s\n got: %s", where, scope.Where)
	}
	if args == nil {
		args = []any{}
	}
	if !reflect.DeepEqual(scope.Args, args) {
		t.Fatalf("args mismatch:\nwant: %#v\n got: %#v", args, scope.Args)
	}
}

func decodeEncodedPayload(t *testing.T, encoded string) map[string]any {
	t.Helper()
	payloadJSON, err := base64.RawURLEncoding.DecodeString(encoded)
	assertNoError(t, err)
	var payload map[string]any
	assertNoError(t, json.Unmarshal(payloadJSON, &payload))
	return payload
}
