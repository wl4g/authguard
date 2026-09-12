package com.authguard.adapter.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.authguard.adapter.access.AuthguardAccess;
import com.authguard.adapter.model.AuthguardTypes.AccessContext;
import com.authguard.adapter.model.AuthguardTypes.AccessGrantSet;
import com.authguard.adapter.model.AuthguardTypes.PathMap;
import com.authguard.adapter.model.AuthguardTypes.ResourceSqlMapping;
import com.authguard.adapter.model.AuthguardTypes.SegmentMap;
import com.authguard.adapter.model.AuthguardTypes.SqlScope;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class AuthguardUtilsTest {
  private static final String EXACT_JOB =
      "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score";
  private static final String JOB_WILDCARD =
      "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*";

  @AfterEach
  void clearContext() {
    AuthguardAccess.ContextHolder.clear();
  }

  @Test
  void compilesExactJobResourceToSqlScope() {
    SqlScope scope = customerGrowthJobMapping().compile(List.of(EXACT_JOB), List.of());

    assertScope(
        scope,
        "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?",
        List.of(
            "global",
            "example-corp",
            "customer-insights",
            "retention-analytics",
            "daily-churn-risk-score"));
  }

  @Test
  void compilesSingleSegmentJobWildcardWithoutJobPredicate() {
    SqlScope scope = customerGrowthJobMapping().compile(List.of(JOB_WILDCARD), List.of());

    assertScope(
        scope,
        "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?",
        List.of("global", "example-corp", "customer-insights", "retention-analytics"));
  }

  @Test
  void combinesMultipleAllowScopesBeforeExplicitDeny() {
    SqlScope scope =
        customerGrowthJobMapping()
            .compile(
                List.of(
                    JOB_WILDCARD,
                    "urn:iam:prod:customer-growth:global:example-corp:workspace/campaign-analytics/project/campaign-attribution/job/daily-channel-attribution"),
                List.of(
                    "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit"));

    assertScope(
        scope,
        "((region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?) OR "
            + "(region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?)) "
            + "AND NOT (region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?)",
        List.of(
            "global",
            "example-corp",
            "customer-insights",
            "retention-analytics",
            "global",
            "example-corp",
            "campaign-analytics",
            "campaign-attribution",
            "daily-channel-attribution",
            "global",
            "example-corp",
            "customer-insights",
            "retention-analytics",
            "vip-retention-risk-audit"));
  }

  @Test
  void returnsDenyAllWhenAllowListIsEmpty() {
    SqlScope scope =
        customerGrowthJobMapping()
            .compile(
                List.of(), List.of("urn:iam:prod:customer-growth:global:example-corp:**"));

    assertScope(scope, "0=1", List.of());
  }

  @Test
  void compilesObjectKeyGlobstarToBoundarySafePrefix() {
    SqlScope scope =
        objectMapping()
            .compile(
                List.of(
                    "urn:iam:prod:object-store:us-west-2:example-corp:bucket/audit-exports/object/2026/08/**"),
                List.of());

    assertScope(
        scope,
        "region = ? AND account_id = ? AND bucket = ? AND (object_key = ? OR object_key LIKE ?)",
        List.of("us-west-2", "example-corp", "audit-exports", "2026/08", "2026/08/%"));
  }

  @Test
  void rejectsSingleSegmentWildcardInsideRemainderColumn() {
    assertThrows(
        UnsupportedOperationException.class,
        () ->
            objectMapping()
                .compile(
                    List.of(
                        "urn:iam:prod:object-store:us-west-2:example-corp:bucket/audit-exports/object/*/report.json"),
                    List.of()));
  }

  @Test
  void accessContextCodecRoundTrips() {
    AccessContext expected = sampleContext();

    String encoded = AuthguardUtils.encodeAccessContext(expected);

    assertFalse(encoded.contains("="));
    assertEquals(expected, AuthguardUtils.decodeAccessContext(encoded));
  }

  @Test
  void accessContextCodecEmitsV3CanonicalFields() {
    String encoded = AuthguardUtils.encodeAccessContext(sampleContext());
    String json =
        new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8);

    assertTrue(json.contains("\"version\":3"));
    assertTrue(json.contains("\"principal_id\":\"revenue-analyst\""));
    assertTrue(json.contains("\"policy_revision\":1"));
    assertFalse(json.contains("\"subject_id\""));
    assertFalse(json.contains("\"policy_version\""));
  }

  @Test
  void accessContextCodecRejectsNoncanonicalFieldNames() {
    long now = Instant.now().getEpochSecond();
    String noncanonicalJson =
        """
        {
          "version": 3,
          "subject_id": "noncanonical-revenue-analyst",
          "action": "customer-growth.job.read",
          "resource_urn": "%s",
          "allow_resource_urns": ["%s"],
          "deny_resource_urns": [],
          "policy_version": 17,
          "issued_at_epoch_seconds": %d,
          "expires_at_epoch_seconds": %d
        }
        """
            .formatted(EXACT_JOB, JOB_WILDCARD, now, now + 30);
    String encoded =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(noncanonicalJson.getBytes(StandardCharsets.UTF_8));

    assertThrows(IllegalArgumentException.class, () -> AuthguardUtils.decodeAccessContext(encoded));
  }

  @Test
  void currentContextCompilesSqlScope() {
    AuthguardAccess.ContextHolder.set(new AccessGrantSet(List.of(JOB_WILDCARD), List.of()));

    SqlScope scope = AuthguardUtils.currentScope(customerGrowthJobMapping());

    assertScope(
        scope,
        "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?",
        List.of("global", "example-corp", "customer-insights", "retention-analytics"));
  }

  @Test
  void currentActionScopeCompilesForMatchingAction() {
    AuthguardAccess.ContextHolder.set(
        AccessContext.active(
                "revenue-analyst",
                "customer-growth.job.read",
                EXACT_JOB,
                List.of(JOB_WILDCARD),
                List.of())
            .requestAccess());

    SqlScope scope =
        AuthguardUtils.currentScopeForAction("customer-growth.job.read", customerGrowthJobMapping());

    assertScope(
        scope,
        "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?",
        List.of("global", "example-corp", "customer-insights", "retention-analytics"));
  }

  @Test
  void currentActionScopeRejectsActionMismatch() {
    AuthguardAccess.ContextHolder.set(sampleContext().requestAccess());

    assertThrows(
        SecurityException.class,
        () ->
            AuthguardUtils.currentScopeForAction(
                "customer-growth.job.update", customerGrowthJobMapping()));
  }

  @Test
  void parsesDescriptiveResourceUrnComponents() {
    var pattern = AuthguardUtils.parseUrnPattern(EXACT_JOB);

    assertEquals("prod", pattern.partition());
    assertEquals("customer-growth", pattern.service());
    assertEquals("global", pattern.region());
    assertEquals("example-corp", pattern.tenant());
    assertEquals(
        List.of(
            "workspace",
            "customer-insights",
            "project",
            "retention-analytics",
            "job",
            "daily-churn-risk-score"),
        pattern.path());
  }

  @Test
  void rejectsNonIamUrnNamespace() {
    assertParseFails("urn:other:prod:customer-growth:global:example-corp:workspace/customer-insights");
  }

  @Test
  void rejectsUrnWithoutResourcePath() {
    assertParseFails("urn:iam:prod:customer-growth:global:example-corp:");
  }

  @Test
  void rejectsEmptyResourcePathSegment() {
    assertParseFails(
        "urn:iam:prod:customer-growth:global:example-corp:workspace//project/retention-analytics");
  }

  @Test
  void rejectsPartialSegmentWildcard() {
    assertParseFails(
        "urn:iam:prod:customer-growth:global:example-corp:workspace/revenue-*/project/retention-analytics");
  }

  @Test
  void rejectsNonTerminalGlobstar() {
    assertParseFails(
        "urn:iam:prod:customer-growth:global:example-corp:workspace/**/job/daily-churn-risk-score");
  }

  @Test
  void ignoresAllowForDifferentService() {
    SqlScope scope =
        customerGrowthJobMapping()
            .compile(
                List.of(
                    "urn:iam:prod:billing:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score"),
                List.of());

    assertScope(scope, "0=1", List.of());
  }

  @Test
  void ignoresDenyForDifferentService() {
    SqlScope scope =
        customerGrowthJobMapping()
            .compile(
                List.of(EXACT_JOB),
                List.of("urn:iam:prod:billing:global:example-corp:**"));

    assertScope(
        scope,
        "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?",
        List.of(
            "global",
            "example-corp",
            "customer-insights",
            "retention-analytics",
            "daily-churn-risk-score"));
  }

  @Test
  void compilesAllSegmentWildcardsToAllowAll() {
    SqlScope scope =
        customerGrowthJobMapping().compile(List.of("urn:iam:*:*:*:*:**"), List.of());

    assertScope(scope, "1=1", List.of());
  }

  @Test
  void globalDenyWildcardCollapsesScopeToDenyAll() {
    SqlScope scope =
        customerGrowthJobMapping()
            .compile(List.of(EXACT_JOB), List.of("urn:iam:*:*:*:*:**"));

    assertScope(scope, "0=1", List.of());
  }

  @Test
  void compilesExactObjectKeyIntoSingleEquality() {
    SqlScope scope =
        objectMapping()
            .compile(
                List.of(
                    "urn:iam:prod:object-store:us-west-2:example-corp:bucket/audit-exports/object/2026/08/report.json"),
                List.of());

    assertScope(
        scope,
        "region = ? AND account_id = ? AND bucket = ? AND object_key = ?",
        List.of("us-west-2", "example-corp", "audit-exports", "2026/08/report.json"));
  }

  @Test
  void currentScopeWithoutAccessContextFailsClosed() {
    AuthguardAccess.ContextHolder.clear();

    assertThrows(
        IllegalStateException.class,
        () -> AuthguardUtils.currentScope(customerGrowthJobMapping()));
  }

  private static void assertParseFails(String urn) {
    assertThrows(IllegalArgumentException.class, () -> AuthguardUtils.parseUrnPattern(urn));
  }

  private static void assertScope(SqlScope scope, String where, List<String> args) {
    assertEquals(where, scope.where());
    assertEquals(args, scope.args());
  }

  private static AccessContext sampleContext() {
    return AccessContext.active(
        "revenue-analyst",
        "customer-growth.job.read",
        EXACT_JOB,
        List.of(JOB_WILDCARD),
        List.of(
            "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit"));
  }

  private static ResourceSqlMapping customerGrowthJobMapping() {
    return new ResourceSqlMapping(
        SegmentMap.constant("prod"),
        SegmentMap.constant("customer-growth"),
        SegmentMap.column("region"),
        SegmentMap.column("tenant_id"),
        List.of(
            PathMap.literal("workspace"),
            PathMap.column("workspace_id"),
            PathMap.literal("project"),
            PathMap.column("project_id"),
            PathMap.literal("job"),
            PathMap.column("job_id")));
  }

  private static ResourceSqlMapping objectMapping() {
    return new ResourceSqlMapping(
        SegmentMap.constant("prod"),
        SegmentMap.constant("object-store"),
        SegmentMap.column("region"),
        SegmentMap.column("account_id"),
        List.of(
            PathMap.literal("bucket"),
            PathMap.column("bucket"),
            PathMap.literal("object"),
            PathMap.remainderColumn("object_key")));
  }
}
