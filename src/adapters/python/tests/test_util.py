from __future__ import annotations

import base64
import json
import unittest

from authguard_adapter import access
from authguard_adapter.access import AccessContextUnavailable
from authguard_adapter.model import AccessContext, AccessGrantSet, PathMap, ResourceSqlMapping, SegmentMap, SqlScope
from authguard_adapter.util import current_scope, current_scope_for_action, decode_access_context, encode_access_context, parse_urn_pattern


EXACT_JOB = "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score"
JOB_WILDCARD = "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/*"


class PythonAdapterUtilTest(unittest.TestCase):
    def tearDown(self) -> None:
        access.clear_current()

    def test_compiles_exact_job_resource_to_sql_scope(self) -> None:
        scope = customer_growth_job_mapping().compile_scope([EXACT_JOB], [])

        self.assert_scope(
            scope,
            "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?",
            ("global", "example-corp", "customer-insights", "retention-analytics", "daily-churn-risk-score"),
        )

    def test_compiles_single_segment_job_wildcard_without_job_predicate(self) -> None:
        scope = customer_growth_job_mapping().compile_scope([JOB_WILDCARD], [])

        self.assert_scope(
            scope,
            "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?",
            ("global", "example-corp", "customer-insights", "retention-analytics"),
        )

    def test_combines_multiple_allow_scopes_before_explicit_deny(self) -> None:
        scope = customer_growth_job_mapping().compile_scope(
            [
                JOB_WILDCARD,
                "urn:iam:prod:customer-growth:global:example-corp:workspace/campaign-analytics/project/campaign-attribution/job/daily-channel-attribution",
            ],
            [
                "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit"
            ],
        )

        self.assert_scope(
            scope,
            "((region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?) OR "
            "(region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?)) "
            "AND NOT (region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?)",
            (
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
                "vip-retention-risk-audit",
            ),
        )

    def test_returns_deny_all_when_allow_list_is_empty(self) -> None:
        scope = customer_growth_job_mapping().compile_scope(
            [],
            ["urn:iam:prod:customer-growth:global:example-corp:**"],
        )

        self.assert_scope(scope, "0=1", ())

    def test_compiles_object_key_globstar_to_boundary_safe_prefix(self) -> None:
        scope = object_mapping().compile_scope(
            ["urn:iam:prod:object-store:us-west-2:example-corp:bucket/audit-exports/object/2026/08/**"],
            [],
        )

        self.assert_scope(
            scope,
            "region = ? AND account_id = ? AND bucket = ? AND (object_key = ? OR object_key LIKE ?)",
            ("us-west-2", "example-corp", "audit-exports", "2026/08", "2026/08/%"),
        )

    def test_rejects_single_segment_wildcard_inside_remainder_column(self) -> None:
        with self.assertRaisesRegex(ValueError, "remainder column"):
            object_mapping().compile_scope(
                ["urn:iam:prod:object-store:us-west-2:example-corp:bucket/audit-exports/object/*/report.json"],
                [],
            )

    def test_access_context_codec_round_trips(self) -> None:
        expected = sample_context()

        encoded = encode_access_context(expected)

        self.assertNotIn("=", encoded)
        self.assertEqual(expected, decode_access_context(encoded))

    def test_access_context_codec_emits_v3_canonical_fields(self) -> None:
        payload = decode_encoded_payload(encode_access_context(sample_context()))

        self.assertEqual(3, payload["version"])
        self.assertEqual("revenue-analyst", payload["principal_id"])
        self.assertEqual(1, payload["policy_revision"])
        self.assertNotIn("subject_id", payload)
        self.assertNotIn("policy_version", payload)

    def test_access_context_codec_rejects_noncanonical_field_names(self) -> None:
        payload = decode_encoded_payload(encode_access_context(sample_context()))
        payload["subject_id"] = payload.pop("principal_id")
        payload["policy_version"] = payload.pop("policy_revision")

        with self.assertRaises(ValueError):
            decode_access_context(encode_unchecked_payload(payload))

    def test_current_context_compiles_sql_scope(self) -> None:
        access.set_current(AccessGrantSet((JOB_WILDCARD,)))

        scope = current_scope(customer_growth_job_mapping())

        self.assert_scope(
            scope,
            "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?",
            ("global", "example-corp", "customer-insights", "retention-analytics"),
        )

    def test_current_action_scope_compiles_for_matching_action(self) -> None:
        context = sample_context()
        access.set_current_access(
            AccessContext.active(
                context.principal_id,
                context.action,
                context.resource_urn,
                context.allow_resource_urns,
            ).request_access()
        )

        scope = current_scope_for_action("customer-growth.job.read", customer_growth_job_mapping())

        self.assert_scope(
            scope,
            "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ?",
            ("global", "example-corp", "customer-insights", "retention-analytics"),
        )

    def test_current_action_scope_rejects_action_mismatch(self) -> None:
        access.set_current_access(sample_context().request_access())

        with self.assertRaisesRegex(PermissionError, "action mismatch"):
            current_scope_for_action("customer-growth.job.update", customer_growth_job_mapping())

    def test_parses_descriptive_resource_urn_components(self) -> None:
        pattern = parse_urn_pattern(EXACT_JOB)

        self.assertEqual("prod", pattern.partition)
        self.assertEqual("customer-growth", pattern.service)
        self.assertEqual("global", pattern.region)
        self.assertEqual("example-corp", pattern.tenant)
        self.assertEqual(
            ("workspace", "customer-insights", "project", "retention-analytics", "job", "daily-churn-risk-score"),
            pattern.path,
        )

    def test_rejects_non_iam_urn_namespace(self) -> None:
        self.assert_parse_fails("urn:other:prod:customer-growth:global:example-corp:workspace/customer-insights")

    def test_rejects_urn_without_resource_path(self) -> None:
        self.assert_parse_fails("urn:iam:prod:customer-growth:global:example-corp:")

    def test_rejects_empty_resource_path_segment(self) -> None:
        self.assert_parse_fails(
            "urn:iam:prod:customer-growth:global:example-corp:workspace//project/retention-analytics"
        )

    def test_rejects_partial_segment_wildcard(self) -> None:
        self.assert_parse_fails(
            "urn:iam:prod:customer-growth:global:example-corp:workspace/revenue-*/project/retention-analytics"
        )

    def test_rejects_non_terminal_globstar(self) -> None:
        self.assert_parse_fails(
            "urn:iam:prod:customer-growth:global:example-corp:workspace/**/job/daily-churn-risk-score"
        )

    def test_ignores_allow_for_different_service(self) -> None:
        scope = customer_growth_job_mapping().compile_scope(
            [
                "urn:iam:prod:billing:global:example-corp:workspace/customer-insights/project/retention-analytics/job/daily-churn-risk-score"
            ],
            [],
        )

        self.assert_scope(scope, "0=1", ())

    def test_ignores_deny_for_different_service(self) -> None:
        scope = customer_growth_job_mapping().compile_scope(
            [EXACT_JOB],
            ["urn:iam:prod:billing:global:example-corp:**"],
        )

        self.assert_scope(
            scope,
            "region = ? AND tenant_id = ? AND workspace_id = ? AND project_id = ? AND job_id = ?",
            ("global", "example-corp", "customer-insights", "retention-analytics", "daily-churn-risk-score"),
        )

    def test_compiles_all_segment_wildcards_to_allow_all(self) -> None:
        scope = customer_growth_job_mapping().compile_scope(["urn:iam:*:*:*:*:**"], [])

        self.assert_scope(scope, "1=1", ())

    def test_global_deny_wildcard_collapses_scope_to_deny_all(self) -> None:
        scope = customer_growth_job_mapping().compile_scope([EXACT_JOB], ["urn:iam:*:*:*:*:**"])

        self.assert_scope(scope, "0=1", ())

    def test_compiles_exact_object_key_into_single_equality(self) -> None:
        scope = object_mapping().compile_scope(
            [
                "urn:iam:prod:object-store:us-west-2:example-corp:bucket/audit-exports/object/2026/08/report.json"
            ],
            [],
        )

        self.assert_scope(
            scope,
            "region = ? AND account_id = ? AND bucket = ? AND object_key = ?",
            ("us-west-2", "example-corp", "audit-exports", "2026/08/report.json"),
        )

    def test_current_scope_without_access_context_fails_closed(self) -> None:
        access.clear_current()

        with self.assertRaises(AccessContextUnavailable):
            current_scope(customer_growth_job_mapping())

    def assert_parse_fails(self, urn: str) -> None:
        with self.assertRaises(ValueError):
            parse_urn_pattern(urn)

    def assert_scope(self, scope: SqlScope, where: str, args: tuple[str, ...]) -> None:
        self.assertEqual(where, scope.where)
        self.assertEqual(args, scope.args)


def sample_context() -> AccessContext:
    return AccessContext.active(
        "revenue-analyst",
        "customer-growth.job.read",
        EXACT_JOB,
        (JOB_WILDCARD,),
        (
            "urn:iam:prod:customer-growth:global:example-corp:workspace/customer-insights/project/retention-analytics/job/vip-retention-risk-audit",
        ),
    )


def customer_growth_job_mapping() -> ResourceSqlMapping:
    return ResourceSqlMapping(
        SegmentMap.constant("prod"),
        SegmentMap.constant("customer-growth"),
        SegmentMap.column("region"),
        SegmentMap.column("tenant_id"),
        (
            PathMap.literal("workspace"),
            PathMap.column("workspace_id"),
            PathMap.literal("project"),
            PathMap.column("project_id"),
            PathMap.literal("job"),
            PathMap.column("job_id"),
        ),
    )


def object_mapping() -> ResourceSqlMapping:
    return ResourceSqlMapping(
        SegmentMap.constant("prod"),
        SegmentMap.constant("object-store"),
        SegmentMap.column("region"),
        SegmentMap.column("account_id"),
        (
            PathMap.literal("bucket"),
            PathMap.column("bucket"),
            PathMap.literal("object"),
            PathMap.remainder_column("object_key"),
        ),
    )


def decode_encoded_payload(encoded: str) -> dict[str, object]:
    padding = "=" * (-len(encoded) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded + padding))


def encode_unchecked_payload(payload: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


if __name__ == "__main__":
    unittest.main()
