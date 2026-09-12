import json
import os
from pathlib import Path
import unittest

from sqlalchemy import create_engine
from sqlalchemy.engine import Connection

from authguard_adapter.filter import AccessFilter
from authguard_adapter.model import AccessContext
from authguard_adapter.access import ACCESS_CONTEXT_HMAC_KEY_ENV
from authguard_adapter.util import ACCESS_CONTEXT_HEADER, sign_access_context
from app.controller.customer_growth_job_controller import CustomerGrowthJobController
from app.dto.customer_growth_job_dto import (
    CustomerGrowthJobSearchRequest,
    CreateCustomerGrowthJobRequest,
    UpdateCustomerGrowthJobRequest,
)
from app.repository.customer_growth_job_repository import CustomerGrowthJobRepository
from app.service.customer_growth_job_service import CustomerGrowthJobService


CONFIG_DIR = Path(__file__).resolve().parents[3] / "config"
TEST_SIGNING_KEY = "test-access-context-hmac-key-32-bytes-minimum"


class HeaderRequest:
    def __init__(self, headers: dict[str, str]) -> None:
        self._headers = headers

    def header(self, name: str) -> str | None:
        return self._headers.get(name)


class PythonCustomerGrowthJobServiceE2ETest(unittest.TestCase):
    def setUp(self) -> None:
        os.environ[ACCESS_CONTEXT_HMAC_KEY_ENV] = TEST_SIGNING_KEY

    def tearDown(self) -> None:
        os.environ.pop(ACCESS_CONTEXT_HMAC_KEY_ENV, None)

    def test_authorization_scenarios_from_shared_fixture(self) -> None:
        fixture = load_authorization_fixture()
        scenarios = fixture["scenarios"]
        self.assertGreaterEqual(len(scenarios), 30)

        for scenario in scenarios:
            with self.subTest(scenario=scenario["id"]):
                engine = create_engine("sqlite:///:memory:")
                with engine.begin() as db:
                    controller = new_customer_growth_job_controller(db)
                    request = access_request(fixture["access_context_version"], scenario)
                    with AccessFilter().enter(request) as access_scope:
                        self.assertEqual(access_scope.authenticated, scenario["gateway_allowed"])
                        allowed, ids, status = execute_scenario(db, controller, scenario)

                    self.assertEqual(allowed, scenario["expected_allowed"])
                    if not scenario["expected_allowed"]:
                        assert_denied_mutation_did_not_change_database(db, scenario)
                    if scenario["operation"] == "list" and scenario["expected_allowed"]:
                        self.assertEqual(ids, scenario.get("expected_job_ids", []))
                    if expected_status := scenario.get("expected_status"):
                        self.assertEqual(status, expected_status)


def assert_denied_mutation_did_not_change_database(
    db: Connection, scenario: dict[str, object]
) -> None:
    operation = scenario["operation"]
    if operation == "create":
        count = db.exec_driver_sql(
            "SELECT COUNT(*) FROM customer_growth_jobs WHERE id = ?",
            (scenario["job"]["id"],),
        ).scalar_one()
        if count != 0:
            raise AssertionError("denied create changed the database")
    elif operation == "update":
        status = db.exec_driver_sql(
            "SELECT status FROM customer_growth_jobs WHERE id = ?",
            (scenario["target_job_id"],),
        ).scalar_one()
        if status != "READY":
            raise AssertionError(f"denied update changed status to {status}")
    elif operation == "delete":
        count = db.exec_driver_sql(
            "SELECT COUNT(*) FROM customer_growth_jobs WHERE id = ?",
            (scenario["target_job_id"],),
        ).scalar_one()
        if count != 1:
            raise AssertionError("denied delete changed the database")


def execute_scenario(
    db: Connection,
    controller: CustomerGrowthJobController,
    scenario: dict[str, object],
) -> tuple[bool, list[int], str]:
    try:
        operation = scenario["operation"]
        if operation == "list":
            criteria = scenario.get("criteria", {})
            rows = controller.list_visible_jobs(
                CustomerGrowthJobSearchRequest(
                    workspace_id=criteria.get("workspace_id"),
                    project_id=criteria.get("project_id"),
                    status=criteria.get("status"),
                    owner_user_id=criteria.get("owner_user_id"),
                )
            )
            return True, [row.id for row in rows], ""
        if operation == "get":
            job = controller.get_job(scenario["target_job_id"])
            return job is not None, [], ""
        if operation == "create":
            job = scenario["job"]
            created = controller.create_job(
                CreateCustomerGrowthJobRequest(
                    id=job["id"],
                    region=job["region"],
                    tenant_id=job["tenant_id"],
                    workspace_id=job["workspace_id"],
                    project_id=job["project_id"],
                    job_id=job["job_id"],
                    display_name=job["display_name"],
                    status=job["status"],
                    owner_user_id=job["owner_user_id"],
                )
            )
            return created.id == job["id"], [], created.status
        if operation == "update":
            update = scenario["update"]
            updated = controller.update_job(
                scenario["target_job_id"],
                UpdateCustomerGrowthJobRequest(
                    display_name=update["display_name"],
                    status=update["status"],
                    owner_user_id=update["owner_user_id"],
                ),
            )
            return True, [], updated.status
        if operation == "delete":
            controller.delete_job(scenario["target_job_id"])
            remaining = db.exec_driver_sql(
                "SELECT COUNT(*) FROM customer_growth_jobs WHERE id = ?",
                (scenario["target_job_id"],),
            ).scalar_one()
            return remaining == 0, [], ""
        raise AssertionError(f"unsupported operation: {operation}")
    except (RuntimeError, PermissionError, LookupError):
        return False, [], ""


def access_request(version: int, scenario: dict[str, object]) -> HeaderRequest:
    if not scenario["gateway_allowed"]:
        return HeaderRequest({})
    context = AccessContext.active(
        str(scenario["principal_id"]),
        str(scenario["action"]),
        str(scenario["resource_urn"]),
        tuple(scenario["allow_resource_urns"]),
        tuple(scenario["deny_resource_urns"]),
    )
    if context.version != version:
        raise AssertionError(f"unsupported fixture version: {version}")
    return HeaderRequest(
        {ACCESS_CONTEXT_HEADER: sign_access_context(context, TEST_SIGNING_KEY)}
    )


def new_customer_growth_job_controller(db: Connection) -> CustomerGrowthJobController:
    seed_customer_growth_jobs(db)
    return CustomerGrowthJobController(CustomerGrowthJobService(CustomerGrowthJobRepository(db)))


def seed_customer_growth_jobs(db: Connection) -> None:
    sql = (CONFIG_DIR / "init.sql").read_text(encoding="utf-8")
    for statement in sql.split(";"):
        if statement.strip():
            db.exec_driver_sql(statement)


def load_authorization_fixture() -> dict[str, object]:
    fixture = json.loads(
        (CONFIG_DIR / "authguard-e2e-scenarios.json").read_text(encoding="utf-8")
    )
    return fixture["authz"]


if __name__ == "__main__":
    unittest.main()
