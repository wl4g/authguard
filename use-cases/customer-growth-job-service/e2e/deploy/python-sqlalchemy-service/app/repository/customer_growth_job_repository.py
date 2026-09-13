from __future__ import annotations

from sqlalchemy.engine import Connection

from authguard_adapter.model import SqlScope
from app.entity.customer_growth_job_entity import CustomerGrowthJobEntity, CustomerGrowthJobQueryCriteria


class CustomerGrowthJobRepository:
    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def create(self, job: CustomerGrowthJobEntity) -> CustomerGrowthJobEntity:
        self._connection.exec_driver_sql(
            self._sql(
                "INSERT INTO e2e_authguard_customer_growth_jobs(id, region, tenant_id, workspace_id, project_id, job_id, display_name, status, owner_user_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            ),
            (
                job.id,
                job.region,
                job.tenant_id,
                job.workspace_id,
                job.project_id,
                job.job_id,
                job.display_name,
                job.status,
                job.owner_user_id,
            ),
        )
        return job

    def find_by_id_visible(self, scope: SqlScope, job_id: int) -> CustomerGrowthJobEntity | None:
        row = self._connection.exec_driver_sql(
            self._sql(f"SELECT * FROM e2e_authguard_customer_growth_jobs WHERE id = ? AND ({scope.where})"),
            (job_id, *scope.args),
        ).fetchone()
        return _row_to_entity(row) if row is not None else None

    def update_visible(self, scope: SqlScope, job: CustomerGrowthJobEntity) -> CustomerGrowthJobEntity:
        result = self._connection.exec_driver_sql(
            self._sql(
                "UPDATE e2e_authguard_customer_growth_jobs SET display_name = ?, status = ?, owner_user_id = ? "
                f"WHERE id = ? AND ({scope.where})"
            ),
            (job.display_name, job.status, job.owner_user_id, job.id, *scope.args),
        )
        if result.rowcount == 0:
            raise LookupError(f"customer growth job not found or not authorized: {job.id}")
        return job

    def delete_by_id_visible(self, scope: SqlScope, job_id: int) -> None:
        result = self._connection.exec_driver_sql(
            self._sql(f"DELETE FROM e2e_authguard_customer_growth_jobs WHERE id = ? AND ({scope.where})"),
            (job_id, *scope.args),
        )
        if result.rowcount == 0:
            raise LookupError(f"customer growth job not found or not authorized: {job_id}")

    def is_candidate_visible(self, scope: SqlScope, job: CustomerGrowthJobEntity) -> bool:
        count = self._connection.exec_driver_sql(
            self._sql(
                "SELECT COUNT(*) FROM ("
                "SELECT CAST(? AS VARCHAR(32)) AS region, "
                "CAST(? AS VARCHAR(128)) AS tenant_id, "
                "CAST(? AS VARCHAR(128)) AS workspace_id, "
                "CAST(? AS VARCHAR(128)) AS project_id, "
                "CAST(? AS VARCHAR(128)) AS job_id"
                f") candidate WHERE {scope.where}"
            ),
            (
                job.region,
                job.tenant_id,
                job.workspace_id,
                job.project_id,
                job.job_id,
                *scope.args,
            ),
        ).scalar_one()
        return count == 1

    def find_visible_jobs(
        self,
        scope: SqlScope,
        criteria: CustomerGrowthJobQueryCriteria,
    ) -> list[CustomerGrowthJobEntity]:
        clauses = [scope.where]
        args: list[str] = list(scope.args)
        _add_equals(clauses, args, "workspace_id", criteria.workspace_id)
        _add_equals(clauses, args, "project_id", criteria.project_id)
        _add_equals(clauses, args, "status", criteria.status)
        _add_equals(clauses, args, "owner_user_id", criteria.owner_user_id)
        rows = self._connection.exec_driver_sql(
            self._sql(
                "SELECT * "
                f"FROM e2e_authguard_customer_growth_jobs WHERE {' AND '.join(clauses)} "
                "ORDER BY region, tenant_id, workspace_id, project_id, job_id"
            ),
            tuple(args),
        ).fetchall()
        return [_row_to_entity(row) for row in rows]

    def _sql(self, sql: str) -> str:
        if self._connection.dialect.name == "postgresql":
            return sql.replace("?", "%s")
        return sql


def _add_equals(clauses: list[str], args: list[str], column: str, value: str | None) -> None:
    if value is None or not value.strip():
        return
    clauses.append(f"{column} = ?")
    args.append(value)


def _row_to_entity(row: object) -> CustomerGrowthJobEntity:
    values = row._mapping
    return CustomerGrowthJobEntity(
        id=values["id"],
        region=values["region"],
        tenant_id=values["tenant_id"],
        workspace_id=values["workspace_id"],
        project_id=values["project_id"],
        job_id=values["job_id"],
        display_name=values["display_name"],
        status=values["status"],
        owner_user_id=values["owner_user_id"],
    )
