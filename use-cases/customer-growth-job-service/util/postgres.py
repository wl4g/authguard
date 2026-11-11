"""PostgreSQL import and query helpers over an injected command executor."""
import re
from pathlib import Path
from typing import Callable


class E2EPostgresChecker:
    @staticmethod
    def command(
        sql: str,
        *,
        database_variable: str = "POSTGRES_DB",
        password_variable: str = "POSTGRES_PASSWORD",
        user: str = "postgres",
        schema: str = "public",
    ) -> tuple[str, ...]:
        for value in (schema, database_variable, password_variable, user):
            if re.fullmatch("[A-Za-z_][A-Za-z0-9_]*", value) is None:
                raise ValueError(
                    "invalid PostgreSQL identifier or environment variable"
                )
        return (
            "bash",
            "-ec",
            f'PGPASSWORD="${password_variable}" PGOPTIONS="-c search_path={schema}" psql -U {user} -d "${database_variable}" -At --set=ON_ERROR_STOP=1 --command "$1"',
            "e2e-postgres-query",
            sql,
        )

    @staticmethod
    def scalar(query: Callable[[str], str], sql: str) -> str:
        rows = query(sql).splitlines()
        if len(rows) != 1:
            raise ValueError(f"expected one PostgreSQL row, got {len(rows)}")
        return rows[0]

    @staticmethod
    def check_counts(
        query: Callable[[str], str], checks: dict[str, tuple[str, int, int | None]]
    ) -> dict[str, int]:
        sql = "SELECT " + " || '|' || ".join(
            (f"({expression})::text" for expression, _, _ in checks.values())
        )
        raw = query(sql).strip()
        try:
            values = tuple((int(value) for value in raw.split("|")))
        except ValueError as error:
            raise RuntimeError(
                "database count query returned a non-integer result"
            ) from error
        if len(values) != len(checks):
            raise RuntimeError(
                f"database count query returned {len(values)} fields, expected {len(checks)}"
            )
        observed = dict(zip(checks, values, strict=True))
        for name, (_, minimum, maximum) in checks.items():
            value = observed[name]
            if value < minimum or (maximum is not None and value > maximum):
                raise RuntimeError(
                    f"{name}: observed {value}, expected {minimum}..{(maximum if maximum is not None else 'unbounded')}"
                )
        return observed


class E2EPostgresImporter:
    @staticmethod
    def import_file(query: Callable[[str], str], path: Path) -> str:
        return query("BEGIN;\n" + path.read_text(encoding="utf-8") + "\nCOMMIT;")
