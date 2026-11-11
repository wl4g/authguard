"""SQLite scenario data import and query helpers."""
from pathlib import Path
import sqlite3


class E2ESQLiteImporter:
    @staticmethod
    def import_file(connection: sqlite3.Connection, path: Path) -> None:
        connection.executescript(path.read_text(encoding="utf-8"))


class E2ESQLiteChecker:
    @staticmethod
    def query(
        connection: sqlite3.Connection, sql: str, parameters: tuple = ()
    ) -> list[tuple]:
        return connection.execute(sql, parameters).fetchall()
