from __future__ import annotations

from collections.abc import Sequence
from contextlib import AbstractContextManager
from typing import Any, Protocol

import psycopg
from psycopg.rows import dict_row


class QueryClient(Protocol):
    def fetch_one(self, query: str, params: Sequence[Any] | None = None) -> dict[str, Any]: ...

    def fetch_all(
        self, query: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]: ...


class Database(AbstractContextManager["Database"]):
    """Small read-only database adapter used by security checks."""

    def __init__(self, dsn: str, connect_timeout: int = 10) -> None:
        self._connection = psycopg.connect(
            dsn,
            autocommit=False,
            connect_timeout=connect_timeout,
            row_factory=dict_row,
            application_name="pgsecurecheck",
        )
        self._connection.execute("SET TRANSACTION READ ONLY")

    def fetch_one(self, query: str, params: Sequence[Any] | None = None) -> dict[str, Any]:
        with self._connection.transaction():
            with self._connection.cursor() as cursor:
                cursor.execute(query, params)
                row = cursor.fetchone()
        if row is None:
            raise RuntimeError("Query returned no rows")
        return dict(row)

    def fetch_all(self, query: str, params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        with self._connection.transaction():
            with self._connection.cursor() as cursor:
                cursor.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]

    def __exit__(self, *exc_info: object) -> None:
        self._connection.rollback()
        self._connection.close()
