from typing import Any

from pgsecurecheck.checks.functions import (
    SecurityDefinerPublicExecuteCheck,
    SecurityDefinerSearchPathCheck,
)
from pgsecurecheck.checks.logging import ConnectionLoggingCheck, LogIdentityCheck
from pgsecurecheck.checks.privileges import PublicTablePrivilegesCheck


class RowsDatabase:
    def __init__(
        self,
        *,
        one: dict[str, Any] | None = None,
        all_rows: list[dict[str, Any]] | None = None,
    ) -> None:
        self.one = one
        self.all_rows = all_rows or []

    def fetch_one(self, query: str, params: object = None) -> dict[str, Any]:
        assert self.one is not None
        return self.one

    def fetch_all(self, query: str, params: object = None) -> list[dict[str, Any]]:
        return self.all_rows


def test_security_definer_without_search_path_is_reported() -> None:
    database = RowsDatabase(
        all_rows=[
            {
                "oid": 1,
                "schema_name": "app",
                "function_name": "admin_action",
                "identity_arguments": "integer",
                "proconfig": None,
                "public_execute": True,
            }
        ]
    )

    search_path_findings = SecurityDefinerSearchPathCheck().run(database)  # type: ignore[arg-type]
    execute_findings = SecurityDefinerPublicExecuteCheck().run(database)  # type: ignore[arg-type]

    assert search_path_findings[0].check_id == "PGSC-FUNC-001"
    assert execute_findings[0].check_id == "PGSC-FUNC-002"


def test_security_definer_with_fixed_search_path_is_not_reported() -> None:
    database = RowsDatabase(
        all_rows=[
            {
                "oid": 1,
                "schema_name": "app",
                "function_name": "safe_action",
                "identity_arguments": "",
                "proconfig": ["search_path=app, pg_temp"],
                "public_execute": False,
            }
        ]
    )

    assert SecurityDefinerSearchPathCheck().run(database) == []  # type: ignore[arg-type]
    assert SecurityDefinerPublicExecuteCheck().run(database) == []  # type: ignore[arg-type]


def test_public_write_privilege_is_high_severity() -> None:
    database = RowsDatabase(
        all_rows=[
            {
                "schema_name": "app",
                "relation_name": "orders",
                "privileges": ["SELECT", "UPDATE"],
            }
        ]
    )

    finding = PublicTablePrivilegesCheck().run(database)[0]  # type: ignore[arg-type]
    assert finding.severity.value == "high"


def test_disabled_connection_logging_is_reported() -> None:
    database = RowsDatabase(one={"log_connections": "off", "log_disconnections": "off"})

    finding = ConnectionLoggingCheck().run(database)[0]  # type: ignore[arg-type]
    assert finding.evidence == {"log_connections": "off", "log_disconnections": "off"}


def test_log_prefix_requires_audit_identity() -> None:
    database = RowsDatabase(one={"value": "%m [%p] "})

    finding = LogIdentityCheck().run(database)[0]  # type: ignore[arg-type]
    assert finding.evidence["missing_tokens"] == ["%u", "%d"]
