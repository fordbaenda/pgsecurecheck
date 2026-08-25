from typing import Any

from pgsecurecheck.checks.access_control import (
    DefaultPublicPrivilegesCheck,
    RlsOwnerBypassCheck,
    RlsPolicyPresenceCheck,
    RoleConnectionLimitCheck,
)
from pgsecurecheck.checks.extensions import PgAuditCheck
from pgsecurecheck.checks.logging import (
    DebugLoggingCheck,
    ErrorStatementLoggingCheck,
    LoggingInfrastructureCheck,
)


class FakeDatabase:
    def __init__(
        self,
        *,
        one: dict[str, Any] | None = None,
        rows: list[dict[str, Any]] | None = None,
    ) -> None:
        self.one = one or {}
        self.rows = rows or []

    def fetch_one(self, query: str, params: object = None) -> dict[str, Any]:
        return self.one

    def fetch_all(self, query: str, params: object = None) -> list[dict[str, Any]]:
        return self.rows


def test_logging_infrastructure_requires_collector_for_stderr() -> None:
    database = FakeDatabase(one={"collector": "off", "destination": "stderr"})
    assert LoggingInfrastructureCheck().run(database)[0].check_id == "PGSC-LOG-003"  # type: ignore[arg-type]


def test_external_syslog_does_not_require_collector() -> None:
    database = FakeDatabase(one={"collector": "off", "destination": "syslog"})
    assert LoggingInfrastructureCheck().run(database) == []  # type: ignore[arg-type]


def test_restrictive_error_threshold_is_reported() -> None:
    database = FakeDatabase(one={"value": "fatal"})
    assert ErrorStatementLoggingCheck().run(database)[0].check_id == "PGSC-LOG-004"  # type: ignore[arg-type]


def test_enabled_debug_settings_are_reported() -> None:
    database = FakeDatabase(
        one={
            "debug_print_parse": "off",
            "debug_print_rewritten": "off",
            "debug_print_plan": "on",
        }
    )
    finding = DebugLoggingCheck().run(database)[0]  # type: ignore[arg-type]
    assert finding.evidence["enabled_settings"] == ["debug_print_plan"]


def test_missing_pgaudit_is_low_severity() -> None:
    database = FakeDatabase(one={"installed": False, "preload": ""})
    finding = PgAuditCheck().run(database)[0]  # type: ignore[arg-type]
    assert finding.severity.value == "low"


def test_inconsistent_pgaudit_is_high_severity() -> None:
    database = FakeDatabase(one={"installed": True, "preload": ""})
    finding = PgAuditCheck().run(database)[0]  # type: ignore[arg-type]
    assert finding.severity.value == "high"


def test_access_control_inventory_checks_emit_resources() -> None:
    cases = [
        (
            DefaultPublicPrivilegesCheck(),
            {
                "owner_name": "app_owner",
                "schema_name": "app",
                "object_type": "r",
                "privileges": ["SELECT"],
            },
            "default-acl:app_owner:app:r",
        ),
        (
            RoleConnectionLimitCheck(),
            {"rolname": "app", "rolconnlimit": -1},
            "role:app",
        ),
        (
            RlsPolicyPresenceCheck(),
            {"schema_name": "app", "table_name": "tenant_data"},
            "table:app.tenant_data",
        ),
        (
            RlsOwnerBypassCheck(),
            {"schema_name": "app", "table_name": "tenant_data", "owner": "app"},
            "table:app.tenant_data",
        ),
    ]
    for check, row, expected_resource in cases:
        database = FakeDatabase(rows=[row])
        assert check.run(database)[0].resource == expected_resource  # type: ignore[arg-type]
