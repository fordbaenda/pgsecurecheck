from typing import Any

from pgsecurecheck.checks.configuration import SslEnabledCheck
from pgsecurecheck.engine import scan
from pgsecurecheck.models import Severity


class FakeDatabase:
    def fetch_one(self, query: str, params: object = None) -> dict[str, Any]:
        if "version()" in query:
            return {"version": "PostgreSQL 17.0 test"}
        if "current_setting('ssl')" in query:
            return {"value": "off"}
        raise AssertionError(query)

    def fetch_all(self, query: str, params: object = None) -> list[dict[str, Any]]:
        raise AssertionError(query)


def test_scan_reports_disabled_tls() -> None:
    report = scan(FakeDatabase(), [SslEnabledCheck()])  # type: ignore[arg-type]

    assert len(report.findings) == 1
    assert report.findings[0].check_id == "PGSC-CONF-001"
    assert report.findings[0].severity == Severity.HIGH
