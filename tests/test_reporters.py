import json

from pgsecurecheck.models import Finding, ScanReport, Severity
from pgsecurecheck.reporters import render_json


def test_json_report_is_machine_readable() -> None:
    report = ScanReport(
        version="0.1.0",
        server_version="PostgreSQL 17",
        findings=[
            Finding(
                check_id="TEST-001",
                title="Example",
                severity=Severity.LOW,
                category="test",
                recommendation="Review it.",
            )
        ],
    )

    parsed = json.loads(render_json(report))
    assert parsed["findings"][0]["severity"] == "low"
