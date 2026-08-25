import json

from pgsecurecheck.models import Finding, ScanReport, Severity
from pgsecurecheck.reporters import render_html, render_json, render_sarif


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


def test_sarif_report_contains_rule_result_and_stable_fingerprint() -> None:
    report = ScanReport(
        version="0.1.0",
        server_version="PostgreSQL 17",
        findings=[
            Finding(
                check_id="PGSC-TEST-001",
                title="Example finding",
                severity=Severity.HIGH,
                category="test",
                resource="role:example",
                evidence={"enabled": True},
                recommendation="Review the role.",
                references=["https://example.invalid/reference"],
            )
        ],
    )

    first = json.loads(render_sarif(report))
    second = json.loads(render_sarif(report))
    run = first["runs"][0]
    result = run["results"][0]

    assert first["version"] == "2.1.0"
    assert run["tool"]["driver"]["rules"][0]["id"] == "PGSC-TEST-001"
    assert result["level"] == "error"
    assert result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == ("role:example")
    assert result["partialFingerprints"] == second["runs"][0]["results"][0]["partialFingerprints"]


def test_html_report_contains_summary_and_escapes_finding_content() -> None:
    report = ScanReport(
        version="0.1.0",
        server_version="PostgreSQL <17>",
        findings=[
            Finding(
                check_id="PGSC-TEST-HTML",
                title="Unsafe <script>alert(1)</script>",
                severity=Severity.HIGH,
                category="test",
                resource="role:example&admin",
                evidence={"value": "<unsafe>"},
                recommendation="Review & remediate.",
            )
        ],
        skipped_checks={"PGSC-SKIP": "permission <denied>"},
    )

    rendered = render_html(report)

    assert "<!doctype html>" in rendered
    assert "PGSC-TEST-HTML" in rendered
    assert "PostgreSQL &lt;17&gt;" in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "<script>alert(1)</script>" not in rendered
    assert "role:example&amp;admin" in rendered
    assert "permission &lt;denied&gt;" in rendered
    assert "Yönetici özeti" in rendered
    assert "Önerilen aksiyon sırası" in rendered
    assert "Kritik ve yüksek önem seviyeli bulgular" in rendered
    assert "Atlanan kontrol" in rendered
