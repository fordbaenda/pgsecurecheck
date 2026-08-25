from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from rich.console import Console
from rich.table import Table

from pgsecurecheck.models import ScanReport

_SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_console(report: ScanReport, console: Console) -> None:
    table = Table(title="pgSecureCheck findings")
    table.add_column("Severity")
    table.add_column("Check")
    table.add_column("Resource")
    table.add_column("Finding")
    for finding in report.findings:
        table.add_row(
            finding.severity.value.upper(),
            finding.check_id,
            finding.resource,
            finding.title,
        )
    console.print(table)
    console.print(
        f"[bold]{len(report.findings)} finding(s)[/bold], "
        f"{len(report.skipped_checks)} check(s) skipped"
    )


def render_json(report: ScanReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True)


def render_sarif(report: ScanReport) -> str:
    """Render findings as SARIF 2.1.0 for GitHub Code Scanning."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        rules.setdefault(
            finding.check_id,
            {
                "id": finding.check_id,
                "name": finding.check_id.replace("-", "_"),
                "shortDescription": {"text": finding.title},
                "help": {
                    "text": finding.recommendation,
                    "markdown": finding.recommendation,
                },
                "properties": {
                    "category": finding.category,
                    "defaultSeverity": finding.severity.value,
                    "references": finding.references,
                },
            },
        )
        fingerprint_source = f"{finding.check_id}\0{finding.resource}"
        fingerprint = sha256(fingerprint_source.encode()).hexdigest()
        results.append(
            {
                "ruleId": finding.check_id,
                "level": _SARIF_LEVELS[finding.severity.value],
                "message": {
                    "text": f"{finding.title}. {finding.recommendation}",
                },
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "fullyQualifiedName": finding.resource,
                                "kind": finding.category,
                            }
                        ]
                    }
                ],
                "partialFingerprints": {"pgSecureCheck/v1": fingerprint},
                "properties": {
                    "severity": finding.severity.value,
                    "resource": finding.resource,
                    "evidence": finding.evidence,
                },
            }
        )

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool,
                        "version": report.version,
                        "informationUri": "https://github.com/fordbaenda/pgsecurecheck",
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": "pgsecurecheck/"},
                "results": results,
                "properties": {
                    "serverVersion": report.server_version,
                    "skippedChecks": report.skipped_checks,
                },
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True)
