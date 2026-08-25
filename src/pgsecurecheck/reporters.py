from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from pgsecurecheck.models import ScanReport


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
