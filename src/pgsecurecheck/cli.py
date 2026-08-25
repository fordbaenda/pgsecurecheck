from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from pgsecurecheck.checks import ALL_CHECKS
from pgsecurecheck.database import Database
from pgsecurecheck.engine import scan as run_scan
from pgsecurecheck.models import SEVERITY_RANK, Severity
from pgsecurecheck.reporters import render_console, render_html, render_json, render_sarif

app = typer.Typer(help="Read-only security posture assessment for PostgreSQL.")
console = Console(stderr=True)


class OutputFormat(str, Enum):
    CONSOLE = "console"
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"


@app.command()
def scan(
    dsn: Annotated[str, typer.Option(envvar="PGSECURECHECK_DSN", help="PostgreSQL DSN.")],
    output_format: Annotated[OutputFormat, typer.Option("--format")] = OutputFormat.CONSOLE,
    output: Annotated[Path | None, typer.Option(help="Write the report to this file.")] = None,
    fail_on: Annotated[
        Severity | None, typer.Option(help="Fail at or above this severity.")
    ] = None,
) -> None:
    """Run the configured read-only security checks."""
    try:
        with Database(dsn) as database:
            report = run_scan(database, ALL_CHECKS)
    except Exception as error:
        console.print(f"[red]Scan failed:[/red] {error}")
        raise typer.Exit(code=2) from error

    if output_format != OutputFormat.CONSOLE:
        renderers = {
            OutputFormat.JSON: render_json,
            OutputFormat.SARIF: render_sarif,
            OutputFormat.HTML: render_html,
        }
        rendered = renderers[output_format](report)
        if output:
            output.write_text(rendered + "\n", encoding="utf-8")
        else:
            typer.echo(rendered)
    else:
        render_console(report, console)

    if fail_on is not None and any(
        SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[fail_on] for finding in report.findings
    ):
        raise typer.Exit(code=1)


@app.command("checks")
def list_checks() -> None:
    """List built-in checks without connecting to a database."""
    for check in ALL_CHECKS:
        typer.echo(f"{check.id}\t{check.title}")


if __name__ == "__main__":
    app()
