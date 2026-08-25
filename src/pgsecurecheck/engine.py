from __future__ import annotations

from collections.abc import Iterable

from psycopg import Error as PsycopgError

from pgsecurecheck import __version__
from pgsecurecheck.checks.base import Check, CheckSkipped
from pgsecurecheck.database import QueryClient
from pgsecurecheck.models import Finding, ScanReport


def scan(database: QueryClient, checks: Iterable[Check]) -> ScanReport:
    version_row = database.fetch_one("SELECT version() AS version")
    findings: list[Finding] = []
    skipped: dict[str, str] = {}

    for check in checks:
        try:
            findings.extend(check.run(database))
        except (CheckSkipped, PsycopgError) as error:
            skipped[check.id] = str(error).strip() or error.__class__.__name__

    return ScanReport(
        version=__version__,
        server_version=version_row["version"],
        findings=findings,
        skipped_checks=skipped,
    )
