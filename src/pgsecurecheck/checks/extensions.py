from pgsecurecheck.checks.base import Check
from pgsecurecheck.database import QueryClient
from pgsecurecheck.models import Finding, Severity


class PgAuditCheck(Check):
    id = "PGSC-AUDIT-001"
    title = "pgAudit status is visible and consistent"

    def run(self, database: QueryClient) -> list[Finding]:
        row = database.fetch_one(
            """
            SELECT
                EXISTS (SELECT FROM pg_extension WHERE extname = 'pgaudit') AS installed,
                current_setting('shared_preload_libraries') AS preload
            """
        )
        preloaded = "pgaudit" in {item.strip() for item in row["preload"].split(",")}
        if row["installed"] and preloaded:
            return []
        inconsistent = row["installed"] != preloaded
        return [
            Finding(
                check_id=self.id,
                title=(
                    "pgAudit installation is inconsistent"
                    if inconsistent
                    else "pgAudit is not enabled"
                ),
                severity=Severity.HIGH if inconsistent else Severity.LOW,
                category="audit",
                evidence={"extension_installed": row["installed"], "preloaded": preloaded},
                recommendation=("Enable pgAudit when required by the organization's audit policy."),
                references=["https://github.com/pgaudit/pgaudit"],
            )
        ]
