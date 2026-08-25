from pgsecurecheck.checks.base import Check
from pgsecurecheck.database import QueryClient
from pgsecurecheck.models import Finding, Severity


class SslEnabledCheck(Check):
    id = "PGSC-CONF-001"
    title = "TLS is enabled"

    def run(self, database: QueryClient) -> list[Finding]:
        row = database.fetch_one("SELECT current_setting('ssl') AS value")
        if row["value"] == "on":
            return []
        return [
            Finding(
                check_id=self.id,
                title="TLS is disabled",
                severity=Severity.HIGH,
                category="network",
                evidence={"ssl": row["value"]},
                recommendation="Enable TLS with ssl=on and require hostssl where appropriate.",
                references=["https://www.postgresql.org/docs/current/ssl-tcp.html"],
            )
        ]
