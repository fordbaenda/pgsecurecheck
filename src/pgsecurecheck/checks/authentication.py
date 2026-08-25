from ipaddress import ip_network

from psycopg.errors import InsufficientPrivilege

from pgsecurecheck.checks.base import Check, CheckSkipped
from pgsecurecheck.database import QueryClient
from pgsecurecheck.models import Finding, Severity


class PasswordEncryptionCheck(Check):
    id = "PGSC-AUTH-001"
    title = "SCRAM password encryption is configured"

    def run(self, database: QueryClient) -> list[Finding]:
        row = database.fetch_one("SELECT current_setting('password_encryption') AS value")
        if row["value"] == "scram-sha-256":
            return []
        return [
            Finding(
                check_id=self.id,
                title="SCRAM-SHA-256 is not the configured password encryption",
                severity=Severity.HIGH,
                category="authentication",
                evidence={"password_encryption": row["value"]},
                recommendation=(
                    "Plan client compatibility, then use scram-sha-256 for new passwords."
                ),
                references=["https://www.postgresql.org/docs/current/auth-password.html"],
            )
        ]


class HbaAuthenticationCheck(Check):
    id = "PGSC-AUTH-002"
    title = "HBA rules avoid unsafe authentication"

    def run(self, database: QueryClient) -> list[Finding]:
        try:
            rows = database.fetch_all(
                """
                SELECT line_number, type, database, user_name, address, auth_method, error
                FROM pg_hba_file_rules
                WHERE error IS NOT NULL OR auth_method IN ('trust', 'password', 'md5')
                ORDER BY line_number
                """
            )
        except InsufficientPrivilege as error:
            raise CheckSkipped("requires access to pg_hba_file_rules") from error

        findings: list[Finding] = []
        for row in rows:
            invalid = row["error"] is not None
            method = row["auth_method"]
            severity = Severity.CRITICAL if method == "trust" else Severity.HIGH
            if invalid:
                severity = Severity.HIGH
            findings.append(
                Finding(
                    check_id=self.id,
                    title="Invalid HBA rule" if invalid else f"Unsafe HBA method: {method}",
                    severity=severity,
                    category="authentication",
                    resource=f"pg_hba.conf:{row['line_number']}",
                    evidence=row,
                    recommendation=(
                        "Correct the invalid HBA entry."
                        if invalid
                        else "Use scram-sha-256 and restrict database, role, and network scope."
                    ),
                    references=[
                        "https://www.postgresql.org/docs/current/view-pg-hba-file-rules.html"
                    ],
                )
            )
        return findings


def _hba_rows(database: QueryClient) -> list[dict[str, object]]:
    try:
        return database.fetch_all(
            """
            SELECT line_number, type, database, user_name, address, auth_method, error
            FROM pg_hba_file_rules
            WHERE error IS NULL AND type <> 'local'
            ORDER BY line_number
            """
        )
    except InsufficientPrivilege as error:
        raise CheckSkipped("requires access to pg_hba_file_rules") from error


class HbaNetworkScopeCheck(Check):
    id = "PGSC-AUTH-003"
    title = "HBA network rules have restricted scope"

    def run(self, database: QueryClient) -> list[Finding]:
        findings: list[Finding] = []
        for row in _hba_rows(database):
            address = row["address"]
            overly_broad = address == "all"
            if isinstance(address, str) and "/" in address:
                try:
                    network = ip_network(address, strict=False)
                    overly_broad = network.prefixlen < (8 if network.version == 4 else 32)
                except ValueError:
                    pass
            if not overly_broad:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title="HBA rule permits an overly broad network",
                    severity=Severity.HIGH,
                    category="authentication",
                    resource=f"pg_hba.conf:{row['line_number']}",
                    evidence=row,
                    recommendation="Restrict the rule to the smallest required client network.",
                    references=["https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"],
                )
            )
        return findings


class HbaTlsRequirementCheck(Check):
    id = "PGSC-AUTH-004"
    title = "Remote HBA rules require encrypted transport"

    def run(self, database: QueryClient) -> list[Finding]:
        return [
            Finding(
                check_id=self.id,
                title="HBA rule allows an unencrypted remote connection",
                severity=Severity.HIGH,
                category="network",
                resource=f"pg_hba.conf:{row['line_number']}",
                evidence=row,
                recommendation="Use hostssl and ensure TLS is enabled on the server.",
                references=["https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"],
            )
            for row in _hba_rows(database)
            if row["type"] in {"host", "hostnossl"}
            and row["address"] not in {"127.0.0.1", "127.0.0.1/32", "::1", "::1/128"}
        ]
