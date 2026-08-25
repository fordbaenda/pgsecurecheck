from pgsecurecheck.checks.base import Check
from pgsecurecheck.database import QueryClient
from pgsecurecheck.models import Finding, Severity


class ConnectionLoggingCheck(Check):
    id = "PGSC-LOG-001"
    title = "Connection lifecycle events are logged"

    def run(self, database: QueryClient) -> list[Finding]:
        row = database.fetch_one(
            """
            SELECT
                current_setting('log_connections') AS log_connections,
                current_setting('log_disconnections') AS log_disconnections
            """
        )
        disabled = [name for name, value in row.items() if value == "off"]
        if not disabled:
            return []
        return [
            Finding(
                check_id=self.id,
                title="Connection lifecycle logging is incomplete",
                severity=Severity.MEDIUM,
                category="logging",
                evidence={name: row[name] for name in disabled},
                recommendation=(
                    "Enable log_connections and log_disconnections where policy permits."
                ),
                references=["https://www.postgresql.org/docs/current/runtime-config-logging.html"],
            )
        ]


class LogIdentityCheck(Check):
    id = "PGSC-LOG-002"
    title = "Log prefix contains timestamp, user, and database identity"

    def run(self, database: QueryClient) -> list[Finding]:
        row = database.fetch_one("SELECT current_setting('log_line_prefix') AS value")
        prefix = row["value"]
        missing = [token for token in ("%m", "%u", "%d") if token not in prefix]
        if not missing:
            return []
        return [
            Finding(
                check_id=self.id,
                title="Log prefix lacks useful audit identity fields",
                severity=Severity.MEDIUM,
                category="logging",
                evidence={"log_line_prefix": prefix, "missing_tokens": missing},
                recommendation="Include %m, %u, and %d in log_line_prefix.",
                references=["https://www.postgresql.org/docs/current/runtime-config-logging.html"],
            )
        ]


class LoggingInfrastructureCheck(Check):
    id = "PGSC-LOG-003"
    title = "File-oriented log destinations use the logging collector"

    def run(self, database: QueryClient) -> list[Finding]:
        row = database.fetch_one(
            """
            SELECT
                current_setting('logging_collector') AS collector,
                current_setting('log_destination') AS destination
            """
        )
        destinations = {item.strip() for item in row["destination"].split(",")}
        needs_collector = bool(destinations & {"stderr", "csvlog", "jsonlog"})
        if row["collector"] == "on" or not needs_collector:
            return []
        return [
            Finding(
                check_id=self.id,
                title="Logging collector is disabled for a file-oriented destination",
                severity=Severity.MEDIUM,
                category="logging",
                evidence=row,
                recommendation=(
                    "Enable logging_collector or use a managed external log destination."
                ),
                references=["https://www.postgresql.org/docs/current/runtime-config-logging.html"],
            )
        ]


class ErrorStatementLoggingCheck(Check):
    id = "PGSC-LOG-004"
    title = "Statements that cause errors are logged"

    def run(self, database: QueryClient) -> list[Finding]:
        row = database.fetch_one("SELECT current_setting('log_min_error_statement') AS value")
        if row["value"].lower() not in {"panic", "fatal"}:
            return []
        return [
            Finding(
                check_id=self.id,
                title="Error-causing statements may not be logged",
                severity=Severity.MEDIUM,
                category="logging",
                evidence=row,
                recommendation="Use ERROR or a more verbose log_min_error_statement threshold.",
                references=["https://www.postgresql.org/docs/current/runtime-config-logging.html"],
            )
        ]


class DebugLoggingCheck(Check):
    id = "PGSC-LOG-005"
    title = "Debug query-tree logging is disabled"

    def run(self, database: QueryClient) -> list[Finding]:
        row = database.fetch_one(
            """
            SELECT
                current_setting('debug_print_parse') AS debug_print_parse,
                current_setting('debug_print_rewritten') AS debug_print_rewritten,
                current_setting('debug_print_plan') AS debug_print_plan
            """
        )
        enabled = [name for name, value in row.items() if value == "on"]
        if not enabled:
            return []
        return [
            Finding(
                check_id=self.id,
                title="Debug query-tree logging is enabled",
                severity=Severity.MEDIUM,
                category="logging",
                evidence={"enabled_settings": enabled},
                recommendation="Disable debug query-tree logging outside controlled diagnostics.",
                references=["https://www.postgresql.org/docs/current/runtime-config-logging.html"],
            )
        ]
