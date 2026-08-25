from __future__ import annotations

from typing import Any

from pgsecurecheck.checks.base import Check
from pgsecurecheck.database import QueryClient
from pgsecurecheck.models import Finding, Severity

_SECURITY_DEFINER_QUERY = """
    SELECT
        p.oid,
        n.nspname AS schema_name,
        p.proname AS function_name,
        pg_get_function_identity_arguments(p.oid) AS identity_arguments,
        p.proconfig,
        has_function_privilege('public', p.oid, 'EXECUTE') AS public_execute
    FROM pg_proc AS p
    JOIN pg_namespace AS n ON n.oid = p.pronamespace
    WHERE p.prosecdef
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    ORDER BY n.nspname, p.proname, p.oid
"""


def _resource(row: dict[str, Any]) -> str:
    return f"function:{row['schema_name']}.{row['function_name']}({row['identity_arguments']})"


class SecurityDefinerSearchPathCheck(Check):
    id = "PGSC-FUNC-001"
    title = "SECURITY DEFINER functions pin search_path"

    def run(self, database: QueryClient) -> list[Finding]:
        rows = database.fetch_all(_SECURITY_DEFINER_QUERY)
        findings: list[Finding] = []
        for row in rows:
            settings = row["proconfig"] or []
            search_path = next(
                (value for value in settings if value.lower().startswith("search_path=")),
                None,
            )
            if search_path is not None:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title="SECURITY DEFINER function does not pin search_path",
                    severity=Severity.HIGH,
                    category="functions",
                    resource=_resource(row),
                    evidence={"proconfig": settings},
                    recommendation=(
                        "Set a trusted search_path on the function and schema-qualify "
                        "referenced objects."
                    ),
                    references=["https://www.postgresql.org/docs/current/sql-createfunction.html"],
                )
            )
        return findings


class SecurityDefinerPublicExecuteCheck(Check):
    id = "PGSC-FUNC-002"
    title = "SECURITY DEFINER functions are not executable by PUBLIC"

    def run(self, database: QueryClient) -> list[Finding]:
        return [
            Finding(
                check_id=self.id,
                title="SECURITY DEFINER function is executable by PUBLIC",
                severity=Severity.HIGH,
                category="functions",
                resource=_resource(row),
                evidence={"public_execute": True},
                recommendation=(
                    "Revoke EXECUTE from PUBLIC and grant it only to explicitly approved roles."
                ),
                references=["https://www.postgresql.org/docs/current/sql-createfunction.html"],
            )
            for row in database.fetch_all(_SECURITY_DEFINER_QUERY)
            if row["public_execute"]
        ]
