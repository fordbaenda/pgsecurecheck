from pgsecurecheck.checks.base import Check
from pgsecurecheck.database import QueryClient
from pgsecurecheck.models import Finding, Severity


class DefaultPublicPrivilegesCheck(Check):
    id = "PGSC-PRIV-004"
    title = "Default privileges do not grant access to PUBLIC"

    def run(self, database: QueryClient) -> list[Finding]:
        rows = database.fetch_all(
            """
            SELECT
                owner.rolname AS owner_name,
                COALESCE(n.nspname, '*') AS schema_name,
                d.defaclobjtype::text AS object_type,
                array_agg(DISTINCT acl.privilege_type ORDER BY acl.privilege_type)
                    AS privileges
            FROM pg_default_acl AS d
            JOIN pg_roles AS owner ON owner.oid = d.defaclrole
            LEFT JOIN pg_namespace AS n ON n.oid = d.defaclnamespace
            CROSS JOIN LATERAL aclexplode(d.defaclacl) AS acl
            WHERE acl.grantee = 0
            GROUP BY owner.rolname, n.nspname, d.defaclobjtype
            ORDER BY owner.rolname, n.nspname, d.defaclobjtype
            """
        )
        return [
            Finding(
                check_id=self.id,
                title="Default privileges grant access to PUBLIC",
                severity=Severity.HIGH,
                category="privileges",
                resource=(
                    f"default-acl:{row['owner_name']}:{row['schema_name']}:{row['object_type']}"
                ),
                evidence={"privileges": row["privileges"]},
                recommendation="Revoke default PUBLIC access and grant it to explicit roles.",
                references=[
                    "https://www.postgresql.org/docs/current/sql-alterdefaultprivileges.html"
                ],
            )
            for row in rows
        ]


class RoleConnectionLimitCheck(Check):
    id = "PGSC-PRIV-005"
    title = "Non-administrative login roles have connection limits"

    def run(self, database: QueryClient) -> list[Finding]:
        rows = database.fetch_all(
            """
            SELECT rolname, rolconnlimit
            FROM pg_roles
            WHERE rolcanlogin AND NOT rolsuper AND rolconnlimit = -1
            ORDER BY rolname
            """
        )
        return [
            Finding(
                check_id=self.id,
                title="Login role has no connection limit",
                severity=Severity.LOW,
                category="availability",
                resource=f"role:{row['rolname']}",
                evidence={"connection_limit": row["rolconnlimit"]},
                recommendation="Set a workload-appropriate connection limit for this login role.",
            )
            for row in rows
        ]


class RlsPolicyPresenceCheck(Check):
    id = "PGSC-RLS-001"
    title = "RLS-enabled tables have explicit policies"

    def run(self, database: QueryClient) -> list[Finding]:
        rows = database.fetch_all(
            """
            SELECT n.nspname AS schema_name, c.relname AS table_name
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p')
              AND c.relrowsecurity
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND NOT EXISTS (SELECT FROM pg_policy AS p WHERE p.polrelid = c.oid)
            ORDER BY n.nspname, c.relname
            """
        )
        return [
            Finding(
                check_id=self.id,
                title="RLS is enabled but no policy exists",
                severity=Severity.MEDIUM,
                category="row_security",
                resource=f"table:{row['schema_name']}.{row['table_name']}",
                evidence={"default_deny": True},
                recommendation=(
                    "Confirm default-deny is intentional or create explicit RLS policies."
                ),
                references=["https://www.postgresql.org/docs/current/ddl-rowsecurity.html"],
            )
            for row in rows
        ]


class RlsOwnerBypassCheck(Check):
    id = "PGSC-RLS-002"
    title = "RLS enforcement accounts for table owners"

    def run(self, database: QueryClient) -> list[Finding]:
        rows = database.fetch_all(
            """
            SELECT n.nspname AS schema_name, c.relname AS table_name, owner.rolname AS owner
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            JOIN pg_roles AS owner ON owner.oid = c.relowner
            WHERE c.relkind IN ('r', 'p')
              AND c.relrowsecurity
              AND NOT c.relforcerowsecurity
              AND owner.rolcanlogin
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
            ORDER BY n.nspname, c.relname
            """
        )
        return [
            Finding(
                check_id=self.id,
                title="Login-capable table owner can bypass RLS",
                severity=Severity.MEDIUM,
                category="row_security",
                resource=f"table:{row['schema_name']}.{row['table_name']}",
                evidence={"owner": row["owner"], "force_row_security": False},
                recommendation=("Use a NOLOGIN owner role and consider FORCE ROW LEVEL SECURITY."),
                references=["https://www.postgresql.org/docs/current/ddl-rowsecurity.html"],
            )
            for row in rows
        ]
