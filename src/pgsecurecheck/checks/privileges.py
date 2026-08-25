from pgsecurecheck.checks.base import Check
from pgsecurecheck.database import QueryClient
from pgsecurecheck.models import Finding, Severity


class PrivilegedRolesCheck(Check):
    id = "PGSC-PRIV-001"
    title = "Login roles avoid excessive administrative privileges"

    def run(self, database: QueryClient) -> list[Finding]:
        rows = database.fetch_all(
            """
            SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
            FROM pg_roles
            WHERE rolcanlogin
              AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
            ORDER BY rolname
            """
        )
        return [
            Finding(
                check_id=self.id,
                title="Login role has administrative privileges",
                severity=Severity.HIGH if row["rolsuper"] else Severity.MEDIUM,
                category="privileges",
                resource=f"role:{row['rolname']}",
                evidence=row,
                recommendation="Review necessity and grant only the minimum required privileges.",
            )
            for row in rows
        ]


class PublicSchemaCreateCheck(Check):
    id = "PGSC-PRIV-002"
    title = "PUBLIC cannot create objects in the public schema"

    def run(self, database: QueryClient) -> list[Finding]:
        row = database.fetch_one(
            """
            SELECT has_schema_privilege('public', 'public', 'CREATE') AS allowed
            """
        )
        if not row["allowed"]:
            return []
        return [
            Finding(
                check_id=self.id,
                title="PUBLIC can create objects in the public schema",
                severity=Severity.MEDIUM,
                category="privileges",
                resource="schema:public",
                evidence={"create_allowed": True},
                recommendation=(
                    "Revoke CREATE on schema public from PUBLIC after compatibility review."
                ),
            )
        ]


class PublicTablePrivilegesCheck(Check):
    id = "PGSC-PRIV-003"
    title = "PUBLIC has no direct privileges on application tables"

    def run(self, database: QueryClient) -> list[Finding]:
        rows = database.fetch_all(
            """
            SELECT
                n.nspname AS schema_name,
                c.relname AS relation_name,
                array_agg(DISTINCT acl.privilege_type::text ORDER BY acl.privilege_type::text)
                    AS privileges
            FROM pg_class AS c
            JOIN pg_namespace AS n ON n.oid = c.relnamespace
            CROSS JOIN LATERAL aclexplode(
                COALESCE(c.relacl, acldefault('r', c.relowner))
            ) AS acl
            WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
              AND acl.grantee = 0
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
            GROUP BY n.nspname, c.relname
            ORDER BY n.nspname, c.relname
            """
        )
        return [
            Finding(
                check_id=self.id,
                title="PUBLIC has privileges on a relation",
                severity=(
                    Severity.HIGH
                    if any(
                        privilege in {"INSERT", "UPDATE", "DELETE", "TRUNCATE"}
                        for privilege in row["privileges"]
                    )
                    else Severity.MEDIUM
                ),
                category="privileges",
                resource=f"relation:{row['schema_name']}.{row['relation_name']}",
                evidence={"privileges": row["privileges"]},
                recommendation="Revoke PUBLIC privileges and grant access to explicit roles.",
            )
            for row in rows
        ]
