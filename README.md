# pgSecureCheck

Read-only security posture assessment for PostgreSQL.

> **Status:** early alpha. Findings are decision support, not proof of compliance.

pgSecureCheck connects to a PostgreSQL database, evaluates security-relevant
configuration and privileges, and emits evidence-backed findings. It never applies
remediation or intentionally reads application table data.

## Customer deployment

The recommended customer artifact is a single standalone Linux executable. It requires
no Python, pip, virtual environment, package installation, or root access on the target
machine:

```bash
sha256sum --check SHA256SUMS
chmod 700 pgsecurecheck-linux-amd64
./pgsecurecheck-linux-amd64 scan --dsn "$PGSECURECHECK_DSN"
```

Prefer running it remotely from an administration or jump host. See the
[standalone Linux deployment guide](docs/standalone-linux.md).

## Current checks

| Check ID | Description |
| --- | --- |
| `PGSC-CONF-001` | TLS is enabled |
| `PGSC-AUTH-001` | SCRAM-SHA-256 is configured for new passwords |
| `PGSC-AUTH-002` | HBA rules avoid invalid or unsafe authentication methods |
| `PGSC-AUTH-003` | HBA network rules have restricted scope |
| `PGSC-AUTH-004` | Remote HBA rules require encrypted transport |
| `PGSC-PRIV-001` | Login roles avoid excessive administrative privileges |
| `PGSC-PRIV-002` | `PUBLIC` cannot create objects in the `public` schema |
| `PGSC-PRIV-003` | `PUBLIC` has no direct application relation privileges |
| `PGSC-PRIV-004` | Default privileges do not grant access to `PUBLIC` |
| `PGSC-PRIV-005` | Non-administrative login roles have connection limits |
| `PGSC-FUNC-001` | `SECURITY DEFINER` functions pin `search_path` |
| `PGSC-FUNC-002` | `SECURITY DEFINER` functions are not executable by `PUBLIC` |
| `PGSC-LOG-001` | Connection lifecycle events are logged |
| `PGSC-LOG-002` | Log prefix contains timestamp, user, and database identity |
| `PGSC-LOG-003` | File-oriented logs use the logging collector |
| `PGSC-LOG-004` | Statements that cause errors are logged |
| `PGSC-LOG-005` | Debug query-tree logging is disabled |
| `PGSC-AUDIT-001` | pgAudit installation and preload status are consistent |
| `PGSC-RLS-001` | RLS-enabled tables have explicit policies |
| `PGSC-RLS-002` | Login-capable table owners do not silently bypass RLS |

## Install for development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

On PowerShell, activate the environment with `.venv\Scripts\Activate.ps1`.

## Usage

Prefer an environment variable over placing credentials in shell history:

```bash
export PGSECURECHECK_DSN='postgresql://auditor@localhost/postgres'
pgsecurecheck scan
```

Generate JSON for CI and fail when a high or critical finding exists:

```bash
pgsecurecheck scan --format json --output report.json --fail-on high
```

Generate SARIF for GitHub Code Scanning:

```bash
pgsecurecheck scan --format sarif --output pgsecurecheck.sarif --fail-on high
```

See the [GitHub Code Scanning integration guide](docs/github-code-scanning.md).

Generate a self-contained HTML report for review or PDF printing:

```bash
pgsecurecheck scan --format html --output pgsecurecheck-report.html
```

List checks without connecting:

```bash
pgsecurecheck checks
```

Exit codes are `0` for success, `1` when `--fail-on` is reached, and `2` when the
scan cannot run.

## Permissions

Use a dedicated, non-superuser login. Most checks use ordinary catalog visibility.
Reading `pg_hba_file_rules` normally requires elevated access; when access is absent,
that check is reported as skipped instead of producing a false pass.

Do not grant broad privileges solely to make every check pass. A future release will
include more version-aware privilege guidance. A minimal role script for the current
checks is available at [`sql/create_auditor.sql`](sql/create_auditor.sql).

Create the auditor in the database you want to assess:

```bash
sudo -u postgres psql --dbname appdb --file sql/create_auditor.sql
sudo -u postgres psql --dbname appdb --command '\password pgsecurecheck_auditor'
```

Then scan with that role:

```bash
export PGSECURECHECK_DSN='postgresql://pgsecurecheck_auditor@localhost:5432/appdb'
pgsecurecheck scan
```

## Safety model

- The connection starts a read-only transaction.
- Every scan rolls back before closing.
- Application table contents are outside the scope of the scanner.
- Credentials are not included in reports.
- No telemetry is collected.
- pgSecureCheck does not modify PostgreSQL configuration or privileges.

## Development

```bash
ruff check .
mypy src
pytest
```

### PostgreSQL integration lab

The repository includes an intentionally insecure PostgreSQL instance. It binds only
to loopback on port `55432`; never expose it to another network.

```bash
docker compose up -d --wait
export PGSECURECHECK_TEST_DSN='postgresql://postgres@localhost:55432/pgsecurecheck_lab'
pytest -m integration
pgsecurecheck scan --dsn "$PGSECURECHECK_TEST_DSN"
docker compose down --volumes
```

The lab deliberately disables TLS, uses `trust` host authentication, configures MD5
password encryption, grants `PUBLIC` schema creation, and creates an over-privileged
login. It also adds unsafe table privileges and a deliberately unsafe
`SECURITY DEFINER` function. Its purpose is to prove that each initial check produces
a finding.

## Roadmap

- Expand privilege, RLS, logging, extension, and `SECURITY DEFINER` checks
- Add PostgreSQL 14–18 integration tests
- Add configurable policies, suppressions, and baselines
- Publish signed Python packages and container images

## License

Apache License 2.0. See [LICENSE](LICENSE).
