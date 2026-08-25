# Standalone Linux deployment

The standalone executable is the recommended distribution for customer environments.
It embeds the Python runtime and application dependencies; the target machine does not
need Python, pip, a virtual environment, or root access.

## Supported baseline

- Linux x86-64
- glibc-based distributions compatible with Ubuntu 22.04
- PostgreSQL 14 through 18

The executable may work on other glibc distributions, but they are not part of the
initial compatibility contract. Alpine Linux uses musl and is not supported by this
artifact.

## Verify the artifact

Download the executable and `SHA256SUMS` from the same GitHub release, then run:

```bash
sha256sum --check SHA256SUMS
chmod 700 pgsecurecheck-linux-amd64
./pgsecurecheck-linux-amd64 checks
```

Do not execute an artifact when checksum verification fails.

## Zero-install remote scan

Run the executable from an administration workstation or jump host with network access
to PostgreSQL:

```bash
read -rsp 'Auditor password: ' PGPASSWORD
export PGPASSWORD
export PGSECURECHECK_DSN='postgresql://pgsecurecheck_auditor@db.example:5432/appdb?sslmode=verify-full'

./pgsecurecheck-linux-amd64 scan --format json --output report.json

unset PGPASSWORD PGSECURECHECK_DSN
```

Use `sslmode=verify-full` and an appropriate CA configuration for remote production
connections. Never place a password directly in the command line.

## Temporary local execution

When PostgreSQL accepts only Unix-socket connections, copy the executable temporarily:

```bash
scp pgsecurecheck-linux-amd64 customer-host:/tmp/pgsecurecheck
ssh customer-host
chmod 700 /tmp/pgsecurecheck
/tmp/pgsecurecheck scan --dsn 'postgresql:///appdb?user=pgsecurecheck_auditor'
rm -f /tmp/pgsecurecheck
```

The executable does not install a service or write application state. Removing it
removes the scanner. Report files are written only when `--output` is explicitly used.

## Build from source

Development and release machines may build the executable with Python and PyInstaller:

```bash
python3 -m pip install ".[release]"
sh scripts/build-linux.sh
```

Build artifacts are written to `dist/`. Customer database servers should consume the
prebuilt release instead of running this build process.

