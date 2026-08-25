# GitHub Code Scanning integration

pgSecureCheck can emit SARIF 2.1.0 so PostgreSQL findings appear in a repository's
Security tab. The scan still connects directly to PostgreSQL; GitHub does not receive
database credentials.

Store the complete connection string as an Actions secret named
`PGSECURECHECK_DSN`. Prefer a dedicated auditor role, TLS verification, and a
self-hosted runner or private network path when the database is not publicly reachable.

```yaml
name: PostgreSQL security posture

on:
  workflow_dispatch:
  schedule:
    - cron: "17 3 * * 1"

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - name: Run pgSecureCheck
        env:
          PGSECURECHECK_DSN: ${{ secrets.PGSECURECHECK_DSN }}
        run: >-
          ./pgsecurecheck-linux-amd64 scan
          --format sarif
          --output pgsecurecheck.sarif
          --fail-on high
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: pgsecurecheck.sarif
```

`if: always()` uploads the report even when `--fail-on` returns exit code 1. Do not
print the DSN, place it in command-line arguments, or upload it as an artifact.

SARIF results use database resources such as `role:app_user` and
`table:public.accounts` as logical locations. Stable fingerprints allow GitHub to
track the same finding across subsequent scans.

