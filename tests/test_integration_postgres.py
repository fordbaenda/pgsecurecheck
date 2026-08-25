import os

import pytest

from pgsecurecheck.checks import ALL_CHECKS
from pgsecurecheck.database import Database
from pgsecurecheck.engine import scan


@pytest.mark.integration
def test_insecure_lab_produces_expected_findings() -> None:
    dsn = os.environ.get("PGSECURECHECK_TEST_DSN")
    if dsn is None:
        pytest.skip("PGSECURECHECK_TEST_DSN is not configured")

    with Database(dsn) as database:
        report = scan(database, ALL_CHECKS)

    finding_ids = {finding.check_id for finding in report.findings}
    assert "PGSC-CONF-001" in finding_ids
    assert "PGSC-AUTH-001" in finding_ids
    assert "PGSC-AUTH-002" in finding_ids
    assert "PGSC-AUTH-003" in finding_ids
    assert "PGSC-AUTH-004" in finding_ids
    assert "PGSC-PRIV-001" in finding_ids
    assert "PGSC-PRIV-002" in finding_ids
    assert "PGSC-PRIV-003" in finding_ids
    assert "PGSC-PRIV-004" in finding_ids
    assert "PGSC-PRIV-005" in finding_ids
    assert "PGSC-FUNC-001" in finding_ids
    assert "PGSC-FUNC-002" in finding_ids
    assert "PGSC-LOG-001" in finding_ids
    assert "PGSC-LOG-002" in finding_ids
    assert "PGSC-LOG-003" in finding_ids
    assert "PGSC-LOG-004" in finding_ids
    assert "PGSC-LOG-005" in finding_ids
    assert "PGSC-AUDIT-001" in finding_ids
    assert "PGSC-RLS-001" in finding_ids
    assert "PGSC-RLS-002" in finding_ids
