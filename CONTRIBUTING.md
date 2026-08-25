# Contributing

Thank you for helping improve pgSecureCheck.

1. Open an issue before large behavioral changes.
2. Keep checks read-only and deterministic.
3. Include evidence and a practical recommendation with each finding.
4. Add tests for new checks and version-specific behavior.
5. Never include real credentials or production database output in fixtures.

Run the local quality gates before submitting a pull request:

```bash
ruff check .
mypy src
pytest
```

Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not the public
issue tracker.

