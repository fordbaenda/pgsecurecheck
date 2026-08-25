from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Finding(BaseModel):
    check_id: str
    title: str
    severity: Severity
    category: str
    resource: str = "cluster"
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str
    references: list[str] = Field(default_factory=list)


class ScanReport(BaseModel):
    tool: str = "pgSecureCheck"
    version: str
    server_version: str
    findings: list[Finding]
    skipped_checks: dict[str, str] = Field(default_factory=dict)
