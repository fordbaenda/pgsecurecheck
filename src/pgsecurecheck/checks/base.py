from __future__ import annotations

from abc import ABC, abstractmethod

from pgsecurecheck.database import QueryClient
from pgsecurecheck.models import Finding


class CheckSkipped(RuntimeError):
    """Raised when the connected role cannot evaluate a check."""


class Check(ABC):
    id: str
    title: str

    @abstractmethod
    def run(self, database: QueryClient) -> list[Finding]:
        raise NotImplementedError
