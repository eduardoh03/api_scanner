from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ScanFinding:
    module: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    recommendation: str | None = None


class BaseScanner(ABC):
    """Interface base para todos os módulos de scanning."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Nome do módulo de scanning."""
        ...

    @abstractmethod
    async def scan(self, target: str) -> list[ScanFinding]:
        """Executa o scan no target e retorna lista de findings."""
        ...
