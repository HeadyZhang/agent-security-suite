"""Base scanner interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Sequence, TypeVar

T = TypeVar("T", bound="ScanResult", covariant=True)


@dataclass
class ScanResult:
    """Base scan result."""
    source_file: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    name: str = "BaseScanner"

    @abstractmethod
    def scan(self, path: Path) -> Sequence[ScanResult]:
        """
        Scan the given path and return results.

        Args:
            path: Path to scan (file or directory)

        Returns:
            Sequence of scan results
        """
        pass
