"""Detector contract and the scan context they share."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..models import Finding, ScanResult

__all__ = ["Detector", "ScanContext"]


@dataclass
class ScanContext:
    """Everything a detector may need beyond the scan result itself."""

    #: Approved snapshot to diff against, when one was supplied.
    baseline: Any = None
    #: Trained semantic model, when one is available.
    model: Any = None
    #: Probability above which a description is treated as malicious.
    semantic_threshold: float = 0.5
    #: Free-form per-detector switches (``--enable`` / ``--disable``).
    options: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Detector(Protocol):
    """A detector reads a :class:`ScanResult` and appends findings."""

    name: str

    def run(self, result: ScanResult, ctx: ScanContext) -> list[Finding]:
        ...
