"""Detector registry."""

from __future__ import annotations

from .base import Detector, ScanContext
from .drift import DriftDetector
from .pinning import PinningDetector
from .semantic import SemanticDetector
from .shadowing import ShadowingDetector
from .toxic_flow import ToxicFlowDetector

__all__ = [
    "ALL_DETECTORS",
    "Detector",
    "DriftDetector",
    "PinningDetector",
    "ScanContext",
    "SemanticDetector",
    "ShadowingDetector",
    "ToxicFlowDetector",
    "get_detectors",
]

#: Order matters for the report: supply chain first (it explains how a hostile
#: definition could arrive at all), then what the definition says, then what
#: the definitions do together.
ALL_DETECTORS: tuple[Detector, ...] = (
    PinningDetector(),
    DriftDetector(),
    SemanticDetector(),
    ShadowingDetector(),
    ToxicFlowDetector(),
)


def get_detectors(enable: list[str] | None = None, disable: list[str] | None = None) -> list[Detector]:
    """Resolve the detector set from ``--enable`` / ``--disable`` flags."""
    selected = list(ALL_DETECTORS)
    if enable:
        wanted = {e.strip().lower() for e in enable}
        unknown = wanted - {d.name for d in ALL_DETECTORS}
        if unknown:
            raise ValueError(f"unknown detector(s) in --enable: {', '.join(sorted(unknown))}")
        selected = [d for d in selected if d.name in wanted]
    if disable:
        unwanted = {d.strip().lower() for d in disable}
        unknown = unwanted - {d.name for d in ALL_DETECTORS}
        if unknown:
            raise ValueError(f"unknown detector(s) in --disable: {', '.join(sorted(unknown))}")
        selected = [d for d in selected if d.name not in unwanted]
    return selected
