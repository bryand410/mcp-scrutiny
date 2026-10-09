"""Collectors turn the outside world into :class:`ServerSpec` objects."""

from __future__ import annotations

from .config import KNOWN_CONFIG_PATHS, discover_configs, load_config
from .probe import ProbeError, probe_server

__all__ = [
    "KNOWN_CONFIG_PATHS",
    "ProbeError",
    "discover_configs",
    "load_config",
    "probe_server",
]
