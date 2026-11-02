"""mcp-scrutiny - static and semantic security scanner for MCP servers.

The scanner answers four questions about an MCP deployment:

1. Is anything here launched from a floating version? (supply chain)
2. Has any tool definition changed since it was approved? (rug pull)
3. Does any description contain instructions the model would obey? (poisoning)
4. Do the tools, combined, form a capability path no single tool should have?
   (toxic flow)
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

try:
    # The installed distribution is the only authority on the version, so read
    # it instead of repeating the number from pyproject.toml here. Keeping a
    # literal made drift inevitable: 0.1.1 was tagged and built with metadata
    # saying 0.1.1 while `--version` - and every snapshot this scanner wrote -
    # still said 0.1.0. Evidence that misnames the tool that produced it is
    # worse than no evidence.
    __version__ = _distribution_version("mcp-scrutiny")
except PackageNotFoundError:  # pragma: no cover - uninstalled source checkout
    __version__ = "0.0.0+source"

from .models import Finding, ScanResult, ServerSpec, Severity, ToolSpec

__all__ = [
    "Finding",
    "ScanResult",
    "ServerSpec",
    "Severity",
    "ToolSpec",
    "__version__",
]
