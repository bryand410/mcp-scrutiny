"""mcp-sentinel - static and semantic security scanner for MCP servers.

The scanner answers four questions about an MCP deployment:

1. Is anything here launched from a floating version? (supply chain)
2. Has any tool definition changed since it was approved? (rug pull)
3. Does any description contain instructions the model would obey? (poisoning)
4. Do the tools, combined, form a capability path no single tool should have?
   (toxic flow)
"""

from __future__ import annotations

__version__ = "0.1.0"

from .models import Finding, ScanResult, ServerSpec, Severity, ToolSpec

__all__ = [
    "Finding",
    "ScanResult",
    "ServerSpec",
    "Severity",
    "ToolSpec",
    "__version__",
]
