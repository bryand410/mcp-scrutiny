"""Read MCP client configuration files into :class:`ServerSpec` objects.

There is no single MCP config format. Every client invented its own dialect:

* Claude Desktop / Cursor / Claude Code / Windsurf use ``{"mcpServers": {...}}``
* VS Code uses ``{"servers": {...}}`` and requires an explicit ``type``
* some tools nest the block under ``mcp.servers`` or ``context.servers``

The parser therefore searches for the first mapping that looks like a server
table, rather than hard-coding one key. A config we cannot parse is an error we
report, never a silent skip: an unscanned server is an unknown server.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..models import ServerSpec

__all__ = [
    "KNOWN_CONFIG_PATHS",
    "ConfigError",
    "discover_configs",
    "load_config",
    "servers_from_mapping",
]


class ConfigError(RuntimeError):
    """Raised when a config file exists but cannot be understood."""


#: Locations the well-known clients use, in the order we prefer them.
KNOWN_CONFIG_PATHS: tuple[str, ...] = (
    # Claude Code (project + user scope)
    ".mcp.json",
    "~/.claude.json",
    # Claude Desktop
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "%APPDATA%/Claude/claude_desktop_config.json",
    # Cursor
    "~/.cursor/mcp.json",
    # VS Code (1.102+)
    "%APPDATA%/Code/User/mcp.json",
    "~/.config/Code/User/mcp.json",
    "~/Library/Application Support/Code/User/mcp.json",
    # Windsurf
    "~/.codeium/windsurf/mcp_config.json",
    # Cline
    "%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
    # Zed
    "~/.config/zed/settings.json",
)

#: Keys whose value is a table of servers.
_SERVER_TABLE_KEYS = ("mcpServers", "servers", "mcp_servers", "mcp.servers")

#: Keys that mean "this entry is a server", used to validate a candidate table.
_SERVER_KEYS = ("command", "url", "type", "transport", "args", "httpUrl")


def load_config(path: str | os.PathLike[str]) -> list[ServerSpec]:
    """Parse one config file into a list of servers.

    Raises :class:`ConfigError` if the file is missing or malformed. Both are
    worth failing loudly on: a typo in a path silently disables the scan.
    """
    p = Path(path).expanduser()
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")
    text = p.read_text(encoding="utf-8-sig")
    if p.suffix.lower() == ".toml":
        data = _load_toml(text, p)
    else:
        try:
            data = json.loads(_strip_json_comments(text))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{p}: invalid JSON at line {exc.lineno}: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{p}: top level must be an object")
    servers = servers_from_mapping(_find_server_table(data))
    if not servers:
        raise ConfigError(f"{p}: no server table found (looked for {', '.join(_SERVER_TABLE_KEYS)})")
    return servers


def discover_configs(start: str | os.PathLike[str] | None = None) -> list[Path]:
    """Return every known config path that exists on this machine.

    ``start`` adds a directory to search for project-scoped ``.mcp.json``.
    """
    found: list[Path] = []
    for raw in KNOWN_CONFIG_PATHS:
        p = Path(os.path.expandvars(raw)).expanduser()
        if p.is_file() and p not in found:
            found.append(p)
    if start:
        base = Path(start).expanduser()
        for candidate in (base / ".mcp.json", base / ".cursor" / "mcp.json"):
            if candidate.is_file() and candidate not in found:
                found.append(candidate)
    return found


def servers_from_mapping(table: dict[str, Any]) -> list[ServerSpec]:
    """Turn a ``{name: block}`` mapping into servers, skipping non-server keys."""
    servers: list[ServerSpec] = []
    for name, block in table.items():
        if not isinstance(block, dict):
            continue
        if not any(k in block for k in _SERVER_KEYS):
            # e.g. Claude Desktop's "globalShortcut" sitting next to mcpServers
            continue
        servers.append(_to_server(name, block))
    return servers


def _to_server(name: str, block: dict[str, Any]) -> ServerSpec:
    url = block.get("url") or block.get("httpUrl") or block.get("serverUrl")
    transport = str(block.get("type") or block.get("transport") or ("http" if url else "stdio"))
    command = block.get("command")
    args = block.get("args") or []
    env = block.get("env") or {}
    return ServerSpec(
        name=name,
        command=str(command) if command else None,
        args=[str(a) for a in args] if isinstance(args, list) else [],
        env={str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {},
        url=str(url) if url else None,
        transport=transport,
        raw=block,
    )


def _find_server_table(data: dict[str, Any]) -> dict[str, Any]:
    """Locate the server table in a config of unknown shape."""
    for key in _SERVER_TABLE_KEYS:
        node: Any = data
        for part in key.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if isinstance(node, dict) and any(
            isinstance(v, dict) and any(k in v for k in _SERVER_KEYS) for v in node.values()
        ):
            return node
    # Zed nests it as {"context_servers": {"name": {"command": {...}}}}
    for key in ("context_servers", "mcp"):
        node = data.get(key)
        if isinstance(node, dict):
            inner = node.get("servers") if isinstance(node.get("servers"), dict) else node
            if any(isinstance(v, dict) and any(k in v for k in _SERVER_KEYS) for v in inner.values()):
                return inner
    return {}


def _strip_json_comments(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments.

    VS Code and Zed ship JSONC configs; ``json.loads`` rejects them, and asking
    the user to strip comments by hand is not a security control.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    escaped = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _load_toml(text: str, path: Path) -> dict[str, Any]:
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError as exc:  # pragma: no cover - 3.10 only
        raise ConfigError(f"{path}: TOML configs need Python 3.11+") from exc
    try:
        return tomllib.loads(text)
    except Exception as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc


def _iter_json_lines(path: Path) -> Iterator[dict[str, Any]]:  # pragma: no cover - helper
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
