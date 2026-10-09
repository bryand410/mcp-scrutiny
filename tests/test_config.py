"""Config parsing across the client dialects."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_scrutiny.collectors.config import ConfigError, load_config, servers_from_mapping


def test_parses_claude_desktop_shape(tmp_path: Path) -> None:
    path = tmp_path / "claude_desktop_config.json"
    path.write_text(
        json.dumps(
            {
                "globalShortcut": "Cmd+Space",
                "mcpServers": {
                    "fs": {"command": "npx", "args": ["-y", "pkg@1.0.0"], "env": {"A": "b"}}
                },
            }
        ),
        encoding="utf-8",
    )
    servers = load_config(path)
    assert len(servers) == 1
    assert servers[0].name == "fs"
    assert servers[0].command == "npx"
    assert servers[0].env == {"A": "b"}
    # The non-server key must not be mistaken for a server.
    assert servers[0].raw.get("command") == "npx"


def test_parses_vscode_servers_key(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text(
        json.dumps({"servers": {"web": {"type": "http", "url": "https://x.example/mcp"}}}),
        encoding="utf-8",
    )
    servers = load_config(path)
    assert servers[0].transport == "http"
    assert servers[0].url == "https://x.example/mcp"


def test_strips_jsonc_comments(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text(
        """
        {
          // the comment Zed and VS Code users write
          "servers": {
            "fs": { "command": "uvx", "args": ["pkg==1.0"] } /* trailing */
          }
        }
        """,
        encoding="utf-8",
    )
    servers = load_config(path)
    assert servers[0].command == "uvx"


def test_comment_like_text_inside_a_string_is_preserved(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text(
        json.dumps({"mcpServers": {"x": {"command": "python", "args": ["-c", "print('http://a')"]}}}),
        encoding="utf-8",
    )
    servers = load_config(path)
    assert servers[0].args == ["-c", "print('http://a')"]


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.json")


def test_invalid_json_raises_with_line(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text('{"mcpServers": {', encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid JSON"):
        load_config(path)


def test_config_without_server_table_raises(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"unrelated": {"a": 1}}), encoding="utf-8")
    with pytest.raises(ConfigError, match="no server table"):
        load_config(path)


def test_servers_from_mapping_skips_non_server_entries() -> None:
    servers = servers_from_mapping(
        {
            "globalShortcut": "Cmd+Space",
            "fs": {"command": "npx"},
            "not_a_dict": "string",
        }
    )
    assert [s.name for s in servers] == ["fs"]


def test_vulnerable_fixture_parses(vulnerable_config: Path) -> None:
    servers = {s.name: s for s in load_config(vulnerable_config)}
    assert set(servers) == {
        "filesystem",
        "postmark",
        "git",
        "containers",
        "remote-analytics",
        "legacy-vault",
    }
    assert servers["containers"].command == "docker"
    assert servers["remote-analytics"].url == "http://mcp.vendor-analytics.example.com/sse"
