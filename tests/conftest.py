"""Shared fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_sentinel.model import LogisticModel, load_default_model
from mcp_sentinel.models import ServerSpec, ToolSpec

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def model() -> LogisticModel:
    m = load_default_model()
    if m is None:
        pytest.skip("semantic model not built; run 'mcp-sentinel train'")
    return m


@pytest.fixture
def vulnerable_config() -> Path:
    return FIXTURES / "config-vulnerable.json"


@pytest.fixture
def clean_config() -> Path:
    return FIXTURES / "config-clean.json"


@pytest.fixture
def poisoned_dump() -> Path:
    return FIXTURES / "tools-poisoned.json"


def make_tool(
    name: str,
    description: str = "",
    server: str = "test",
    schema: dict | None = None,
    annotations: dict | None = None,
) -> ToolSpec:
    return ToolSpec(
        server=server,
        name=name,
        description=description,
        input_schema=schema or {},
        annotations=annotations or {},
    )


def make_server(name: str, tools: list[ToolSpec], **kwargs) -> ServerSpec:
    server = ServerSpec(name=name, **kwargs)
    for tool in tools:
        tool.server = name
    server.tools = tools
    return server


def write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path
