"""Supply-chain checks on how a server is launched.

A server that runs ``npx -y @some/pkg`` has no version pinned anywhere in the
config. Whatever is published as ``latest`` at the moment the client starts is
what executes. That is the exact mechanism behind ``postmark-mcp``: a
legitimate-looking package name, one published version later, a hidden BCC.

Nothing here needs the server to be running, which is the point: these findings
are available before a single byte of untrusted code executes.
"""

from __future__ import annotations

import re

from ..models import Finding, ScanResult, ServerSpec, Severity
from .base import ScanContext

__all__ = ["PinningDetector"]

_RUNNERS = {"npx", "npx.cmd", "pnpm", "pnpm.cmd", "yarn", "bunx", "uvx", "uvx.exe", "pipx"}
_DOCKER = {"docker", "docker.exe", "podman"}
_SECRETISH_ENV = re.compile(
    r"(api[-_]?key|token|secret|password|passwd|credential|private[-_]?key|access[-_]?key)", re.I
)


class PinningDetector:
    """Flag launch specs that resolve to a moving target."""

    name = "pinning"

    def run(self, result: ScanResult, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for server in result.servers:
            findings.extend(self._check_server(server))
        return findings

    def _check_server(self, server: ServerSpec) -> list[Finding]:
        out: list[Finding] = []
        base = (server.command or "").split("/")[-1].split("\\")[-1]

        if server.url:
            out.extend(self._check_remote(server))
        elif base in _RUNNERS:
            floating = server.floating_package
            if floating:
                auto_yes = any(a in {"-y", "--yes"} for a in server.args)
                out.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.HIGH,
                        title=f"Unpinned package executed on every start: {floating}",
                        detail=(
                            f"'{server.name}' launches {floating} through {base} without a version. "
                            "The client resolves the version at start time, so any future publish "
                            "to that package name runs with your credentials. This is how "
                            "postmark-mcp (Sept 2025) reached roughly 300 organisations."
                        ),
                        server=server.name,
                        evidence={"package": floating, "runner": base, "auto_confirm": auto_yes},
                        remediation=(
                            f"Pin an exact version and an integrity hash: "
                            f"\"args\": [\"{floating}@<version>\"]"
                            + (" and drop the -y flag" if auto_yes else "")
                            + ". Re-pin deliberately, after reviewing the diff."
                        ),
                    )
                )
            if base in {"npx", "npx.cmd"} and any(a.startswith("http") for a in server.args):
                out.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.CRITICAL,
                        title="npx is executing code fetched from a URL",
                        detail=(
                            f"'{server.name}' passes a remote URL to npx. The payload is fetched at "
                            "start time and is not covered by any lockfile or registry review."
                        ),
                        server=server.name,
                        evidence={"args": server.args},
                        remediation="Install the package from the registry, pinned, instead of fetching a URL.",
                    )
                )
        elif base in _DOCKER:
            out.extend(self._check_docker(server))

        out.extend(self._check_env_hygiene(server))
        return out

    def _check_docker(self, server: ServerSpec) -> list[Finding]:
        out: list[Finding] = []
        for arg in server.args:
            if arg.startswith("-"):
                continue
            image = arg
            tag = image.rsplit("/", 1)[-1]
            if ":" not in tag or tag.endswith(":latest"):
                out.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.HIGH,
                        title=f"Container image is not pinned by digest: {image}",
                        detail=(
                            f"'{server.name}' runs '{image}'. A tag is a mutable pointer; the image "
                            "behind 'latest' today is not the image behind it tomorrow."
                        ),
                        server=server.name,
                        evidence={"image": image},
                        remediation="Pin by digest, e.g. image@sha256:<digest>, and update deliberately.",
                    )
                )
            break
        return out

    def _check_remote(self, server: ServerSpec) -> list[Finding]:
        out: list[Finding] = []
        assert server.url
        if server.url.startswith("http://"):
            out.append(
                Finding(
                    detector=self.name,
                    severity=Severity.HIGH,
                    title="Remote MCP server is contacted over plain HTTP",
                    detail=(
                        f"'{server.name}' points at {server.url}. Tool definitions travel in clear "
                        "text, so anyone on the path can rewrite the descriptions the model reads "
                        "- a rug pull that never touches your config file."
                    ),
                    server=server.name,
                    evidence={"url": server.url},
                    remediation="Use https:// and verify the server certificate.",
                )
            )
        elif not server.url.startswith("https://"):
            out.append(
                Finding(
                    detector=self.name,
                    severity=Severity.MEDIUM,
                    title=f"Remote server URL has an unexpected scheme: {server.url.split(':', 1)[0]}",
                    detail=f"'{server.name}' does not use https://. Tool definitions may not be authenticated.",
                    server=server.name,
                    evidence={"url": server.url},
                    remediation="Use an https:// endpoint.",
                )
            )
        if not any(_SECRETISH_ENV.search(k) for k in server.env):
            out.append(
                Finding(
                    detector=self.name,
                    severity=Severity.LOW,
                    title="Remote server has no credential in its config block",
                    detail=(
                        f"'{server.name}' is a remote endpoint with no token in 'env'. If the server "
                        "authenticates by network position alone, any process that reaches the URL "
                        "can list and invoke its tools."
                    ),
                    server=server.name,
                    evidence={"url": server.url, "env_keys": sorted(server.env)},
                    remediation="Require a bearer token on the server and pass it through env, not argv.",
                )
            )
        return out

    def _check_env_hygiene(self, server: ServerSpec) -> list[Finding]:
        out: list[Finding] = []
        for key, value in server.env.items():
            if not _SECRETISH_ENV.search(key):
                continue
            if value and not _looks_like_placeholder(value):
                out.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.LOW,
                        title=f"Long-lived credential stored in the MCP config: {key}",
                        detail=(
                            f"'{server.name}' carries {key} inline. Config files are copied between "
                            "machines, synced to dotfile repos and read by every process that can "
                            "open the file. GitGuardian's 2026 report found internal repositories are "
                            "six times more likely than public ones to hold a hardcoded secret."
                        ),
                        server=server.name,
                        evidence={"env_key": key, "value_length": len(value)},
                        remediation=(
                            "Keep the secret in the OS keychain or a secret manager and inject it at "
                            "launch time; give it the narrowest scope and a rotation date."
                        ),
                    )
                )
        for arg in server.args:
            if _SECRETISH_ENV.search(arg) and "=" in arg:
                out.append(
                    Finding(
                        detector=self.name,
                        severity=Severity.MEDIUM,
                        title="Credential passed on the command line",
                        detail=(
                            f"'{server.name}' passes a secret as an argument. Arguments are visible "
                            "in the process table to every user on the machine."
                        ),
                        server=server.name,
                        evidence={"arg_prefix": arg.split("=", 1)[0]},
                        remediation="Move the value into the server's env block, or better, into the keychain.",
                    )
                )
        return out


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in ("${", "$(", "<", "your_", "changeme", "xxx", "redacted", "placeholder", "env:")
    )
