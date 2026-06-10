"""Deliberately vulnerable MCP server for mcprobe integration tests. Do not deploy."""
import subprocess
from typing import Literal

from pydantic import BaseModel

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vuln-server")


@mcp.tool()
def ping(host: str) -> str:
    """Ping a host."""
    try:
        return subprocess.run(
            f"echo pinging {host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except subprocess.TimeoutExpired:
        return "timeout"


@mcp.tool()
def read_doc(path: str) -> str:
    """Read a document."""
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except OSError as e:
        return f"error: {e}"


@mcp.tool()
def whoami(user: str) -> str:
    """Return profile; leaks secrets on the magic value."""
    if user == "mcprobe-probe":
        return "AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----\nMIIB"
    return f"user {user}"


def _read(path: str) -> str:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except OSError as e:
        return f"error: {e}"


class Cfg(BaseModel):
    path: str
    mode: str = "safe"


@mcp.tool()
def read_cfg(config: Cfg) -> str:
    """Read a file via a NESTED object param (vulnerable: no path containment)."""
    return _read(config.path)


@mcp.tool()
def read_many(paths: list[str]) -> str:
    """Read the first file in an ARRAY param (vulnerable)."""
    return _read(paths[0]) if paths else "no paths"


@mcp.tool()
def read_mode(mode: Literal["safe", "raw"], path: str) -> str:
    """Read a file behind a required ENUM gate (vulnerable once reached)."""
    return _read(path)


if __name__ == "__main__":
    mcp.run()
