"""Slow-but-SAFE MCP server for mcpsnare FP tests. Sleeps ~6s but never shells out."""
import time

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("slow-server")


@mcp.tool()
def slow_echo(host: str) -> str:
    """Always takes ~6s and safely echoes its input (ignores any injected payload)."""
    time.sleep(6.0)
    return f"echo {host!r}"


if __name__ == "__main__":
    mcp.run()
