"""MCP server whose benign output ALWAYS contains secret-shaped strings (docs/validator
shape) - used to prove mcprobe does not false-flag info-leak. Not a real leak."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("secret-server")

# Two secret-SHAPED example strings that appear on every call, payload or not.
_EXAMPLE = "example AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----\nMIIB"


@mcp.tool()
def validate(text: str) -> str:
    """Returns documentation that always contains example-key strings (not a leak)."""
    return f"validating {text!r}; see docs: {_EXAMPLE}"


if __name__ == "__main__":
    mcp.run()
