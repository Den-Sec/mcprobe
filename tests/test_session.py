import sys

import pytest

from mcprobe.connect.session import stdio_session


@pytest.mark.asyncio
async def test_stdio_session_lists_and_calls_tools():
    cmd = [sys.executable, "tests/fixtures/vuln_server/server.py"]
    async with stdio_session(cmd) as sess:
        tools = await sess.list_tools()
        names = {t.name for t in tools}
        assert {"ping", "read_doc", "whoami"} <= names
        out = await sess.call_tool("ping", {"host": "example.com"})
        assert "pinging example.com" in out
