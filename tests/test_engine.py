import pytest
from mcprobe.models import ToolInfo
from mcprobe.engine import scan_session
import mcprobe.checks  # register checks

class FakeSession:
    async def list_tools(self):
        return [ToolInfo("read_doc", "", {"type": "object",
                "properties": {"path": {"type": "string"}}, "required": ["path"]})]
    async def call_tool(self, name, args):
        if "etc/passwd" in args.get("path", ""):
            return "root:x:0:0:root:/root:/bin/bash"
        return "ok"

@pytest.mark.asyncio
async def test_engine_confirms_traversal_end_to_end():
    findings = await scan_session(FakeSession(), oob=None, transport="stdio")
    assert any(f.check == "path_traversal" and f.confidence.value == "confirmed"
               for f in findings)
