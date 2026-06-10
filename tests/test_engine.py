import asyncio
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


class FetchSession:
    """Tool with a 'url' param so SSRF generates an OOB probe."""
    async def list_tools(self):
        return [ToolInfo("fetch", "", {"type": "object",
                "properties": {"url": {"type": "string"}}, "required": ["url"]})]
    async def call_tool(self, name, args):
        return "ok"


class DelayedOOB:
    """Simulates a remote interactsh-style backend: the callback for a token
    only becomes visible after the in-loop probe round-trip completes, i.e. it
    is delivered asynchronously and only surfaces on a poll that happens later.
    interactions() therefore returns empty if polled inline (before the wait)
    and a hit once the deferred poll runs."""
    def __init__(self):
        self._delivered: set[str] = set()

    def new_token(self):
        import uuid
        token = uuid.uuid4().hex[:12]
        # The callback lands only after control returns to the event loop,
        # i.e. it is NOT visible to an inline (pre-wait) poll. call_soon runs
        # before the engine resumes from its single oob_wait sleep.
        asyncio.get_running_loop().call_soon(self._delivered.add, token)
        return token, f"http://oob.test/{token}"

    def interactions(self, token):
        return [{"path": f"/{token}"}] if token in self._delivered else []


@pytest.mark.asyncio
async def test_engine_defers_oob_eval_for_delayed_callback():
    # With deferral + a single oob_wait, the delayed callback is caught.
    findings = await scan_session(FetchSession(), oob=DelayedOOB(),
                                  transport="http", oob_wait=0)
    assert any(f.check in ("ssrf", "cmd_injection") and f.confidence.value == "confirmed"
               for f in findings)


import sys
from pathlib import Path
from mcprobe.connect.session import stdio_session
import mcprobe.checks  # noqa: F401  (register checks)

_SERVER = str(Path(__file__).parent / "fixtures" / "vuln_server" / "server.py")


@pytest.mark.asyncio
async def test_scan_confirms_nested_array_enum_traversal():
    async with stdio_session([sys.executable, _SERVER]) as session:
        findings = await scan_session(session, oob=None, transport="stdio")
    confirmed = {(f.check, f.param) for f in findings if f.confidence.value == "confirmed"}
    assert ("path_traversal", "config.path") in confirmed   # nested object
    assert ("path_traversal", "paths[0]") in confirmed       # array item
    assert ("path_traversal", "path") in confirmed           # enum-gated tool (read_mode)


class CountingSession:
    """Records calibration calls and reports a benign response."""
    def __init__(self):
        self.calls = []
    async def list_tools(self):
        return [ToolInfo("echo", "", {"type": "object",
                "properties": {"text": {"type": "string"}}, "required": ["text"]})]
    async def call_tool(self, name, args):
        self.calls.append((name, dict(args)))
        return "benign output"


@pytest.mark.asyncio
async def test_engine_calibrates_once_per_tool():
    from mcprobe.engine import _CALIBRATION_CALLS
    sess = CountingSession()
    await scan_session(sess, oob=None, transport="stdio", check_ids=["info_leak"])
    calib = sess.calls[:_CALIBRATION_CALLS]
    assert len(calib) == _CALIBRATION_CALLS
    assert all(c == ("echo", {"text": "mcprobe"}) for c in calib)


@pytest.mark.asyncio
async def test_engine_populates_baseline_response_and_latency():
    captured = {}

    class SpyCheck:
        id = "spy"
        def generate(self, point, ctx):
            captured["baseline"] = ctx.baseline
            return []
        def evaluate(self, probe, response, ctx):
            return None

    from mcprobe.checks.base import REGISTRY
    REGISTRY["spy"] = SpyCheck()
    try:
        await scan_session(CountingSession(), oob=None, transport="stdio", check_ids=["spy"])
    finally:
        del REGISTRY["spy"]
    b = captured["baseline"]
    assert b is not None
    assert b.response == "benign output"
    assert b.latency >= 0.0


@pytest.mark.asyncio
async def test_engine_calibration_can_be_disabled():
    sess = CountingSession()
    await scan_session(sess, oob=None, transport="stdio", check_ids=["info_leak"], calibrate=False)
    assert len(sess.calls) == 1  # only the single info_leak probe, no calibration calls


def test_aggregate_latency_uses_min():
    from mcprobe.engine import _aggregate_latency
    assert _aggregate_latency([0.5, 0.1]) == 0.1
    assert _aggregate_latency([]) == 0.0
