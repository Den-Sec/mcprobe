from mcprobe.models import InjectionPoint
from mcprobe.checks.base import CheckContext, register, REGISTRY


def test_register_adds_to_registry():
    @register
    class Dummy:
        id = "dummy"
        def generate(self, point, ctx): return []
        def evaluate(self, probe, response, ctx): return None
    assert "dummy" in REGISTRY
    assert REGISTRY["dummy"].id == "dummy"

def test_context_holds_callables():
    ctx = CheckContext(call_tool=lambda n, a: "resp", oob=None, transport="stdio")
    assert ctx.call_tool("x", {}) == "resp"
    assert ctx.transport == "stdio"


# --- Task 6: path_traversal ---
from mcprobe.checks.path_traversal import PathTraversal


def _ctx(): return CheckContext(call_tool=lambda n, a: "", oob=None, transport="stdio")

def test_traversal_generates_payloads():
    pt = PathTraversal()
    point = InjectionPoint("read", "path", {"path": "mcprobe"}, "path")
    probes = pt.generate(point, _ctx())
    assert any("../" in p.payload for p in probes)
    assert all(p.args["path"] == p.payload for p in probes)

def test_traversal_confirmed_on_passwd_canary():
    pt = PathTraversal()
    point = InjectionPoint("read", "path", {"path": "mcprobe"}, "path")
    probe = pt.generate(point, _ctx())[0]
    f = pt.evaluate(probe, "root:x:0:0:root:/root:/bin/bash\n", _ctx())
    assert f is not None and f.confidence.value == "confirmed" and f.cwe == "CWE-22"

def test_traversal_none_on_clean_response():
    pt = PathTraversal()
    point = InjectionPoint("read", "path", {"path": "mcprobe"}, "path")
    probe = pt.generate(point, _ctx())[0]
    assert pt.evaluate(probe, "file not found", _ctx()) is None
