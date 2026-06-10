# mcprobe v1.1 M2 - False-Positive Elimination Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the integrity of mcprobe's "confirmed / zero-FP" positioning by calibrating a per-tool baseline (latency + benign response) and feeding it to the time-based and info-leak oracles, so a slow-but-safe tool no longer false-fires the timing oracle and a tool whose normal output always contains secret-shaped strings is no longer flagged as a leak.

**Architecture:** The engine owns IO, so it performs calibration: before probing each tool it issues N benign control calls (schema-valid baseline args) and records the median latency + first response into a `ToolBaseline`, exposed to checks via a new `CheckContext.baseline` field. The cmd-injection time oracle fires only when `elapsed >= max(baseline.latency + sleep*0.8, baseline.latency*N)` instead of a fixed 5s. The info-leak oracle reports a secret-shaped match only when it appears in the probe response but NOT in the benign baseline response (FIRM on a triggered diff; TENTATIVE pattern-only when no baseline is available; suppressed entirely when the secret is also in the baseline).

**Tech Stack:** Python 3.11+, official `mcp` SDK (FastMCP for fixtures), pytest + pytest-asyncio (`asyncio_mode=auto`). Pure-core/async-edge split preserved: oracles (check `evaluate`) stay pure and consume `ctx.baseline`; calibration IO lives at the engine edge.

**Covers PRD v1.1 requirements:** R-B1 (per-tool baseline calibration), R-B2 (time-based oracle uses baseline), R-B3 (info-leak baseline diff + confidence downgrade). Success metric M-NoFP. (R-B4 auth-bypass robust oracle is P1 / M6 - explicitly OUT of M2.)

---

## Execution notes (read before starting)

- **Run tests with the project venv** (system Python lacks `pytest-asyncio`):
  `.venv/Scripts/python.exe -m pytest -q`
- **Commit author:** `Dennis Sepede <dennisepede@proton.me>`. **No trailer.** Use:
  `git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "..."`
- **Branch:** `main` (working copy `C:\Users\Dennis\dev\mcprobe`). Commit after each task.
- **Baseline before starting:** 62 tests pass (M1 complete and pushed).
- **Backward-compat contracts that must stay true:**
  - `CheckContext` is constructed by keyword everywhere; adding `baseline=None` as the LAST field keeps positional/keyword callers working.
  - `cmd_injection` time oracle with NO baseline (`ctx.baseline is None`) must keep the v1 fixed-threshold behavior so `test_cmdi_firm_on_time_delay` (elapsed 6.0 ≥ threshold 5) still FIRMs.
  - `info_leak` with NO baseline must keep "≥2 markers → finding" so `test_info_leak_needs_two_markers` stays green (it asserts a finding + CWE-200 but NOT the confidence level, so a downgrade to TENTATIVE is allowed).
- **Decision (user-approved):** M-NoFP is proven with REAL integration fixtures (a tool that genuinely sleeps ~6s, a tool that always returns secret-shaped strings), even though the slow one adds ~20-25s. The slow test is marked `@pytest.mark.slow` so `-m "not slow"` can skip it, but it runs by default. Each lives in its OWN minimal fixture server so its cost/findings don't bleed into other tools.

---

## File Structure

| File | Responsibility | Action |
|------|----------------|--------|
| `mcprobe/models.py` | Add `ToolBaseline` dataclass (`latency: float`, `response: str`). | **Modify** |
| `mcprobe/checks/base.py` | `CheckContext` gains `baseline: ToolBaseline | None = None`. | **Modify** |
| `mcprobe/engine.py` | Per-tool calibration: `_calibrate()` helper + set `ctx.baseline` before probing each tool; new `calibrate=True` param. | **Modify** |
| `mcprobe/checks/cmd_injection.py` | Time oracle uses `ctx.baseline` (relative margin) instead of fixed 5s. | **Modify** |
| `mcprobe/checks/info_leak.py` | Baseline-diff oracle: FIRM on triggered diff, TENTATIVE pattern-only, suppressed if in baseline. | **Modify** |
| `tests/fixtures/slow_server/__init__.py`, `server.py` | Minimal FastMCP server with one slow-but-safe tool (genuine ~6s sleep). | **Create** |
| `tests/fixtures/secret_server/__init__.py`, `server.py` | Minimal FastMCP server with one tool whose output always contains secret-shaped strings. | **Create** |
| `pyproject.toml` | Register the `slow` pytest marker. | **Modify** |
| `tests/test_models.py`, `tests/test_checks.py`, `tests/test_engine.py` | Unit + integration tests. | **Modify** |

---

## Task 1: ToolBaseline model + CheckContext.baseline field

**Files:**
- Modify: `mcprobe/models.py` (add `ToolBaseline`)
- Modify: `mcprobe/checks/base.py` (add `baseline` field + import)
- Test: `tests/test_models.py`, `tests/test_checks.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_models.py`:

```python
def test_tool_baseline_holds_latency_and_response():
    from mcprobe.models import ToolBaseline
    b = ToolBaseline(latency=0.42, response="hello")
    assert b.latency == 0.42
    assert b.response == "hello"
```

Append to `tests/test_checks.py`:

```python
def test_check_context_baseline_defaults_none_and_accepts_value():
    from mcprobe.checks.base import CheckContext
    from mcprobe.models import ToolBaseline
    ctx = CheckContext(oob=None, transport="stdio")
    assert ctx.baseline is None
    ctx2 = CheckContext(oob=None, transport="stdio", baseline=ToolBaseline(latency=1.0, response="r"))
    assert ctx2.baseline.latency == 1.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_models.py::test_tool_baseline_holds_latency_and_response tests/test_checks.py::test_check_context_baseline_defaults_none_and_accepts_value -q`
Expected: FAIL (`ImportError: cannot import name 'ToolBaseline'`; `TypeError` for unexpected `baseline` kwarg)

- [ ] **Step 3: Add the ToolBaseline dataclass**

In `mcprobe/models.py`, add after the `ToolInfo` dataclass (keep existing dataclasses unchanged):

```python
@dataclass
class ToolBaseline:
    latency: float
    response: str
```

- [ ] **Step 4: Add the baseline field to CheckContext**

In `mcprobe/checks/base.py`, update the import line and the `CheckContext` dataclass. The current top of the file is:

```python
from dataclasses import dataclass
from typing import Callable, Protocol
from mcprobe.models import InjectionPoint, Probe, Finding
```

Change the import to also bring in `ToolBaseline`:

```python
from dataclasses import dataclass
from typing import Callable, Protocol
from mcprobe.models import InjectionPoint, Probe, Finding, ToolBaseline
```

Change the `CheckContext` dataclass from:

```python
@dataclass
class CheckContext:
    oob: object | None
    transport: str
    call_tool: Callable[[str, dict], str] | None = None
    call_tool_unauth: Callable[[str, dict], str] | None = None
```

to (add `baseline` as the LAST field so positional/keyword callers stay compatible):

```python
@dataclass
class CheckContext:
    oob: object | None
    transport: str
    call_tool: Callable[[str, dict], str] | None = None
    call_tool_unauth: Callable[[str, dict], str] | None = None
    baseline: ToolBaseline | None = None
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_models.py tests/test_checks.py -q`
Expected: PASS

- [ ] **Step 6: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (was 62; expect 64)

- [ ] **Step 7: Commit**

```bash
git add mcprobe/models.py mcprobe/checks/base.py tests/test_models.py tests/test_checks.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(models): add ToolBaseline + CheckContext.baseline field"
```

---

## Task 2: Per-tool calibration in the engine (R-B1)

**Files:**
- Modify: `mcprobe/engine.py` (add `_calibrate` + wire `ctx.baseline` per tool; add `calibrate` param)
- Test: `tests/test_engine.py`

> The current `engine.py` builds `ctx` once, lists tools, and for each tool iterates `injection_points(tool)` → checks → probes. This task computes `injection_points(tool)` ONCE per tool, calibrates (when `calibrate` is True and the tool has injection points), and stores the result on `ctx.baseline` before the per-point loop. Calibration uses `build_baseline(tool.input_schema)` as benign args - the same schema-valid baseline the injection points share - and records the median latency over `_CALIBRATION_CALLS` (2) calls plus the first response text.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_engine.py`:

```python
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
    # the first _CALIBRATION_CALLS calls are the benign baseline (text="mcprobe")
    calib = sess.calls[:_CALIBRATION_CALLS]
    assert len(calib) == _CALIBRATION_CALLS
    assert all(c == ("echo", {"text": "mcprobe"}) for c in calib)


@pytest.mark.asyncio
async def test_engine_populates_baseline_response_and_latency():
    from mcprobe.checks.base import CheckContext
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
    # info_leak sends exactly one probe; with calibration off there are no extra benign calls
    assert len(sess.calls) == 1  # only the single info_leak probe, no calibration calls
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_engine.py -k "calibrat or baseline_response" -q`
Expected: FAIL (`ImportError: cannot import name '_CALIBRATION_CALLS'`; baseline is None; calibration calls present even when disabled)

- [ ] **Step 3: Rewrite the engine with calibration**

Replace the entire contents of `mcprobe/engine.py` with:

```python
import asyncio
import statistics
import time
from mcprobe.inject.mapper import injection_points, build_baseline
from mcprobe.checks.base import REGISTRY, CheckContext
from mcprobe.models import ToolBaseline

_CALIBRATION_CALLS = 2


async def _calibrate(session, tool):
    """Issue benign control calls to learn this tool's baseline latency + response.

    Uses the schema-valid baseline args (no payloads). Returns a ToolBaseline with
    the median latency over _CALIBRATION_CALLS calls and the first response text.
    """
    args = build_baseline(tool.input_schema)
    latencies, response = [], ""
    for i in range(_CALIBRATION_CALLS):
        start = time.monotonic()
        try:
            r = await session.call_tool(tool.name, args)
        except Exception as e:
            r = f"error: {e}"
        latencies.append(time.monotonic() - start)
        if i == 0:
            response = r
    return ToolBaseline(latency=statistics.median(latencies), response=response)


async def scan_session(session, oob=None, transport="stdio", call_tool_unauth=None,
                       check_ids=None, oob_wait=2.0, calibrate=True):
    ctx = CheckContext(oob=oob, transport=transport,
                       call_tool_unauth=call_tool_unauth)
    tools = await session.list_tools()
    checks = [c for cid, c in REGISTRY.items() if not check_ids or cid in check_ids]
    findings, seen = [], set()

    def collect(finding):
        if not finding:
            return
        key = (finding.check, finding.tool, finding.param)
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    deferred = []
    for tool in tools:
        points = injection_points(tool)
        ctx.baseline = await _calibrate(session, tool) if (calibrate and points) else None
        for point in points:
            for check in checks:
                for probe in check.generate(point, ctx):
                    start = time.monotonic()
                    try:
                        resp = await session.call_tool(tool.name, probe.args)
                    except Exception as e:
                        resp = f"error: {e}"
                    probe.meta["elapsed"] = time.monotonic() - start
                    if probe.token and oob is not None:
                        # Remote OOB callbacks may arrive later; defer evaluation.
                        deferred.append((check, probe, resp))
                    else:
                        collect(check.evaluate(probe, resp, ctx))

    if deferred:
        await asyncio.sleep(oob_wait)
        for check, probe, resp in deferred:
            collect(check.evaluate(probe, resp, ctx))
    return findings
```

(Note: only token-bearing probes are deferred, and their checks - cmd-injection OOB, ssrf - evaluate via `ctx.oob`, never `ctx.baseline`; so the per-tool `ctx.baseline` being overwritten by later tools before the deferred pass is harmless. The baseline-consuming oracles - time-based cmd-injection, info-leak - are non-token and evaluate inline while `ctx.baseline` is the current tool's.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_engine.py -q`
Expected: PASS (the new calibration tests + the existing engine tests, which tolerate the extra benign calls)

- [ ] **Step 5: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (was 64; expect 67). Existing FakeSessions all accept arbitrary `call_tool` args, so calibration adds benign calls without new findings.

- [ ] **Step 6: Commit**

```bash
git add mcprobe/engine.py tests/test_engine.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(engine): per-tool baseline calibration (latency + response)"
```

---

## Task 3: Time-based oracle uses the baseline (R-B2)

**Files:**
- Modify: `mcprobe/checks/cmd_injection.py` (the time-based branch of `evaluate` + a module constant)
- Test: `tests/test_checks.py`

> The current time branch fires on `elapsed >= probe.meta["threshold"]` (fixed 5s). Replace with a baseline-relative margin: `max(baseline.latency + sleep*0.8, baseline.latency*_LATENCY_MULT)`. With no baseline, fall back to the fixed threshold (preserves v1 behavior and the existing test).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_checks.py`:

```python
def _ctx_with_baseline(latency, response=""):
    from mcprobe.checks.base import CheckContext
    from mcprobe.models import ToolBaseline
    return CheckContext(oob=None, transport="stdio",
                        baseline=ToolBaseline(latency=latency, response=response))


def test_cmdi_no_time_fp_on_slow_safe_tool():
    # Tool whose baseline latency is ~6s; the sleep probe also returns in ~6s (it
    # ignored the payload). A fixed-5s oracle would FALSE-fire; the relative one must not.
    c = CmdInjection()
    point = InjectionPoint("slow", "host", {"host": "mcprobe"}, "host")
    ctx = _ctx_with_baseline(6.0)
    time_probe = [p for p in c.generate(point, ctx) if "sleep" in p.payload][0]
    time_probe.meta["elapsed"] = 6.1
    assert c.evaluate(time_probe, "", ctx) is None


def test_cmdi_firm_when_delay_exceeds_baseline_margin():
    # Baseline ~0.1s; under the sleep payload it takes 5.1s -> a real injected delay.
    c = CmdInjection()
    point = InjectionPoint("ping", "host", {"host": "mcprobe"}, "host")
    ctx = _ctx_with_baseline(0.1)
    time_probe = [p for p in c.generate(point, ctx) if "sleep" in p.payload][0]
    time_probe.meta["elapsed"] = 5.1
    f = c.evaluate(time_probe, "", ctx)
    assert f is not None and f.confidence.value == "firm"
```

(The existing `test_cmdi_firm_on_time_delay` uses `_ctx()` which has no baseline and elapsed 6.0 ≥ threshold 5 → must still FIRM.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_checks.py -k cmdi -q`
Expected: FAIL on `test_cmdi_no_time_fp_on_slow_safe_tool` (current fixed-5s oracle fires at elapsed 6.1)

- [ ] **Step 3: Update the time-based oracle**

In `mcprobe/checks/cmd_injection.py`, add a module constant near the top (after `_SLEEP_SECONDS = 5`):

```python
_LATENCY_MULT = 3
```

Replace the `evaluate` method. The current one is:

```python
    def evaluate(self, probe, response, ctx):
        if probe.token and ctx.oob and ctx.oob.interactions(probe.token):
            return self._finding(probe, Confidence.CONFIRMED, "OOB callback received")
        if probe.meta.get("time_based") and probe.meta.get("elapsed", 0) >= probe.meta["threshold"]:
            return self._finding(probe, Confidence.FIRM,
                                 f"response delayed {probe.meta['elapsed']:.1f}s")
        return None
```

Replace it with:

```python
    def evaluate(self, probe, response, ctx):
        if probe.token and ctx.oob and ctx.oob.interactions(probe.token):
            return self._finding(probe, Confidence.CONFIRMED, "OOB callback received")
        if probe.meta.get("time_based"):
            elapsed = probe.meta.get("elapsed", 0)
            sleep_s = probe.meta["threshold"]
            baseline = getattr(ctx, "baseline", None)
            if baseline is not None:
                margin = max(baseline.latency + sleep_s * 0.8, baseline.latency * _LATENCY_MULT)
                evidence = f"response delayed {elapsed:.1f}s vs baseline {baseline.latency:.1f}s"
            else:
                margin = sleep_s  # no calibration: fall back to the fixed threshold
                evidence = f"response delayed {elapsed:.1f}s"
            if elapsed >= margin:
                return self._finding(probe, Confidence.FIRM, evidence)
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_checks.py -k cmdi -q`
Expected: PASS (new FP + delay tests, and the existing no-baseline FIRM test)

- [ ] **Step 5: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (was 67; expect 69)

- [ ] **Step 6: Commit**

```bash
git add mcprobe/checks/cmd_injection.py tests/test_checks.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(checks): time-based oracle uses calibrated baseline (no fixed-5s FP)"
```

---

## Task 4: info-leak baseline diff + confidence downgrade (R-B3)

**Files:**
- Modify: `mcprobe/checks/info_leak.py` (`evaluate` + a `_finding` helper)
- Test: `tests/test_checks.py`

> A secret-shaped match is reported only if it appears in the probe response but NOT in the benign baseline response. With a baseline: a triggered diff → FIRM; same secrets in baseline → suppressed (None). Without a baseline (calibration off): pattern-only, keep the v1 "≥2 markers" heuristic but downgrade to TENTATIVE.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_checks.py`:

```python
def test_info_leak_suppressed_when_secret_in_baseline():
    # docs/validator tool: the same secret-shaped strings are in the benign baseline,
    # so the input did NOT trigger them -> not a leak.
    il = InfoLeak()
    point = InjectionPoint("docs", "q", {"q": "mcprobe"}, "q")
    secrets = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----"
    ctx = _ctx_with_baseline(0.1, response=secrets)
    probe = il.generate(point, ctx)[0]
    assert il.evaluate(probe, secrets, ctx) is None


def test_info_leak_firm_on_triggered_diff():
    il = InfoLeak()
    point = InjectionPoint("lookup", "q", {"q": "mcprobe"}, "q")
    ctx = _ctx_with_baseline(0.1, response="nothing secret here")
    probe = il.generate(point, ctx)[0]
    leaked = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----"
    f = il.evaluate(probe, leaked, ctx)
    assert f is not None and f.confidence.value == "firm" and f.cwe == "CWE-200"


def test_info_leak_tentative_pattern_only_without_baseline():
    il = InfoLeak()
    point = InjectionPoint("lookup", "q", {"q": "mcprobe"}, "q")
    two = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN PRIVATE KEY-----"
    f = il.evaluate(il.generate(point, _ctx())[0], two, _ctx())
    assert f is not None and f.confidence.value == "tentative"
```

(The existing `test_info_leak_needs_two_markers` uses `_ctx()` (no baseline): one marker → None, two markers → finding with CWE-200. It does NOT assert confidence, so the TENTATIVE downgrade keeps it green.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_checks.py -k info_leak -q`
Expected: FAIL (current oracle fires FIRM on ≥2 markers regardless of baseline; suppression/TENTATIVE not implemented)

- [ ] **Step 3: Rewrite the info-leak oracle**

In `mcprobe/checks/info_leak.py`, replace the `evaluate` method. The current one is:

```python
    def evaluate(self, probe, response, ctx):
        hits = [m.pattern for m in _MARKERS if m.search(response or "")]
        if len(hits) >= 2:
            return Finding(check=self.id, tool=probe.point.tool, param=probe.point.param_name,
                           severity=Severity.HIGH, confidence=Confidence.FIRM, cwe="CWE-200",
                           title=f"Secret/info leak via {probe.point.tool}",
                           payload=probe.payload, evidence=f"matched: {hits}",
                           remediation="Never return secrets/credentials in tool output or errors.")
        return None
```

Replace it with:

```python
    def evaluate(self, probe, response, ctx):
        hits = [m.pattern for m in _MARKERS if m.search(response or "")]
        if not hits:
            return None
        baseline = getattr(ctx, "baseline", None)
        if baseline is not None:
            base_hits = {m.pattern for m in _MARKERS if m.search(baseline.response or "")}
            triggered = [h for h in hits if h not in base_hits]
            if not triggered:
                return None  # secrets also present in benign baseline = normal output, not a leak
            return self._finding(probe, Confidence.FIRM,
                                 f"secret-shaped match triggered by input (absent in baseline): {triggered}")
        if len(hits) >= 2:
            return self._finding(probe, Confidence.TENTATIVE,
                                 f"secret-shaped pattern match (no baseline to diff): {hits}")
        return None

    def _finding(self, probe, conf, evidence):
        return Finding(check=self.id, tool=probe.point.tool, param=probe.point.param_name,
                       severity=Severity.HIGH, confidence=conf, cwe="CWE-200",
                       title=f"Secret/info leak via {probe.point.tool}",
                       payload=probe.payload, evidence=evidence,
                       remediation="Never return secrets/credentials in tool output or errors.")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_checks.py -k info_leak -q`
Expected: PASS (suppression, FIRM-diff, TENTATIVE-no-baseline, and the existing ≥2-markers test)

- [ ] **Step 5: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (was 69; expect 72)

- [ ] **Step 6: Commit**

```bash
git add mcprobe/checks/info_leak.py tests/test_checks.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(checks): info-leak baseline diff (FIRM on trigger, TENTATIVE pattern-only)"
```

---

## Task 5: Real M-NoFP integration fixtures + e2e

**Files:**
- Create: `tests/fixtures/slow_server/__init__.py` (empty), `tests/fixtures/slow_server/server.py`
- Create: `tests/fixtures/secret_server/__init__.py` (empty), `tests/fixtures/secret_server/server.py`
- Modify: `pyproject.toml` (register `slow` marker)
- Modify: `tests/test_engine.py` (two e2e tests)

> Each tool lives in its OWN minimal server so the scan calibrates/probes only that one tool - isolating cost and keeping the "zero findings" assertion clean (the shared vuln_server has tools that legitimately leak/confirm). The slow test genuinely sleeps and is marked `slow`.

- [ ] **Step 1: Write the failing e2e tests**

Append to `tests/test_engine.py`:

```python
_SLOW_SERVER = str(Path(__file__).parent / "fixtures" / "slow_server" / "server.py")
_SECRET_SERVER = str(Path(__file__).parent / "fixtures" / "secret_server" / "server.py")


@pytest.mark.slow
@pytest.mark.asyncio
async def test_slow_safe_tool_no_time_based_fp():
    # Real ~6s tool. A fixed-5s oracle would false-fire; the calibrated relative
    # oracle must report NOTHING. (Slow: ~24s. Run with -m "not slow" to skip.)
    async with stdio_session([sys.executable, _SLOW_SERVER]) as session:
        findings = await scan_session(session, oob=None, transport="stdio",
                                      check_ids=["cmd_injection"])
    assert findings == []


@pytest.mark.asyncio
async def test_docs_secret_tool_no_info_leak_fp():
    # Tool whose benign output always contains secret-shaped strings. Because the
    # calibration baseline contains the same secrets, the probe triggers no diff.
    async with stdio_session([sys.executable, _SECRET_SERVER]) as session:
        findings = await scan_session(session, oob=None, transport="stdio",
                                      check_ids=["info_leak"])
    assert findings == []
```

- [ ] **Step 2: Run them to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_engine.py -k "slow_safe or docs_secret" -q`
Expected: FAIL (fixture servers don't exist yet → connection/spawn error)

- [ ] **Step 3: Create the slow-but-safe fixture server**

Create `tests/fixtures/slow_server/__init__.py` (empty file).

Create `tests/fixtures/slow_server/server.py`:

```python
"""Slow-but-SAFE MCP server for mcprobe FP tests. Sleeps ~6s but never shells out."""
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
```

- [ ] **Step 4: Create the docs-secret fixture server**

Create `tests/fixtures/secret_server/__init__.py` (empty file).

Create `tests/fixtures/secret_server/server.py`:

```python
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
```

- [ ] **Step 5: Register the `slow` marker**

In `pyproject.toml`, the current `[tool.pytest.ini_options]` block is:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

Replace it with:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
markers = [
    "slow: marks tests that take many seconds (deselect with -m 'not slow')",
]
```

- [ ] **Step 6: Run the new e2e tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_engine.py -k "slow_safe or docs_secret" -q`
Expected: PASS. The slow one takes ~20-25s (2 calibration + 2 time-based sleep probes, each ~6s). `docs_secret` is fast.

If `test_slow_safe_tool_no_time_based_fp` does NOT pass, do NOT weaken the assertion. Diagnose: print the findings and their `f.evidence`. The expected mechanism: calibration measures ~6s baseline; the sleep payload also returns in ~6s (the safe tool ignores it); margin = max(6 + 4, 18) = 18; elapsed ~6 < 18 → no finding. If it fires, check that calibration actually ran (baseline latency ~6, not 0) and that `slow_echo` truly ignores the payload. Report BLOCKED with the evidence if the environment cannot sustain a 6s sleep deterministically.

- [ ] **Step 7: Run the full suite (including slow)**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (was 72; expect 74). Then confirm the fast subset works: `.venv/Scripts/python.exe -m pytest -q -m "not slow"` → 73 passed, 1 deselected.

- [ ] **Step 8: Commit**

```bash
git add tests/fixtures/slow_server tests/fixtures/secret_server pyproject.toml tests/test_engine.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "test(fp): real slow-safe + docs-secret fixtures prove zero false positives"
```

---

## Definition of Done (M2)

- [ ] R-B1 met: the engine calibrates each tool once (median latency + benign response) and exposes it via `ctx.baseline`; `calibrate=False` disables it.
- [ ] R-B2 met: the time oracle fires on a baseline-relative margin, not a fixed 5s; a ~6s slow-safe tool produces no time-based finding; a real injected delay still FIRMs.
- [ ] R-B3 met: info-leak reports a secret only on a baseline-triggered diff (FIRM); a tool whose benign output already contains the secret is suppressed; pattern-only with no baseline downgrades to TENTATIVE.
- [ ] M-NoFP met: real slow-safe and docs-secret fixtures each yield ZERO findings via a live stdio scan.
- [ ] Full suite green with `.venv/Scripts/python.exe -m pytest -q`; the `-m "not slow"` subset green too; commits authored `Dennis Sepede <dennisepede@proton.me>`, no trailer.

## Self-review notes (author)

- **Spec coverage:** R-B1 (Task 2), R-B2 (Task 3), R-B3 (Task 4), M-NoFP fixtures (Task 5). R-B4 (auth-bypass robust oracle) is P1 → M6, explicitly out. ✓
- **Backward-compat:** `CheckContext.baseline` is the last field (default None); no-baseline paths preserve v1 time-oracle and info-leak behavior; existing `test_cmdi_firm_on_time_delay` and `test_info_leak_needs_two_markers` stay green (neither asserts the now-changed confidence on the no-baseline path; info-leak ≥2 path still returns a CWE-200 finding). ✓
- **Type consistency:** `ToolBaseline(latency, response)` defined Task 1, consumed in Tasks 2/3/4; `CheckContext.baseline` field name consistent; `_CALIBRATION_CALLS`/`_LATENCY_MULT` defined where used. ✓
- **Calibration/deferred-eval interaction:** only token checks defer, and they read `ctx.oob` not `ctx.baseline`; baseline-consuming oracles are non-token and evaluate inline under the correct per-tool baseline. Documented in Task 2. ✓
- **Cost honesty:** the slow fixture genuinely sleeps ~6s (user-approved fidelity over speed); isolated in its own server + `slow` marker so `-m "not slow"` keeps the default loop fast. ✓
