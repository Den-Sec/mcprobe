# mcprobe v1.1 M6 - Depth & Scale (P1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close the P1 depth/scale gaps: reach vulns behind format/content validation (embed-in-valid-value), inspect structured tool output, make auth-bypass robust to volatile fields, run a real interactsh OOB path with a one-round-trip poll, and scan multi-tool servers concurrently with a rate limit.

**Architecture:** Localized check/oracle upgrades (R-A4 embed, R-A5 structured output, R-B4 tolerant auth compare) plus an engine concurrency refactor: each tool gets its own `CheckContext` (so concurrent tools never share a mutated `baseline`), probes run under an `asyncio.Semaphore` and an optional token-bucket rate limiter, and OOB providers gain `poll_all()` so the poll loop does one round-trip per iteration. Real interactsh is delivered as an injectable client adapter + runbook + an env-gated skippable e2e (no network in CI).

**Tech Stack:** Python 3.11+, `mcp` SDK, pytest + pytest-asyncio. New deterministic fakes for concurrency/rate tests; real-network tests are env-gated and skipped by default.

**Covers PRD v1.1:** R-A4, R-A5, R-B4, R-C3, R-E1, R-E2. (All P1.) Carries folded in: `poll_all()` OOB, CLI flags for OOB/concurrency/rate.

---

## Execution notes
- Run tests: `.venv/Scripts/python.exe -m pytest -q` (and `-m "not slow"`).
- Commit author `Dennis Sepede <dennisepede@proton.me>`, NO trailer: `git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "..."`.
- Branch `main`. Commit after each task. Baseline: 88 tests pass.

---

## Task 1: Structured tool output surfaced to oracles (R-A5)

**Files:** Modify `mcprobe/connect/session.py`; Test `tests/test_session.py`.

- [ ] **Step 1: Failing test.** Append to `tests/test_session.py`:

```python
def test_call_tool_flattens_structured_content():
    import asyncio
    from mcprobe.connect.session import Session

    class _Text:
        text = "plain part"

    class _Resp:
        content = [_Text()]
        structuredContent = {"secret": "AKIAIOSFODNN7EXAMPLE"}

    class _CS:
        async def call_tool(self, name, args):
            return _Resp()

    out = asyncio.run(Session(_CS()).call_tool("t", {}))
    assert "plain part" in out
    assert "AKIAIOSFODNN7EXAMPLE" in out  # structured content reaches the oracles
```

- [ ] **Step 2: Run, expect FAIL** (structuredContent ignored): `.venv/Scripts/python.exe -m pytest tests/test_session.py::test_call_tool_flattens_structured_content -q`

- [ ] **Step 3: Implement.** In `mcprobe/connect/session.py`, the current `call_tool` is:

```python
    async def call_tool(self, name, args):
        resp = await self._cs.call_tool(name, args)
        parts = []
        for c in resp.content:
            parts.append(getattr(c, "text", "") or "")
        return "\n".join(parts)
```

Replace with (append flattened structured content):

```python
    async def call_tool(self, name, args):
        resp = await self._cs.call_tool(name, args)
        parts = []
        for c in resp.content:
            parts.append(getattr(c, "text", "") or "")
        structured = getattr(resp, "structuredContent", None)
        if structured:
            import json
            parts.append(json.dumps(structured, default=str))
        return "\n".join(p for p in parts if p)
```

- [ ] **Step 4: Run** `.venv/Scripts/python.exe -m pytest tests/test_session.py -q` → PASS.
- [ ] **Step 5: Full suite** → expect 89.
- [ ] **Step 6: Commit** `feat(connect): flatten structuredContent into tool output for oracles`.

---

## Task 2: Robust auth-bypass oracle (R-B4)

**Files:** Modify `mcprobe/checks/auth_bypass.py`; Test `tests/test_checks.py`.

> Replace exact-equality with a tolerant compare: normalize away volatile fields (timestamps, UUIDs, common id/nonce keys) before comparing. CONFIRMED only on a clear bypass; still None when the unauth call is denied/errors.

- [ ] **Step 1: Failing tests.** Append to `tests/test_checks.py`:

```python
def test_auth_bypass_confirmed_when_only_timestamp_differs():
    a = AuthBypass()
    point = InjectionPoint("admin", "x", {"x": "mcprobe"}, "x")
    auth_resp = '{"user":"root","ts":"2026-06-10T10:00:00Z","data":"secret"}'
    unauth_resp = '{"user":"root","ts":"2026-06-10T10:00:09Z","data":"secret"}'
    ctx = CheckContext(call_tool=lambda n, args: auth_resp, oob=None, transport="http",
                       call_tool_unauth=lambda n, args: unauth_resp)
    probe = a.generate(point, ctx)[0]
    f = a.evaluate(probe, auth_resp, ctx)
    assert f is not None and f.cwe == "CWE-306"


def test_auth_bypass_none_when_unauth_substantively_differs():
    a = AuthBypass()
    point = InjectionPoint("admin", "x", {"x": "mcprobe"}, "x")
    ctx = CheckContext(call_tool=lambda n, args: '{"data":"secret"}', oob=None, transport="http",
                       call_tool_unauth=lambda n, args: '{"error":"401 unauthorized"}')
    probe = a.generate(point, ctx)[0]
    assert a.evaluate(probe, '{"data":"secret"}', ctx) is None
```

(Existing `test_auth_bypass_confirmed_when_unauth_succeeds` (identical strings) and `test_auth_bypass_none_when_unauth_denied` (PermissionError) must stay green.)

- [ ] **Step 2: Run, expect FAIL** on the timestamp test (exact equality fails when ts differs): `.venv/Scripts/python.exe -m pytest tests/test_checks.py -k auth_bypass -q`

- [ ] **Step 3: Implement.** Replace the whole `mcprobe/checks/auth_bypass.py` with:

```python
import re
from mcprobe.models import Probe, Finding, Severity, Confidence
from mcprobe.checks.base import register

# Volatile substrings stripped before comparing auth vs unauth responses, so a bypass
# is detected even when the two bodies differ only by a timestamp / id / nonce.
_VOLATILE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?"          # ISO timestamps
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"  # UUIDs
    r"|\"(?:id|ts|timestamp|nonce|request[_-]?id|trace[_-]?id)\"\s*:\s*\"?[^\",}]*\"?",
    re.IGNORECASE,
)


def _normalize(s: str) -> str:
    return _VOLATILE.sub("", s or "").strip()


@register
class AuthBypass:
    id = "auth_bypass"
    def generate(self, point, ctx):
        if ctx.transport != "http" or ctx.call_tool_unauth is None:
            return []
        return [Probe(check=self.id, point=point, payload="<no auth header>",
                      args=dict(point.base_args))]
    def evaluate(self, probe, response, ctx):
        try:
            unauth = ctx.call_tool_unauth(probe.point.tool, probe.args)
        except Exception:
            return None
        if unauth and _normalize(unauth) == _normalize(response) and _normalize(unauth):
            return Finding(check=self.id, tool=probe.point.tool, param="-",
                           severity=Severity.HIGH, confidence=Confidence.CONFIRMED, cwe="CWE-306",
                           title=f"Missing authentication on {probe.point.tool}",
                           payload=probe.payload,
                           evidence="tool callable without auth header (responses match modulo volatile fields)",
                           remediation="Enforce auth on the HTTP transport for all sensitive tools.")
        return None
```

- [ ] **Step 4: Run** `.venv/Scripts/python.exe -m pytest tests/test_checks.py -k auth_bypass -q` → PASS (incl. the two existing tests).
- [ ] **Step 5: Full suite** → expect 91.
- [ ] **Step 6: Commit** `feat(checks): auth-bypass tolerates volatile fields (timestamps/ids/nonces)`.

---

## Task 3: Embed-in-valid-value injection strategy (R-A4)

**Files:** Modify `mcprobe/models.py` (add `InjectionPoint.embed`); Modify `mcprobe/checks/cmd_injection.py` (emit embed variants for OOB payloads, deduped); Test `tests/test_models.py`, `tests/test_checks.py`.

> Beyond whole-value replacement (`set`), allow embedding the payload onto the baseline-VALID value (which honors format/enum), so a param requiring e.g. an `@` is still probed with a value that passes validation. cmd-injection emits both a `set` variant and an `embed` variant per OOB separator, deduped when identical.

- [ ] **Step 1: Failing tests.**

Append to `tests/test_models.py`:

```python
def test_injection_point_embed_prefixes_valid_value():
    from mcprobe.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="email",
                       base_args={"email": "probe@mcprobe.example"}, param_name="email")
    out = p.embed("; curl http://oob/x")
    assert out["email"] == "probe@mcprobe.example; curl http://oob/x"


def test_injection_point_embed_empty_when_leaf_absent():
    from mcprobe.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="missing", base_args={}, param_name="missing")
    assert p.embed("PAY")["missing"] == "PAY"
```

Append to `tests/test_checks.py`:

```python
def test_cmdi_emits_embed_variant_for_formatted_param():
    c = CmdInjection()
    oob = PerPayloadOOB()
    ctx = CheckContext(call_tool=lambda n, a: "", oob=oob, transport="stdio")
    # baseline value looks like an email (format-constrained)
    point = InjectionPoint("send", "to", {"to": "probe@mcprobe.example"}, "to")
    payloads = [p.payload for p in c.generate(point, ctx)]
    # at least one payload preserves the valid '@' prefix (embed strategy)
    assert any(p.startswith("probe@mcprobe.example") and "curl" in p for p in payloads)
```

- [ ] **Step 2: Run, expect FAIL** (no `embed`; cmd-injection only does whole-value).

- [ ] **Step 3a: Add `InjectionPoint.embed`.** In `mcprobe/models.py`, inside the `InjectionPoint` dataclass (after the existing `set` method), add:

```python
    def embed(self, payload, position="suffix") -> dict:
        """Return base_args with ``payload`` embedded onto the baseline-VALID value at
        json_path (suffix by default), rather than replacing it. Reaches vulns behind
        format/content validation. Falls back to the payload alone if the leaf is absent."""
        import copy
        from mcprobe.inject.jsonpath import deep_get, deep_set
        args = copy.deepcopy(self.base_args)
        try:
            valid = deep_get(args, self.json_path)
        except (KeyError, IndexError, TypeError):
            valid = ""
        valid = valid if isinstance(valid, str) else ""
        combined = f"{valid}{payload}" if position == "suffix" else f"{payload}{valid}"
        deep_set(args, self.json_path, combined)
        return args
```

- [ ] **Step 3b: Emit embed variants in cmd-injection.** In `mcprobe/checks/cmd_injection.py`, replace the OOB loop in `generate`. Current:

```python
        if ctx.oob is not None:
            for tpl in _OOB_TEMPLATES:
                token, url = ctx.oob.new_token()
                pl = f"mcprobe{tpl.format(url=url)}"
                probes.append(Probe(check=self.id, point=point, payload=pl,
                                    args=point.set(pl), token=token))
```

Replace with (emit whole-value AND embed, deduped on args):

```python
        if ctx.oob is not None:
            for tpl in _OOB_TEMPLATES:
                token, url = ctx.oob.new_token()
                cmd = tpl.format(url=url)                  # separator+command, e.g. "; curl <url>"
                whole_args = point.set(f"mcprobe{cmd}")
                embed_args = point.embed(cmd)             # valid-value prefix + cmd
                variants = [whole_args]
                if embed_args != whole_args:
                    variants.append(embed_args)
                for args in variants:
                    from mcprobe.inject.jsonpath import deep_get
                    payload = deep_get(args, point.json_path)
                    probes.append(Probe(check=self.id, point=point, payload=str(payload),
                                        args=args, token=token))
```

(Discard the first ugly block; use only the clean version. Keep the sleep loop and `evaluate`/`_finding` unchanged. The `point.json_path` for top-level params is the bare key, so `deep_get` returns the payload string.)

- [ ] **Step 4: Run** `.venv/Scripts/python.exe -m pytest tests/test_models.py tests/test_checks.py -k "embed or cmdi" -q` → PASS. The existing cmd-injection tests must stay green: for a default `mcprobe` param, `point.set("mcprobe; curl url")` and `point.embed("; curl url")` (valid="mcprobe" → "mcprobe; curl url") produce IDENTICAL args, so the dedup keeps exactly one probe per separator — `test_cmdi_per_payload_tokens_identify_separator` (expects `len(oob_probes) >= 6`, distinct tokens) still holds (6 separators × 1 deduped variant = 6 tokens; each variant of the same separator shares the separator's token).
- [ ] **Step 5: Full suite** → expect 94 (3 new tests).
- [ ] **Step 6: Commit** `feat: embed-in-valid-value injection strategy for format-constrained params (R-A4)`.

---

## Task 4: poll_all() OOB primitive + real interactsh adapter & runbook (R-C3)

**Files:** Modify `mcprobe/oob/base.py`, `mcprobe/oob/local.py`, `mcprobe/oob/interactsh.py`, `mcprobe/engine.py`; Create `docs/interactsh-runbook.md`; Test `tests/test_oob_local.py`, `tests/test_engine.py`.

> Add `poll_all()` to the OOB protocol so the engine polls once per loop iteration (not once per token) - the M3 carry. Document a concrete interactsh client + an env-gated e2e runbook (no network in CI).

- [ ] **Step 1: Failing test.** Append to `tests/test_oob_local.py`:

```python
def test_local_oob_poll_all_returns_all_interactions():
    import httpx
    from mcprobe.oob.local import LocalOOB
    with LocalOOB() as oob:
        t1, u1 = oob.new_token()
        t2, u2 = oob.new_token()
        httpx.get(u1, timeout=5)
        httpx.get(u2, timeout=5)
        allhits = oob.poll_all()
        assert t1 in allhits and t2 in allhits
        assert allhits[t1] and allhits[t2]
```

- [ ] **Step 2: Run, expect FAIL** (`LocalOOB` has no `poll_all`).

- [ ] **Step 3a: Add to the protocol.** In `mcprobe/oob/base.py`:

```python
from typing import Protocol


class OOBProvider(Protocol):
    def new_token(self) -> tuple[str, str]: ...
    def interactions(self, token: str) -> list[dict]: ...
    def poll_all(self) -> dict[str, list[dict]]: ...
```

- [ ] **Step 3b: Implement in LocalOOB.** In `mcprobe/oob/local.py`, add a method to the `LocalOOB` class (after `interactions`):

```python
    def poll_all(self) -> dict[str, list[dict]]:
        return {tok: list(hits) for tok, hits in self._hits.items()}
```

- [ ] **Step 3c: Implement in InteractshOOB.** In `mcprobe/oob/interactsh.py`, add (after `interactions`):

```python
    def poll_all(self) -> dict[str, list[dict]]:
        self._cache.extend(self._client.poll() or [])
        out: dict[str, list[dict]] = {}
        for tok in self._tokens:
            hits = [i for i in self._cache if tok in str(i)]
            if hits:
                out[tok] = hits
        return out
```

And track issued tokens: change `new_token` to record them. The current `new_token`:

```python
    def new_token(self) -> tuple[str, str]:
        token = uuid.uuid4().hex[:12]
        return token, f"http://{token}.{self._domain}"
```

becomes:

```python
    def new_token(self) -> tuple[str, str]:
        token = uuid.uuid4().hex[:12]
        self._tokens.append(token)
        return token, f"http://{token}.{self._domain}"
```

And initialize `self._tokens: list[str] = []` in `__init__` (next to `self._cache`).

- [ ] **Step 3d: Use poll_all in the engine loop.** In `mcprobe/engine.py`, the poll loop currently calls `all(oob.interactions(t) for t in tokens)`. Replace the early-exit check to use one `poll_all()`:

```python
        for _ in range(polls):
            # One round-trip per iteration (poll_all) instead of one per token.
            if oob is not None:
                hits = oob.poll_all()
                if all(hits.get(t) for t in tokens):
                    break
            await asyncio.sleep(oob_poll_interval)
```

(Leave the final per-deferred `evaluate` loop unchanged - checks still call `ctx.oob.interactions(token)` in evaluate, which is correct.)

- [ ] **Step 3e: Update test fakes.** The fakes in `tests/test_engine.py` (`DelayedOOB`, `CountResolveOOB`, `MultiDelayedOOB`, `ShellLikeOOB`) and `tests/test_checks.py` (`FakeOOB`, `PerPayloadOOB`) are used where the engine now calls `poll_all()`. Add a `poll_all` to the ENGINE-used fakes that the poll loop touches (`DelayedOOB`, `CountResolveOOB`, `MultiDelayedOOB`, `ShellLikeOOB`). For each, add:

```python
    def poll_all(self):
        # minimal: report any tokens this fake currently considers delivered
        return {t: [{"path": f"/{t}"}] for t in getattr(self, "_delivered", set())}
```

For `CountResolveOOB` (single token, count-based), add instead:

```python
    def poll_all(self):
        self._calls += 1
        hit = (self._tok is not None and self._calls >= self.resolve_after)
        return {self._tok: [{"path": "/tok"}]} if hit else {}
```

For `DelayedOOB`/`MultiDelayedOOB` (have `_delivered` set) the generic version above works. For `ShellLikeOOB` (has `delivered` set), add:

```python
    def poll_all(self):
        return {t: [{"path": f"/{t}"}] for t in self.delivered}
```

(`FakeOOB`/`PerPayloadOOB` in test_checks.py are used only at the check level, not the engine poll loop, so they don't need `poll_all` - but adding a trivial one is harmless if a test breaks.)

- [ ] **Step 4: Run** `.venv/Scripts/python.exe -m pytest tests/test_oob_local.py tests/test_engine.py -q` → PASS. Adjust any fake that the poll loop now needs.

- [ ] **Step 5: Create the runbook** `docs/interactsh-runbook.md`:

```markdown
# Real out-of-band (OOB) confirmation with interactsh

mcprobe's `InteractshOOB` is a client-agnostic wrapper. To confirm OOB against a
target that cannot reach your localhost (e.g. a remote HTTP MCP server), supply a
client object exposing `register() -> domain` and `poll() -> list[dict]`.

## Option A - public OAST

Use any interactsh client library (e.g. the `interactsh-client` CLI/SDK or a thin
HTTP wrapper around a public server such as `oast.fun`). Wrap it:

    class MyInteractshClient:
        def register(self) -> str: ...      # returns your assigned domain
        def poll(self) -> list[dict]: ...   # returns new interactions since last poll

    from mcprobe.oob.interactsh import InteractshOOB
    oob = InteractshOOB(MyInteractshClient())

## Option B - self-hosted

Run your own interactsh server and point the client at it. Same interface.

## End-to-end check

1. Start a deliberately-vulnerable MCP server reachable over HTTP.
2. `mcprobe scan --http <url> --oob interactsh` (with your client wired in `cli.py`,
   or via the SDK).
3. A real remote callback lands in `poll()`, the engine's poll-until-hit loop catches
   it, and the finding is CONFIRMED with the firing payload.

> CI note: mcprobe's automated suite uses fake OOB providers (deterministic, no
> network). This runbook is the real-network validation path; it is not run in CI.
```

- [ ] **Step 6: Link it from README.** In `README.md`, in the OOB section bullet for `--oob interactsh`, append: `See [docs/interactsh-runbook.md](docs/interactsh-runbook.md) for a real end-to-end runbook.`

- [ ] **Step 7: Full suite** → expect 95.
- [ ] **Step 8: Commit** `feat(oob): poll_all() one-round-trip polling + interactsh runbook (R-C3)`.

---

## Task 5: Bounded concurrency (R-E1)

**Files:** Modify `mcprobe/engine.py`; Test `tests/test_engine.py`.

> Run probes under an `asyncio.Semaphore(concurrency)` so multi-tool servers scan faster, WITHOUT the per-tool `ctx.baseline` race: give each tool its OWN `CheckContext` (via `dataclasses.replace`) so concurrent tools never clobber a shared baseline. Preserve dedup (collect has no await → atomic) and per-tool calibration ordering (calibrate before queueing that tool's probes).

- [ ] **Step 1: Failing tests.** Append to `tests/test_engine.py`:

```python
class ManyToolsSession:
    """N tools, each call sleeps a little - lets concurrency beat sequential."""
    def __init__(self, n, delay=0.02):
        self.n, self.delay = n, delay
    async def list_tools(self):
        return [ToolInfo(f"t{i}", "", {"type": "object",
                "properties": {"path": {"type": "string"}}, "required": ["path"]})
                for i in range(self.n)]
    async def call_tool(self, name, args):
        await asyncio.sleep(self.delay)
        return "root:x:0:0:" if "etc/passwd" in args.get("path", "") else "ok"


@pytest.mark.asyncio
async def test_engine_concurrency_identical_findings():
    seq = await scan_session(ManyToolsSession(6), oob=None, transport="stdio",
                             check_ids=["path_traversal"], concurrency=1)
    conc = await scan_session(ManyToolsSession(6), oob=None, transport="stdio",
                              check_ids=["path_traversal"], concurrency=6)
    seq_keys = {(f.check, f.tool, f.param) for f in seq}
    conc_keys = {(f.check, f.tool, f.param) for f in conc}
    assert seq_keys == conc_keys and len(conc_keys) == 6  # one traversal finding per tool


@pytest.mark.asyncio
async def test_engine_concurrency_is_faster():
    import time
    s = ManyToolsSession(8, delay=0.03)
    t0 = time.monotonic()
    await scan_session(s, oob=None, transport="stdio", check_ids=["path_traversal"], concurrency=1)
    seq_t = time.monotonic() - t0
    t0 = time.monotonic()
    await scan_session(ManyToolsSession(8, delay=0.03), oob=None, transport="stdio",
                       check_ids=["path_traversal"], concurrency=8)
    conc_t = time.monotonic() - t0
    assert conc_t < seq_t * 0.7  # materially faster
```

- [ ] **Step 2: Run, expect FAIL** (`concurrency` kwarg unknown).

- [ ] **Step 3: Refactor the engine.** In `mcprobe/engine.py`: add `from dataclasses import replace` to the imports. Change the `scan_session` signature to add `concurrency=4` (after `aggressive=False`):

```python
async def scan_session(session, oob=None, transport="stdio", call_tool_unauth=None,
                       check_ids=None, oob_poll_interval=2.5, oob_timeout=20.0, calibrate=True,
                       aggressive=False, concurrency=4):
```

Replace the scan body (the `deferred = []` block through the per-point loop) so probes run concurrently under a semaphore with per-tool contexts. The current body is:

```python
    deferred = []
    for tool in tools:
        points = injection_points(tool)
        # ctx.baseline is mutated per tool. ...
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
                        deferred.append((check, probe, resp))
                    else:
                        collect(check.evaluate(probe, resp, ctx))
```

Replace it with:

```python
    deferred = []
    sem = asyncio.Semaphore(max(1, concurrency))

    async def _run_probe(tool, tool_ctx, check, probe):
        async with sem:
            start = time.monotonic()
            try:
                resp = await session.call_tool(tool.name, probe.args)
            except Exception as e:
                resp = f"error: {e}"
            probe.meta["elapsed"] = time.monotonic() - start
        # collect/append run synchronously (no await) -> atomic under asyncio
        if probe.token and oob is not None:
            deferred.append((check, probe, resp))
        else:
            collect(check.evaluate(probe, resp, tool_ctx))

    tasks = []
    for tool in tools:
        points = injection_points(tool)
        # Per-tool context: concurrent tools must NOT share a mutated baseline.
        baseline = await _calibrate(session, tool) if (calibrate and points) else None
        tool_ctx = replace(ctx, baseline=baseline)
        for point in points:
            for check in checks:
                for probe in check.generate(point, tool_ctx):
                    tasks.append(_run_probe(tool, tool_ctx, check, probe))
    if tasks:
        await asyncio.gather(*tasks)
```

(The `ctx = CheckContext(...)` line at the top stays as the template; per-tool `tool_ctx` is derived via `replace`. The deferred-OOB poll block below is unchanged. Remove the now-stale `# ctx.baseline is mutated per tool` comment.)

- [ ] **Step 4: Run** `.venv/Scripts/python.exe -m pytest tests/test_engine.py -q` → PASS. All prior engine tests must stay green (calibration tests use `concurrency` default 4; the deferred-OOB tests still work because `_run_probe` appends to `deferred` and the poll loop runs after `gather`).
- [ ] **Step 5: Full suite** → expect 97.
- [ ] **Step 6: Commit** `feat(engine): bounded concurrency with per-tool contexts (R-E1)`.

---

## Task 6: Rate limiting (R-E2)

**Files:** Modify `mcprobe/engine.py`; Test `tests/test_engine.py`.

> A `--rate` (req/s) throttle honored across the concurrency layer: a shared async token-bucket gate acquired before each probe call.

- [ ] **Step 1: Failing test.** Append to `tests/test_engine.py`:

```python
@pytest.mark.asyncio
async def test_engine_rate_limit_caps_request_rate():
    import time
    # 6 tools, rate=20 req/s -> >= ~6 calls should take >= ~0.25s (6/20 - first is free)
    s = ManyToolsSession(6, delay=0.0)
    t0 = time.monotonic()
    await scan_session(s, oob=None, transport="stdio", check_ids=["path_traversal"],
                       concurrency=6, rate=20.0)
    elapsed = time.monotonic() - t0
    # path_traversal sends 2 probes/tool = 12 calls + 6 calibration*2 = 24 calls /20rps ~ 1.1s
    assert elapsed >= 0.4  # throttled well above the unthrottled ~0s
```

- [ ] **Step 2: Run, expect FAIL** (`rate` kwarg unknown).

- [ ] **Step 3: Implement a token-bucket gate.** In `mcprobe/engine.py`, add after the imports:

```python
class _RateGate:
    """Serialises probe starts to at most `rate` per second (None = unlimited)."""
    def __init__(self, rate):
        self.interval = (1.0 / rate) if rate else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        if not self.interval:
            return
        async with self._lock:
            now = time.monotonic()
            sleep_for = self._next - now
            self._next = max(now, self._next) + self.interval
        if sleep_for > 0:
            await asyncio.sleep(sleep_for)
```

Add `rate=None` to the `scan_session` signature (after `concurrency=4`). Construct the gate near `sem`:

```python
    sem = asyncio.Semaphore(max(1, concurrency))
    gate = _RateGate(rate)
```

And in `_run_probe`, acquire the gate INSIDE the semaphore, before the call:

```python
        async with sem:
            await gate.wait()
            start = time.monotonic()
            try:
                resp = await session.call_tool(tool.name, probe.args)
            ...
```

Also gate the calibration calls so `--rate` is honored everywhere: pass the gate into `_calibrate` (add a `gate=None` param; `await gate.wait()` before each calibration `call_tool` if gate). Update the `_calibrate` call site to `await _calibrate(session, tool, gate)`. The new `_calibrate`:

```python
async def _calibrate(session, tool, gate=None):
    args = build_baseline(tool.input_schema)
    latencies, response = [], ""
    for i in range(_CALIBRATION_CALLS):
        if gate is not None:
            await gate.wait()
        start = time.monotonic()
        try:
            r = await session.call_tool(tool.name, args)
        except Exception as e:
            r = f"error: {e}"
        latencies.append(time.monotonic() - start)
        if i == 0:
            response = r
    return ToolBaseline(latency=_aggregate_latency(latencies), response=response)
```

(Existing `_calibrate` callers pass no gate → default None → unchanged behavior.)

- [ ] **Step 4: Run** `.venv/Scripts/python.exe -m pytest tests/test_engine.py -k "rate or calibrat or concurrency" -q` → PASS.
- [ ] **Step 5: Full suite** → expect 98.
- [ ] **Step 6: Commit** `feat(engine): --rate token-bucket throttle across concurrency (R-E2)`.

---

## Task 7: Wire new CLI flags (carries)

**Files:** Modify `mcprobe/cli.py`; Test `tests/test_cli.py`.

> Expose `--concurrency`, `--rate`, `--oob-timeout`, `--oob-poll-interval` so operators can tune scale/OOB without editing code.

- [ ] **Step 1: Failing test.** Append to `tests/test_cli.py`:

```python
def test_cli_parses_scale_flags():
    args = build_parser().parse_args(
        ["scan", "--http", "http://h/mcp", "--concurrency", "8", "--rate", "10",
         "--oob-timeout", "30", "--oob-poll-interval", "1.5"])
    assert args.concurrency == 8 and args.rate == 10.0
    assert args.oob_timeout == 30.0 and args.oob_poll_interval == 1.5
```

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Add the args + wire them.** In `mcprobe/cli.py`, in `build_parser` after `--aggressive`:

```python
    s.add_argument("--concurrency", type=int, default=4, help="max concurrent probe requests (default 4)")
    s.add_argument("--rate", type=float, default=None, help="max requests/second (default unlimited)")
    s.add_argument("--oob-timeout", type=float, default=20.0, help="seconds to poll for OOB callbacks (default 20)")
    s.add_argument("--oob-poll-interval", type=float, default=2.5, help="OOB poll interval seconds (default 2.5)")
```

Add these kwargs to ALL THREE `scan_session(...)` calls in `_run`:

```python
            aggressive=args.aggressive, concurrency=args.concurrency, rate=args.rate,
            oob_timeout=args.oob_timeout, oob_poll_interval=args.oob_poll_interval,
```

(Append them to each existing call's argument list.)

- [ ] **Step 4: Run** `.venv/Scripts/python.exe -m pytest tests/test_cli.py -q` → PASS.
- [ ] **Step 5: Full suite** → expect 99.
- [ ] **Step 6: Commit** `feat(cli): --concurrency/--rate/--oob-timeout/--oob-poll-interval flags`.

---

## Definition of Done (M6)

- [ ] R-A4: `InjectionPoint.embed`; cmd-injection reaches format-constrained params.
- [ ] R-A5: `structuredContent` flattened into oracle input.
- [ ] R-B4: auth-bypass tolerant compare (volatile fields stripped); CONFIRMED only on clear bypass.
- [ ] R-C3: `poll_all()` one-round-trip polling; interactsh runbook + README link.
- [ ] R-E1: bounded concurrency with per-tool contexts; identical findings vs sequential; materially faster.
- [ ] R-E2: `--rate` throttle honored across concurrency + calibration.
- [ ] Full suite green; new CLI flags wired; commits authored `Dennis Sepede <dennisepede@proton.me>`, no trailer.

## Self-review notes
- R-E1 is the risky one: the per-tool `ctx.baseline` race (flagged since M2) is resolved by `replace(ctx, baseline=...)` per tool, so concurrency is safe. dedup/append are await-free → atomic under asyncio.
- Concurrency timing test (`* 0.7`) has mild flakiness risk; generous margin + per-call sleep makes it robust. If it flakes on a loaded box, it's the only timing-sensitive test - acceptable, deterministic findings test covers correctness.
- R-C3 honestly delivers the testable parts (poll_all + runbook); a real remote callback is the runbook's job, not CI (consistent with the M5 honesty pass; claims-matrix already discloses interactsh is runbook-not-CI).
- R-A4 dedup keeps probe count flat for default params (set==embed), only adding a probe when a real valid prefix exists.
