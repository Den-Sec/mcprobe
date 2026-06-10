# mcprobe v1.1 M1 - Coverage Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make mcprobe's injection engine schema-aware so it reaches vulnerable string params nested in objects, inside arrays, and gated behind required enums - by recursing JSON Schema, building schema-valid baselines, and deep-setting payloads at structured `json_path`s.

**Architecture:** A new pure `inject/jsonpath.py` utility parses/applies dotted+indexed paths (`params.cmd`, `hosts[0]`) into nested dict/list structures. `InjectionPoint` gains a `set(value)` helper that deep-copies its baseline and deep-sets the payload. `inject/mapper.py` is rewritten: `build_baseline` produces a schema-VALID baseline (honoring enum/const/format/required/$ref, recursion-capped at depth 4), and `injection_points` recurses the schema to emit one `InjectionPoint` per string leaf with its structured path. The 5 checks switch from top-level key assignment to `point.set(payload)`. New vulnerable fixtures (nested/array/enum) prove confirmed findings end-to-end.

**Tech Stack:** Python 3.11+, official `mcp` SDK (FastMCP for fixtures), pytest + pytest-asyncio (`asyncio_mode=auto`). Pure-core/async-edge split preserved: jsonpath + mapper + checks stay pure & unit-testable.

**Covers PRD v1.1 requirements:** R-A1 (schema-aware injection points), R-A2 (schema-valid baselines), R-A3 (deep value injection) + deep-set utility + nested/array/enum fixtures. Success metric M-Coverage.

---

## Execution notes (read before starting)

- **Run tests with the project venv** (system Python lacks `pytest-asyncio`):
  `.venv/Scripts/python.exe -m pytest -q`
- **Commit author:** `Dennis Sepede <dennisepede@proton.me>`. **No `Co-Authored-By` / `Generated with` trailer.** Use:
  `git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "..."`
- **Branch:** `main` (working copy `C:\Users\Dennis\dev\mcprobe`). Commit after each task.
- **Baseline before starting:** 30 tests pass. Keep them green at every task.
- **Backward-compatibility contract that must stay true:** existing checks call `point.set(payload)` for a top-level `json_path` and get `{param: payload}` back - so `tests/test_checks.py` (which asserts `p.args["path"] == p.payload`) keeps passing unchanged.

---

## File Structure

| File | Responsibility | Action |
|------|----------------|--------|
| `mcprobe/inject/jsonpath.py` | Parse `json_path` strings; `deep_get`/`deep_set` into nested dict/list, creating intermediate containers. Pure, stdlib-only. | **Create** |
| `mcprobe/models.py` | `InjectionPoint` gains `set(value)` returning a deep-copied baseline with the payload deep-set at `json_path`. | **Modify** |
| `mcprobe/inject/mapper.py` | `build_baseline` = schema-VALID (enum/const/format/required/$ref, depth-capped); `injection_points` = recursive string-leaf discovery with structured paths. | **Rewrite** |
| `mcprobe/checks/{cmd_injection,ssrf,path_traversal,info_leak}.py` | Inject payloads via `point.set(payload)` instead of `args[param_name]=payload`. | **Modify** |
| `tests/test_jsonpath.py` | Unit tests for parse/deep_get/deep_set. | **Create** |
| `tests/test_mapper.py` | Extend with nested/array/enum/$ref/format/depth-cap cases. | **Modify** |
| `tests/fixtures/vuln_server/server.py` | Add `read_cfg` (nested), `read_many` (array), `read_mode` (enum-gated) vulnerable tools. | **Modify** |
| `tests/test_engine.py` | Add stdio integration test scanning the new fixtures -> 3 confirmed findings. | **Modify** |

---

## Task 1: Deep get/set json_path utility

**Files:**
- Create: `mcprobe/inject/jsonpath.py`
- Test: `tests/test_jsonpath.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_jsonpath.py
import pytest
from mcprobe.inject.jsonpath import parse_path, deep_get, deep_set


def test_parse_dotted_keys():
    assert parse_path("params.cmd") == ["params", "cmd"]


def test_parse_array_index():
    assert parse_path("hosts[0]") == ["hosts", 0]


def test_parse_mixed():
    assert parse_path("cfg.items[0].name") == ["cfg", "items", 0, "name"]


def test_deep_get_nested():
    assert deep_get({"params": {"cmd": "x"}}, "params.cmd") == "x"


def test_deep_get_array():
    assert deep_get({"hosts": ["a", "b"]}, "hosts[1]") == "b"


def test_deep_set_creates_nested_object():
    assert deep_set({}, "params.cmd", "X") == {"params": {"cmd": "X"}}


def test_deep_set_preserves_siblings():
    out = deep_set({"params": {"mode": "safe"}}, "params.cmd", "X")
    assert out == {"params": {"mode": "safe", "cmd": "X"}}


def test_deep_set_creates_array():
    assert deep_set({}, "hosts[0]", "X") == {"hosts": ["X"]}


def test_deep_set_array_index_in_existing_list():
    assert deep_set({"hosts": ["a", "b"]}, "hosts[1]", "X") == {"hosts": ["a", "X"]}


def test_deep_set_array_of_objects():
    assert deep_set({}, "a[0].b", "X") == {"a": [{"b": "X"}]}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_jsonpath.py -q`
Expected: FAIL - `ModuleNotFoundError: No module named 'mcprobe.inject.jsonpath'`

- [ ] **Step 3: Write the implementation**

```python
# mcprobe/inject/jsonpath.py
"""Deep get/set into nested dict/list structures addressed by a json_path string.

Path grammar: dot-separated object keys, ``[n]`` for array indices.
    "params.cmd"        -> ["params", "cmd"]
    "hosts[0]"          -> ["hosts", 0]
    "cfg.items[0].name" -> ["cfg", "items", 0, "name"]

Pure, stdlib-only. ``deep_set`` mutates and returns the passed object; callers
that must not mutate shared state (see InjectionPoint.set) deep-copy first.
"""
import re

_SEG = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def parse_path(path: str) -> list:
    segs = []
    for name, idx in _SEG.findall(path):
        segs.append(name if name else int(idx))
    return segs


def _container_for(seg) -> object:
    return [] if isinstance(seg, int) else {}


def deep_get(obj, path: str):
    cur = obj
    for seg in parse_path(path):
        cur = cur[seg]
    return cur


def deep_set(obj, path: str, value) -> object:
    segs = parse_path(path)
    cur = obj
    for i, seg in enumerate(segs[:-1]):
        nxt = segs[i + 1]
        if isinstance(seg, int):
            while len(cur) <= seg:
                cur.append(None)
            if not isinstance(cur[seg], (dict, list)):
                cur[seg] = _container_for(nxt)
            cur = cur[seg]
        else:
            if not isinstance(cur.get(seg), (dict, list)):
                cur[seg] = _container_for(nxt)
            cur = cur[seg]
    last = segs[-1]
    if isinstance(last, int):
        while len(cur) <= last:
            cur.append(None)
        cur[last] = value
    else:
        cur[last] = value
    return obj
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_jsonpath.py -q`
Expected: PASS (10 passed)

- [ ] **Step 5: Commit**

```bash
git add mcprobe/inject/jsonpath.py tests/test_jsonpath.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(inject): add json_path deep get/set utility for nested injection"
```

---

## Task 2: InjectionPoint.set() helper (R-A3 foundation)

**Files:**
- Modify: `mcprobe/models.py:26-31` (the `InjectionPoint` dataclass)
- Test: `tests/test_models.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_models.py`:

```python
def test_injection_point_set_top_level():
    from mcprobe.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="host", base_args={"host": "mcprobe"}, param_name="host")
    assert p.set("X") == {"host": "X"}


def test_injection_point_set_nested_preserves_siblings():
    from mcprobe.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="config.path",
                       base_args={"config": {"path": "mcprobe", "mode": "safe"}},
                       param_name="config.path")
    assert p.set("X") == {"config": {"path": "X", "mode": "safe"}}


def test_injection_point_set_does_not_mutate_base_args():
    from mcprobe.models import InjectionPoint
    base = {"config": {"path": "mcprobe"}}
    p = InjectionPoint(tool="t", json_path="config.path", base_args=base, param_name="config.path")
    p.set("X")
    assert base == {"config": {"path": "mcprobe"}}  # unchanged - deep copy


def test_injection_point_set_array():
    from mcprobe.models import InjectionPoint
    p = InjectionPoint(tool="t", json_path="paths[0]", base_args={"paths": ["mcprobe"]},
                       param_name="paths[0]")
    assert p.set("X") == {"paths": ["X"]}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_models.py -q`
Expected: FAIL - `AttributeError: 'InjectionPoint' object has no attribute 'set'`

- [ ] **Step 3: Modify the InjectionPoint dataclass**

In `mcprobe/models.py`, replace the existing `InjectionPoint` dataclass (lines 26-31):

```python
@dataclass
class InjectionPoint:
    tool: str
    json_path: str
    base_args: dict
    param_name: str

    def set(self, value) -> dict:
        """Return a deep copy of base_args with ``value`` deep-set at json_path.

        Deep-copies so the shared baseline is never mutated across probes.
        """
        import copy
        from mcprobe.inject.jsonpath import deep_set
        args = copy.deepcopy(self.base_args)
        deep_set(args, self.json_path, value)
        return args
```

(The `from mcprobe.inject.jsonpath import deep_set` is local to the method to keep `models` import-cycle-free; `inject/__init__.py` is empty so this is safe either way.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_models.py -q`
Expected: PASS

- [ ] **Step 5: Run the full suite to confirm no regressions**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (all prior tests still green)

- [ ] **Step 6: Commit**

```bash
git add mcprobe/models.py tests/test_models.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(models): add InjectionPoint.set() for deep payload injection"
```

---

## Task 3: Schema-valid build_baseline (R-A2)

**Files:**
- Modify: `mcprobe/inject/mapper.py` (rewrite `build_baseline` + add helpers; keep `injection_points` working until Task 4)
- Test: `tests/test_mapper.py`

> Note: this task rewrites `build_baseline` and adds `_resolve`/`_branch`/`_baseline` helpers. `injection_points` stays as-is this task (it only reads `properties`); it is rewritten in Task 4. The existing `_DEFAULTS` dict is removed.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_mapper.py`:

```python
def test_baseline_honors_enum():
    schema = {"type": "object",
              "properties": {"mode": {"type": "string", "enum": ["safe", "raw"]}},
              "required": ["mode"]}
    assert build_baseline(schema)["mode"] == "safe"


def test_baseline_honors_const():
    schema = {"type": "object",
              "properties": {"kind": {"const": "fixed"}},
              "required": ["kind"]}
    assert build_baseline(schema)["kind"] == "fixed"


def test_baseline_honors_format_uri():
    schema = {"type": "object",
              "properties": {"url": {"type": "string", "format": "uri"}},
              "required": ["url"]}
    assert build_baseline(schema)["url"].startswith("http")


def test_baseline_recurses_required_nested_object():
    schema = {"type": "object",
              "properties": {"config": {"type": "object",
                                        "properties": {"path": {"type": "string"}},
                                        "required": ["path"]}},
              "required": ["config"]}
    assert build_baseline(schema) == {"config": {"path": "mcprobe"}}


def test_baseline_resolves_ref():
    schema = {"$defs": {"Cfg": {"type": "object",
                                "properties": {"path": {"type": "string"}},
                                "required": ["path"]}},
              "type": "object",
              "properties": {"config": {"$ref": "#/$defs/Cfg"}},
              "required": ["config"]}
    assert build_baseline(schema) == {"config": {"path": "mcprobe"}}


def test_baseline_array_of_strings():
    schema = {"type": "object",
              "properties": {"paths": {"type": "array", "items": {"type": "string"}}},
              "required": ["paths"]}
    assert build_baseline(schema) == {"paths": ["mcprobe"]}
```

(The existing `test_build_baseline_fills_required_by_type` must keep passing: `host` -> `"mcprobe"`, `count` -> `1`, no `verbose`.)

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_mapper.py -q`
Expected: FAIL on the new tests (old `build_baseline` uses type defaults only - returns `{}` for nested/enum, no $ref resolution)

- [ ] **Step 3: Rewrite build_baseline + helpers**

Replace the top of `mcprobe/inject/mapper.py` (the `_DEFAULTS` dict and `build_baseline`) with:

```python
from mcprobe.models import ToolInfo, InjectionPoint

_MAX_DEPTH = 4
_STRING_DEFAULT = "mcprobe"
_FORMAT_SAMPLES = {
    "uri": "https://mcprobe.example/probe",
    "uri-reference": "https://mcprobe.example/probe",
    "url": "https://mcprobe.example/probe",
    "email": "probe@mcprobe.example",
    "idn-email": "probe@mcprobe.example",
    "date": "2026-01-01",
    "date-time": "2026-01-01T00:00:00Z",
    "time": "00:00:00",
    "uuid": "00000000-0000-4000-8000-000000000000",
    "ipv4": "127.0.0.1",
    "ipv6": "::1",
    "hostname": "mcprobe.example",
}


def _deref(ref, root):
    if not ref.startswith("#/"):
        return {}
    node = root
    for part in ref[2:].split("/"):
        if not isinstance(node, dict):
            return {}
        node = node.get(part, {})
    return node if isinstance(node, dict) else {}


def _resolve(schema, root):
    seen = set()
    while isinstance(schema, dict) and "$ref" in schema:
        ref = schema["$ref"]
        if ref in seen:
            return {}
        seen.add(ref)
        schema = _deref(ref, root)
    return schema if isinstance(schema, dict) else {}


def _branch(schema, root):
    """Collapse anyOf/oneOf to a single viable (non-null) branch, best-effort."""
    for key in ("anyOf", "oneOf"):
        for opt in schema.get(key, []):
            resolved = _resolve(opt, root)
            if resolved.get("type") != "null":
                return resolved
    return schema


def _string_value(schema):
    fmt = schema.get("format")
    if fmt in _FORMAT_SAMPLES:
        return _FORMAT_SAMPLES[fmt]
    val = _STRING_DEFAULT
    minlen = schema.get("minLength")
    if isinstance(minlen, int) and len(val) < minlen:
        val += "x" * (minlen - len(val))
    return val


def _baseline(schema, root, depth):
    schema = _branch(_resolve(schema, root), root)
    if "const" in schema:
        return schema["const"]
    if schema.get("enum"):
        return schema["enum"][0]
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), "string")
    if t == "string":
        return _string_value(schema)
    if t == "integer":
        return int(schema.get("minimum", 1)) or 1
    if t == "number":
        return schema.get("minimum", 1) or 1
    if t == "boolean":
        return True
    if t == "array":
        if depth >= _MAX_DEPTH:
            return []
        items = _resolve(schema.get("items", {}), root)
        n = max(int(schema.get("minItems", 1)), 1)
        return [_baseline(items, root, depth + 1) for _ in range(n)] if items else []
    if t == "object":
        if depth >= _MAX_DEPTH:
            return {}
        props = schema.get("properties", {})
        required = schema.get("required", list(props))
        return {name: _baseline(props[name], root, depth + 1)
                for name in required if name in props}
    return _STRING_DEFAULT


def build_baseline(schema: dict) -> dict:
    root = schema or {}
    resolved = _resolve(root, root)
    props = resolved.get("properties", {})
    required = resolved.get("required", list(props))
    return {name: _baseline(props[name], root, 1)
            for name in required if name in props}
```

(Leave the existing `injection_points` function below unchanged for now - Task 4 rewrites it. It still imports `InjectionPoint`, already imported above.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_mapper.py -q`
Expected: PASS (old + new mapper tests)

- [ ] **Step 5: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (no regressions)

- [ ] **Step 6: Commit**

```bash
git add mcprobe/inject/mapper.py tests/test_mapper.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(inject): schema-valid build_baseline (enum/const/format/ref/nested)"
```

---

## Task 4: Schema-aware injection_points (R-A1)

**Files:**
- Modify: `mcprobe/inject/mapper.py` (rewrite `injection_points` + add `_walk`)
- Test: `tests/test_mapper.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_mapper.py`:

```python
def _paths(schema):
    tool = ToolInfo(name="t", description="", input_schema=schema)
    return {p.json_path for p in injection_points(tool)}


def test_points_nested_object_path():
    schema = {"type": "object",
              "properties": {"params": {"type": "object",
                                        "properties": {"cmd": {"type": "string"}}}},
              "required": ["params"]}
    assert "params.cmd" in _paths(schema)


def test_points_array_item_path():
    schema = {"type": "object",
              "properties": {"hosts": {"type": "array", "items": {"type": "string"}}},
              "required": ["hosts"]}
    assert "hosts[0]" in _paths(schema)


def test_points_resolve_ref():
    schema = {"$defs": {"Cfg": {"type": "object",
                                "properties": {"path": {"type": "string"}},
                                "required": ["path"]}},
              "type": "object",
              "properties": {"config": {"$ref": "#/$defs/Cfg"}},
              "required": ["config"]}
    assert "config.path" in _paths(schema)


def test_points_skip_enum_string():
    schema = {"type": "object",
              "properties": {"mode": {"type": "string", "enum": ["safe", "raw"]},
                             "path": {"type": "string"}},
              "required": ["mode", "path"]}
    paths = _paths(schema)
    assert "path" in paths and "mode" not in paths


def test_points_baseline_is_schema_valid():
    schema = {"type": "object",
              "properties": {"mode": {"type": "string", "enum": ["safe", "raw"]},
                             "path": {"type": "string"}},
              "required": ["mode", "path"]}
    tool = ToolInfo(name="t", description="", input_schema=schema)
    pt = next(p for p in injection_points(tool) if p.json_path == "path")
    assert pt.base_args["mode"] == "safe"  # enum gate satisfied


def test_points_self_referential_ref_terminates():
    schema = {"$defs": {"Node": {"type": "object",
                                 "properties": {"name": {"type": "string"},
                                                "child": {"$ref": "#/$defs/Node"}}}},
              "type": "object",
              "properties": {"root": {"$ref": "#/$defs/Node"}},
              "required": ["root"]}
    tool = ToolInfo(name="t", description="", input_schema=schema)
    points = injection_points(tool)  # must not hang (depth cap + visited refs)
    assert "root.name" in {p.json_path for p in points}
```

(Existing `test_injection_points_only_strings` must keep passing: `{p.param_name for p in pts} == {"host"}` and `pts[0].base_args["count"] == 1`.)

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_mapper.py -q`
Expected: FAIL - current `injection_points` only sees top-level string props (no nesting, no $ref, no enum skip)

- [ ] **Step 3: Rewrite injection_points + add _walk**

Replace the existing `injection_points` function in `mcprobe/inject/mapper.py` with:

```python
def _walk(schema, path, root, depth, out, seen_refs):
    if depth > _MAX_DEPTH:
        return
    if isinstance(schema, dict) and "$ref" in schema:
        ref = schema["$ref"]
        if ref in seen_refs:
            return
        seen_refs = seen_refs | {ref}
    schema = _branch(_resolve(schema, root), root)
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), None)
    if t == "string":
        if not schema.get("enum") and "const" not in schema:
            out.append(path)
        return
    if t == "object":
        for name, sub in schema.get("properties", {}).items():
            child = f"{path}.{name}" if path else name
            _walk(sub, child, root, depth + 1, out, seen_refs)
    elif t == "array":
        items = schema.get("items")
        if isinstance(items, dict):
            _walk(items, f"{path}[0]", root, depth + 1, out, seen_refs)


def injection_points(tool: ToolInfo) -> list[InjectionPoint]:
    root = tool.input_schema or {}
    paths = []
    _walk(root, "", root, 0, paths, frozenset())
    base = build_baseline(root)
    return [InjectionPoint(tool=tool.name, json_path=p, base_args=base, param_name=p)
            for p in paths]
```

(Note: `param_name` is now the full `json_path` - for top-level params it equals the bare name, so existing checks/tests are unaffected; for nested params it carries the precise path into findings/dedup.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_mapper.py -q`
Expected: PASS

- [ ] **Step 5: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (no regressions)

- [ ] **Step 6: Commit**

```bash
git add mcprobe/inject/mapper.py tests/test_mapper.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(inject): schema-aware injection_points (nested/array/enum/ref, depth-capped)"
```

---

## Task 5: Wire checks to deep injection (R-A3)

**Files:**
- Modify: `mcprobe/checks/cmd_injection.py`, `mcprobe/checks/ssrf.py`, `mcprobe/checks/path_traversal.py`, `mcprobe/checks/info_leak.py`
- Test: `tests/test_checks.py` (existing tests must stay green) + one new nested-injection test

> `auth_bypass.py` is intentionally NOT changed: it sends the baseline as-is (`dict(point.base_args)`) without injecting a payload into a param, and never mutates args.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_checks.py`:

```python
def test_path_traversal_deep_sets_nested_path():
    from mcprobe.checks.path_traversal import PathTraversal
    from mcprobe.models import InjectionPoint
    pt = PathTraversal()
    point = InjectionPoint("read_cfg", "config.path",
                           {"config": {"path": "mcprobe"}}, "config.path")
    probe = pt.generate(point, _ctx())[0]
    assert probe.args == {"config": {"path": probe.payload}}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_checks.py::test_path_traversal_deep_sets_nested_path -q`
Expected: FAIL - current code does `args["config.path"] = payload` (a flat key), producing `{"config": {"path": "mcprobe"}, "config.path": payload}`

- [ ] **Step 3: Update the four checks**

In `mcprobe/checks/cmd_injection.py`, in `generate`, replace BOTH payload loops' arg construction. Change every occurrence of:

```python
            args = dict(base); args[point.param_name] = pl
```
to:
```python
            args = point.set(pl)
```
(There are two such lines - the OOB loop and the time-based loop. Remove the now-unused `base = point.base_args` line at the top of `generate`.)

Resulting `generate`:

```python
    def generate(self, point, ctx):
        probes = []
        if ctx.oob is not None:
            token, url = ctx.oob.new_token()
            for tpl in (f"; curl {url}", f"$(curl {url})", f"& curl {url}"):
                pl = f"mcprobe{tpl}"
                probes.append(Probe(check=self.id, point=point, payload=pl,
                                    args=point.set(pl), token=token))
        for tpl in (f"; sleep {_SLEEP_SECONDS}", f"$(sleep {_SLEEP_SECONDS})"):
            pl = f"mcprobe{tpl}"
            probes.append(Probe(check=self.id, point=point, payload=pl, args=point.set(pl),
                                meta={"time_based": True, "threshold": _SLEEP_SECONDS}))
        return probes
```

In `mcprobe/checks/ssrf.py`, change:
```python
        args = dict(point.base_args); args[point.param_name] = url
        return [Probe(check=self.id, point=point, payload=url, args=args, token=token)]
```
to:
```python
        return [Probe(check=self.id, point=point, payload=url, args=point.set(url), token=token)]
```

In `mcprobe/checks/path_traversal.py`, change:
```python
            args = dict(point.base_args); args[point.param_name] = pl
            out.append(Probe(check=self.id, point=point, payload=pl, args=args))
```
to:
```python
            out.append(Probe(check=self.id, point=point, payload=pl, args=point.set(pl)))
```

In `mcprobe/checks/info_leak.py`, change:
```python
        args = dict(point.base_args); args[point.param_name] = "mcprobe-probe"
        return [Probe(check=self.id, point=point, payload="mcprobe-probe", args=args)]
```
to:
```python
        return [Probe(check=self.id, point=point, payload="mcprobe-probe",
                      args=point.set("mcprobe-probe"))]
```

- [ ] **Step 4: Run the check tests + new test to verify they pass**

Run: `.venv/Scripts/python.exe -m pytest tests/test_checks.py -q`
Expected: PASS (existing top-level tests still green because `point.set("X")` on json_path `"path"` returns `{"path": "X"}`; the new nested test passes)

- [ ] **Step 5: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (no regressions)

- [ ] **Step 6: Commit**

```bash
git add mcprobe/checks/cmd_injection.py mcprobe/checks/ssrf.py mcprobe/checks/path_traversal.py mcprobe/checks/info_leak.py tests/test_checks.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "feat(checks): inject payloads via InjectionPoint.set (deep json_path)"
```

---

## Task 6: Nested/array/enum fixtures + end-to-end confirmation (M-Coverage)

**Files:**
- Modify: `tests/fixtures/vuln_server/server.py` (add 3 vulnerable tools)
- Modify: `tests/test_engine.py` (add stdio integration test)

> The new tools mirror the existing `read_doc` file-reader so confirmation uses the offline, deterministic path-traversal canary (`[fonts]` from `win.ini` on Windows; `root:x:0:0:` from `/etc/passwd` on Linux) - no OOB infra needed. They prove a confirmed finding reaches a param that is (a) nested in an object, (b) an array item, (c) gated behind a required enum.

- [ ] **Step 1: Write the failing integration test**

Append to `tests/test_engine.py`:

```python
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/test_engine.py::test_scan_confirms_nested_array_enum_traversal -q`
Expected: FAIL - the fixture server has no `read_cfg`/`read_many`/`read_mode` tools yet, so none of those params are confirmed.

- [ ] **Step 3: Add the vulnerable tools to the fixture server**

In `tests/fixtures/vuln_server/server.py`, add imports at the top (after the existing `import subprocess`):

```python
from typing import Literal

from pydantic import BaseModel
```

Add a shared reader helper and the three tools (after the existing `whoami` tool, before `if __name__`):

```python
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
```

- [ ] **Step 4: Run the integration test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/test_engine.py::test_scan_confirms_nested_array_enum_traversal -q`
Expected: PASS (the scan deep-sets the traversal payload into `config.path`, `paths[0]`, and `read_mode.path` - the latter only reachable because the enum baseline picks `"safe"` - and the canary confirms each)

- [ ] **Step 5: Run the full suite**

Run: `.venv/Scripts/python.exe -m pytest -q`
Expected: PASS (all green - target ~50 tests)

- [ ] **Step 6: Commit**

```bash
git add tests/fixtures/vuln_server/server.py tests/test_engine.py
git -c user.name="Dennis Sepede" -c user.email="dennisepede@proton.me" commit -m "test(coverage): nested/array/enum vuln fixtures confirmed end-to-end"
```

---

## Definition of Done (M1)

- [ ] R-A1 met: `injection_points` emits structured `json_path`s for string leaves nested in objects, inside array `items`, resolving `$ref`/`anyOf`/`oneOf` best-effort, recursion-capped at depth 4 (self-referential `$ref` terminates).
- [ ] R-A2 met: `build_baseline` produces schema-valid baselines (enum/const/format/required-nested/$ref).
- [ ] R-A3 met: checks deep-set payloads at `json_path` via `InjectionPoint.set`; baseline never mutated.
- [ ] M-Coverage met: nested / array / enum-gated fixtures each yield a CONFIRMED finding via the stdio scan.
- [ ] Full suite green with `.venv/Scripts/python.exe -m pytest -q`; 6 commits authored `Dennis Sepede <dennisepede@proton.me>`, no trailer.

## Self-review notes (author)

- **Spec coverage:** R-A1 (Task 4), R-A2 (Task 3), R-A3 (Tasks 2+5), deep-set utility (Task 1), nested/array/enum fixtures + M-Coverage (Task 6). R-A4/A5/A6 are P1/P2 -> out of M1 (deferred to M6/M7 per PRD §7). ✓
- **Type consistency:** `InjectionPoint.set(value)` defined Task 2, consumed Task 5; `json_path`/`param_name`/`base_args` field names consistent across tasks; `_resolve`/`_branch`/`_baseline`/`_walk`/`_MAX_DEPTH` defined Task 3, reused Task 4. ✓
- **Real-shape grounding:** fixture schemas verified against actual FastMCP output (nested -> `$ref`/`#/$defs/Cfg`; array -> `items`; enum -> `enum`) before writing the plan. ✓
