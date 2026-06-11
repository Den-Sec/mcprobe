# mcpsnare v1.1 - Product Requirements Document

**Project:** mcpsnare (active, confirmation-driven security scanner for MCP server implementations)
**Version target:** v1.1 - "Hardening pass: depth, calibration, real-world fidelity"
**Date:** 2026-06-08
**Author:** Dennis Sepede (Den-Sec)
**Status:** COMPLETE (2026-06-10) - all milestones M1-M7 shipped. Every P0/P1/P2 requirement (R-A1..A6, R-B1..B4, R-C1..C3, R-D1, R-E1..E3, R-F1) is delivered and tested, or explicitly deferred where noted. 110 tests green. Per-milestone plans in `docs/superpowers/plans/2026-06-10-mcprobe-m{1..7}-*.md`; claim-to-test mapping in `docs/claims-matrix.md`. The unchecked `[ ]` boxes below are the original spec checklist, kept for the record - see the claims matrix for the live status.
**Predecessors:** `docs/superpowers/specs/2026-06-08-mcprobe-design.md` (v1 spec), `docs/superpowers/plans/2026-06-08-mcprobe.md` (v1 plan)

---

## 1. Background & motivation

v1 shipped a clean, TDD'd MVP: connector (stdio+HTTP), schema-naive injection mapper, 5 checks (cmd-injection, SSRF, path-traversal, auth-bypass, info-leak), OOB/time/canary oracles, engine, multi-format reporters. It passes 30 tests and an end-to-end demo that confirms 3 real vulns on a fixture.

A post-ship critical code review (2026-06-08) found that v1 **works on the toy fixture but is shallow against real-world MCP servers**, and that its public positioning ("confirmation-driven / zero false positives / Burp Active Scan for MCP, beats the incumbents") currently **overstates** what the implementation guarantees. v1.1 exists to close that gap *before* mcpsnare is promoted to the security audience that will scrutinize it.

**Guiding principle:** every claim in the README must be earned by verified behavior. Depth and correctness before new check classes; honesty before distribution.

### Findings driving v1.1 (from the review)
- **Coverage:** injection points are top-level string params only (`mcpsnare/inject/mapper.py:21-22`); nested objects, array items, and enums are ignored; payloads replace the whole value; schema constraints are not satisfied (`build_baseline` uses type defaults only); only `tools` are scanned (resources/prompts ignored); only `TextContent` is parsed (`mcpsnare/connect/session.py:29`).
- **False positives vs the "confirmed/zero-FP" claim:** time-based oracle uses a fixed 5s threshold with no baseline (`mcpsnare/checks/cmd_injection.py:27`); info-leak fires FIRM on a single benign probe matching 2 secret-shaped patterns (`mcpsnare/checks/info_leak.py`); auth-bypass uses exact string equality (`mcpsnare/checks/auth_bypass.py:17`).
- **Headline differentiator is timing-fragile:** OOB confirmation uses a single 2s wait then one poll (`mcpsnare/engine.py:39-42`) - too short for real interactsh callbacks; cmd-injection shares one token across 3 payloads so the confirming payload is unknown.
- **OS-blind payloads:** cmd-injection payloads are Unix-shell only (`mcpsnare/checks/cmd_injection.py:14,18`); in v1's own demo only `&` fired on Windows.
- **Engineering/safety:** scanning is fully sequential (`mcpsnare/engine.py:23-37`); rate-limiting promised in the v1 spec is unimplemented; `--aggressive` is a parsed no-op.

---

## 2. Goals & non-goals

### Goals
- **G1 - Real coverage:** detect injection points and reach vulnerable code paths in realistically-shaped MCP tool schemas (nested, arrays, enums, validated inputs).
- **G2 - Defensible confidence:** every reported confidence level is justified; eliminate the known false-positive classes so "confirmed-only" is true and "FIRM"/"TENTATIVE" are meaningful.
- **G3 - Working remote OOB:** the headline out-of-band confirmation reliably catches delayed/remote callbacks, with per-payload evidence.
- **G4 - Honest positioning:** README/differentiation match verified behavior; a documented confidence taxonomy.
- **G5 - Usable at scale:** bounded concurrency + rate-limiting so it runs on multi-tool servers without being slow or abusive.

### Non-goals (v1.1)
- **NG1** GUI / web UI.
- **NG2** Autonomous LLM-driven scanning agent.
- **NG3** Becoming a defensive tool-description-poisoning / rug-pull scanner as a *headline* feature (saturated space - Snyk/Invariant, Cisco). A light passive check may be added later, never as the differentiator.
- **NG4** New check classes beyond what's needed to prove the foundation (SQLi is optional/last; see §7).

### Success metrics (acceptance, measured by new fixtures)
- **M-Coverage:** mcpsnare detects a confirmed vuln in a tool whose vulnerable param is (a) nested in an object, (b) an array item, and (c) gated behind a required enum - three fixtures, each yields a confirmed finding.
- **M-NoFP:** three "clean but tricky" fixtures produce **zero** findings: a tool that always takes ~6s (slow-but-safe), a tool whose normal output always contains secret-shaped strings (docs/validator), and an HTTP tool whose responses contain a per-call timestamp.
- **M-OOB:** an e2e test with a callback delayed to ~8s is still confirmed; evidence names the exact payload/separator that fired.
- **M-Honesty:** a checklist maps each README claim to a passing test; confidence taxonomy documented.
- **M-Scale:** a 25-tool synthetic fixture scans materially faster with concurrency than sequential (recorded), with no dropped findings.

---

## 3. Requirements - P0 (must ship in v1.1)

> IDs use `[ ]` for tracking; each has acceptance criteria. Priorities: **P0** = ship-blocking for v1.1, **P1** = strongly desired, **P2** = nice-to-have/optional.

### Theme A - Coverage depth

- [ ] **R-A1 (P0) Schema-aware injection points.** Recurse the JSON Schema to find every string-typed leaf: top-level, inside nested `object` `properties`, and inside `array` `items` (and `items.properties`). Each injection point records a structured `json_path` (e.g. `params.cmd`, `hosts[0]`). Handle `anyOf`/`oneOf`/`$ref` best-effort (pick first viable branch; cap recursion depth, default 4, to avoid blowup).
  - *Acceptance:* given `{"params":{"type":"object","properties":{"cmd":{"type":"string"}}}}` → an injection point at `params.cmd`; given `{"hosts":{"type":"array","items":{"type":"string"}}}` → a point injecting `hosts[0]`. Recursion-depth cap proven by a deeply-nested fixture not hanging.
- [ ] **R-A2 (P0) Schema-valid baselines.** `build_baseline` must satisfy validation: honor `enum`/`const` (pick a valid member), `format` (uri/email/date/uuid → a plausible valid value), required nested objects (recurse), and `minLength`/`minimum` where trivial. Goal: the baseline call is accepted by a schema-strict server so injected probes reach the handler.
  - *Acceptance:* a tool with a required `enum` param no longer gets rejected; a fixture that errors on invalid enum is reached and its real vuln confirmed.
- [ ] **R-A3 (P0) Deep value injection.** The engine/checks set the payload at the injection point's `json_path` (deep-set into nested dict/array), not just a top-level key.
  - *Acceptance:* injecting `params.cmd` produces `{"params":{"cmd":"<payload>", ...valid siblings...}}`.
- [ ] **R-A4 (P1) Embed-in-valid-value strategy.** In addition to whole-value replacement, support injecting the payload *within* a baseline-valid value (prefix/suffix), so vulns behind format/content validation are reachable. Checks declare which strategy(ies) they want.
  - *Acceptance:* a tool that requires the value to contain `@` is still probed with a payload-bearing value that passes that check.
- [ ] **R-A5 (P1) Structured tool output.** `Session.call_tool` must also surface structured/JSON content (MCP `structuredContent` / non-text content), flattened to text for oracles AND available for inspection - not just `TextContent`.
  - *Acceptance:* a tool that returns a leak only in structured content is detected.
- [ ] **R-A6 (P2) Resources surface.** Enumerate MCP `resources` and resource templates; treat templated URI params as injection points for path-traversal/info-leak.
  - *Acceptance:* a resource template `file:///{path}` yields a traversal injection point and a confirmed finding on a vulnerable fixture.

### Theme B - False-positive elimination

- [ ] **R-B1 (P0) Per-tool baseline calibration.** Before probing a tool, issue 1-2 control calls with benign baseline args; record baseline latency (median) and baseline response text. Make this calibration data available to checks via `CheckContext`.
  - *Acceptance:* calibration runs once per tool; latency + baseline response captured; adds at most a small fixed overhead.
- [ ] **R-B2 (P0) Time-based oracle uses the baseline.** Fire only when `elapsed >= max(baseline_latency + sleep_seconds*0.8, baseline_latency*N)` (tunable), not a fixed 5s.
  - *Acceptance:* a tool that always takes ~6s yields NO time-based finding (no delta); a tool 0.1s→5.1s under the sleep payload DOES. (M-NoFP fixture.)
- [ ] **R-B3 (P0) info-leak baseline diff + confidence downgrade.** A secret-shaped match is reported only if it appears in the probe response but NOT in the baseline response (i.e., the input triggered it). Default confidence TENTATIVE; FIRM only with a triggered diff. Tune patterns to cut obvious doc/example noise.
  - *Acceptance:* a tool whose normal output always contains an example key is NOT flagged; a tool that leaks only on crafted input is flagged. (M-NoFP fixture.)
- [ ] **R-B4 (P1) auth-bypass robust oracle.** Replace exact equality with a tolerant comparison: strip/ignore volatile fields (timestamps, ids, nonces) before comparing, or use success-vs-denied semantics (unauth returns substantive data where auth was required). CONFIRMED only on a clear bypass.
  - *Acceptance:* bypass detected when responses differ only by a timestamp; not flagged when unauth is denied. (M-NoFP fixture.)

### Theme C - Make remote OOB real

- [ ] **R-C1 (P0) Poll-until-hit OOB.** Replace the single `oob_wait` sleep with a polling loop: after issuing all OOB probes, poll the provider every `oob_poll_interval` (default 2-3s) up to `oob_timeout` (default tuned for interactsh, e.g. 20s), exiting early once all outstanding tokens have resolved.
  - *Acceptance:* a callback delivered at ~8s is caught with defaults; a clean target returns promptly after timeout without per-probe stalls. (M-OOB.)
- [ ] **R-C2 (P0) Per-payload OOB tokens.** Each OOB payload (e.g. cmd-injection's `;`, `$()`, `&` variants) gets its own token so the confirming payload is identifiable in evidence.
  - *Acceptance:* evidence reports the exact payload/separator that triggered the callback.
- [ ] **R-C3 (P1) Real interactsh verification.** Provide and document a concrete interactsh client integration (self-hosted or public OAST) and an e2e test/runbook proving remote OOB end-to-end - not only `FakeClient`.
  - *Acceptance:* documented e2e run captures a real remote callback; README links the runbook.

### Theme D - OS-aware exploitation

- [ ] **R-D1 (P0) Cross-OS cmd-injection payloads.** Add Windows cmd.exe (`&`, `|`) and PowerShell (`;`, `Start-Sleep -s N`, `iwr`/`curl.exe`) payload sets alongside POSIX; send the full matrix (deduped) unless a `--target-os` hint narrows it.
  - *Acceptance:* a PowerShell-backed vulnerable fixture is confirmed via OOB; a cmd.exe one too.

### Theme E - Engineering, scale & safety

- [ ] **R-E1 (P1) Bounded concurrency.** Scan with a configurable concurrency limit (asyncio semaphore, default small e.g. 4) across tools/probes; preserve dedup and per-tool calibration ordering.
  - *Acceptance:* the 25-tool fixture scans materially faster than sequential with identical findings. (M-Scale.)
- [ ] **R-E2 (P1) Rate limiting.** A `--rate` (req/s) throttle, honored across the concurrency layer, to avoid abusing/destabilizing targets (v1 spec promised this).
  - *Acceptance:* observed request rate stays at/below `--rate`.
- [ ] **R-E3 (P0) Make `--aggressive` honest.** Give it real meaning: by default send only non-blocking confirmation probes (OOB + canary + pattern); `--aggressive` additionally enables blocking time-based (`sleep`) probes. This makes the default fast and gentle and the flag truthful (also fixes the v1 no-op overclaim).
  - *Acceptance:* default run emits no `sleep` payloads; `--aggressive` enables them; README matches.

### Theme F - Honesty & docs

- [ ] **R-F1 (P0) Confidence taxonomy + claims audit.** Document what CONFIRMED / FIRM / TENTATIVE mean (CONFIRMED = OOB callback or canary read; FIRM = calibrated timing or baseline-diff; TENTATIVE = pattern-only). Re-audit README/differentiation so every claim maps to a passing test; soften anything not yet earned.
  - *Acceptance:* a claims→test matrix in the repo; no claim without backing.

---

## 4. Out of scope / explicitly deferred

- **SQLi check** (calibrated time + error-based) - **P2**, only after Themes A-C land; it's "more of the same," not a foundation. (See §7.)
- **MCP-specific passive checks** (tool-description poisoning, rug-pull hashing, excessive scope) - **deferred indefinitely as a headline**; saturated competitive space. If added, clearly secondary/passive, never the selling point.
- GUI, LLM-agent mode, non-MCP transports.

---

## 5. Technical approach & constraints

- **Language/stack unchanged:** Python 3.11+, official `mcp` SDK (1.27.x verified), httpx, rich. Keep the pure-core / async-edge split: mapper, checks, oracles stay pure & unit-testable; IO (connector, OOB polling, concurrency) stays at the engine edge.
- **Backward-compatible interfaces where possible:** extend `CheckContext` (add `baseline`, `aggressive`) and `InjectionPoint` (structured `json_path`, `set(args, value)` helper) rather than rewrite. Checks keep the `generate`/`evaluate` contract.
- **New deep-set/deep-get utility** in `inject/` for json_path application (dict/array). One responsibility, fully unit-tested.
- **Calibration** lives in the engine (it owns IO); checks consume `ctx.baseline`. Avoid per-check calibration calls (cost).
- **OOB provider interface** gains a `poll_all()`/timeout-aware contract; `LocalOOB` and `InteractshOOB` both implement it. Local stays synchronous-fast (early exit).
- **Determinism:** mcpsnare remains a direct MCP client (no LLM in loop) - probes/timing deterministic; that property must be preserved.

---

## 6. Risks & mitigations

- **Schema recursion blowup** (anyOf/oneOf combinatorial, recursive `$ref`): cap depth (default 4) + visited-ref set; prefer first viable branch. (R-A1)
- **Calibration cost** (extra calls per tool): cap to 1-2 control calls; reuse baseline response for diff oracles so it pays for itself. (R-B1)
- **interactsh dependency** for real OOB e2e: keep the wrapper client-agnostic; document a concrete client; gate CLI `--oob interactsh` with a graceful error (already in v1). (R-C3)
- **Concurrency vs target stability:** conservative default (4) + rate limit; never unbounded. (R-E1/E2)
- **Over-tuning to fixtures:** the M-NoFP/M-Coverage fixtures must model *realistic* shapes, not be reverse-engineered to the checks; review fixtures adversarially.

---

## 7. Phasing (milestone order, each TDD'd with new fixtures)

1. **M1 - Coverage foundation (P0):** R-A1, R-A2, R-A3 + the deep-set utility + nested/array/enum fixtures. (Biggest impact; unblocks everything.)
2. **M2 - FP elimination (P0):** R-B1 (calibration) → R-B2, R-B3; + slow-safe / docs-secret fixtures. Restores the "confirmed/zero-FP" integrity.
3. **M3 - OOB fidelity (P0):** R-C1, R-C2 + delayed-callback e2e. Makes the differentiator real.
4. **M4 - OS payloads + safety flag (P0):** R-D1, R-E3 (honest `--aggressive`).
5. **M5 - Honesty pass (P0):** R-F1 claims→test matrix + README/differentiation update. Gate before any promotion.
6. **M6 - Depth & scale (P1):** R-A4, R-A5, R-B4, R-C3, R-E1, R-E2.
7. **M7 - Optional (P2):** R-A6 (resources), SQLi check.

**Definition of done for v1.1:** all P0 requirements implemented + tested; M-Coverage, M-NoFP, M-OOB, M-Honesty success metrics met; README claims audited; full suite green in CI.

**Promotion gate:** mcpsnare is only promoted to the security community **after M5** (honesty pass) is complete - so the tool withstands scrutiny under whatever it claims.

---

## 8. Open questions

- **Target-OS:** auto-detect (probe behavior) vs send-all-deduped vs `--target-os` hint? (Lean: send-all in v1.1; revisit auto-detect later.)
- **interactsh client:** which concrete library/self-hosted instance to standardize on for R-C3?
- **Calibration aggressiveness:** 1 vs 2 control calls; how to handle tools with naturally high latency variance (jitter) for the timing oracle margin.
- **Embed-strategy scope (R-A4):** apply to all checks or only injection-class (cmd/sqli/traversal)?
