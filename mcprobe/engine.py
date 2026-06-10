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
