import time
from mcprobe.inject.mapper import injection_points
from mcprobe.checks.base import REGISTRY, CheckContext

async def scan_session(session, oob=None, transport="stdio", call_tool_unauth=None,
                       check_ids=None, oob_wait=2.0):
    ctx = CheckContext(call_tool=None, oob=oob, transport=transport,
                       call_tool_unauth=call_tool_unauth)
    tools = await session.list_tools()
    checks = [c for cid, c in REGISTRY.items() if not check_ids or cid in check_ids]
    findings, seen = [], set()
    for tool in tools:
        for point in injection_points(tool):
            for check in checks:
                for probe in check.generate(point, ctx):
                    start = time.monotonic()
                    try:
                        resp = await session.call_tool(tool.name, probe.args)
                    except Exception as e:
                        resp = f"error: {e}"
                    probe.meta["elapsed"] = time.monotonic() - start
                    finding = check.evaluate(probe, resp, ctx)
                    if finding:
                        key = (finding.check, finding.tool, finding.param)
                        if key not in seen:
                            seen.add(key); findings.append(finding)
    return findings
