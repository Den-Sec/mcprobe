import json
from collections import Counter
from mcpsnare.models import Finding

def _summary(findings):
    c = Counter(f.severity.value for f in findings)
    return {s: c.get(s, 0) for s in ("critical", "high", "medium", "low", "info")}

def to_json(findings: list[Finding]) -> str:
    return json.dumps({
        "summary": _summary(findings),
        "findings": [{
            "check": f.check, "tool": f.tool, "param": f.param,
            "severity": f.severity.value, "confidence": f.confidence.value,
            "cwe": f.cwe, "title": f.title, "payload": f.payload,
            "evidence": f.evidence, "remediation": f.remediation,
        } for f in findings],
    }, indent=2)

def to_sarif(findings: list[Finding]) -> str:
    rules = {f.check for f in findings}
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "mcpsnare",
                                "rules": [{"id": r} for r in sorted(rules)]}},
            "results": [{
                "ruleId": f.check,
                "level": "error" if f.severity.value in ("critical", "high") else "warning",
                "message": {"text": f"{f.title} | payload={f.payload} | {f.evidence}"},
            } for f in findings],
        }],
    }, indent=2)

def to_markdown(findings: list[Finding]) -> str:
    lines = ["# mcpsnare report", "", f"**Findings:** {len(findings)}", ""]
    for f in findings:
        lines += [f"## {f.title}",
                  f"- **Severity:** {f.severity.value.upper()}  ({f.confidence.value})",
                  f"- **CWE:** {f.cwe}",
                  f"- **Tool/param:** `{f.tool}` / `{f.param}`",
                  f"- **Payload:** `{f.payload}`",
                  f"- **Evidence:** {f.evidence}",
                  f"- **Remediation:** {f.remediation}", ""]
    return "\n".join(lines)
