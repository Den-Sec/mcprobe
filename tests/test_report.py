import json
from mcpsnare.models import Finding, Severity, Confidence
from mcpsnare.report.render import to_json, to_sarif, to_markdown

def _f():
    return [Finding("cmd_injection", "ping", "host", Severity.CRITICAL, Confidence.CONFIRMED,
                    "CWE-78", "Command injection in ping.host", "; sleep 5", "oob hit", "no shell")]

def test_json_report_structure():
    data = json.loads(to_json(_f()))
    assert data["summary"]["critical"] == 1
    assert data["findings"][0]["cwe"] == "CWE-78"

def test_sarif_is_valid_json_with_rules():
    s = json.loads(to_sarif(_f()))
    assert s["version"] == "2.1.0"
    assert s["runs"][0]["results"][0]["ruleId"] == "cmd_injection"

def test_markdown_contains_title_and_severity():
    md = to_markdown(_f())
    assert "Command injection in ping.host" in md and "CRITICAL" in md
