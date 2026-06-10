from mcprobe.models import Probe, Finding, Severity, Confidence
from mcprobe.checks.base import register

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
        if unauth and unauth == response:
            return Finding(check=self.id, tool=probe.point.tool, param="-",
                           severity=Severity.HIGH, confidence=Confidence.CONFIRMED, cwe="CWE-306",
                           title=f"Missing authentication on {probe.point.tool}",
                           payload=probe.payload, evidence="tool callable without auth header",
                           remediation="Enforce auth on the HTTP transport for all sensitive tools.")
        return None
