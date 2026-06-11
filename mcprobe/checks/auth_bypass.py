import re
from mcprobe.models import Probe, Finding, Severity, Confidence
from mcprobe.checks.base import register

# Volatile substrings stripped before the tolerant compare, so a bypass is detected
# even when the two bodies differ only by a timestamp / request-id / nonce. NOTE: a
# bare record "id" is intentionally NOT stripped - a different record id is a real data
# difference, not a volatile field, and stripping it would risk a false bypass.
_VOLATILE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?"          # ISO timestamps
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"  # UUIDs
    r"|\"(?:ts|timestamp|nonce|request[_-]?id|trace[_-]?id)\"\s*:\s*\"?[^\",}]*\"?",
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
                      args=dict(point.base_args), meta={"needs_unauth": True})]
    def evaluate(self, probe, response, ctx):
        unauth = probe.meta.get("unauth_response")
        if not unauth:
            return None
        if unauth == response:
            # Raw byte-identical: a clear, directly-observed bypass.
            return self._finding(probe, Confidence.CONFIRMED,
                                 "tool callable without auth header (identical response)")
        nu, nr = _normalize(unauth), _normalize(response)
        if nu and nu == nr:
            # Match only after stripping volatile fields: strong but inferred -> FIRM.
            return self._finding(probe, Confidence.FIRM,
                                 "tool callable without auth header (responses match modulo volatile fields)")
        return None
    def _finding(self, probe, conf, evidence):
        return Finding(check=self.id, tool=probe.point.tool, param="-",
                       severity=Severity.HIGH, confidence=conf, cwe="CWE-306",
                       title=f"Missing authentication on {probe.point.tool}",
                       payload=probe.payload, evidence=evidence,
                       remediation="Enforce auth on the HTTP transport for all sensitive tools.")
