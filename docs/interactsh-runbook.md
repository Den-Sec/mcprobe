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
2. Scan it with the interactsh OOB backend wired in (`--oob interactsh` once your
   client is installed, or via the SDK).
3. A real remote callback lands in `poll()`, the engine's poll-until-hit loop catches
   it via `poll_all()`, and the finding is CONFIRMED with the firing payload.

> CI note: mcprobe's automated suite uses fake OOB providers (deterministic, no
> network). This runbook is the real-network validation path; it is not run in CI.
