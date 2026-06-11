from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from mcprobe.models import ToolInfo


class Session:
    def __init__(self, cs):
        self._cs = cs

    async def list_tools(self):
        resp = await self._cs.list_tools()
        return [
            ToolInfo(
                name=t.name,
                description=t.description or "",
                input_schema=t.inputSchema or {},
            )
            for t in resp.tools
        ]

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

    async def list_resource_templates(self):
        resp = await self._cs.list_resource_templates()
        return [(t.name, t.uriTemplate) for t in resp.resourceTemplates]

    async def read_resource(self, uri):
        resp = await self._cs.read_resource(uri)
        parts = []
        for c in resp.contents:
            parts.append(getattr(c, "text", "") or "")
        return "\n".join(p for p in parts if p)


@asynccontextmanager
async def stdio_session(command):
    params = StdioServerParameters(command=command[0], args=command[1:])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as cs:
            await cs.initialize()
            yield Session(cs)


@asynccontextmanager
async def http_session(url, headers=None):
    # The SDK's streamable_http_client takes headers via a caller-owned httpx client
    # (the old headers= kwarg is gone). create_mcp_http_client applies the same MCP
    # defaults the old path used (30s timeout, 300s SSE read, follow_redirects), so
    # routing headers through it is behaviour-preserving - not a bare AsyncClient,
    # which would default to a ~5s read timeout and break long-lived streams.
    async with create_mcp_http_client(headers=headers or {}) as http_client:
        async with streamable_http_client(url, http_client=http_client) as (read, write, *_):
            async with ClientSession(read, write) as cs:
                await cs.initialize()
                yield Session(cs)
