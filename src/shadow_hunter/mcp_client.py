"""MCP client for the explicitly approved loopback public-data companion.

The model cannot add endpoints, tools, headers, credentials or arguments.
Remote descriptions are untrusted and never inserted into the planner prompt.
"""
from __future__ import annotations
import asyncio
import os
import re
import threading
from types import MappingProxyType

ENDPOINT="http://127.0.0.1:8766/mcp"
CONTRACTS=MappingProxyType({"mcp_public_package":("public_package","package"),
                            "mcp_repo_metadata":("public_repository","repository")})
PACKAGES=frozenset({"requests","httpx","fastapi"})
REPOSITORIES=frozenset({"python/cpython","pallets/flask","fastapi/fastapi"})
_SLOTS=threading.BoundedSemaphore(2)

def companion_enabled():
    return os.environ.get("SHADOW_HUNTER_MCP_COMPANION_ENABLED","").lower()=="true"

def validate_input(capability,resource):
    if not companion_enabled():
        raise ValueError("MCP companion disabled")
    allowed=PACKAGES if capability=="mcp_public_package" else REPOSITORIES if capability=="mcp_repo_metadata" else ()
    if resource not in allowed:
        raise ValueError("MCP resource not approved")

def approved_discovery(listed):
    tools=listed.tools
    if len(tools)>32 or listed.next_cursor is not None:
        raise ValueError("Unbounded MCP catalog")
    names=[tool.name for tool in tools]
    if len(names)!=len(set(names)):
        raise ValueError("Duplicate MCP tools")
    approved={}
    for capability,(name,argument) in CONTRACTS.items():
        for tool in tools:
            if tool.name!=name:
                continue
            schema=tool.input_schema
            if not isinstance(schema,dict) or schema.get("type")!="object":
                continue
            props=schema.get("properties")
            if not isinstance(props,dict) or set(props)!={argument} or schema.get("required")!=[argument]:
                continue
            prop=props[argument]
            if not isinstance(prop,dict) or prop.get("type")!="string" or any(k not in {"type","title","description"} for k in prop):
                continue
            if any(k not in {"type","title","description","properties","required","additionalProperties"} for k in schema):
                continue
            approved[capability]=(name,argument)
    return approved

def verify_result(capability,resource,result):
    if result.is_error or result.structured_content is None:
        raise ValueError("MCP result unavailable")
    payload=result.structured_content
    # Some SDK versions wrap a generic dictionary result under 'result'.
    if isinstance(payload,dict) and set(payload)=={"result"}:
        payload=payload["result"]
    if not isinstance(payload,dict) or payload.get("status")!="completed":
        raise ValueError("Unverified MCP result")
    if capability=="mcp_public_package":
        version=payload.get("version")
        if set(payload)!={"status","package","version"} or payload.get("package")!=resource or not isinstance(version,str) or not re.fullmatch(r"[A-Za-z0-9.+!_-]{1,80}",version):
            raise ValueError("Invalid MCP package result")
    else:
        if set(payload)!={"status","repository","stars","forks","default_branch"} or payload.get("repository")!=resource:
            raise ValueError("Invalid MCP repository result")
        if any(type(payload[k]) is not int or payload[k]<0 for k in ("stars","forks")) or not isinstance(payload["default_branch"],str) or not re.fullmatch(r"[A-Za-z0-9._/-]{1,128}",payload["default_branch"]):
            raise ValueError("Invalid MCP repository fields")
    return {**payload,"provider":"mcp_companion"}

async def _exchange(capability=None,resource=None):
    import httpx2
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from .capability_catalog import enabled_names
    async with asyncio.timeout(15):
        async with httpx2.AsyncClient(trust_env=False,follow_redirects=False,timeout=7) as http:
            async with streamable_http_client(ENDPOINT,http_client=http, max_sse_event_size=65536) as (read,write):
                async with ClientSession(read,write,read_timeout_seconds=7) as session:
                    await session.initialize()
                    approved=approved_discovery(await session.list_tools())
                    approved={k:v for k,v in approved.items() if k in enabled_names()}
                    if capability is None:
                        return sorted(approved)
                    if capability not in approved:
                        raise ValueError("MCP capability not discovered")
                    validate_input(capability,resource)
                    name,arg=approved[capability]
                    return verify_result(capability,resource,await session.call_tool(name,{arg:resource}))

def _run(capability=None,resource=None):
    if not companion_enabled():
        raise ValueError("MCP companion disabled")
    if not _SLOTS.acquire(blocking=False):
        raise RuntimeError("MCP client busy")
    try:
        return asyncio.run(_exchange(capability,resource))
    except Exception:
        # Do not return remote errors, tool descriptions or untrusted text.
        raise RuntimeError("Approved MCP exchange failed") from None
    finally:
        _SLOTS.release()

def discover():
    return _run()

def invoke(capability,resource):
    from .capability_catalog import require_enabled
    require_enabled(capability)
    validate_input(capability,resource)
    return _run(capability,resource)
