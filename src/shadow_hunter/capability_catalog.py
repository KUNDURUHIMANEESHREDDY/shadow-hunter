"""Server-owned capability discovery and routing metadata.

The catalog is not an authorization grant. The gateway still authenticates
and authorizes individual business reads. Configuration can only remove tools.
"""
from __future__ import annotations
from dataclasses import dataclass
from types import MappingProxyType
import os
import re


@dataclass(frozen=True)
class Capability:
    name: str
    label: str
    domain: str
    intent: str | None
    input_kind: str
    description: str
    signals: tuple[str, ...]
    external: bool = False

    def matches(self, text: str) -> bool:
        return bool(self.signals) and all(re.search(pattern,text,re.I) for pattern in self.signals)

    def public(self):
        return {"name":self.name,"label":self.label,"domain":self.domain,
                "input_kind":self.input_kind,"description":self.description,
                "external":self.external,"read_only":True}


CAPABILITY_CATALOG=MappingProxyType({item.name:item for item in (
    Capability("order_summary","Order summary","support","order_details","order",
               "Read order details and remaining refundable balance.",
               (r"\b(?:order|purchase|refund|refundable|eligib)",)),
    Capability("refund_status","Refund status","support","refund_eligibility","order",
               "Check eligibility for a refund; never initiate one.",
               (r"\b(?:order|purchase|refund|refundable|eligib)",)),
    Capability("order_and_refund_review","Order and refund review","support","both","order",
               "Read details and refund eligibility through the governed gateway.",()),
    Capability("model_readiness","Local model health","local",None,"fixed",
               "Check the configured loopback model service.",
               (r"\b(?:ollama|model|inference)\b",r"\b(?:health|ready|readiness|available|status|working|online|running)\b")),
    Capability("numeric_summary","Numeric summary","local",None,"numbers",
               "Calculate count, sum, range and mean for bounded decimal inputs.",
               (r"\b(?:summarize|summarise|summary|average|mean|statistics|stats|sum|minimum|maximum|analyze|analyse)\b",)),
    Capability("unit_conversion","Unit conversion","local",None,"conversion",
               "Convert between supported metric units.",
               (r"\b(?:convert|express|how many)\b",)),
    Capability("public_repo_metadata","Public repository metadata","external",None,"repository",
               "Read metadata for an explicitly approved public GitHub repository.",
               (r"\b(?:metadata|stars|forks|default branch|repository info|repository details|star count)\b",),True),
    Capability("mcp_public_package","MCP Python package metadata","mcp",None,"package",
               "Read the published version of an approved Python package via local MCP.",
               (r"\b(?:pypi|python package|package)\b",r"\b(?:version|metadata|release)\b"),True),
    Capability("mcp_repo_metadata","MCP public repository metadata","mcp",None,"repository",
               "Read approved GitHub metadata via the local MCP companion.",
               (r"\bmcp\b",r"\b(?:metadata|stars|forks|default branch|repository info|repository details|star count)\b"),True),
)})
CAPABILITIES=MappingProxyType({key:item.intent for key,item in CAPABILITY_CATALOG.items()})


def enabled_names() -> frozenset[str]:
    """An unset configuration enables built-ins; malformed values fail closed."""
    raw=os.environ.get("SHADOW_HUNTER_ENABLED_CAPABILITIES")
    from .mcp_client import companion_enabled, CONTRACTS
    available=frozenset(CAPABILITY_CATALOG) if companion_enabled() else frozenset(CAPABILITY_CATALOG)-CONTRACTS.keys()
    if raw is None:
        return available
    names=frozenset(part.strip() for part in raw.split(",") if part.strip())
    if not names.issubset(CAPABILITY_CATALOG):
        return frozenset()
    return names & available


def discover_capabilities():
    enabled=enabled_names()
    return [item.public() for name,item in CAPABILITY_CATALOG.items() if name in enabled]


def matching_capabilities(text):
    """Return server-owned candidates, never execute or probe external services."""
    return tuple(item for item in CAPABILITY_CATALOG.values() if item.matches(text))


def require_enabled(name):
    if not isinstance(name,str) or name not in enabled_names():
        raise ValueError("Capability unavailable or not approved")
