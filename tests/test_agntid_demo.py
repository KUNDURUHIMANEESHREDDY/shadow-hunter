from __future__ import annotations

import json

import pytest

from shadow_hunter.agntid_demo import (
    DemoConfigurationError,
    _endpoint_label,
    _headers,
    _result_payload,
)


def test_endpoint_label_strips_userinfo_query_and_fragment():
    assert _endpoint_label(
        "https://user:secret@proxy.example/mcp?token=x#fragment"
    ) == "https://proxy.example/mcp"


def test_endpoint_label_rejects_non_http_urls():
    with pytest.raises(DemoConfigurationError):
        _endpoint_label("file:///tmp/mcp")


def test_headers_add_generated_demo_correlation():
    result = _headers("9c7f5c21-7c18-4b99-9c14-f07fcf79c401")
    assert result["X-Shadow-Hunter-Demo-ID"] == "9c7f5c21-7c18-4b99-9c14-f07fcf79c401"


def test_headers_reject_crlf_and_correlation_override(monkeypatch):
    monkeypatch.setenv(
        "AGNTID_MCP_HEADERS_JSON",
        json.dumps({"X-Test": "bad\r\nInjected: yes"}),
    )
    with pytest.raises(DemoConfigurationError):
        _headers("9c7f5c21-7c18-4b99-9c14-f07fcf79c401")
    monkeypatch.setenv(
        "AGNTID_MCP_HEADERS_JSON",
        json.dumps({"X-Shadow-Hunter-Demo-ID": "override"}),
    )
    with pytest.raises(DemoConfigurationError):
        _headers("9c7f5c21-7c18-4b99-9c14-f07fcf79c401")


def test_result_payload_prefers_structured_content():
    class Result:
        structured_content = {"decision": "ALLOW"}
        content = []
    assert _result_payload(Result()) == {"decision": "ALLOW"}
