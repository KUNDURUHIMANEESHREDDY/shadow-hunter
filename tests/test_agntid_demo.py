from __future__ import annotations

import json

import pytest

from shadow_hunter.agntid_demo import (
    DemoConfigurationError,
    _endpoint_label,
    _headers,
    _ollama_chat,
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


@pytest.mark.parametrize(
    "base_url",
    [
        "file:///tmp/ollama",
        "ftp://ollama.example",
        "http:///missing-host",
        "http://ollama.example:bad",
        "http://user:secret@ollama.example",
        "http://ollama.example?token=secret",
        "http://ollama.example/#fragment",
    ],
)
def test_ollama_chat_rejects_unsafe_base_url_before_network(monkeypatch, base_url):
    def unexpected_network_call(*args, **kwargs):
        raise AssertionError("invalid Ollama URL must be rejected before network access")

    monkeypatch.setattr("shadow_hunter.agntid_demo.http.client.HTTPConnection", unexpected_network_call)
    monkeypatch.setattr("shadow_hunter.agntid_demo.http.client.HTTPSConnection", unexpected_network_call)
    with pytest.raises(DemoConfigurationError):
        _ollama_chat(
            base_url=base_url,
            model="test-model",
            messages=[],
            tools=[],
        )


@pytest.mark.parametrize(
    ("base_url", "expected_host", "expected_port", "expected_path"),
    [
        ("http://127.0.0.1:11434/", "127.0.0.1", 11434, "/api/chat"),
        ("https://ollama.example:8443/proxy", "ollama.example", 8443, "/proxy/api/chat"),
    ],
)
def test_ollama_chat_uses_valid_http_transport(
    monkeypatch, base_url, expected_host, expected_port, expected_path
):
    connections = []

    class Response:
        status = 200

        def read(self):
            return b'{"message":{"content":"ok"}}'

    class Connection:
        def __init__(self, host, port, timeout):
            connections.append({"host": host, "port": port, "timeout": timeout})

        def request(self, method, path, body, headers):
            connections[-1].update({"method": method, "path": path, "headers": headers})

        def getresponse(self):
            return Response()

        def close(self):
            connections[-1]["closed"] = True

    monkeypatch.setattr("shadow_hunter.agntid_demo.http.client.HTTPConnection", Connection)
    monkeypatch.setattr("shadow_hunter.agntid_demo.http.client.HTTPSConnection", Connection)
    result = _ollama_chat(
        base_url=base_url,
        model="test-model",
        messages=[],
        tools=[],
    )

    assert result == {"content": "ok"}
    assert connections == [
        {
            "host": expected_host,
            "port": expected_port,
            "timeout": 180,
            "method": "POST",
            "path": expected_path,
            "headers": {"Content-Type": "application/json"},
            "closed": True,
        }
    ]


def test_result_payload_prefers_structured_content():
    class Result:
        structured_content = {"decision": "ALLOW"}
        content = []
    assert _result_payload(Result()) == {"decision": "ALLOW"}
