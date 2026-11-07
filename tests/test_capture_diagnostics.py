"""HTTP diagnostics exclude credentials in equivalent failure representations."""

import base64
import json

import httpx
import pytest

from neuralstrike.adapters.openai_endpoint import OpenAIEndpointAdapter


@pytest.mark.parametrize("status", [302, 401, 503])
async def test_status_errors_do_not_copy_userinfo_query_fragment_or_redirect_location(status, caplog):
    password = "SYNTHETIC@PASSWORD"
    query, fragment, location = "SYNTHETIC_QUERY", "SYNTHETIC_FRAGMENT", "LOCATION_PASSWORD"
    adapter = OpenAIEndpointAdapter(
        f"http://user:SYNTHETIC%40PASSWORD@fixture/v1/chat/completions?token={query}#{fragment}",
        model="fixture",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                status,
                headers={"location": f"https://other:{location}@redirect.invalid/?key={location}"},
                text="fixture outage",
            )
        ),
    )
    try:
        response = await adapter.query("fixture")
    finally:
        await adapter.close()
    assert response.error and str(status) in response.error
    encoded = json.dumps({"error": response.error, "exchanges": response.exchanges}) + caplog.text
    for secret in [password, "SYNTHETIC%40PASSWORD", query, fragment, location]:
        assert secret not in encoded
    assert response.exchanges[0]["response_text"] == "fixture outage"


@pytest.mark.parametrize("error_type", [httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError])
async def test_authenticated_transport_errors_cannot_echo_encoded_or_decoded_credentials(error_type, caplog):
    secret = "SYNTHETIC_AUTH_SECRET"
    encoded_secret = base64.b64encode(secret.encode()).decode()

    def handler(request):
        raise error_type(f"credential echo: {secret}; encoding: {encoded_secret}", request=request)

    adapter = OpenAIEndpointAdapter(
        "http://fixture", model="fixture", api_key=secret, transport=httpx.MockTransport(handler)
    )
    try:
        response = await adapter.query("fixture")
    finally:
        await adapter.close()
    diagnostic = json.dumps({"error": response.error, "exchanges": response.exchanges}) + caplog.text
    assert secret not in diagnostic
    assert encoded_secret not in diagnostic
    assert error_type.__name__ in response.error


async def test_ordinary_credential_free_connection_detail_is_retained():
    def handler(request):
        raise httpx.ConnectError("boom", request=request)

    adapter = OpenAIEndpointAdapter("http://fixture", model="fixture", transport=httpx.MockTransport(handler))
    try:
        response = await adapter.query("fixture")
    finally:
        await adapter.close()
    assert "boom" in response.error


@pytest.mark.parametrize("status", [200, 302, 503])
@pytest.mark.parametrize("redactor", ["formatter", "filter"])
async def test_sdk_info_logs_redact_url_credentials(status, redactor, monkeypatch):
    import io
    import logging

    from neuralstrike.core.config import settings
    from neuralstrike.utils.logging import RedactingFilter, RedactingFormatter

    monkeypatch.setattr(settings, "redact_logs", True)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(
        RedactingFormatter("%(message)s") if redactor == "formatter" else logging.Formatter("%(message)s")
    )
    if redactor == "filter":
        handler.addFilter(RedactingFilter())
    logger = logging.getLogger("httpx")
    old_level, old_propagate = logger.level, logger.propagate
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    adapter = OpenAIEndpointAdapter(
        "http://synthetic-user:SYNTHETIC_LOG_PASSWORD@fixture?key=SYNTHETIC_LOG_QUERY#SYNTHETIC_LOG_FRAGMENT",
        model="fixture",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(status, json={"choices": [{"message": {"content": "fixture"}}]})
        ),
    )
    try:
        await adapter.query("fixture")
    finally:
        await adapter.close()
        logger.removeHandler(handler)
        logger.setLevel(old_level)
        logger.propagate = old_propagate
    rendered = stream.getvalue()
    assert "HTTP Request: POST" in rendered
    assert "http://fixture" in rendered
    for secret in [
        "synthetic-user",
        "SYNTHETIC_LOG_PASSWORD",
        "SYNTHETIC_LOG_QUERY",
        "SYNTHETIC_LOG_FRAGMENT",
    ]:
        assert secret not in rendered


async def test_repeatedly_encoded_url_diagnostic_is_opaque_without_configured_auth():
    from urllib.parse import quote

    message = "https://other:INDEPENDENT_SYNTHETIC_PASSWORD@fixture?key=INDEPENDENT_QUERY"
    for _ in range(5):
        message = quote(message, safe="")

    def handler(request):
        raise httpx.ConnectError(message, request=request)

    adapter = OpenAIEndpointAdapter("http://fixture", model="fixture", transport=httpx.MockTransport(handler))
    try:
        response = await adapter.query("fixture")
    finally:
        await adapter.close()
    assert "INDEPENDENT_SYNTHETIC_PASSWORD" not in response.error
    assert "INDEPENDENT_QUERY" not in response.error
