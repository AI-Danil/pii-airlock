from __future__ import annotations

import io
from urllib import error

import pytest

from pii_airlock import clients
from pii_airlock.clients import OpenAIResponsesClient
from pii_airlock.models import AirlockError


class OversizedResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size: int) -> bytes:
        return b"x" * (clients.MAX_PROVIDER_RESPONSE_BYTES + 1)


def test_cloud_endpoint_requires_https_except_for_loopback() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        OpenAIResponsesClient(api_key="test", model="test", base_url="http://example.test/v1")
    OpenAIResponsesClient(api_key="test", model="test", base_url="http://127.0.0.1:9999/v1")


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:9999/v1",
        "http://user@127.0.0.1:9999/v1",
        "https://api.openai.com/v1?debug=true",
    ],
)
def test_cloud_endpoint_rejects_ambiguous_or_credentialed_urls(base_url: str) -> None:
    with pytest.raises(ValueError):
        OpenAIResponsesClient(api_key="test", model="test", base_url=base_url)


def test_cloud_configuration_requires_nonempty_values_and_positive_timeout() -> None:
    with pytest.raises(ValueError):
        OpenAIResponsesClient(api_key="", model="test")
    with pytest.raises(ValueError):
        OpenAIResponsesClient(api_key="test", model="")
    with pytest.raises(ValueError):
        OpenAIResponsesClient(api_key="test", model="test", timeout=0)


def test_cloud_response_size_is_bounded(monkeypatch) -> None:
    monkeypatch.setattr(clients.request, "urlopen", lambda *_args, **_kwargs: OversizedResponse())
    client = OpenAIResponsesClient(api_key="test", model="test")
    with pytest.raises(AirlockError, match="2 MB"):
        client.complete(instructions="Summarize", input_text="safe")

    raw_secret = "provider-reflected-secret"
    http_error = error.HTTPError(
        "https://api.openai.com/v1/responses", 500, "error", {}, io.BytesIO(raw_secret.encode())
    )
    monkeypatch.setattr(clients.request, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(http_error))
    with pytest.raises(AirlockError) as caught:
        client.complete(instructions="Summarize", input_text="safe")
    assert raw_secret not in str(caught.value)
