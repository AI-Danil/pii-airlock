from __future__ import annotations

import json
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Protocol
from urllib import error, request
from urllib.parse import urlparse

from .models import AirlockError

MAX_PROVIDER_RESPONSE_BYTES = 2 * 1024 * 1024


class CloudClient(Protocol):
    def complete(self, *, instructions: str, input_text: str) -> str: ...


@dataclass
class OpenAIResponsesClient:
    api_key: str
    model: str
    base_url: str = "https://api.openai.com/v1"
    timeout: float = 120.0

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        try:
            is_loopback = bool(parsed.hostname and ip_address(parsed.hostname).is_loopback)
        except ValueError:
            is_loopback = False
        is_loopback_http = parsed.scheme == "http" and is_loopback
        if (
            (parsed.scheme != "https" and not is_loopback_http)
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Cloud base URL must use HTTPS, except for an explicit loopback test endpoint.")
        if not self.api_key.strip() or not self.model.strip():
            raise ValueError("Cloud API key and model must be non-empty.")
        if self.timeout <= 0:
            raise ValueError("Cloud timeout must be positive.")

    def complete(self, *, instructions: str, input_text: str) -> str:
        payload = {"model": self.model, "instructions": instructions, "input": input_text, "store": False}
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = request.Request(
            f"{self.base_url.rstrip('/')}/responses",
            data=body,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                data = response.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
                if len(data) > MAX_PROVIDER_RESPONSE_BYTES:
                    raise AirlockError("OpenAI Responses output exceeded the 2 MB limit.")
                raw = json.loads(data.decode("utf-8"))
        except error.HTTPError as exc:
            raise AirlockError(f"OpenAI Responses HTTP {exc.code}.") from exc
        except error.URLError as exc:
            raise AirlockError(f"OpenAI Responses unavailable: {exc.reason}") from exc
        except (TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AirlockError("OpenAI Responses timed out or returned non-JSON output.") from exc
        text = _extract_output_text(raw)
        if not text:
            raise AirlockError("OpenAI Responses returned no text output.")
        return text


def _extract_output_text(payload: dict[str, object]) -> str:
    direct = payload.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    parts: list[str] = []
    output = payload.get("output")
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    parts.append(block["text"])
    return "\n".join(parts).strip()
