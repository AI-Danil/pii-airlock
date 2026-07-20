from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol
from urllib import error, request

from .models import AirlockError


class CloudClient(Protocol):
    def complete(self, *, instructions: str, input_text: str) -> str: ...


@dataclass
class OpenAIResponsesClient:
    api_key: str
    model: str = "gpt-5.6-luna"
    base_url: str = "https://api.openai.com/v1"
    timeout: float = 120.0

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
                raw = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise AirlockError(f"OpenAI Responses HTTP {exc.code}: {detail}") from exc
        except error.URLError as exc:
            raise AirlockError(f"OpenAI Responses unavailable: {exc.reason}") from exc
        except (TimeoutError, json.JSONDecodeError) as exc:
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
