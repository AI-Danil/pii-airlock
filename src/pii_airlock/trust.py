from __future__ import annotations

import re

_PROMPT_OVERRIDE = re.compile(
    r"(?:ignore|disregard|forget|override|игнорир(?:уй|овать)|забудь|отмени)\b.{0,80}"
    r"(?:instruction|prompt|system|правил|инструкц|промпт)",
    re.I | re.S,
)
_TOOL_ACTION = re.compile(
    r"(?:run|execute|call|open|browse|send|upload|delete|запусти|выполни|вызови|отправь|загрузи|удали)\b.{0,80}"
    r"(?:tool|command|shell|terminal|browser|email|file|инструмент|команд|терминал|браузер|письм|файл)",
    re.I | re.S,
)
_EXFILTRATION = re.compile(
    r"(?:reveal|print|return|send|exfiltrate|покажи|раскрой|выведи|верни|отправь)\b.{0,80}"
    r"(?:system prompt|secret|credential|api key|системн\w* промпт|секрет|ключ|парол)",
    re.I | re.S,
)


def inspect_untrusted_content(fields: dict[str, str]) -> list[str]:
    """Return warning codes only; privacy redaction is not a prompt-injection classifier."""
    corpus = "\n".join(fields.values())
    warnings: list[str] = []
    if _PROMPT_OVERRIDE.search(corpus):
        warnings.append("possible_instruction_override")
    if _TOOL_ACTION.search(corpus):
        warnings.append("possible_tool_or_external_action_request")
    if _EXFILTRATION.search(corpus):
        warnings.append("possible_secret_exfiltration_request")
    return warnings
