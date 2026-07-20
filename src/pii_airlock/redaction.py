from __future__ import annotations

import re
import secrets

from .models import DetectionError, Entity, RedactionResult

RESERVED_TOKEN_PREFIX = "__PII_"
TOKEN_PATTERN = re.compile(r"__PII_[A-F0-9]{8,32}_[A-Z_]+_\d{4}__")


def redact_fields(fields: dict[str, str], entities: list[Entity], *, nonce: str | None = None) -> RedactionResult:
    if not fields or not any(value.strip() for value in fields.values()):
        raise DetectionError("At least one non-empty text field is required.", code="empty_input")
    for text in fields.values():
        if RESERVED_TOKEN_PREFIX.casefold() in text.casefold():
            raise DetectionError("Input already contains a reserved PII token.", code="reserved_token_in_input")

    safe_nonce = (nonce or secrets.token_hex(16)).upper()
    if not re.fullmatch(r"[A-F0-9]{8,32}", safe_nonce):
        raise ValueError("Nonce must be 8 to 32 uppercase hexadecimal characters.")

    accepted: list[Entity] = []
    seen_values: set[str] = set()
    corpus = "\n".join(fields.values())
    for entity in sorted(entities, key=lambda item: (-len(item.value), item.type.value, item.value)):
        if not entity.value or entity.value in seen_values:
            continue
        if entity.value not in corpus:
            raise DetectionError(
                f"Entity is not an exact input substring: {entity.type.value}", code="non_exact_substring"
            )
        accepted.append(entity)
        seen_values.add(entity.value)

    mapping: dict[str, str] = {}
    value_to_token: dict[str, str] = {}
    type_counts: dict[str, int] = {}
    for entity in accepted:
        type_counts[entity.type.value] = type_counts.get(entity.type.value, 0) + 1
        token = f"__PII_{safe_nonce}_{entity.type.value}_{type_counts[entity.type.value]:04d}__"
        mapping[token] = entity.value
        value_to_token[entity.value] = token

    sanitized: dict[str, str] = {}
    for name, original in fields.items():
        value = original
        for entity in accepted:
            value = value.replace(entity.value, value_to_token[entity.value])
        sanitized[name] = value
    return RedactionResult(sanitized_fields=sanitized, mapping=mapping, entities=tuple(accepted), nonce=safe_nonce)


def restore_text(text: str, mapping: dict[str, str]) -> str:
    exact_tokens = set(TOKEN_PATTERN.findall(text))
    unknown = sorted(token for token in exact_tokens if token not in mapping)
    without_known_tokens = text
    for token in mapping:
        without_known_tokens = without_known_tokens.replace(token, "")
    reserved_fragment_remains = RESERVED_TOKEN_PREFIX.casefold() in without_known_tokens.casefold()
    if unknown or reserved_fragment_remains:
        from .models import UnknownTokenError

        raise UnknownTokenError("Cloud response contains unknown, altered or forged PII token(s).")
    restored = text
    for token, value in mapping.items():
        restored = restored.replace(token, value)
    return restored
