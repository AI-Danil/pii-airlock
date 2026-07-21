from __future__ import annotations

import re
import secrets
from collections import Counter

from .models import (
    DetectionError,
    Entity,
    EntityType,
    RedactionResult,
    RedactionSpan,
    ReviewError,
    TokenMode,
    UnknownTokenError,
)

RESERVED_TOKEN_PREFIX = "__PII_"
TOKEN_PATTERN = re.compile(r"__PII_[A-F0-9]{8,32}_(?:[A-Z][A-Z_]*_)?\d{4}__")


def redact_fields(
    fields: dict[str, str],
    entities: list[Entity],
    *,
    nonce: str | None = None,
    token_mode: TokenMode | str = TokenMode.OPAQUE,
) -> RedactionResult:
    _validate_fields(fields)

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

    selected_by_field: dict[str, list[tuple[int, int, Entity]]] = {}
    used_values: set[str] = set()
    for field_name, original in fields.items():
        candidates: list[tuple[int, int, Entity]] = []
        for entity in accepted:
            start = 0
            while True:
                start = original.find(entity.value, start)
                if start < 0:
                    break
                candidates.append((start, start + len(entity.value), entity))
                start += 1
        selected: list[tuple[int, int, Entity]] = []
        for start, end, entity in sorted(
            candidates,
            key=lambda item: (-(item[1] - item[0]), item[0], item[2].type.value, item[2].value),
        ):
            if any(start < chosen_end and end > chosen_start for chosen_start, chosen_end, _ in selected):
                continue
            selected.append((start, end, entity))
            used_values.add(entity.value)
        selected_by_field[field_name] = sorted(selected, key=lambda item: (item[0], item[1]))

    selections = {
        field: [(start, end, entity.type) for start, end, entity in spans] for field, spans in selected_by_field.items()
    }
    return redact_spans(fields, selections, nonce=nonce, token_mode=token_mode)


def redact_spans(
    fields: dict[str, str],
    spans_by_field: dict[str, list[tuple[int, int, EntityType]]],
    *,
    nonce: str | None = None,
    token_mode: TokenMode | str = TokenMode.OPAQUE,
) -> RedactionResult:
    """Redact only the exact reviewed source spans; never expand a manual choice globally."""
    _validate_fields(fields)
    safe_nonce = _validated_nonce(nonce)
    selected_token_mode = TokenMode(token_mode)
    selected_by_field: dict[str, list[tuple[int, int, Entity]]] = {}
    for field_name, original in fields.items():
        selected: list[tuple[int, int, Entity]] = []
        for start, end, entity_type in sorted(spans_by_field.get(field_name, []), key=lambda item: (item[0], item[1])):
            if start < 0 or end <= start or end > len(original):
                raise ReviewError(f"Invalid source span in {field_name}.")
            if any(start < chosen_end and end > chosen_start for chosen_start, chosen_end, _ in selected):
                raise ReviewError(f"Overlapping source spans in {field_name}.")
            selected.append((start, end, Entity(original[start:end], entity_type)))
        selected_by_field[field_name] = selected
    unknown_fields = set(spans_by_field) - set(fields)
    if unknown_fields:
        raise ReviewError("Review contains an unknown field.")

    mapping: dict[str, str] = {}
    entity_to_token: dict[tuple[str, EntityType], str] = {}
    type_counts: Counter[str] = Counter()
    used_entities: list[Entity] = []
    unique_entities = {
        (entity.value, entity.type): entity
        for field_name in fields
        for _start, _end, entity in selected_by_field[field_name]
    }
    for entity in sorted(unique_entities.values(), key=lambda item: (-len(item.value), item.type.value, item.value)):
        used_entities.append(entity)
        if selected_token_mode is TokenMode.TYPED:
            key = (entity.value, entity.type)
            type_counts[entity.type.value] += 1
            token = f"__PII_{safe_nonce}_{entity.type.value}_{type_counts[entity.type.value]:04d}__"
            entity_to_token[key] = token
            mapping[token] = entity.value

    sanitized: dict[str, str] = {}
    redactions: list[RedactionSpan] = []
    opaque_index = 0
    for field_name, original in fields.items():
        pieces: list[str] = []
        cursor = 0
        for start, end, entity in selected_by_field[field_name]:
            if selected_token_mode is TokenMode.TYPED:
                token = entity_to_token[(entity.value, entity.type)]
            else:
                opaque_index += 1
                token = f"__PII_{safe_nonce}_{opaque_index:04d}__"
                mapping[token] = entity.value
            pieces.extend((original[cursor:start], token))
            redactions.append(RedactionSpan(field_name, start, end, entity.type, token))
            cursor = end
        pieces.append(original[cursor:])
        sanitized[field_name] = "".join(pieces)
    return RedactionResult(
        sanitized,
        mapping,
        tuple(used_entities),
        tuple(redactions),
        safe_nonce,
        selected_token_mode,
    )


def audit_cloud_tokens(
    text: str,
    mapping: dict[str, str],
    *,
    max_occurrences: dict[str, int] | None = None,
) -> dict[str, object]:
    exact_tokens = set(TOKEN_PATTERN.findall(text))
    unknown = sorted(token for token in exact_tokens if token not in mapping)
    without_known_tokens = text
    for token in mapping:
        without_known_tokens = without_known_tokens.replace(token, "")
    reserved_fragment_remains = RESERVED_TOKEN_PREFIX.casefold() in without_known_tokens.casefold()
    if unknown or reserved_fragment_remains:
        raise UnknownTokenError("Cloud response contains unknown, altered or forged PII token(s).")
    observed = {token: text.count(token) for token in mapping}
    if max_occurrences is not None:
        overused = [token for token, count in observed.items() if count > max_occurrences.get(token, 0)]
        if overused:
            raise UnknownTokenError("Cloud response duplicated a PII token beyond its outbound occurrence limit.")
    return {
        "observed_token_counts": observed,
        "omitted_tokens": sorted(token for token, count in observed.items() if count == 0),
    }


def restore_text(
    text: str,
    mapping: dict[str, str],
    *,
    max_occurrences: dict[str, int] | None = None,
) -> str:
    audit_cloud_tokens(text, mapping, max_occurrences=max_occurrences)
    restored = text
    for token, value in mapping.items():
        restored = restored.replace(token, value)
    return restored


def _validate_fields(fields: dict[str, str]) -> None:
    if not fields or not any(value.strip() for value in fields.values()):
        raise DetectionError("At least one non-empty text field is required.", code="empty_input")
    for text in fields.values():
        if RESERVED_TOKEN_PREFIX.casefold() in text.casefold():
            raise DetectionError("Input already contains a reserved PII token.", code="reserved_token_in_input")


def _validated_nonce(nonce: str | None) -> str:
    safe_nonce = (nonce or secrets.token_hex(16)).upper()
    if not re.fullmatch(r"[A-F0-9]{8,32}", safe_nonce):
        raise ValueError("Nonce must be 8 to 32 uppercase hexadecimal characters.")
    return safe_nonce
