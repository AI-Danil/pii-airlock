from __future__ import annotations

from collections import Counter

from .detectors import RuleDetector
from .models import GateBlocked, RedactionResult
from .redaction import RESERVED_TOKEN_PREFIX, TOKEN_PATTERN


def assert_no_deterministic_leaks(result: RedactionResult) -> None:
    reasons: list[str] = []
    rule_detector = RuleDetector()
    for name, text in result.sanitized_fields.items():
        for token in TOKEN_PATTERN.findall(text):
            if token not in result.mapping:
                reasons.append(f"Unknown reserved token in {name}")
        without_known_tokens = text
        for token in result.mapping:
            without_known_tokens = without_known_tokens.replace(token, "")
        if RESERVED_TOKEN_PREFIX.casefold() in without_known_tokens.casefold():
            reasons.append(f"Malformed reserved token in {name}")
        residual = rule_detector.detect(without_known_tokens)
        if residual:
            counts = Counter(entity.type.value for entity in residual)
            summary = ", ".join(f"{kind}:{count}" for kind, count in sorted(counts.items()))
            reasons.append(f"Residual high-confidence sensitive data in {name}: {summary}")
    if not result.mapping:
        reasons.append("No sensitive entities were detected; manual review required before cloud send.")
    if reasons:
        raise GateBlocked(reasons)


def entity_counts(result: RedactionResult) -> dict[str, int]:
    counts = Counter(entity.type.value for entity in result.entities)
    return dict(sorted(counts.items()))
