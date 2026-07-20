from __future__ import annotations

from collections import Counter

from .detectors import RuleDetector
from .models import EntityType, GateBlocked, RedactionResult
from .redaction import TOKEN_PATTERN


def assert_safe_to_send(result: RedactionResult) -> None:
    reasons: list[str] = []
    rule_detector = RuleDetector()
    for name, text in result.sanitized_fields.items():
        residual = rule_detector.detect(text)
        if residual:
            counts = Counter(entity.type.value for entity in residual)
            summary = ", ".join(f"{kind}:{count}" for kind, count in sorted(counts.items()))
            reasons.append(f"Residual high-confidence sensitive data in {name}: {summary}")
        for token in TOKEN_PATTERN.findall(text):
            if token not in result.mapping:
                reasons.append(f"Unknown reserved token in {name}")
    if not result.mapping:
        reasons.append("No sensitive entities were detected; manual review required before cloud send.")
    if reasons:
        raise GateBlocked(reasons)


def entity_counts(result: RedactionResult) -> dict[str, int]:
    counts = Counter(entity.type.value for entity in result.entities)
    return dict(sorted(counts.items()))
