from __future__ import annotations

import math
from collections import Counter
from typing import Any

from .models import EntityType, ReviewError


def validate_label_rows(items: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, set[tuple[str, str]]]:
    item_by_id = {str(item["item_id"]): item for item in items}
    if len(item_by_id) != len(items):
        raise ReviewError("Blind review item IDs must be unique.")
    labels: dict[str, set[tuple[str, str]]] = {}
    for row in rows:
        item_id = str(row.get("item_id", ""))
        if item_id not in item_by_id or item_id in labels:
            raise ReviewError("Review contains an unknown or duplicate item ID.")
        text = str(item_by_id[item_id]["text"])
        entities: set[tuple[str, str]] = set()
        raw_entities = row.get("entities")
        if not isinstance(raw_entities, list):
            raise ReviewError("Each review row requires an entities array.")
        for entity in raw_entities:
            if not isinstance(entity, dict):
                raise ReviewError("Each review entity must be an object.")
            value = str(entity.get("value", ""))
            entity_type = EntityType(str(entity.get("type", ""))).value
            if not value or value not in text:
                raise ReviewError("Every review value must be an exact substring of its blind item.")
            entities.add((value, entity_type))
        labels[item_id] = entities
    missing = sorted(set(item_by_id) - set(labels))
    if missing:
        raise ReviewError(f"Review is incomplete: {len(missing)} item(s) are missing.")
    return labels


def score_against_human_review(
    items: list[dict[str, Any]],
    human_rows: list[dict[str, Any]],
    prediction_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    reference = validate_label_rows(items, human_rows)
    predictions = validate_label_rows(items, prediction_rows)
    true_positives = 0
    predicted = 0
    expected = 0
    per_type_expected: Counter[str] = Counter()
    per_type_predicted: Counter[str] = Counter()
    per_type_true_positive: Counter[str] = Counter()
    case_results: list[dict[str, Any]] = []
    for item in items:
        item_id = str(item["item_id"])
        expected_entities = reference[item_id]
        predicted_entities = predictions[item_id]
        matched = expected_entities & predicted_entities
        true_positives += len(matched)
        predicted += len(predicted_entities)
        expected += len(expected_entities)
        for _value, entity_type in expected_entities:
            per_type_expected[entity_type] += 1
        for _value, entity_type in predicted_entities:
            per_type_predicted[entity_type] += 1
        for _value, entity_type in matched:
            per_type_true_positive[entity_type] += 1
        case_results.append(
            {
                "item_id": item_id,
                "expected": len(expected_entities),
                "predicted": len(predicted_entities),
                "true_positives": len(matched),
            }
        )
    precision = _ratio(true_positives, predicted)
    recall = _ratio(true_positives, expected)
    return {
        "scope": "Exact entity matches against completed independent human review.",
        "items": len(items),
        "expected_entities": expected,
        "predicted_entities": predicted,
        "true_positives": true_positives,
        "precision": precision,
        "recall": recall,
        "recall_wilson_95": _wilson_interval(true_positives, expected),
        "per_type": {
            entity_type.value: {
                "expected": per_type_expected[entity_type.value],
                "predicted": per_type_predicted[entity_type.value],
                "true_positives": per_type_true_positive[entity_type.value],
                "false_positives": max(
                    0,
                    per_type_predicted[entity_type.value] - per_type_true_positive[entity_type.value],
                ),
                "false_negatives": max(
                    0,
                    per_type_expected[entity_type.value] - per_type_true_positive[entity_type.value],
                ),
                "precision": _ratio(
                    per_type_true_positive[entity_type.value],
                    per_type_predicted[entity_type.value],
                ),
                "recall": _ratio(
                    per_type_true_positive[entity_type.value],
                    per_type_expected[entity_type.value],
                ),
            }
            for entity_type in EntityType
        },
        "case_results": case_results,
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total <= 0:
        return None
    proportion = successes / total
    denominator = 1 + z**2 / total
    center = (proportion + z**2 / (2 * total)) / denominator
    margin = z * math.sqrt((proportion * (1 - proportion) + z**2 / (4 * total)) / total) / denominator
    return [round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4)]
