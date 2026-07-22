from __future__ import annotations

import pytest

from pii_airlock.human_review import score_against_human_review, validate_label_rows
from pii_airlock.models import ReviewError

ITEMS = [
    {"item_id": "one", "language": "en", "text": "Contact Alice Carter at alice@example.test."},
    {"item_id": "two", "language": "en", "text": "No labelled entity here."},
]
HUMAN = [
    {
        "item_id": "one",
        "entities": [
            {"value": "Alice Carter", "type": "PERSON"},
            {"value": "alice@example.test", "type": "EMAIL"},
        ],
    },
    {"item_id": "two", "entities": []},
]


def test_human_review_scorer_uses_exact_complete_labels_and_wilson_interval() -> None:
    predictions = [
        {"item_id": "one", "entities": [{"value": "Alice Carter", "type": "PERSON"}]},
        {"item_id": "two", "entities": []},
    ]
    report = score_against_human_review(ITEMS, HUMAN, predictions)
    assert report["precision"] == 1.0
    assert report["recall"] == 0.5
    assert report["recall_wilson_95"] is not None
    assert report["per_type"]["EMAIL"]["false_negatives"] == 1


def test_human_review_rejects_missing_items_and_non_exact_values() -> None:
    with pytest.raises(ReviewError, match="incomplete"):
        validate_label_rows(ITEMS, HUMAN[:1])
    invalid = [
        {"item_id": "one", "entities": [{"value": "Invented", "type": "PERSON"}]},
        {"item_id": "two", "entities": []},
    ]
    with pytest.raises(ReviewError, match="exact substring"):
        validate_label_rows(ITEMS, invalid)
