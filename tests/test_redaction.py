from __future__ import annotations

import pytest

from pii_airlock.models import DetectionError, Entity, EntityType, UnknownTokenError
from pii_airlock.redaction import audit_cloud_tokens, redact_fields, redact_spans, restore_text


def test_redacts_longest_values_and_reuses_stable_token() -> None:
    fields = {"task": "Reply to Elena", "text": "Elena Morozova asked Elena Morozova to call +1 202 555 0199."}
    entities = [
        Entity("Elena", EntityType.PERSON),
        Entity("Elena Morozova", EntityType.PERSON),
        Entity("+1 202 555 0199", EntityType.PHONE),
    ]
    result = redact_fields(fields, entities, nonce="A1B2C3D4")

    assert "Elena Morozova" not in result.sanitized_fields["text"]
    person_token = "__PII_A1B2C3D4_PERSON_0001__"
    assert result.sanitized_fields["text"].count(person_token) == 2
    assert restore_text(result.sanitized_fields["text"], result.mapping) == fields["text"]
    assert {item.field for item in result.redactions} == {"task", "text"}


def test_nested_value_is_not_retained_without_a_separate_occurrence() -> None:
    result = redact_fields(
        {"text": "Elena Morozova"},
        [Entity("Elena Morozova", EntityType.PERSON), Entity("Elena", EntityType.PERSON)],
        nonce="A1B2C3D4",
    )
    assert list(result.mapping.values()) == ["Elena Morozova"]
    assert [item.start for item in result.redactions] == [0]


def test_short_value_is_retained_at_a_non_overlapping_occurrence() -> None:
    result = redact_fields(
        {"text": "Elena Morozova called Elena"},
        [Entity("Elena Morozova", EntityType.PERSON), Entity("Elena", EntityType.PERSON)],
        nonce="A1B2C3D4",
    )
    assert list(result.mapping.values()) == ["Elena Morozova", "Elena"]
    assert [(item.start, item.end) for item in result.redactions] == [(0, 14), (22, 27)]


def test_redaction_spans_are_field_local_and_public_metadata_has_no_raw_value() -> None:
    result = redact_fields(
        {"task": "Email Elena", "text": "Elena Morozova"},
        [Entity("Elena Morozova", EntityType.PERSON), Entity("Elena", EntityType.PERSON)],
        nonce="A1B2C3D4",
    )
    assert [(item.field, item.start, item.end) for item in result.redactions] == [
        ("task", 6, 11),
        ("text", 0, 14),
    ]


def test_rejects_entity_not_present_in_input() -> None:
    with pytest.raises(DetectionError):
        redact_fields({"text": "safe"}, [Entity("invented", EntityType.PERSON)], nonce="A1B2C3D4")


def test_rejects_reserved_token_in_source() -> None:
    with pytest.raises(DetectionError):
        redact_fields({"text": "__PII_A1B2C3D4_PERSON_0001__"}, [], nonce="A1B2C3D4")


def test_rejects_malformed_reserved_prefix_in_source() -> None:
    with pytest.raises(DetectionError):
        redact_fields({"text": "Do not alter __pii_incomplete"}, [], nonce="A1B2C3D4")


def test_unknown_cloud_token_is_blocked() -> None:
    with pytest.raises(UnknownTokenError):
        restore_text("Forged __PII_A1B2C3D4_PERSON_9999__", {"__PII_A1B2C3D4_PERSON_0001__": "Elena"})


def test_altered_cloud_token_is_blocked() -> None:
    mapping = {"__PII_A1B2C3D4_PERSON_0001__": "Elena"}
    with pytest.raises(UnknownTokenError):
        restore_text("Altered __PII_A1B2C3D4_PERSON_0001_CHANGED__", mapping)


@pytest.mark.parametrize(
    "forged",
    ["__PII_", "__pii_A1B2C3D4_PERSON_0001__", "__PII_A1B2C3D4_PERSON_0001"],
)
def test_any_reserved_prefix_left_by_cloud_is_blocked(forged: str) -> None:
    with pytest.raises(UnknownTokenError):
        restore_text(f"Altered {forged}", {"__PII_A1B2C3D4_PERSON_0001__": "Elena"})


def test_generated_nonce_has_128_bits() -> None:
    result = redact_fields({"text": "Elena"}, [Entity("Elena", EntityType.PERSON)])
    assert len(result.nonce) == 32


def test_manual_span_redaction_does_not_expand_to_an_unselected_duplicate() -> None:
    text = "Elena called Elena"
    result = redact_spans({"text": text}, {"text": [(0, 5, EntityType.PERSON)]}, nonce="A1B2C3D4")
    assert result.sanitized_fields["text"] == "__PII_A1B2C3D4_PERSON_0001__ called Elena"
    assert len(result.redactions) == 1


def test_cloud_cannot_duplicate_a_known_token_beyond_outbound_limit() -> None:
    token = "__PII_A1B2C3D4_PERSON_0001__"
    mapping = {token: "Elena"}
    with pytest.raises(UnknownTokenError, match="duplicated"):
        restore_text(f"{token} {token}", mapping, max_occurrences={token: 1})


def test_omitted_known_token_is_reported_without_restoring_raw_data() -> None:
    token = "__PII_A1B2C3D4_PERSON_0001__"
    audit = audit_cloud_tokens("No name is needed.", {token: "Elena"}, max_occurrences={token: 1})
    assert audit == {"observed_token_counts": {token: 0}, "omitted_tokens": [token]}
