from __future__ import annotations

import pytest

from pii_airlock.models import DetectionError, Entity, EntityType, UnknownTokenError
from pii_airlock.redaction import redact_fields, restore_text


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


def test_rejects_entity_not_present_in_input() -> None:
    with pytest.raises(DetectionError):
        redact_fields({"text": "safe"}, [Entity("invented", EntityType.PERSON)], nonce="A1B2C3D4")


def test_rejects_reserved_token_in_source() -> None:
    with pytest.raises(DetectionError):
        redact_fields({"text": "__PII_A1B2C3D4_PERSON_0001__"}, [], nonce="A1B2C3D4")


def test_unknown_cloud_token_is_blocked() -> None:
    with pytest.raises(UnknownTokenError):
        restore_text("Forged __PII_A1B2C3D4_PERSON_9999__", {"__PII_A1B2C3D4_PERSON_0001__": "Elena"})


def test_altered_cloud_token_is_blocked() -> None:
    mapping = {"__PII_A1B2C3D4_PERSON_0001__": "Elena"}
    with pytest.raises(UnknownTokenError):
        restore_text("Altered __PII_A1B2C3D4_PERSON_0001_CHANGED__", mapping)
