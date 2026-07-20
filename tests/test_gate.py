from __future__ import annotations

import pytest

from pii_airlock.gate import assert_no_deterministic_leaks
from pii_airlock.models import Entity, EntityType, GateBlocked
from pii_airlock.redaction import redact_fields


def test_gate_accepts_redacted_high_confidence_values() -> None:
    result = redact_fields(
        {"text": "Email alice@example.test and call +1 202 555 0147"},
        [Entity("alice@example.test", EntityType.EMAIL), Entity("+1 202 555 0147", EntityType.PHONE)],
        nonce="A1B2C3D4",
    )
    assert_no_deterministic_leaks(result)


def test_gate_does_not_classify_digits_inside_generated_token_as_phone() -> None:
    result = redact_fields(
        {"text": "Email alice@example.test"},
        [Entity("alice@example.test", EntityType.EMAIL)],
        nonce="01234567890123456789012345678901",
    )
    assert_no_deterministic_leaks(result)


def test_gate_blocks_residual_email() -> None:
    result = redact_fields(
        {"text": "Alice Carter uses alice@example.test"},
        [Entity("Alice Carter", EntityType.PERSON)],
        nonce="A1B2C3D4",
    )
    with pytest.raises(GateBlocked, match="Residual"):
        assert_no_deterministic_leaks(result)


def test_gate_requires_manual_review_when_nothing_detected() -> None:
    result = redact_fields({"text": "A generic paragraph."}, [], nonce="A1B2C3D4")
    with pytest.raises(GateBlocked, match="No sensitive entities"):
        assert_no_deterministic_leaks(result)
