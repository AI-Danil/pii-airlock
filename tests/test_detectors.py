from __future__ import annotations

import pytest

from pii_airlock import detectors
from pii_airlock.detectors import LMStudioDetector, RuleDetector
from pii_airlock.models import EntityType


def test_rule_detector_does_not_treat_iso_date_as_phone() -> None:
    entities = RuleDetector().detect("Due 2026-07-20 under contract CN-2049")
    assert all(entity.type is not EntityType.PHONE for entity in entities)


def test_context_disambiguates_passport_and_tax_id() -> None:
    entities = RuleDetector().detect("Passport 4510 123456; tax ID 7701234567")
    pairs = {(entity.value, entity.type) for entity in entities}
    assert ("4510 123456", EntityType.PASSPORT) in pairs
    assert ("7701234567", EntityType.TAX_ID) in pairs


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:1234/v1",
        "https://127.0.0.1:1234/v1",
        "http://user@127.0.0.1:1234/v1",
        "http://127.0.0.1:1234/not-v1",
        "http://127.0.0.1:1234/v1?debug=true",
    ],
)
def test_lm_studio_endpoint_is_literal_loopback_v1(base_url: str) -> None:
    with pytest.raises(ValueError):
        LMStudioDetector(base_url=base_url)


def test_lm_studio_timeout_must_be_positive() -> None:
    with pytest.raises(ValueError):
        LMStudioDetector(timeout=0)


def test_reasoning_content_compatibility_is_still_schema_validated(monkeypatch) -> None:
    monkeypatch.setattr(
        detectors,
        "_post_json",
        lambda *_args: {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "reasoning_content": '{"entities":[{"value":"Ada","type":"PERSON"}]}',
                    }
                }
            ]
        },
    )
    entities = LMStudioDetector().detect("Ada signed.", model="qwen/qwen3.5-9b")
    assert [(item.value, item.type) for item in entities] == [("Ada", EntityType.PERSON)]


def test_contextual_rules_cover_contract_and_secret_labels() -> None:
    text = "Agreement US-DEMO-204; temporary phrase DEMO-ACCESS-OMEGA-9911."
    entities = {(item.value, item.type) for item in RuleDetector().detect(text)}
    assert ("US-DEMO-204", EntityType.CONTRACT_ID) in entities
    assert ("DEMO-ACCESS-OMEGA-9911", EntityType.OTHER_SECRET) in entities
