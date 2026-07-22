from __future__ import annotations

import pytest

from pii_airlock import detectors
from pii_airlock.detectors import ENSEMBLE_MODEL, LOCAL_MODELS, HybridDetector, LMStudioDetector, RuleDetector
from pii_airlock.models import DetectionError, Entity, EntityType


def test_rule_detector_does_not_treat_iso_date_as_phone() -> None:
    entities = RuleDetector().detect("Due 2026-07-20 under contract CN-2049")
    assert all(entity.type is not EntityType.PHONE for entity in entities)


def test_card_rule_does_not_capture_trailing_whitespace() -> None:
    entities = RuleDetector().detect("Card 4111 1111 1111 1111 in sandbox")
    card = next(item for item in entities if item.type is EntityType.CARD)
    assert card.value == "4111 1111 1111 1111"


def test_plain_at_before_real_email_does_not_expand_email_span() -> None:
    entities = RuleDetector().detect("Contact Elena Morozova at elena.morozova@example.test")
    emails = [item.value for item in entities if item.type is EntityType.EMAIL]
    assert emails == ["elena.morozova@example.test"]


def test_context_disambiguates_passport_and_tax_id() -> None:
    entities = RuleDetector().detect("Passport 4510 123456; tax ID 7701234567")
    pairs = {(entity.value, entity.type) for entity in entities}
    assert ("4510 123456", EntityType.PASSPORT) in pairs
    assert ("7701234567", EntityType.TAX_ID) in pairs


@pytest.mark.parametrize(
    "base_url",
    [
        "https://127.0.0.1:1234/v1",
        "http://user@127.0.0.1:1234/v1",
        "http://127.0.0.1:1234/not-v1",
        "http://127.0.0.1:1234/v1?debug=true",
        "http://localhost.attacker.test:1234/v1",
        "http://192.168.1.10:1234/v1",
    ],
)
def test_lm_studio_endpoint_is_loopback_v1(base_url: str) -> None:
    with pytest.raises(ValueError):
        LMStudioDetector(base_url=base_url)


@pytest.mark.parametrize("base_url", ["http://127.0.0.1:1234/v1", "http://localhost:1234/v1", "http://[::1]:1234/v1"])
def test_lm_studio_endpoint_accepts_every_loopback_spelling(base_url: str) -> None:
    assert LMStudioDetector(base_url=base_url).base_url == base_url


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


@pytest.mark.parametrize(
    ("text", "expected", "entity_type"),
    [
        ("Email alice\u200b@example.test", "alice\u200b@example.test", EntityType.EMAIL),
        ("Email alice [at] example [dot] test", "alice [at] example [dot] test", EntityType.EMAIL),
        ("Call +1 202\n555 0199", "+1 202\n555 0199", EntityType.PHONE),
        ("Key ｓｋ－SyntheticKey123456789", "ｓｋ－SyntheticKey123456789", EntityType.API_KEY),
    ],
)
def test_rule_detector_normalizes_obfuscation_but_returns_exact_source_span(
    text: str,
    expected: str,
    entity_type: EntityType,
) -> None:
    entities = {(item.value, item.type) for item in RuleDetector().detect(text)}
    assert (expected, entity_type) in entities


class _PerModelSemantic:
    """Each model finds a different value, and some models fail outright."""

    def __init__(self, by_model: dict[str, list[Entity]], failing: set[str] | None = None) -> None:
        self.by_model = by_model
        self.failing = failing or set()

    def detect(self, text: str, *, model: str):
        if model in self.failing:
            raise DetectionError("not exact", code="non_exact_substring")
        return list(self.by_model.get(model, []))


def test_ensemble_keeps_what_either_model_found() -> None:
    qwen, gemma = LOCAL_MODELS
    semantic = _PerModelSemantic(
        {
            qwen: [Entity("Elena Morozova", EntityType.PERSON)],
            gemma: [Entity("Northern Star", EntityType.ORG)],
        }
    )
    outcome = HybridDetector(semantic).detect_outcome(
        "Elena Morozova at Northern Star, alice@example.test",
        model=ENSEMBLE_MODEL,
    )
    found = {(item.value, item.type) for item in outcome.entities}
    assert ("Elena Morozova", EntityType.PERSON) in found
    assert ("Northern Star", EntityType.ORG) in found
    assert ("alice@example.test", EntityType.EMAIL) in found
    assert outcome.warnings == ()
    assert outcome.requires_manual_review is False


def test_ensemble_survives_one_failing_model_but_says_so() -> None:
    qwen, gemma = LOCAL_MODELS
    semantic = _PerModelSemantic({gemma: [Entity("Northern Star", EntityType.ORG)]}, failing={qwen})
    outcome = HybridDetector(semantic).detect_outcome("Northern Star", model=ENSEMBLE_MODEL)
    assert ("Northern Star", EntityType.ORG) in {(item.value, item.type) for item in outcome.entities}
    assert outcome.warnings == ("semantic_detector_qwen3.5-9b_non_exact_substring",)
    assert outcome.requires_manual_review is False


def test_ensemble_requires_review_when_every_model_fails() -> None:
    semantic = _PerModelSemantic({}, failing=set(LOCAL_MODELS))
    outcome = HybridDetector(semantic).detect_outcome("Email alice@example.test", model=ENSEMBLE_MODEL)
    assert [(item.value, item.type) for item in outcome.entities] == [("alice@example.test", EntityType.EMAIL)]
    assert len(outcome.warnings) == len(LOCAL_MODELS)
    assert outcome.requires_manual_review is True


def test_hybrid_preserves_rule_spans_but_requires_review_when_semantic_detector_fails() -> None:
    class FailingSemantic:
        def detect(self, text: str, *, model: str):
            raise DetectionError("not exact", code="non_exact_substring")

    outcome = HybridDetector(FailingSemantic()).detect_outcome("Email alice@example.test", model="test")
    assert [(item.value, item.type) for item in outcome.entities] == [("alice@example.test", EntityType.EMAIL)]
    assert outcome.warnings == ("semantic_detector_non_exact_substring",)
    assert outcome.requires_manual_review is True
