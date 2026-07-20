from __future__ import annotations

from pii_airlock import detectors
from pii_airlock.detectors import LMStudioDetector, RuleDetector
from pii_airlock.models import EntityType


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
