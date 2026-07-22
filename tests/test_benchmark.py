from __future__ import annotations

import json

from pii_airlock.benchmark import run_benchmark
from pii_airlock.detectors import RuleDetector


def test_benchmark_reports_per_type_language_clean_and_adversarial_metrics(tmp_path) -> None:
    cases = [
        {
            "id": "positive",
            "language": "en",
            "category": "unicode",
            "text": "Email demo\u200b.user@example.test",
            "entities": [{"value": "demo\u200b.user@example.test", "type": "EMAIL"}],
        },
        {
            "id": "clean",
            "language": "en",
            "category": "clean-negative",
            "text": "A synthetic description without contact data.",
            "entities": [],
        },
    ]
    fixture = tmp_path / "cases.jsonl"
    fixture.write_text("\n".join(json.dumps(case) for case in cases), encoding="utf-8")

    events = []
    report = run_benchmark(
        fixture,
        models=["rules"],
        detector=RuleDetector(),
        progress=lambda *event: events.append(event),
    )["models"][0]
    assert report["entity_recall"] == 1.0
    assert report["entity_precision"] == 1.0
    assert report["per_type"]["EMAIL"]["recall"] == 1.0
    assert report["per_language"]["en"]["recall"] == 1.0
    assert report["clean_cases"] == 1
    assert report["clean_cases_without_detections"] == 1
    assert report["adversarial_cases"] == 2
    assert report["fixture_assisted_review_passes"] == 1
    assert events == [("rules", 1, 2, "positive"), ("rules", 2, 2, "clean")]
