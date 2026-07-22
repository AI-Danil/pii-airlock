"""Measure what the local model adds on top of deterministic rules.

Scoring matches src/pii_airlock/benchmark.py: an entity counts as found only
when both its exact value and its type match the fixture answer key.
"""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pii_airlock.benchmark import load_cases  # noqa: E402
from pii_airlock.detectors import HybridDetector, LMStudioDetector, RuleDetector  # noqa: E402

FIXTURES = ROOT / "fixtures" / "synthetic_cases.jsonl"
OUTPUT = ROOT / "docs" / "evaluation" / "baselines.json"
QWEN = "qwen/qwen3.5-9b"
GEMMA = "google/gemma-4-e4b"


def score(found_per_case: list[set[tuple[str, str]]], cases: list[dict]) -> dict[str, object]:
    expected_total = 0
    true_positives = 0
    predicted = 0
    per_type_expected: Counter[str] = Counter()
    per_type_found: Counter[str] = Counter()
    documents_fully_covered = 0
    documents_with_entities = 0
    values_left_for_the_person = 0

    for case, found in zip(cases, found_per_case):
        expected = {(item["value"], item["type"]) for item in case["entities"]}
        expected_total += len(expected)
        predicted += len(found)
        hits = expected & found
        true_positives += len(hits)
        for _value, entity_type in expected:
            per_type_expected[entity_type] += 1
        for _value, entity_type in hits:
            per_type_found[entity_type] += 1
        if expected:
            documents_with_entities += 1
            if expected <= found:
                documents_fully_covered += 1
            values_left_for_the_person += len(expected - found)

    return {
        "expected_values": expected_total,
        "found_values": true_positives,
        "predicted_values": predicted,
        "recall": round(true_positives / expected_total, 4) if expected_total else 0.0,
        "precision": round(true_positives / predicted, 4) if predicted else 0.0,
        "documents_with_entities": documents_with_entities,
        "documents_fully_covered": documents_fully_covered,
        "values_left_for_the_person": values_left_for_the_person,
        "per_type_recall": {
            entity_type: round(per_type_found[entity_type] / per_type_expected[entity_type], 4)
            for entity_type in sorted(per_type_expected)
        },
        "per_type_expected": dict(sorted(per_type_expected.items())),
    }


def main() -> None:
    cases = load_cases(FIXTURES)
    rules = RuleDetector()
    hybrid = HybridDetector(LMStudioDetector())

    started = time.perf_counter()
    rules_found = [{(entity.value, entity.type.value) for entity in rules.detect(str(case["text"]))} for case in cases]

    def run_model(model: str) -> list[set[tuple[str, str]]]:
        # One model at a time: alternating them makes LM Studio swap weights
        # between every single case.
        found: list[set[tuple[str, str]]] = []
        for index, case in enumerate(cases, start=1):
            try:
                outcome = hybrid.detect_outcome(str(case["text"]), model=model)
                found.append({(entity.value, entity.type.value) for entity in outcome.entities})
            except Exception as exc:  # a detector failure means "found nothing" for scoring
                print(f"  {model} failed on {case['id']}: {type(exc).__name__}", file=sys.stderr)
                found.append(set())
            print(f"[{model}] {index}/{len(cases)} {case['id']}", file=sys.stderr, flush=True)
        return found

    qwen_found = run_model(QWEN)
    gemma_found = run_model(GEMMA)

    union_found = [q | g for q, g in zip(qwen_found, gemma_found)]

    report = {
        "generated_from": "fixtures/synthetic_cases.jsonl",
        "dataset_cases": len(cases),
        "scope": (
            "Synthetic fixtures only. Scoring matches the published benchmark: exact value and type. "
            "Configurations differ only in the detector; the deterministic gate and review flow are identical."
        ),
        "elapsed_seconds": round(time.perf_counter() - started, 1),
        "configurations": {
            "rules_only": score(rules_found, cases),
            "rules_plus_qwen": score(qwen_found, cases),
            "rules_plus_gemma": score(gemma_found, cases),
            "rules_plus_both_models": score(union_found, cases),
        },
    }
    OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["configurations"], ensure_ascii=False, indent=2))
    print("written to", OUTPUT)


if __name__ == "__main__":
    main()
