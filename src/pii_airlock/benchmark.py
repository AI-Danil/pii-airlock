from __future__ import annotations

import json
import statistics
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from .detectors import Detector, HybridDetector, LMStudioDetector
from .gate import assert_no_deterministic_leaks
from .models import AirlockError, DetectionError, Entity, EntityType, GateBlocked
from .redaction import redact_fields, restore_text


def load_cases(path: Path) -> list[dict[str, object]]:
    cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    ids = [str(case["id"]) for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("Benchmark case IDs must be unique.")
    for case in cases:
        for item in case["entities"]:
            EntityType(item["type"])
            if item["value"] not in case["text"]:
                raise ValueError(f"Fixture entity is not an exact substring: {case['id']}")
    return cases


def run_benchmark(
    path: Path,
    *,
    models: list[str],
    detector: Detector | None = None,
    progress: Callable[[str, int, int, str], None] | None = None,
) -> dict[str, object]:
    cases = load_cases(path)
    selected_detector = detector or HybridDetector(LMStudioDetector())
    reports: list[dict[str, object]] = []
    for model in models:
        durations: list[float] = []
        detected_expected = 0
        total_expected = 0
        extra_replacement_values = 0
        runtime_gate_passes = 0
        fixture_oracle_passes = 0
        deterministic_restoration_checks = 0
        detection_failures = 0
        detection_failures_by_code: Counter[str] = Counter()
        runtime_gate_blocks = 0
        known_control_leak_cases = 0
        true_positives = 0
        predicted_entities = 0
        per_type_expected: Counter[str] = Counter()
        per_type_predicted: Counter[str] = Counter()
        per_type_true_positive: Counter[str] = Counter()
        per_language_expected: Counter[str] = Counter()
        per_language_true_positive: Counter[str] = Counter()
        clean_cases = 0
        clean_cases_without_detections = 0
        adversarial_cases = 0
        fixture_assisted_review_passes = 0
        case_results: list[dict[str, object]] = []
        for case in cases:
            text = str(case["text"])
            expected = {(item["value"], item["type"]) for item in case["entities"]}
            language = str(case.get("language", "unknown"))
            category = str(case.get("category", "standard"))
            if not expected:
                clean_cases += 1
            if category != "standard":
                adversarial_cases += 1
            total_expected += len(expected)
            for _value, entity_type in expected:
                per_type_expected[entity_type] += 1
                per_language_expected[language] += 1
            started = time.perf_counter()
            actual: set[tuple[str, str]] = set()
            leaked: list[str] = []
            try:
                detect_outcome = getattr(selected_detector, "detect_outcome", None)
                if callable(detect_outcome):
                    outcome = detect_outcome(text, model=model)
                    entities = list(outcome.entities)
                    manual_warning = outcome.warnings[0] if outcome.requires_manual_review else None
                else:
                    entities = selected_detector.detect(text, model=model)
                    manual_warning = None
                actual = {(entity.value, entity.type.value) for entity in entities}
                case_true_positives = len(expected & actual)
                detected_expected += case_true_positives
                true_positives += case_true_positives
                predicted_entities += len(actual)
                for _value, entity_type in actual:
                    per_type_predicted[entity_type] += 1
                for _value, entity_type in expected & actual:
                    per_type_true_positive[entity_type] += 1
                    per_language_true_positive[language] += 1
                if not expected and not actual:
                    clean_cases_without_detections += 1
                extra_replacement_values += len({value for value, _ in actual} - {value for value, _ in expected})
                redaction = redact_fields({"text": text}, entities)
                assert_no_deterministic_leaks(redaction)
                leaked = [value for value, _ in expected if value in redaction.sanitized_fields["text"]]
                cloud_echo = "Acknowledged: " + " ".join(redaction.mapping)
                restored = restore_text(cloud_echo, redaction.mapping)
                if all(value in restored for value in redaction.mapping.values()):
                    deterministic_restoration_checks += 1
                if manual_warning:
                    detection_failures += 1
                    failure_code = manual_warning.removeprefix("semantic_detector_")
                    detection_failures_by_code[failure_code] += 1
                    status = f"blocked:{manual_warning}"
                else:
                    runtime_gate_passes += 1
                    if leaked:
                        known_control_leak_cases += 1
                        status = "blocked:fixture_oracle"
                    else:
                        fixture_oracle_passes += 1
                        status = "passed"
            except DetectionError as exc:
                detection_failures += 1
                detection_failures_by_code[exc.code] += 1
                status = f"blocked:{exc.code}"
            except GateBlocked as exc:
                runtime_gate_blocks += 1
                status = f"blocked:{type(exc).__name__}"
            except AirlockError as exc:
                runtime_gate_blocks += 1
                status = f"blocked:{type(exc).__name__}"
            duration = time.perf_counter() - started
            durations.append(duration)
            if expected:
                fixture_entities = [Entity(value, EntityType(entity_type)) for value, entity_type in expected]
                fixture_redaction = redact_fields({"text": text}, fixture_entities)
                try:
                    assert_no_deterministic_leaks(fixture_redaction)
                except GateBlocked:
                    pass
                else:
                    if not any(value in fixture_redaction.sanitized_fields["text"] for value, _ in expected):
                        fixture_assisted_review_passes += 1
            case_results.append(
                {
                    "id": case["id"],
                    "language": language,
                    "category": category,
                    "status": status,
                    "expected_entities": len(expected),
                    "true_positives": len(expected & actual),
                    "predicted_entities": len(actual),
                    "known_control_values_remaining": len(leaked),
                    "seconds": round(duration, 3),
                }
            )
            if progress is not None:
                progress(model, len(case_results), len(cases), str(case["id"]))
        per_type = {
            entity_type.value: _metrics(
                per_type_true_positive[entity_type.value],
                per_type_predicted[entity_type.value],
                per_type_expected[entity_type.value],
            )
            for entity_type in EntityType
        }
        per_language = {
            language: {
                "expected": per_language_expected[language],
                "true_positives": per_language_true_positive[language],
                "recall": _ratio(per_language_true_positive[language], per_language_expected[language]),
            }
            for language in sorted(per_language_expected)
        }
        reports.append(
            {
                "model": model,
                "cases": len(cases),
                "runtime_gate_passes": runtime_gate_passes,
                "fixture_oracle_passes": fixture_oracle_passes,
                "known_control_leak_cases_after_runtime_gate": known_control_leak_cases,
                "known_control_values_in_oracle_passes": 0,
                "entity_recall": round(detected_expected / total_expected, 4) if total_expected else None,
                "entity_precision": _ratio(true_positives, predicted_entities),
                "extra_replacement_values": extra_replacement_values,
                "detection_failures": detection_failures,
                "detection_failures_by_code": dict(sorted(detection_failures_by_code.items())),
                "runtime_gate_blocks": runtime_gate_blocks,
                "deterministic_restoration_checks": deterministic_restoration_checks,
                "clean_cases": clean_cases,
                "clean_cases_without_detections": clean_cases_without_detections,
                "adversarial_cases": adversarial_cases,
                "fixture_assisted_review_passes": fixture_assisted_review_passes,
                "per_type": per_type,
                "per_language": per_language,
                "latency_median_seconds": round(statistics.median(durations), 3) if durations else None,
                "latency_max_seconds": round(max(durations), 3) if durations else None,
                "case_results": case_results,
            }
        )
    return {
        "generated_from": str(path),
        "dataset_cases": len(cases),
        "scope": "Synthetic fixtures only. The fixture oracle is unavailable for arbitrary documents.",
        "models": reports,
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _metrics(true_positives: int, predicted: int, expected: int) -> dict[str, int | float | None]:
    return {
        "expected": expected,
        "predicted": predicted,
        "true_positives": true_positives,
        "false_positives": max(0, predicted - true_positives),
        "false_negatives": max(0, expected - true_positives),
        "precision": _ratio(true_positives, predicted),
        "recall": _ratio(true_positives, expected),
    }
