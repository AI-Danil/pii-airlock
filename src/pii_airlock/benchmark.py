from __future__ import annotations

import json
import statistics
import time
from collections import Counter
from pathlib import Path

from .detectors import HybridDetector, LMStudioDetector
from .gate import assert_no_deterministic_leaks
from .models import AirlockError, DetectionError, GateBlocked
from .redaction import redact_fields, restore_text


def load_cases(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_benchmark(path: Path, *, models: list[str]) -> dict[str, object]:
    cases = load_cases(path)
    detector = HybridDetector(LMStudioDetector())
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
        case_results: list[dict[str, object]] = []
        for case in cases:
            text = str(case["text"])
            expected = {(item["value"], item["type"]) for item in case["entities"]}
            total_expected += len(expected)
            started = time.perf_counter()
            try:
                entities = detector.detect(text, model=model)
                actual = {(entity.value, entity.type.value) for entity in entities}
                detected_expected += len(expected & actual)
                extra_replacement_values += len({value for value, _ in actual} - {value for value, _ in expected})
                redaction = redact_fields({"text": text}, entities)
                assert_no_deterministic_leaks(redaction)
                runtime_gate_passes += 1
                leaked = [value for value, _ in expected if value in redaction.sanitized_fields["text"]]
                cloud_echo = "Acknowledged: " + " ".join(redaction.mapping)
                restored = restore_text(cloud_echo, redaction.mapping)
                if all(value in restored for value in redaction.mapping.values()):
                    deterministic_restoration_checks += 1
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
            case_results.append({"id": case["id"], "status": status, "seconds": round(duration, 3)})
        reports.append(
            {
                "model": model,
                "cases": len(cases),
                "runtime_gate_passes": runtime_gate_passes,
                "fixture_oracle_passes": fixture_oracle_passes,
                "known_control_leak_cases_after_runtime_gate": known_control_leak_cases,
                "known_control_values_in_oracle_passes": 0,
                "entity_recall": round(detected_expected / total_expected, 4) if total_expected else None,
                "extra_replacement_values": extra_replacement_values,
                "detection_failures": detection_failures,
                "detection_failures_by_code": dict(sorted(detection_failures_by_code.items())),
                "runtime_gate_blocks": runtime_gate_blocks,
                "deterministic_restoration_checks": deterministic_restoration_checks,
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
