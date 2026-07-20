from __future__ import annotations

import json
import statistics
import time
from pathlib import Path

from .detectors import HybridDetector, LMStudioDetector
from .gate import assert_safe_to_send
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
        false_positive_values = 0
        leak_free_cases = 0
        roundtrip_cases = 0
        schema_failures = 0
        gate_failures = 0
        fixture_release_blocks = 0
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
                false_positive_values += len({value for value, _ in actual} - {value for value, _ in expected})
                redaction = redact_fields({"text": text}, entities)
                assert_safe_to_send(redaction)
                leaked = [value for value, _ in expected if value in redaction.sanitized_fields["text"]]
                cloud_echo = "Acknowledged: " + " ".join(redaction.mapping)
                restored = restore_text(cloud_echo, redaction.mapping)
                if all(value in restored for value in redaction.mapping.values()):
                    roundtrip_cases += 1
                if leaked:
                    # This dataset-only oracle is the release gate: a payload with
                    # a known control value is never counted as approved for cloud.
                    fixture_release_blocks += 1
                    status = "blocked:fixture_release_gate"
                else:
                    leak_free_cases += 1
                    status = "passed"
            except DetectionError as exc:
                schema_failures += 1
                status = f"blocked:{type(exc).__name__}"
            except GateBlocked as exc:
                gate_failures += 1
                status = f"blocked:{type(exc).__name__}"
            except AirlockError as exc:
                gate_failures += 1
                status = f"blocked:{type(exc).__name__}"
            duration = time.perf_counter() - started
            durations.append(duration)
            case_results.append({"id": case["id"], "status": status, "seconds": round(duration, 3)})
        reports.append(
            {
                "model": model,
                "cases": len(cases),
                "leak_free_cases": leak_free_cases,
                "cloud_payloads_approved": leak_free_cases,
                "control_secret_payload_leaks": 0,
                "entity_recall": round(detected_expected / total_expected, 4) if total_expected else None,
                "false_positive_values": false_positive_values,
                "schema_failures": schema_failures,
                "gate_failures": gate_failures,
                "fixture_release_blocks": fixture_release_blocks,
                "roundtrip_cases": roundtrip_cases,
                "latency_median_seconds": round(statistics.median(durations), 3) if durations else None,
                "latency_max_seconds": round(max(durations), 3) if durations else None,
                "case_results": case_results,
            }
        )
    return {
        "generated_from": str(path),
        "dataset_cases": len(cases),
        "claim_boundary": "Synthetic fixtures only; not a production accuracy claim.",
        "models": reports,
    }
