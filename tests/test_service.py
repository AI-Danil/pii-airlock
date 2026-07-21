from __future__ import annotations

import threading
import time

import pytest

from pii_airlock.models import (
    AirlockError,
    Entity,
    EntityType,
    GateBlocked,
    Operation,
    OperationNotFound,
    StoreCapacityError,
    UnknownTokenError,
)
from pii_airlock.service import AirlockService, OperationStore


class StaticDetector:
    def detect(self, text: str, *, model: str):
        return [Entity("Elena Morozova", EntityType.PERSON)]


class EchoCloud:
    def __init__(self) -> None:
        self.instructions = ""
        self.input_text = ""

    def complete(self, *, instructions: str, input_text: str) -> str:
        self.instructions = instructions
        self.input_text = input_text
        return f"Reply for {next(part for part in input_text.split() if part.startswith('__PII_'))}"


class ForgingCloud:
    def complete(self, *, instructions: str, input_text: str) -> str:
        return "__PII_DEADBEEF_PERSON_9999__"


class BlockingCloud:
    def __init__(self) -> None:
        self.calls = 0
        self.entered = threading.Event()
        self.release = threading.Event()

    def complete(self, *, instructions: str, input_text: str) -> str:
        self.calls += 1
        self.entered.set()
        assert self.release.wait(timeout=2)
        return next(part for part in input_text.split() if part.startswith("__PII_"))


def test_roundtrip_keeps_raw_value_out_of_cloud() -> None:
    cloud = EchoCloud()
    service = AirlockService(detector=StaticDetector(), cloud_client=cloud)
    operation = service.create_operation(
        text="Elena Morozova requests a reply.", task="Answer Elena Morozova", model="test"
    )
    result = service.complete_operation(operation.id)

    assert "Elena Morozova" not in cloud.input_text
    assert "Elena Morozova" not in cloud.instructions
    assert result["restored_text"] == "Reply for Elena Morozova"
    with pytest.raises(AirlockError):
        service.store.get(operation.id)
    service.close()


def test_dry_run_returns_exact_payload_without_cloud() -> None:
    service = AirlockService(detector=StaticDetector(), cloud_client=None)
    operation = service.create_operation(text="Elena Morozova requests a reply.", task="Summarize", model="test")
    result = service.complete_operation(operation.id)
    assert result["cloud_status"] == "DRY_RUN"
    assert "Elena Morozova" not in result["sanitized_fields"]["text"]
    service.close()


def test_forged_cloud_token_is_blocked_and_mapping_destroyed() -> None:
    service = AirlockService(detector=StaticDetector(), cloud_client=ForgingCloud())
    operation = service.create_operation(text="Elena Morozova requests a reply.", task="Summarize", model="test")
    with pytest.raises(UnknownTokenError):
        service.complete_operation(operation.id)
    with pytest.raises(AirlockError):
        service.store.get(operation.id)
    service.close()


def test_expired_mapping_is_not_available() -> None:
    store = OperationStore()
    store.put(Operation("expired", "test", {}, {"token": "value"}, {}, 0, 0))
    with pytest.raises(AirlockError):
        store.get("expired")
    store.close()


class EmptyDetector:
    def detect(self, text: str, *, model: str):
        return []


def test_blocked_operation_destroys_mapping_and_is_deleted_on_completion_attempt() -> None:
    service = AirlockService(detector=EmptyDetector(), cloud_client=None)
    operation = service.create_operation(text="Generic paragraph.", task="Summarize", model="test")
    assert operation.status == "BLOCKED"
    assert operation.mapping == {}
    with pytest.raises(GateBlocked):
        service.complete_operation(operation.id)
    with pytest.raises(AirlockError):
        service.store.get(operation.id)
    service.close()


def test_public_operation_exposes_relative_ttl_not_monotonic_clock() -> None:
    service = AirlockService(detector=StaticDetector(), cloud_client=None, store=OperationStore(ttl_seconds=60))
    operation = service.create_operation(text="Elena Morozova", task="Summarize", model="test")
    public = operation.public_dict()
    assert "expires_at" not in public
    assert 0 < public["expires_in_seconds"] <= 60
    assert public["redactions"] == [
        {
            "field": "text",
            "start": 0,
            "end": 14,
            "type": "PERSON",
            "token": public["sanitized_fields"]["text"],
        }
    ]
    service.close()


def test_completion_is_claimed_exactly_once_under_concurrency() -> None:
    cloud = BlockingCloud()
    service = AirlockService(detector=StaticDetector(), cloud_client=cloud)
    operation = service.create_operation(text="Elena Morozova", task="Reply", model="test")
    results: list[dict[str, object]] = []

    first = threading.Thread(target=lambda: results.append(service.complete_operation(operation.id)))
    first.start()
    assert cloud.entered.wait(timeout=2)
    with pytest.raises(OperationNotFound) as caught:
        service.complete_operation(operation.id)
    assert caught.value.code == "operation_not_found"
    cloud.release.set()
    first.join(timeout=2)
    assert not first.is_alive()

    assert cloud.calls == 1
    assert len(results) == 1
    assert operation.mapping == {}
    service.close()


def test_ttl_sweeper_clears_mapping_without_followup_access_and_stops() -> None:
    store = OperationStore(ttl_seconds=0.03)
    operation = Operation("expires", "test", {}, {"token": "value"}, {}, 0, time.monotonic() + 0.03)
    store.put(operation)
    deadline = time.monotonic() + 1
    while operation.mapping and time.monotonic() < deadline:
        time.sleep(0.01)
    assert operation.mapping == {}
    with pytest.raises(OperationNotFound):
        store.get(operation.id)
    store.close()
    assert not store._sweeper.is_alive()


def test_operation_capacity_is_bounded_and_rejected_mapping_is_cleared() -> None:
    store = OperationStore(max_operations=1)
    first = Operation("first", "test", {}, {"one": "value"}, {}, 0, time.monotonic() + 60)
    second = Operation("second", "test", {}, {"two": "value"}, {}, 0, time.monotonic() + 60)
    store.put(first)
    with pytest.raises(StoreCapacityError):
        store.put(second)
    assert second.mapping == {}
    store.close()
