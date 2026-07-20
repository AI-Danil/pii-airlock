from __future__ import annotations

import pytest

from pii_airlock.models import AirlockError, Entity, EntityType, Operation, UnknownTokenError
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


def test_roundtrip_keeps_raw_value_out_of_cloud() -> None:
    cloud = EchoCloud()
    service = AirlockService(detector=StaticDetector(), cloud_client=cloud)
    operation = service.create_operation(text="Elena Morozova requests a reply.", task="Answer Elena Morozova", model="test")
    result = service.complete_operation(operation.id)

    assert "Elena Morozova" not in cloud.input_text
    assert "Elena Morozova" not in cloud.instructions
    assert result["restored_text"] == "Reply for Elena Morozova"
    with pytest.raises(AirlockError):
        service.store.get(operation.id)


def test_dry_run_returns_exact_payload_without_cloud() -> None:
    service = AirlockService(detector=StaticDetector(), cloud_client=None)
    operation = service.create_operation(text="Elena Morozova requests a reply.", task="Summarize", model="test")
    result = service.complete_operation(operation.id)
    assert result["cloud_status"] == "DRY_RUN"
    assert "Elena Morozova" not in result["sanitized_fields"]["text"]


def test_forged_cloud_token_is_blocked_and_mapping_destroyed() -> None:
    service = AirlockService(detector=StaticDetector(), cloud_client=ForgingCloud())
    operation = service.create_operation(text="Elena Morozova requests a reply.", task="Summarize", model="test")
    with pytest.raises(UnknownTokenError):
        service.complete_operation(operation.id)
    with pytest.raises(AirlockError):
        service.store.get(operation.id)


def test_expired_mapping_is_not_available() -> None:
    store = OperationStore()
    store.put(Operation("expired", "test", {}, {"token": "value"}, {}, 0, 0))
    with pytest.raises(AirlockError):
        store.get("expired")
