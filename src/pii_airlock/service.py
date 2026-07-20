from __future__ import annotations

import os
import threading
import time
import uuid
from dataclasses import dataclass, field

from .clients import CloudClient, OpenAIResponsesClient
from .detectors import Detector, HybridDetector, LMStudioDetector
from .gate import assert_no_deterministic_leaks, entity_counts
from .models import AirlockError, GateBlocked, Operation
from .redaction import redact_fields, restore_text


@dataclass
class OperationStore:
    ttl_seconds: float = 600.0
    _items: dict[str, Operation] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def put(self, operation: Operation) -> None:
        with self._lock:
            self._purge_locked(time.monotonic())
            self._items[operation.id] = operation

    def get(self, operation_id: str) -> Operation:
        with self._lock:
            now = time.monotonic()
            self._purge_locked(now)
            operation = self._items.get(operation_id)
            if operation is None:
                raise AirlockError("Operation not found or expired.")
            return operation

    def delete(self, operation_id: str) -> bool:
        with self._lock:
            return self._items.pop(operation_id, None) is not None

    def _purge_locked(self, now: float) -> None:
        expired = [key for key, value in self._items.items() if value.expires_at <= now]
        for key in expired:
            self._items.pop(key, None)


class AirlockService:
    def __init__(
        self,
        detector: Detector | None = None,
        cloud_client: CloudClient | None = None,
        store: OperationStore | None = None,
    ) -> None:
        self.detector = detector or HybridDetector(LMStudioDetector())
        self.cloud_client = cloud_client if cloud_client is not None else _cloud_from_env()
        self.store = store or OperationStore()

    @property
    def cloud_enabled(self) -> bool:
        return self.cloud_client is not None

    def create_operation(self, *, text: str, task: str, model: str) -> Operation:
        combined = f"TASK\n{task}\nDOCUMENT\n{text}"
        entities = self.detector.detect(combined, model=model)
        redaction = redact_fields({"task": task, "text": text}, entities)
        now = time.monotonic()
        operation = Operation(
            id=uuid.uuid4().hex,
            model=model,
            sanitized_fields=redaction.sanitized_fields,
            mapping=redaction.mapping,
            entity_counts=entity_counts(redaction),
            created_at=now,
            expires_at=now + self.store.ttl_seconds,
        )
        try:
            assert_no_deterministic_leaks(redaction)
        except GateBlocked as exc:
            operation.status = "BLOCKED"
            operation.blocked_reasons = exc.reasons
            # A blocked operation cannot be completed. Retain the sanitized
            # preview, but destroy the only structure containing raw values.
            operation.mapping = {}
        self.store.put(operation)
        return operation

    def complete_operation(self, operation_id: str) -> dict[str, object]:
        operation = self.store.get(operation_id)
        if operation.status != "READY_FOR_REVIEW":
            try:
                raise GateBlocked(operation.blocked_reasons)
            finally:
                self.store.delete(operation_id)
        if not self.cloud_client:
            try:
                return {**operation.public_dict(), "cloud_status": "DRY_RUN", "restored_text": None}
            finally:
                self.store.delete(operation_id)
        try:
            outbound = operation.outbound_content()
            cloud_text = self.cloud_client.complete(
                instructions=outbound["instructions"],
                input_text=outbound["input_text"],
            )
            restored = restore_text(cloud_text, operation.mapping)
            return {**operation.public_dict(), "cloud_status": "COMPLETED", "restored_text": restored}
        finally:
            self.store.delete(operation_id)

    def complete_stateless(self, *, instructions: str, input_text: str, model: str) -> dict[str, object]:
        operation = self.create_operation(text=input_text, task=instructions, model=model)
        try:
            return self.complete_operation(operation.id)
        finally:
            self.store.delete(operation.id)


def _cloud_from_env() -> CloudClient | None:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None
    model = os.getenv("OPENAI_MODEL", "").strip()
    if not model:
        raise AirlockError("OPENAI_MODEL is required when OPENAI_API_KEY is set.")
    return OpenAIResponsesClient(
        api_key=api_key,
        model=model,
        base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
    )
