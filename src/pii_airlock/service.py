from __future__ import annotations

import os
import threading
import time
import uuid
from dataclasses import dataclass, field

from .clients import CloudClient, OpenAIResponsesClient
from .detectors import Detector, HybridDetector, LMStudioDetector
from .gate import assert_no_deterministic_leaks, entity_counts
from .models import AirlockError, GateBlocked, Operation, OperationNotFound, StoreCapacityError
from .redaction import redact_fields, restore_text


@dataclass
class OperationStore:
    ttl_seconds: float = 600.0
    max_operations: int = 100
    _items: dict[str, Operation] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _condition: threading.Condition = field(init=False)
    _closed: bool = field(default=False, init=False)
    _sweeper: threading.Thread = field(init=False)

    def __post_init__(self) -> None:
        if self.ttl_seconds <= 0:
            raise ValueError("Operation TTL must be positive.")
        if self.max_operations <= 0:
            raise ValueError("Operation capacity must be positive.")
        self._condition = threading.Condition(self._lock)
        self._sweeper = threading.Thread(
            target=self._run_sweeper,
            name="pii-airlock-operation-sweeper",
            daemon=True,
        )
        self._sweeper.start()

    def put(self, operation: Operation) -> None:
        with self._condition:
            if self._closed:
                operation.mapping.clear()
                raise OperationNotFound("Operation store is closed.")
            self._purge_locked(time.monotonic())
            if len(self._items) >= self.max_operations and operation.id not in self._items:
                operation.mapping.clear()
                raise StoreCapacityError("Operation capacity has been reached.")
            self._items[operation.id] = operation
            self._condition.notify()

    def get(self, operation_id: str) -> Operation:
        with self._condition:
            now = time.monotonic()
            self._purge_locked(now)
            operation = self._items.get(operation_id)
            if operation is None:
                raise OperationNotFound("Operation not found, expired, or already claimed.")
            return operation

    def claim_for_completion(self, operation_id: str) -> Operation:
        with self._condition:
            self._purge_locked(time.monotonic())
            operation = self._items.pop(operation_id, None)
            if operation is None:
                raise OperationNotFound("Operation not found, expired, or already claimed.")
            self._condition.notify()
            return operation

    def delete(self, operation_id: str) -> bool:
        with self._condition:
            operation = self._items.pop(operation_id, None)
            if operation is None:
                return False
            operation.mapping.clear()
            self._condition.notify()
            return True

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            for operation in self._items.values():
                operation.mapping.clear()
            self._items.clear()
            self._condition.notify_all()
        if self._sweeper is not threading.current_thread():
            self._sweeper.join(timeout=2)

    def _purge_locked(self, now: float) -> None:
        expired = [key for key, value in self._items.items() if value.expires_at <= now]
        for key in expired:
            operation = self._items.pop(key, None)
            if operation is not None:
                operation.mapping.clear()

    def _run_sweeper(self) -> None:
        with self._condition:
            while not self._closed:
                now = time.monotonic()
                self._purge_locked(now)
                if self._closed:
                    return
                if not self._items:
                    self._condition.wait()
                    continue
                next_expiry = min(operation.expires_at for operation in self._items.values())
                self._condition.wait(timeout=max(0.0, next_expiry - now))


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
            redactions=redaction.redactions,
        )
        try:
            assert_no_deterministic_leaks(redaction)
        except GateBlocked as exc:
            operation.status = "BLOCKED"
            operation.blocked_reasons = exc.reasons
            # A blocked operation cannot be completed. Retain the sanitized
            # preview, but destroy the only structure containing raw values.
            operation.mapping = {}
        try:
            self.store.put(operation)
        except Exception:
            operation.mapping.clear()
            raise
        return operation

    def complete_operation(self, operation_id: str) -> dict[str, object]:
        operation = self.store.claim_for_completion(operation_id)
        try:
            if operation.status != "READY_FOR_REVIEW":
                raise GateBlocked(operation.blocked_reasons)
            if not self.cloud_client:
                return {**operation.public_dict(), "cloud_status": "DRY_RUN", "restored_text": None}
            outbound = operation.outbound_content()
            cloud_text = self.cloud_client.complete(
                instructions=outbound["instructions"],
                input_text=outbound["input_text"],
            )
            restored = restore_text(cloud_text, operation.mapping)
            return {**operation.public_dict(), "cloud_status": "COMPLETED", "restored_text": restored}
        finally:
            operation.mapping.clear()

    def complete_stateless(self, *, instructions: str, input_text: str, model: str) -> dict[str, object]:
        operation = self.create_operation(text=input_text, task=instructions, model=model)
        return self.complete_operation(operation.id)

    def close(self) -> None:
        self.store.close()


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
