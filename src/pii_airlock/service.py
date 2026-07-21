from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from .clients import CloudClient, OpenAIResponsesClient
from .detectors import Detector, HybridDetector, LMStudioDetector
from .gate import assert_no_deterministic_leaks, entity_counts
from .models import (
    AirlockError,
    EntityType,
    GateBlocked,
    Operation,
    OperationNotFound,
    ReviewError,
    ServiceBusyError,
    StoreCapacityError,
)
from .redaction import audit_cloud_tokens, redact_fields, redact_spans, restore_text
from .trust import inspect_untrusted_content


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

    def update(self, operation_id: str, updater: Callable[[Operation], None]) -> Operation:
        with self._condition:
            self._purge_locked(time.monotonic())
            operation = self._items.get(operation_id)
            if operation is None:
                raise OperationNotFound("Operation not found, expired, or already claimed.")
            updater(operation)
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
        max_concurrent_analyses: int = 4,
    ) -> None:
        if max_concurrent_analyses <= 0:
            raise ValueError("Analysis concurrency must be positive.")
        self.detector = detector or HybridDetector(LMStudioDetector())
        self.cloud_client = cloud_client if cloud_client is not None else _cloud_from_env()
        self.store = store or OperationStore()
        self._analysis_slots = threading.BoundedSemaphore(max_concurrent_analyses)

    @property
    def cloud_enabled(self) -> bool:
        return self.cloud_client is not None

    def create_operation(self, *, text: str, task: str, model: str) -> Operation:
        if not self._analysis_slots.acquire(blocking=False):
            raise ServiceBusyError("All local analysis slots are busy; retry later.")
        fields = {"task": task, "text": text}
        try:
            combined = f"TASK\n{task}\nDOCUMENT\n{text}"
            detect_outcome = getattr(self.detector, "detect_outcome", None)
            if callable(detect_outcome):
                outcome = detect_outcome(combined, model=model)
                entities = list(outcome.entities)
                detector_warnings = list(outcome.warnings)
                requires_manual_review = outcome.requires_manual_review
            else:
                entities = self.detector.detect(combined, model=model)
                detector_warnings = []
                requires_manual_review = False
            redaction = redact_fields(fields, entities)
        finally:
            self._analysis_slots.release()
        now = time.monotonic()
        operation = Operation(
            id=uuid.uuid4().hex,
            model=model,
            sanitized_fields=redaction.sanitized_fields,
            mapping=redaction.mapping,
            entity_counts=entity_counts(redaction),
            created_at=now,
            expires_at=now + self.store.ttl_seconds,
            source_hashes={name: _source_hash(value) for name, value in fields.items()},
            redactions=redaction.redactions,
            security_warnings=inspect_untrusted_content(fields),
            detector_warnings=detector_warnings,
        )
        try:
            assert_no_deterministic_leaks(redaction)
        except GateBlocked as exc:
            operation.status = "BLOCKED"
            operation.blocked_reasons = exc.reasons
            # A blocked operation cannot be completed. Retain the sanitized
            # preview, but destroy the only structure containing raw values.
            operation.mapping = {}
        if requires_manual_review:
            operation.status = "BLOCKED"
            operation.blocked_reasons.append(
                "The semantic detector failed; review the rule-based spans before cloud send."
            )
            operation.mapping.clear()
        try:
            self.store.put(operation)
        except Exception:
            operation.mapping.clear()
            raise
        return operation

    def review_redactions(
        self,
        operation_id: str,
        *,
        fields: dict[str, str],
        edits: list[dict[str, object]],
    ) -> Operation:
        def apply_review(operation: Operation) -> None:
            if set(fields) != {"task", "text"}:
                raise ReviewError("Review must contain the original task and text fields.")
            for name, value in fields.items():
                expected = operation.source_hashes.get(name, "")
                if not expected or not hmac.compare_digest(_source_hash(value), expected):
                    raise ReviewError("Review source does not match the analyzed operation.")

            spans: dict[str, list[tuple[int, int, EntityType]]] = {"task": [], "text": []}
            for item in operation.redactions:
                spans[item.field].append((item.start, item.end, item.type))
            for edit in edits:
                action = str(edit.get("action", ""))
                field_name = str(edit.get("field", ""))
                start = int(edit.get("start", -1))
                end = int(edit.get("end", -1))
                if field_name not in fields or start < 0 or end <= start or end > len(fields[field_name]):
                    raise ReviewError("Review contains an invalid source span.")
                matches = [
                    index
                    for index, (old_start, old_end, _old_type) in enumerate(spans[field_name])
                    if old_start == start and old_end == end
                ]
                if action == "remove":
                    if len(matches) != 1:
                        raise ReviewError("The redaction selected for removal was not found.")
                    spans[field_name].pop(matches[0])
                elif action == "add":
                    if matches:
                        raise ReviewError("The selected span is already redacted.")
                    spans[field_name].append((start, end, _entity_type(edit)))
                elif action == "retag":
                    if len(matches) != 1:
                        raise ReviewError("The redaction selected for retagging was not found.")
                    spans[field_name][matches[0]] = (start, end, _entity_type(edit))
                else:
                    raise ReviewError("Unknown redaction review action.")

            replacement = redact_spans(fields, spans)
            old_mapping = operation.mapping
            operation.sanitized_fields = replacement.sanitized_fields
            operation.mapping = replacement.mapping
            operation.redactions = replacement.redactions
            operation.entity_counts = entity_counts(replacement)
            operation.review_revision += 1
            operation.status = "READY_FOR_REVIEW"
            operation.blocked_reasons = []
            try:
                assert_no_deterministic_leaks(replacement)
            except GateBlocked as exc:
                operation.status = "BLOCKED"
                operation.blocked_reasons = exc.reasons
                operation.mapping = {}
            finally:
                old_mapping.clear()

        return self.store.update(operation_id, apply_review)

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
            token_limits = operation.token_limits()
            token_audit = audit_cloud_tokens(cloud_text, operation.mapping, max_occurrences=token_limits)
            restored = restore_text(cloud_text, operation.mapping, max_occurrences=token_limits)
            return {
                **operation.public_dict(),
                "cloud_status": "COMPLETED",
                "restored_text": restored,
                "token_audit": token_audit,
            }
        finally:
            operation.mapping.clear()

    def complete_stateless(self, *, instructions: str, input_text: str, model: str) -> dict[str, object]:
        operation = self.create_operation(text=input_text, task=instructions, model=model)
        if operation.security_warnings:
            self.store.delete(operation.id)
            raise GateBlocked(["Stateless mode rejected possible prompt injection or external-action instructions."])
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


def _source_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _entity_type(edit: dict[str, object]) -> EntityType:
    try:
        return EntityType(str(edit.get("type", "")))
    except ValueError as exc:
        raise ReviewError("Review action requires a supported entity type.") from exc
