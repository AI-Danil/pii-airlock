from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any

from .models import Operation


@dataclass(frozen=True)
class ReceiptSigner:
    key: bytes
    persistent_key: bool = False
    build_commit: str = "unknown"

    @classmethod
    def from_env(cls) -> ReceiptSigner:
        configured = os.getenv("PII_AIRLOCK_RECEIPT_KEY", "").strip()
        if configured and len(configured) < 32:
            raise ValueError("PII_AIRLOCK_RECEIPT_KEY must contain at least 32 characters.")
        return cls(
            key=configured.encode("utf-8") if configured else secrets.token_bytes(32),
            persistent_key=bool(configured),
            build_commit=os.getenv("PII_AIRLOCK_BUILD_COMMIT", "unknown").strip() or "unknown",
        )

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self.key).hexdigest()[:16]

    def sign_operation(self, operation: Operation) -> dict[str, Any]:
        body: dict[str, Any] = {
            "version": 1,
            "operation_id": operation.id,
            "issued_at_unix": int(time.time()),
            "model": operation.model,
            "token_mode": operation.token_mode.value,
            "status": operation.status,
            "review_revision": operation.review_revision,
            "review_channel": operation.review_channel,
            "build_commit": self.build_commit,
            "key_id": self.key_id,
            "key_persistence": "configured" if self.persistent_key else "ephemeral_process_key",
            "source_fingerprints": {
                field: self._fingerprint(f"source:{digest}")
                for field, digest in sorted(operation.source_hashes.items())
            },
            "redactions": [
                {
                    "field": item.field,
                    "start": item.start,
                    "end": item.end,
                    "type": item.type.value,
                    "token_fingerprint": self._fingerprint(f"token:{item.token}"),
                }
                for item in operation.redactions
            ],
            "entity_counts": dict(sorted(operation.entity_counts.items())),
            "security_warnings": sorted(operation.security_warnings),
            "detector_warnings": sorted(operation.detector_warnings),
        }
        return {**body, "signature": self._signature(body)}

    def verify(self, receipt: dict[str, Any]) -> bool:
        signature = receipt.get("signature")
        if not isinstance(signature, str) or receipt.get("key_id") != self.key_id:
            return False
        body = {key: value for key, value in receipt.items() if key != "signature"}
        return hmac.compare_digest(signature, self._signature(body))

    def _fingerprint(self, value: str) -> str:
        return hmac.new(self.key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def _signature(self, body: dict[str, Any]) -> str:
        canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self.key, canonical, hashlib.sha256).hexdigest()
