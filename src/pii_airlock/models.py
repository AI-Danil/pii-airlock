from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class EntityType(StrEnum):
    PERSON = "PERSON"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    ADDRESS = "ADDRESS"
    ORG = "ORG"
    CONTRACT_ID = "CONTRACT_ID"
    PASSPORT = "PASSPORT"
    TAX_ID = "TAX_ID"
    CARD = "CARD"
    API_KEY = "API_KEY"
    OTHER_SECRET = "OTHER_SECRET"


@dataclass(frozen=True)
class Entity:
    value: str
    type: EntityType


@dataclass(frozen=True)
class RedactionResult:
    sanitized_fields: dict[str, str]
    mapping: dict[str, str]
    entities: tuple[Entity, ...]
    nonce: str


@dataclass
class Operation:
    id: str
    model: str
    sanitized_fields: dict[str, str]
    mapping: dict[str, str]
    entity_counts: dict[str, int]
    created_at: float
    expires_at: float
    status: str = "SAFE_TO_SEND"
    blocked_reasons: list[str] = field(default_factory=list)

    def public_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.id,
            "model": self.model,
            "sanitized_fields": dict(self.sanitized_fields),
            "entity_counts": dict(self.entity_counts),
            "status": self.status,
            "blocked_reasons": list(self.blocked_reasons),
            "expires_at": self.expires_at,
        }


class AirlockError(RuntimeError):
    """Base error for a request that must not continue to cloud."""


class DetectionError(AirlockError):
    pass


class GateBlocked(AirlockError):
    def __init__(self, reasons: list[str]):
        self.reasons = reasons
        super().__init__("; ".join(reasons))


class UnknownTokenError(AirlockError):
    pass
