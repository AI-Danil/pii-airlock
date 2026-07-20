from __future__ import annotations

from fastapi.testclient import TestClient

from pii_airlock.api import create_app
from pii_airlock.models import Entity, EntityType
from pii_airlock.service import AirlockService


class StaticDetector:
    def detect(self, text: str, *, model: str):
        return [Entity("Alice Carter", EntityType.PERSON)]


def test_health_and_dry_run_operation() -> None:
    service = AirlockService(detector=StaticDetector(), cloud_client=None)
    client = TestClient(create_app(service))
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    response = client.post(
        "/api/v1/operations",
        json={"text": "Alice Carter needs a summary.", "task": "Summarize", "model": "qwen/qwen3.5-9b"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "SAFE_TO_SEND"
    assert "Alice Carter" not in payload["sanitized_fields"]["text"]
    completion = client.post(f"/api/v1/operations/{payload['operation_id']}/complete")
    assert completion.json()["cloud_status"] == "DRY_RUN"


def test_web_ui_is_served() -> None:
    client = TestClient(create_app(AirlockService(detector=StaticDetector(), cloud_client=None)))
    response = client.get("/")
    assert response.status_code == 200
    assert "PII Airlock" in response.text
