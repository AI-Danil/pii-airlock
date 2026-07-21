from __future__ import annotations

from fastapi.testclient import TestClient

from pii_airlock.api import MAX_HTTP_BODY_BYTES, create_app
from pii_airlock.documents import MAX_BYTES
from pii_airlock.models import Entity, EntityType
from pii_airlock.service import AirlockService, OperationStore

BASE_URL = "http://127.0.0.1:8787"
ORIGIN_HEADERS = {"Origin": BASE_URL}
API_TOKEN = "synthetic-local-token-000000000000"


class StaticDetector:
    def detect(self, text: str, *, model: str):
        return [Entity("Alice Carter", EntityType.PERSON)]


def _app(*, api_token: str = "", store: OperationStore | None = None):
    service = AirlockService(detector=StaticDetector(), cloud_client=None, store=store)
    return create_app(service, api_token=api_token)


def _client(app) -> TestClient:
    return TestClient(app, base_url=BASE_URL, client=("127.0.0.1", 50_000))


def _operation_payload() -> dict[str, str]:
    return {
        "text": "Alice Carter needs a summary.",
        "task": "Summarize",
        "model": "qwen/qwen3.5-9b",
    }


def test_health_and_cookie_authenticated_dry_run_operation() -> None:
    with _client(_app()) as client:
        health = client.get("/api/v1/health")
        assert health.status_code == 200
        assert health.json()["stateless_api_enabled"] is False
        client.get("/")
        response = client.post("/api/v1/operations", json=_operation_payload(), headers=ORIGIN_HEADERS)
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "READY_FOR_REVIEW"
        assert "Alice Carter" not in payload["sanitized_fields"]["text"]
        assert payload["redactions"][0]["field"] == "text"
        assert "value" not in payload["redactions"][0]
        completion = client.post(
            f"/api/v1/operations/{payload['operation_id']}/complete",
            headers=ORIGIN_HEADERS,
        )
        assert completion.json()["cloud_status"] == "DRY_RUN"


def test_web_ui_sets_http_only_strict_session_cookie() -> None:
    with _client(_app()) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "PII Airlock" in response.text
        cookie = response.headers["set-cookie"]
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie


def test_remote_client_and_non_loopback_host_are_rejected() -> None:
    app = _app()
    with TestClient(app, base_url=BASE_URL, client=("203.0.113.10", 50_000)) as remote:
        assert remote.get("/api/v1/health").status_code == 403
    app = _app()
    with TestClient(app, base_url="http://testserver", client=("127.0.0.1", 50_000)) as bad_host:
        assert bad_host.get("/api/v1/health").status_code == 403
    app = _app()
    with _client(app) as bad_port:
        assert bad_port.get("/api/v1/health", headers={"Host": "127.0.0.1:notaport"}).status_code == 403


def test_session_writes_require_cookie_and_exact_origin() -> None:
    with _client(_app()) as client:
        assert client.post("/api/v1/operations", json=_operation_payload(), headers=ORIGIN_HEADERS).status_code == 401
        client.get("/")
        missing_origin = client.post("/api/v1/operations", json=_operation_payload())
        assert missing_origin.status_code == 403
        wrong_origin = client.post(
            "/api/v1/operations",
            json=_operation_payload(),
            headers={"Origin": "https://attacker.example"},
        )
        assert wrong_origin.status_code == 403
    service = AirlockService(detector=StaticDetector(), cloud_client=None)
    app = create_app(service, enforce_loopback=False)
    with TestClient(app, base_url="http://example.test", client=("203.0.113.10", 50_000)) as externally_served:
        assert externally_served.post("/api/v1/operations", json=_operation_payload()).status_code == 401


def test_bearer_auth_works_without_browser_cookie_and_token_is_not_in_health() -> None:
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    with _client(_app(api_token=API_TOKEN)) as client:
        health_text = client.get("/api/v1/health").text
        assert API_TOKEN not in health_text
        response = client.post("/api/v1/operations", json=_operation_payload(), headers=headers)
        assert response.status_code == 200


def test_stateless_api_is_disabled_without_token_and_requires_valid_bearer() -> None:
    payload = {
        "instructions": "Summarize",
        "input_text": "Alice Carter needs a summary.",
        "model": "qwen/qwen3.5-9b",
    }
    with _client(_app()) as client:
        disabled = client.post("/api/v1/complete", json=payload)
        assert disabled.status_code == 503
        assert disabled.json()["detail"]["code"] == "stateless_api_disabled"
    with _client(_app(api_token=API_TOKEN)) as client:
        unauthorized = client.post("/api/v1/complete", json=payload)
        assert unauthorized.status_code == 401
        completed = client.post(
            "/api/v1/complete",
            json=payload,
            headers={"Authorization": f"Bearer {API_TOKEN}"},
        )
        assert completed.status_code == 200
        assert completed.json()["cloud_status"] == "DRY_RUN"


def test_operation_capacity_returns_429() -> None:
    store = OperationStore(max_operations=1)
    with _client(_app(store=store)) as client:
        client.get("/")
        first = client.post("/api/v1/operations", json=_operation_payload(), headers=ORIGIN_HEADERS)
        assert first.status_code == 200
        second = client.post("/api/v1/operations", json=_operation_payload(), headers=ORIGIN_HEADERS)
        assert second.status_code == 429
        assert second.json()["detail"]["code"] == "operation_capacity_exceeded"


def test_declared_and_chunked_http_bodies_are_bounded() -> None:
    with _client(_app()) as client:
        client.get("/")
        declared = client.post(
            "/api/v1/operations",
            content=b"{}",
            headers={**ORIGIN_HEADERS, "Content-Length": str(MAX_HTTP_BODY_BYTES + 1)},
        )
        assert declared.status_code == 413

        def chunks():
            yield b"x" * (MAX_HTTP_BODY_BYTES // 2)
            yield b"x" * (MAX_HTTP_BODY_BYTES // 2 + 1)

        chunked = client.post(
            "/api/v1/operations",
            content=chunks(),
            headers={**ORIGIN_HEADERS, "Transfer-Encoding": "chunked"},
        )
        assert chunked.status_code == 413


def test_document_over_file_limit_returns_413() -> None:
    with _client(_app()) as client:
        client.get("/")
        response = client.post(
            "/api/v1/documents/extract",
            files={"file": ("too-large.txt", b"x" * (MAX_BYTES + 1), "text/plain")},
            headers=ORIGIN_HEADERS,
        )
        assert response.status_code == 413
        assert response.json()["detail"]["code"] == "document_too_large"


def test_cookie_authenticated_manual_redaction_review_is_source_bound() -> None:
    with _client(_app()) as client:
        client.get("/")
        created = client.post("/api/v1/operations", json=_operation_payload(), headers=ORIGIN_HEADERS).json()
        span = created["redactions"][0]
        reviewed = client.patch(
            f"/api/v1/operations/{created['operation_id']}/redactions",
            headers=ORIGIN_HEADERS,
            json={
                "task": _operation_payload()["task"],
                "text": _operation_payload()["text"],
                "edits": [
                    {
                        "action": "retag",
                        "field": span["field"],
                        "start": span["start"],
                        "end": span["end"],
                        "type": "OTHER_SECRET",
                    }
                ],
            },
        )
        assert reviewed.status_code == 200
        assert reviewed.json()["review_revision"] == 1
        assert reviewed.json()["redactions"][0]["type"] == "OTHER_SECRET"

        mismatch = client.patch(
            f"/api/v1/operations/{created['operation_id']}/redactions",
            headers=ORIGIN_HEADERS,
            json={
                "task": _operation_payload()["task"],
                "text": "Changed source",
                "edits": [{"action": "add", "field": "text", "start": 0, "end": 7, "type": "PERSON"}],
            },
        )
        assert mismatch.status_code == 422
        assert mismatch.json()["detail"]["code"] == "invalid_redaction_review"
