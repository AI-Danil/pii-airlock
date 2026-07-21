from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal
from urllib import error, request
from urllib.parse import urlsplit

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from .detectors import SUPPORTED_MODELS
from .documents import MAX_BYTES, extract_bytes_with_manifest
from .models import AirlockError, OperationNotFound, ServiceBusyError, StoreCapacityError, TokenMode
from .service import AirlockService

LOGGER = logging.getLogger("pii_airlock.audit")
WEB_DIR = Path(__file__).with_name("web")
SESSION_COOKIE = "pii_airlock_session"
MAX_HTTP_BODY_BYTES = MAX_BYTES + 64 * 1024


class RequestBodyLimitMiddleware:
    def __init__(self, app, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = self.max_bytes + 1
            if declared_size > self.max_bytes:
                await _body_too_large_response(scope, receive, send)
                return

        consumed = 0
        messages = []
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":
                messages.append(message)
                break
            consumed += len(message.get("body", b""))
            if consumed > self.max_bytes:
                await _body_too_large_response(scope, receive, send)
                return
            messages.append(message)
            more_body = message.get("more_body", False)

        position = 0

        async def replay_receive():
            nonlocal position
            if position < len(messages):
                message = messages[position]
                position += 1
                return message
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)


async def _body_too_large_response(scope, receive, send) -> None:
    response = JSONResponse(
        status_code=413,
        content={"detail": {"code": "request_body_too_large", "message": "Request body exceeds the limit."}},
    )
    await response(scope, receive, send)


class OperationRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)
    task: str = Field(min_length=1, max_length=4_000)
    model: str = "qwen/qwen3.5-9b"
    token_mode: TokenMode = TokenMode.OPAQUE


class StatelessRequest(BaseModel):
    instructions: str = Field(min_length=1, max_length=4_000)
    input_text: str = Field(min_length=1, max_length=20_000)
    input_trust: Literal["untrusted"] = "untrusted"
    model: str = "qwen/qwen3.5-9b"
    token_mode: TokenMode = TokenMode.OPAQUE


class ReviewEdit(BaseModel):
    action: Literal["add", "remove", "retag"]
    field: Literal["task", "text"]
    start: int = Field(ge=0, le=20_000)
    end: int = Field(gt=0, le=20_000)
    type: str | None = None


class RedactionReviewRequest(BaseModel):
    task: str = Field(min_length=1, max_length=4_000)
    text: str = Field(min_length=1, max_length=20_000)
    edits: list[ReviewEdit] = Field(max_length=100)


class ReceiptVerifyRequest(BaseModel):
    receipt: dict[str, object]


def create_app(
    service: AirlockService | None = None,
    *,
    enforce_loopback: bool = True,
    api_token: str | None = None,
    max_body_bytes: int = MAX_HTTP_BODY_BYTES,
) -> FastAPI:
    airlock = service or AirlockService()
    configured_api_token = (api_token if api_token is not None else os.getenv("PII_AIRLOCK_API_TOKEN", "")).strip()
    if configured_api_token and len(configured_api_token) < 32:
        raise ValueError("PII_AIRLOCK_API_TOKEN must contain at least 32 characters.")
    if max_body_bytes <= 0:
        raise ValueError("HTTP body limit must be positive.")
    browser_session = secrets.token_urlsafe(32)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            yield
        finally:
            airlock.close()

    app = FastAPI(title="PII Airlock", version="0.4.0", docs_url="/api/docs", lifespan=lifespan)
    app.add_middleware(RequestBodyLimitMiddleware, max_bytes=max_body_bytes)
    app.state.airlock_service = airlock

    @app.middleware("http")
    async def enforce_local_boundary(http_request: Request, call_next):
        if enforce_loopback:
            client_host = http_request.client.host if http_request.client else ""
            try:
                is_loopback = ipaddress.ip_address(client_host).is_loopback
            except ValueError:
                is_loopback = False
            if not is_loopback or not _valid_loopback_host(http_request.headers.get("host", "")):
                return JSONResponse(status_code=403, content={"detail": "PII Airlock accepts loopback clients only."})
        origin = http_request.headers.get("origin")
        if origin is not None and not _same_origin(http_request, origin):
            return _auth_error(403, "origin_rejected", "Request origin is not allowed.")

        if http_request.method in {"POST", "PUT", "PATCH", "DELETE"} and http_request.url.path.startswith("/api/v1/"):
            bearer_valid = _bearer_matches(http_request, configured_api_token)
            if http_request.url.path == "/api/v1/complete":
                if not configured_api_token:
                    return _auth_error(
                        503,
                        "stateless_api_disabled",
                        "Set PII_AIRLOCK_API_TOKEN to enable the stateless API.",
                    )
                if not bearer_valid:
                    return _auth_error(401, "bearer_required", "A valid bearer token is required.")
            else:
                cookie_valid = hmac.compare_digest(http_request.cookies.get(SESSION_COOKIE, ""), browser_session)
                if not bearer_valid and not cookie_valid:
                    return _auth_error(401, "local_session_required", "A local UI session or bearer token is required.")
                if cookie_valid and not bearer_valid and origin is None:
                    return _auth_error(403, "origin_required", "Session-authenticated writes require Origin.")
        return await call_next(http_request)

    @app.get("/")
    def index() -> FileResponse:
        response = FileResponse(WEB_DIR / "index.html")
        response.set_cookie(
            SESSION_COOKIE,
            browser_session,
            httponly=True,
            samesite="strict",
            secure=False,
            path="/",
        )
        return response

    @app.get("/app.css")
    def css() -> FileResponse:
        return FileResponse(WEB_DIR / "app.css", media_type="text/css")

    @app.get("/app.js")
    def js() -> FileResponse:
        return FileResponse(WEB_DIR / "app.js", media_type="text/javascript")

    @app.get("/api/v1/health")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "cloud_configured": airlock.cloud_enabled,
            "stateless_api_enabled": bool(configured_api_token),
            "supported_models": list(SUPPORTED_MODELS),
            "supported_token_modes": [mode.value for mode in TokenMode],
            "default_token_mode": airlock.token_mode.value,
            "receipt_key_persistent": airlock.receipt_signer.persistent_key,
            "lm_studio": _lm_studio_health(),
        }

    @app.post("/api/v1/documents/extract")
    async def extract_document(file: Annotated[UploadFile, File()]) -> dict[str, object]:
        suffix = Path(file.filename or "").suffix
        try:
            document_bytes = await file.read(MAX_BYTES + 1)
            if len(document_bytes) > MAX_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail={"code": "document_too_large", "message": "Document exceeds the 5 MB limit."},
                )
            extracted = extract_bytes_with_manifest(document_bytes, suffix)
        except HTTPException:
            raise
        except AirlockError as exc:
            raise _as_http_exception(exc) from exc
        return {
            "filename": file.filename or "document",
            "text": extracted.text,
            "manifest": extracted.manifest.public_dict(),
        }

    @app.post("/api/v1/operations")
    def create_operation(payload: OperationRequest) -> dict[str, object]:
        _validate_model(payload.model)
        try:
            operation = airlock.create_operation(
                text=payload.text,
                task=payload.task,
                model=payload.model,
                token_mode=payload.token_mode,
            )
        except AirlockError as exc:
            LOGGER.info(json.dumps({"event": "operation_blocked", "reason": type(exc).__name__}))
            raise _as_http_exception(exc) from exc
        LOGGER.info(
            json.dumps(
                {
                    "event": "operation_created",
                    "operation_id": operation.id,
                    "model": operation.model,
                    "entity_counts": operation.entity_counts,
                    "status": operation.status,
                },
                sort_keys=True,
            )
        )
        return operation.public_dict()

    @app.post("/api/v1/operations/{operation_id}/complete")
    def complete_operation(operation_id: str) -> dict[str, object]:
        try:
            result = airlock.complete_operation(operation_id)
        except AirlockError as exc:
            LOGGER.info(
                json.dumps({"event": "completion_blocked", "operation_id": operation_id, "reason": type(exc).__name__})
            )
            raise _as_http_exception(exc) from exc
        LOGGER.info(
            json.dumps(
                {
                    "event": "completion_finished",
                    "operation_id": operation_id,
                    "cloud_status": result["cloud_status"],
                }
            )
        )
        return result

    @app.patch("/api/v1/operations/{operation_id}/redactions")
    def review_redactions(
        operation_id: str,
        payload: RedactionReviewRequest,
        http_request: Request,
    ) -> dict[str, object]:
        try:
            operation = airlock.review_redactions(
                operation_id,
                fields={"task": payload.task, "text": payload.text},
                edits=[item.model_dump() for item in payload.edits],
                review_channel=("bearer" if _bearer_matches(http_request, configured_api_token) else "browser_session"),
            )
        except AirlockError as exc:
            LOGGER.info(
                json.dumps(
                    {"event": "redaction_review_blocked", "operation_id": operation_id, "reason": type(exc).__name__}
                )
            )
            raise _as_http_exception(exc) from exc
        LOGGER.info(
            json.dumps(
                {
                    "event": "redaction_reviewed",
                    "operation_id": operation_id,
                    "revision": operation.review_revision,
                    "entity_counts": operation.entity_counts,
                    "status": operation.status,
                },
                sort_keys=True,
            )
        )
        return operation.public_dict()

    @app.delete("/api/v1/operations/{operation_id}")
    def delete_operation(operation_id: str) -> dict[str, bool]:
        return {"deleted": airlock.store.delete(operation_id)}

    @app.post("/api/v1/receipts/verify")
    def verify_receipt(payload: ReceiptVerifyRequest) -> dict[str, object]:
        return {
            "valid": airlock.verify_review_receipt(payload.receipt),
            "key_id": airlock.receipt_signer.key_id,
        }

    @app.post("/api/v1/complete")
    def complete_stateless(payload: StatelessRequest) -> dict[str, object]:
        _validate_model(payload.model)
        try:
            return airlock.complete_stateless(
                instructions=payload.instructions,
                input_text=payload.input_text,
                model=payload.model,
                token_mode=payload.token_mode,
            )
        except AirlockError as exc:
            LOGGER.info(json.dumps({"event": "stateless_blocked", "reason": type(exc).__name__}))
            raise _as_http_exception(exc) from exc

    return app


def _validate_model(model: str) -> None:
    if model not in SUPPORTED_MODELS:
        raise HTTPException(status_code=422, detail="Unsupported local model")


def _valid_loopback_host(host_header: str) -> bool:
    try:
        parsed = urlsplit(f"//{host_header}")
        port = parsed.port
        return bool(
            parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and (port is None or 0 < port <= 65_535)
            and ipaddress.ip_address(parsed.hostname).is_loopback
        )
    except ValueError:
        return False


def _same_origin(http_request: Request, origin: str) -> bool:
    expected = f"{http_request.url.scheme}://{http_request.headers.get('host', '')}".rstrip("/")
    return hmac.compare_digest(origin.rstrip("/"), expected)


def _bearer_matches(http_request: Request, configured_api_token: str) -> bool:
    if not configured_api_token:
        return False
    scheme, separator, token = http_request.headers.get("authorization", "").partition(" ")
    return bool(separator and scheme.lower() == "bearer" and hmac.compare_digest(token, configured_api_token))


def _auth_error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": {"code": code, "message": message}})


def _as_http_exception(exc: AirlockError) -> HTTPException:
    if isinstance(exc, (StoreCapacityError, ServiceBusyError)):
        status_code = 429
    elif isinstance(exc, OperationNotFound):
        status_code = 404
    else:
        status_code = 422
    code = getattr(exc, "code", _error_code(exc))
    return HTTPException(status_code=status_code, detail={"code": code, "message": str(exc)})


def _error_code(exc: Exception) -> str:
    name = type(exc).__name__
    return "".join(f"_{char.lower()}" if char.isupper() else char for char in name).lstrip("_")


def _lm_studio_health() -> dict[str, object]:
    try:
        with request.urlopen("http://127.0.0.1:1234/v1/models", timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
        model_ids = [item.get("id") for item in payload.get("data", []) if isinstance(item, dict)]
        return {"reachable": True, "advertised_models": model_ids}
    except (error.URLError, TimeoutError, json.JSONDecodeError):
        return {"reachable": False, "advertised_models": []}


app = create_app()
