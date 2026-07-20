from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
from typing import Annotated
from urllib import error, request

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from .detectors import SUPPORTED_MODELS
from .documents import extract_bytes
from .models import AirlockError
from .service import AirlockService

LOGGER = logging.getLogger("pii_airlock.audit")
WEB_DIR = Path(__file__).with_name("web")


class OperationRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)
    task: str = Field(min_length=1, max_length=4_000)
    model: str = "qwen/qwen3.5-9b"


class StatelessRequest(BaseModel):
    instructions: str = Field(min_length=1, max_length=4_000)
    input_text: str = Field(min_length=1, max_length=20_000)
    model: str = "qwen/qwen3.5-9b"


def create_app(service: AirlockService | None = None, *, enforce_loopback: bool = True) -> FastAPI:
    airlock = service or AirlockService()
    app = FastAPI(title="PII Airlock", version="0.2.0", docs_url="/api/docs")

    if enforce_loopback:

        @app.middleware("http")
        async def reject_remote_clients(http_request: Request, call_next):
            client_host = http_request.client.host if http_request.client else ""
            try:
                is_loopback = ipaddress.ip_address(client_host).is_loopback
            except ValueError:
                is_loopback = False
            if not is_loopback:
                return JSONResponse(status_code=403, content={"detail": "PII Airlock accepts loopback clients only."})
            return await call_next(http_request)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

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
            "supported_models": list(SUPPORTED_MODELS),
            "lm_studio": _lm_studio_health(),
        }

    @app.post("/api/v1/documents/extract")
    async def extract_document(file: Annotated[UploadFile, File()]) -> dict[str, str]:
        suffix = Path(file.filename or "").suffix
        try:
            text = extract_bytes(await file.read(), suffix)
        except AirlockError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"filename": file.filename or "document", "text": text}

    @app.post("/api/v1/operations")
    def create_operation(payload: OperationRequest) -> dict[str, object]:
        _validate_model(payload.model)
        try:
            operation = airlock.create_operation(text=payload.text, task=payload.task, model=payload.model)
        except AirlockError as exc:
            LOGGER.info(json.dumps({"event": "operation_blocked", "reason": type(exc).__name__}))
            raise HTTPException(status_code=422, detail=str(exc)) from exc
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
            raise HTTPException(status_code=422, detail=str(exc)) from exc
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

    @app.delete("/api/v1/operations/{operation_id}")
    def delete_operation(operation_id: str) -> dict[str, bool]:
        return {"deleted": airlock.store.delete(operation_id)}

    @app.post("/api/v1/complete")
    def complete_stateless(payload: StatelessRequest) -> dict[str, object]:
        _validate_model(payload.model)
        try:
            return airlock.complete_stateless(
                instructions=payload.instructions,
                input_text=payload.input_text,
                model=payload.model,
            )
        except AirlockError as exc:
            LOGGER.info(json.dumps({"event": "stateless_blocked", "reason": type(exc).__name__}))
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return app


def _validate_model(model: str) -> None:
    if model not in SUPPORTED_MODELS:
        raise HTTPException(status_code=422, detail="Unsupported local model")


def _lm_studio_health() -> dict[str, object]:
    try:
        with request.urlopen("http://127.0.0.1:1234/v1/models", timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
        model_ids = [item.get("id") for item in payload.get("data", []) if isinstance(item, dict)]
        return {"reachable": True, "advertised_models": model_ids}
    except (error.URLError, TimeoutError, json.JSONDecodeError):
        return {"reachable": False, "advertised_models": []}


app = create_app()
