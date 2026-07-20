from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from .api import create_app
from .benchmark import run_benchmark
from .detectors import SUPPORTED_MODELS
from .documents import extract_path
from .models import AirlockError
from .service import AirlockService


ALIASES = {"qwen": SUPPORTED_MODELS[0], "gemma": SUPPORTED_MODELS[1]}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local-first PII privacy gateway for cloud LLM calls.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="Pseudonymize a document without calling cloud.")
    inspect_parser.add_argument("file", type=Path)
    inspect_parser.add_argument("--task", default="Summarize the document while preserving PII tokens.")
    inspect_parser.add_argument("--model", default="qwen")

    complete_parser = subparsers.add_parser("complete", help="Run the full local-cloud-local round trip.")
    complete_parser.add_argument("file", type=Path)
    complete_parser.add_argument("--task", required=True)
    complete_parser.add_argument("--model", default="qwen")

    benchmark_parser = subparsers.add_parser("benchmark", help="Evaluate installed LM Studio models on synthetic data.")
    benchmark_parser.add_argument("--models", default="qwen,gemma")
    benchmark_parser.add_argument("--fixtures", type=Path, default=Path("fixtures/synthetic_cases.jsonl"))
    benchmark_parser.add_argument("--output", type=Path)

    serve_parser = subparsers.add_parser("serve", help="Start the local Web/API server on loopback.")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", default=8787, type=int)
    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = build_parser().parse_args()
    try:
        if args.command == "serve":
            if args.host not in {"127.0.0.1", "localhost", "::1"}:
                raise SystemExit("PII Airlock refuses non-loopback binding in V1.")
            import uvicorn

            uvicorn.run(create_app(), host=args.host, port=args.port, log_config=None)
            return
        if args.command == "benchmark":
            models = [_resolve_model(item.strip()) for item in args.models.split(",") if item.strip()]
            report = run_benchmark(args.fixtures, models=models)
            rendered = json.dumps(report, ensure_ascii=False, indent=2)
            if args.output:
                args.output.write_text(rendered + "\n", encoding="utf-8")
            print(rendered)
            return

        text = extract_path(args.file)
        service = AirlockService()
        operation = service.create_operation(text=text, task=args.task, model=_resolve_model(args.model))
        if args.command == "inspect":
            print(json.dumps(operation.public_dict(), ensure_ascii=False, indent=2))
            return
        result = service.complete_operation(operation.id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except AirlockError as exc:
        raise SystemExit(f"BLOCKED: {exc}") from exc


def _resolve_model(value: str) -> str:
    return ALIASES.get(value, value)


if __name__ == "__main__":
    main()
