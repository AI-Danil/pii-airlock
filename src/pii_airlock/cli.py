from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .api import create_app
from .benchmark import run_benchmark
from .detectors import SUPPORTED_MODELS, HybridDetector, LMStudioDetector
from .documents import extract_path
from .models import AirlockError, TokenMode
from .receipts import ReceiptSigner
from .service import AirlockService

ALIASES = {"qwen": SUPPORTED_MODELS[0], "gemma": SUPPORTED_MODELS[1]}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local-first PII privacy gateway for cloud LLM calls.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect", help="Pseudonymize a document without calling cloud.")
    inspect_parser.add_argument("file", type=Path)
    inspect_parser.add_argument("--task", default="Summarize the document while preserving PII tokens.")
    inspect_parser.add_argument("--model", default="qwen")
    inspect_parser.add_argument("--token-mode", choices=[mode.value for mode in TokenMode], default="opaque")

    complete_parser = subparsers.add_parser("complete", help="Run the full local-cloud-local round trip.")
    complete_parser.add_argument("file", type=Path)
    complete_parser.add_argument("--task", required=True)
    complete_parser.add_argument("--model", default="qwen")
    complete_parser.add_argument("--token-mode", choices=[mode.value for mode in TokenMode], default="opaque")

    benchmark_parser = subparsers.add_parser("benchmark", help="Evaluate installed LM Studio models on synthetic data.")
    benchmark_parser.add_argument("--models", default="qwen,gemma")
    benchmark_parser.add_argument("--fixtures", type=Path, default=Path("fixtures/synthetic_cases.jsonl"))
    benchmark_parser.add_argument("--output", type=Path)
    benchmark_parser.add_argument("--timeout", type=float, default=30.0, help="Per-case LM Studio timeout in seconds.")
    benchmark_parser.add_argument("--token-mode", choices=[mode.value for mode in TokenMode], default="opaque")

    serve_parser = subparsers.add_parser("serve", help="Start the local Web/API server on loopback.")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", default=8787, type=int)

    verify_parser = subparsers.add_parser("verify-receipt", help="Verify a signed PII-free review receipt.")
    verify_parser.add_argument("file", type=Path)
    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = build_parser().parse_args()
    service: AirlockService | None = None
    try:
        if args.command == "verify-receipt":
            signer = ReceiptSigner.from_env()
            receipt = json.loads(args.file.read_text(encoding="utf-8"))
            if not signer.persistent_key:
                raise SystemExit("Set the same PII_AIRLOCK_RECEIPT_KEY that signed the receipt.")
            if not isinstance(receipt, dict) or not signer.verify(receipt):
                raise SystemExit("INVALID RECEIPT")
            print(f"VALID RECEIPT · key_id={signer.key_id}")
            return
        if args.command == "serve":
            if args.host not in {"127.0.0.1", "localhost", "::1"}:
                raise SystemExit("PII Airlock refuses non-loopback binding in V1.")
            import uvicorn

            uvicorn.run(create_app(), host=args.host, port=args.port, log_config=None)
            return
        if args.command == "benchmark":
            models = [_resolve_model(item.strip()) for item in args.models.split(",") if item.strip()]
            if args.timeout <= 0:
                raise SystemExit("Benchmark timeout must be positive.")
            detector = HybridDetector(LMStudioDetector(timeout=args.timeout))
            report = run_benchmark(
                args.fixtures,
                models=models,
                detector=detector,
                progress=lambda model, current, total, case_id: print(
                    f"[{model}] {current}/{total} {case_id}", file=sys.stderr, flush=True
                ),
                token_mode=args.token_mode,
            )
            rendered = json.dumps(report, ensure_ascii=False, indent=2)
            if args.output:
                args.output.write_text(rendered + "\n", encoding="utf-8")
            print(rendered)
            return

        text = extract_path(args.file)
        service = AirlockService()
        operation = service.create_operation(
            text=text,
            task=args.task,
            model=_resolve_model(args.model),
            token_mode=args.token_mode,
        )
        if args.command == "inspect":
            print(json.dumps(operation.public_dict(), ensure_ascii=False, indent=2))
            return
        result = service.complete_operation(operation.id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except AirlockError as exc:
        raise SystemExit(f"BLOCKED: {exc}") from exc
    finally:
        if service is not None:
            service.close()


def _resolve_model(value: str) -> str:
    return ALIASES.get(value, value)


if __name__ == "__main__":
    main()
