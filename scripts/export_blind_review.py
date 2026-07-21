#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import random
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Export a detached, label-free human-review bundle.")
    parser.add_argument("--fixtures", type=Path, default=Path("fixtures/synthetic_cases.jsonl"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--salt", required=True, help="Use a fresh confidential salt for a real blind review.")
    parser.add_argument("--version", default="v1")
    args = parser.parse_args()

    raw = args.fixtures.read_bytes()
    cases = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    items = [
        {
            "item_id": hmac.new(args.salt.encode(), str(case["id"]).encode(), hashlib.sha256).hexdigest()[:16],
            "language": case.get("language", "unknown"),
            "text": case["text"],
        }
        for case in cases
    ]
    random.Random(hashlib.sha256(args.salt.encode()).digest()).shuffle(items)
    template = [{"item_id": item["item_id"], "entities": [], "reviewer_id": "", "reviewed_at": ""} for item in items]
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(output_dir / "blind-items.jsonl", items)
    _write_jsonl(output_dir / "review-template.jsonl", template)
    manifest = {
        "version": args.version,
        "items": len(items),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "labels_included": False,
        "case_ids_included": False,
        "salt_id": hashlib.sha256(args.salt.encode()).hexdigest()[:12],
        "human_results": "not_collected",
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
