#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from pii_airlock.human_review import score_against_human_review


def main() -> int:
    parser = argparse.ArgumentParser(description="Score exact predictions against a completed blind human review.")
    parser.add_argument("--items", type=Path, required=True)
    parser.add_argument("--human", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = score_against_human_review(
        _load_jsonl(args.items),
        _load_jsonl(args.human),
        _load_jsonl(args.predictions),
    )
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


if __name__ == "__main__":
    raise SystemExit(main())
