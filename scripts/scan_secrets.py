#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
from pathlib import Path

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)
SYNTHETIC_ALLOWLIST = {
    "sk-testOnlyKey1234567890ABCD",
    "ghp_1234567890ABCDEFGHIJ",
}


def scan_text(text: str) -> list[tuple[str, int]]:
    findings: list[tuple[str, int]] = []
    for name, pattern in PATTERNS:
        for match in pattern.finditer(text):
            if match.group(0) in SYNTHETIC_ALLOWLIST:
                continue
            findings.append((name, text.count("\n", 0, match.start()) + 1))
    return findings


def tracked_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [root / item.decode() for item in result.stdout.split(b"\0") if item]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    findings: list[tuple[str, str, int]] = []
    for path in tracked_files(root):
        if not path.is_file() or path.stat().st_size > 5 * 1024 * 1024:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend((str(path.relative_to(root)), name, line) for name, line in scan_text(text))
    for path, name, line in findings:
        print(f"{path}:{line}: possible {name}")
    if findings:
        print(f"Secret scan failed with {len(findings)} finding(s); values are intentionally not printed.")
        return 1
    print("Secret scan passed: no non-allowlisted high-confidence credential patterns found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
