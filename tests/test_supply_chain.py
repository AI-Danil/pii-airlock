from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scan_secrets.py"


def _module():
    spec = importlib.util.spec_from_file_location("scan_secrets", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_secret_scanner_allows_only_named_synthetic_controls() -> None:
    scanner = _module()
    assert scanner.scan_text("sk-testOnlyKey1234567890ABCD") == []
    unknown = "sk-" + "liveCredentialThatMustFail123"
    assert scanner.scan_text(unknown) == [("openai_style_key", 1)]


def test_tracked_repository_passes_deterministic_secret_scan() -> None:
    result = subprocess.run([sys.executable, str(SCRIPT)], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout
