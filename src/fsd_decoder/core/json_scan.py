"""Optional C++ JSON screening, SQL-row/record framing and row-size estimation.

No runtime compilation or arbitrary external search path; unavailable helpers
retain Python handling. Python owns syntax parsing and integrity policy.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path


def _load():
    if os.environ.get("FSD_JSON_BACKEND", "auto") == "python":
        return None, None, None
    spec = importlib.util.find_spec("fsd_decoder.core._json_scan")
    if spec is None:
        # Only a source checkout uses its own dedicated build output. Installed
        # packages never load a binary from an arbitrary working directory.
        project = Path(__file__).resolve().parents[3]
        candidate = project / "artifacts/build/native/fsd_decoder/core/_json_scan.abi3.so"
        if not (project / "pyproject.toml").is_file() or not candidate.is_file():
            return None, None, None
        spec = importlib.util.spec_from_file_location("fsd_decoder.core._json_scan", candidate)
    path = Path(spec.origin).resolve()
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except (ImportError, OSError):
        return None, None, None
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise RuntimeError("Native JSON helper changed while loading")
    return module, path, digest


_module, _binary, _loaded_sha256 = _load()
check = getattr(_module, 'check', None)
frame_rows = getattr(_module, 'frame_rows', None)
estimate_row = getattr(_module, 'estimate_row', None)
frame_records = getattr(_module, 'frame_records', None)


def identity() -> dict:
    """Pin the selected backend and reject replacement of a loaded binary."""
    if check is None:
        return {"backend": "python"}
    current = hashlib.sha256(_binary.read_bytes()).hexdigest()
    if current != _loaded_sha256:
        raise RuntimeError("Native JSON helper changed after loading")
    return {"backend": "cpp", "abi": "CPython stable ABI 3.12+",
            "binary_path": str(_binary), "binary_sha256": current}
