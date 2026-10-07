"""Explicit installed runtime closure and execution environment identity.

Historical execution pins remain historical. New pins describe this installation
without consulting generated exports, prototype paths or a vendor installation.
"""
from __future__ import annotations

import hashlib
from importlib.metadata import PackageNotFoundError, version
from importlib.resources import files
import platform
import sqlite3
import sys

from fsd_decoder.resources.loader import load_json
from fsd_decoder.core.json_scan import identity as json_scan_identity


def environment_identity() -> dict:
    """Execution identity recorded separately from content hashes."""
    try:
        package_version = version("fsd-decoder")
    except PackageNotFoundError:
        from fsd_decoder import __version__
        package_version = __version__
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "sqlite_version": sqlite3.sqlite_version,
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "package_version": package_version,
        "support_matrix": "CPython 3.12-3.14 / Linux; other combinations unverified",
    }


def runtime_manifest() -> tuple[str, ...]:
    # This JSON is an explicit build input, not a filesystem glob of experiments.
    rows = load_json("runtime_manifest.json")["files"]
    if len(rows) != len(set(rows)) or any(name.startswith("/") or ".." in name.split("/") for name in rows):
        raise ValueError("Invalid packaged runtime manifest")
    return tuple(rows)


def code_pins() -> dict[str, str]:
    root = files("fsd_decoder")
    result = {}
    for name in runtime_manifest():
        digest = hashlib.sha256()
        with root.joinpath(name).open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        result["fsd_decoder/" + name] = digest.hexdigest()
    return result


def runtime_identity() -> dict:
    return {"manifest_version": 1, "code_sha256": code_pins(), "environment": environment_identity(),
            "json_preflight": json_scan_identity()}
