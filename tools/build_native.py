#!/usr/bin/env python3
"""Build the optional C++ helper for this checkout; outputs stay in artifacts."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

project = Path(__file__).resolve().parents[1]
build = project / "artifacts/build"
build.mkdir(parents=True, exist_ok=True)
# Never truncate a library that another Python process may already have loaded.
with tempfile.TemporaryDirectory(prefix="native-", dir=build) as staging:
    result = subprocess.run([
        sys.executable, "-B", "setup.py", "build_ext", "--force",
        "--build-lib", staging, "--build-temp", "artifacts/build/native-temp",
    ], cwd=project)
    if result.returncode:
        raise SystemExit(result.returncode)
    relative = Path("fsd_decoder/core/_json_scan.abi3.so")
    binary = Path(staging) / relative
    if not binary.is_file():
        raise SystemExit("Native helper was not built; decoding will use Python.")
    destination = build / "native" / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(binary, destination)
print(f"Native JSON helper ready: {destination}")
