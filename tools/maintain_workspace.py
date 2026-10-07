#!/usr/bin/env python3
"""Audit project layout; remove only enumerated disposable Python caches.

No source databases, stores, proof files, fixtures or ordinary artifacts are
deleted. --clean-caches is opt-in; a JSON audit is written under artifacts.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
TOP_LEVEL = {"AGENTS.md", "agents.md", "skills.md", "README.md", "pyproject.toml", "requirements.txt", "MANIFEST.in", "LICENSE", "setup.cfg", "setup.py", ".gitignore", ".git", "src", "tests", "docs", "tools", "skills", "investigations", "ingest", "artifacts"}
LAYERS = {"__init__.py", "cli", "core", "native", "schema", "portable", "discovery", "exports", "resources"}
DISPOSABLE = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
ARTIFACT_ENTRIES = {"README.md", "runs", "exports", "reports", "scratch", "cache", "build", "profiles", "logs"}
GENERATED_SUFFIXES = (".log", ".fsdx", ".obj", ".png", ".sqlite", ".csv", ".pstats", ".prof", ".whl", ".zip", ".so", ".o", ".a")
# Curated README assets approved by the owner, not general export destinations.
README_IMAGES = frozenset({
    "docs/images/tui-file-selection.png",
    "docs/images/tui-capture-progress.png",
    "docs/images/tui-verification-progress.png",
    "docs/images/tui-discovered-names.png",
    "docs/images/tui-object-types.png",
})


def inspect(root: Path, clean: bool = False) -> dict:
    violations = []
    removed = []
    for child in sorted(root.iterdir()):
        if child.name not in TOP_LEVEL:
            violations.append({"path": str(child.relative_to(root)), "reason": "unexpected project entry"})
    artifacts = root / "artifacts"
    if artifacts.exists():
        for child in sorted(artifacts.iterdir()):
            if child.name not in ARTIFACT_ENTRIES:
                violations.append({"path": str(child.relative_to(root)), "reason": "place generated work inside an artifact category"})
    package = root / "src" / "fsd_decoder"
    if package.exists():
        for child in sorted(package.iterdir()):
            if child.name not in LAYERS and child.name not in DISPOSABLE:
                violations.append({"path": str(child.relative_to(root)), "reason": "unexpected runtime layer"})
    # Walk only the project. Never follow directory symlinks or visit historical
    # datasets elsewhere in the parent workspace.
    import os
    for base, dirs, files in os.walk(root, followlinks=False):
        here = Path(base)
        dirs[:] = [name for name in dirs if not (here / name).is_symlink()]
        if here == root:
            dirs[:] = [name for name in dirs if name not in {"artifacts", ".git"}]
        for name in list(dirs):
            if name in DISPOSABLE:
                path = here / name
                if clean:
                    shutil.rmtree(path)
                    removed.append(str(path.relative_to(root)))
                else:
                    violations.append({"path": str(path.relative_to(root)), "reason": "cache outside artifacts"})
                dirs.remove(name)
        for name in files:
            if name.endswith((".pyc", ".pyo")):
                path = here / name
                if path.is_symlink():
                    violations.append({"path": str(path.relative_to(root)), "reason": "unexpected cache symlink"})
                elif clean:
                    path.unlink()
                    removed.append(str(path.relative_to(root)))
                else:
                    violations.append({"path": str(path.relative_to(root)), "reason": "bytecode outside artifacts"})
            elif (name.endswith(GENERATED_SUFFIXES)
                  and not (root / "tests") in (here, *here.parents)
                  and (here / name).relative_to(root).as_posix() not in README_IMAGES):
                violations.append({"path": str((here / name).relative_to(root)), "reason": "generated output outside artifacts"})
    return {"project": str(root), "status": "PASS" if not violations else "FAIL", "violations": violations, "removed_caches": removed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean-caches", action="store_true")
    args = parser.parse_args()
    result = inspect(ROOT, args.clean_caches)
    directory = ROOT / "artifacts" / "reports"
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = directory / f"layout_audit_{stamp}.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "violations": len(result["violations"]), "removed_caches": len(result["removed_caches"]), "report": str(output)}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
