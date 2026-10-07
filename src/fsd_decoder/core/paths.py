"""Predictable destinations for generated work, independent of the code tree."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import uuid

CATEGORIES = frozenset({"runs", "exports", "reports", "scratch", "cache", "build", "profiles", "logs"})


def project_root() -> Path:
    """Locate a checkout, or use the caller's project in an installed runtime.

    FSD_PROJECT_ROOT is an explicit relocation of the project. An installed wheel
    must never write into site-packages merely because that is its import path.
    """
    override = os.environ.get("FSD_PROJECT_ROOT")
    if override:
        return Path(override).expanduser().absolute()
    for parent in Path(__file__).resolve().parents:
        if parent.name == "fsd" and (parent / "pyproject.toml").is_file():
            return parent
    cwd = Path.cwd()
    return cwd if cwd.name == "fsd" else cwd / "fsd"


def artifact_root() -> Path:
    override = os.environ.get("FSD_ARTIFACT_ROOT")
    return Path(override).expanduser().absolute() if override else project_root() / "artifacts"


def artifact_directory(category: str) -> Path:
    if category not in CATEGORIES:
        raise ValueError(f"Unknown artifact category: {category!r}")
    directory = artifact_root() / category
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def default_run_directory(operation: str) -> Path:
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", operation):
        raise ValueError("Operation must be a short lowercase path component")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = artifact_directory("runs") / f"{operation}_{stamp}_{uuid.uuid4().hex[:10]}"
    path.mkdir(exist_ok=False)
    return path
