"""Build the optional JSON screening, canonical proof framing and size-estimation helper.

Package metadata lives in pyproject.toml; this file configures the extension.
"""
from setuptools import Extension, setup
from pathlib import Path

# setuptools requires egg_base to exist even in a source-only checkout.
# Keep that generated metadata under the project's artifact tree.
(Path(__file__).resolve().parent / "artifacts/build/metadata").mkdir(parents=True, exist_ok=True)

setup(ext_modules=[Extension(
    "fsd_decoder.core._json_scan",
    ["src/fsd_decoder/core/_json_scan.cpp"],
    define_macros=[("Py_LIMITED_API", "0x030c0000")],
    py_limited_api=True, language="c++", optional=True,
    extra_compile_args=["-O3", "-std=c++17"],
)])
