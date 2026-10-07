"""Load immutable derived runtime metadata without a vendor installation."""
from importlib.resources import files
import json

RESOURCE_NAMES = ("bootstrap_types.json", "bootstrap_sizes.json", "bytecode_opcodes.json", "runtime_manifest.json")


def load_json(name: str):
    if name not in RESOURCE_NAMES:
        raise ValueError(f"Unknown runtime resource: {name}")
    return json.loads(files("fsd_decoder.resources").joinpath(name).read_text(encoding="utf-8"))
