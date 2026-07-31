"""Loads versioned control-framework YAML files and maps indicator IDs to their controls."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from app.models.schemas import FrameworkControlRef

_FRAMEWORKS_DIR = Path(__file__).parent / "frameworks"

_REQUIRED_KEYS = {"version", "framework", "framework_key", "controls", "mappings"}


@dataclass(frozen=True)
class LoadedFramework:
    key: str
    name: str
    version: str
    controls_by_id: dict[str, dict]
    mappings: dict[str, list[str]]


def _load_framework_file(path: Path) -> LoadedFramework:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    missing = _REQUIRED_KEYS - data.keys()
    if missing:
        raise ValueError(f"Framework file {path.name} is missing required keys: {sorted(missing)}")

    controls_by_id = {c["id"]: c for c in data["controls"]}
    return LoadedFramework(
        key=data["framework_key"],
        name=data["framework"],
        version=str(data["version"]),
        controls_by_id=controls_by_id,
        mappings=data["mappings"],
    )


@lru_cache(maxsize=1)
def _load_all_frameworks() -> dict[str, LoadedFramework]:
    frameworks: dict[str, LoadedFramework] = {}
    for path in sorted(_FRAMEWORKS_DIR.glob("*.yaml")):
        framework = _load_framework_file(path)
        frameworks[framework.key] = framework
    return frameworks


def loaded_framework_keys() -> list[str]:
    return sorted(_load_all_frameworks().keys())


def map_indicators(indicator_ids: list[str]) -> dict[str, list[FrameworkControlRef]]:
    """Maps a list of indicator IDs to their controls across every loaded framework."""
    result: dict[str, list[FrameworkControlRef]] = {}

    for key, framework in _load_all_frameworks().items():
        refs: list[FrameworkControlRef] = []
        for indicator_id in indicator_ids:
            control_ids = framework.mappings.get(indicator_id, [])
            for control_id in control_ids:
                control = framework.controls_by_id.get(control_id)
                if not control:
                    continue
                refs.append(
                    FrameworkControlRef(
                        indicator_id=indicator_id,
                        control_id=control_id,
                        control_name=control["name"],
                        url=control.get("url"),
                    )
                )
        result[key] = refs

    return result
