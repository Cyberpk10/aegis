"""Loads versioned control-framework YAML files and maps indicator IDs to their controls."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from app.models.schemas import AuditFramework, FrameworkControlRef

_FRAMEWORKS_DIR = Path(__file__).parent / "frameworks"

# Maps the short public API alias (nist|iso|soc2|mitre — used by Audit Mode and the
# copilot) to the internal YAML framework_key. Single source of truth so this mapping
# isn't duplicated across every feature that accepts a framework alias.
_FRAMEWORK_KEY_BY_ALIAS: dict[AuditFramework, str] = {
    AuditFramework.NIST: "nist_csf",
    AuditFramework.ISO: "iso_27001",
    AuditFramework.SOC2: "soc2",
    AuditFramework.MITRE: "mitre_attack",
}

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


def get_framework(framework_key: str) -> LoadedFramework | None:
    """A single loaded framework (name, version, full controls_by_id) — used by Audit
    Mode to build per-control evidence for one chosen framework."""
    return _load_all_frameworks().get(framework_key)


def resolve_framework_alias(alias: AuditFramework) -> str:
    """Maps the short public API alias (nist|iso|soc2|mitre) to the internal YAML
    framework_key."""
    return _FRAMEWORK_KEY_BY_ALIAS[alias]


def total_controls_by_framework() -> dict[str, int]:
    """The full control universe per framework (from the YAML), independent of any
    specific case — the denominator for dashboard coverage percentages."""
    return {key: len(fw.controls_by_id) for key, fw in _load_all_frameworks().items()}


def framework_display_names() -> dict[str, str]:
    return {key: fw.name for key, fw in _load_all_frameworks().items()}


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
