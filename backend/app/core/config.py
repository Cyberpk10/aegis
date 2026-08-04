"""Application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

_TRUTHY = {"1", "true", "yes", "on"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUTHY


@dataclass
class Settings:
    cors_origins: list[str] = field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )
    max_upload_bytes: int = 10 * 1024 * 1024  # 10 MiB

    # LLM reasoning layer (M2): off by default so the app and test suite stay
    # fully offline and deterministic unless explicitly opted in.
    enable_llm_reasoning: bool = field(
        default_factory=lambda: _env_bool("ENABLE_LLM_REASONING", False)
    )
    llm_model: str = field(
        default_factory=lambda: os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5")
    )


settings = Settings()
