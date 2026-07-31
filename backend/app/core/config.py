"""Application configuration."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    cors_origins: list[str] = field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )
    max_upload_bytes: int = 10 * 1024 * 1024  # 10 MiB


settings = Settings()
