from __future__ import annotations

from pathlib import Path

import yaml

DEFAULT_CONFIG = Path("config.yaml")


def load_config(path: Path | None = None) -> dict:
    path = path or DEFAULT_CONFIG
    if not path.exists():
        raise FileNotFoundError(f"Fail konfigurasi tidak dijumpai: {path}")
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def model_for(cfg: dict, role: str) -> str:
    models = cfg.get("models", {})
    return models.get(role) or models.get("default", "qwen2.5:7b")
