from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from config import DATA_DIR


def write_json(name: str, payload: Any) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / name
    if hasattr(payload, "to_dict"):
        data = payload.to_dict()
    elif hasattr(payload, "__dataclass_fields__"):
        data = asdict(payload)
    else:
        data = payload
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def read_json(name: str) -> dict[str, Any]:
    path = DATA_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Missing {path}. Run the previous pipeline stage first.")
    return json.loads(path.read_text(encoding="utf-8"))
