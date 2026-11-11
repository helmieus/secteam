"""Audit log JSONL - setiap keputusan, panggilan alat dan kelulusan direkodkan."""
from __future__ import annotations

import datetime as dt
import json
import threading
from pathlib import Path


class AuditLog:
    def __init__(self, log_dir: Path | str = "logs") -> None:
        self.dir = Path(log_dir)
        self._lock = threading.Lock()

    def log(self, event: str, **data) -> None:
        now = dt.datetime.now().astimezone()
        record = {"ts": now.isoformat(timespec="seconds"), "event": event, **data}
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            self.dir.mkdir(parents=True, exist_ok=True)
            with open(self.dir / f"audit-{now:%Y%m%d}.jsonl", "a", encoding="utf-8") as f:
                f.write(line + "\n")
