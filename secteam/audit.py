"""Audit log JSONL - setiap keputusan, panggilan alat dan kelulusan direkodkan.

Setiap rekod mengandungi `t` (epoch, milisaat) untuk garis masa dashboard, `session` (ID sesi CLI)
dan `agent` (pakar yang sedang aktif, jika ada)."""
from __future__ import annotations

import datetime as dt
import json
import threading
import time
from pathlib import Path


class AuditLog:
    def __init__(self, log_dir: Path | str = "logs") -> None:
        self.dir = Path(log_dir)
        self._lock = threading.Lock()
        self.session: str | None = None
        self.agent: str | None = None

    def log(self, event: str, **data) -> None:
        now = dt.datetime.now().astimezone()
        record = {"ts": now.isoformat(timespec="seconds"), "t": round(time.time(), 3), "event": event}
        if self.session:
            record["session"] = self.session
        if self.agent and "agent" not in data:
            record["agent"] = self.agent
        record.update(data)
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            self.dir.mkdir(parents=True, exist_ok=True)
            with open(self.dir / f"audit-{now:%Y%m%d}.jsonl", "a", encoding="utf-8") as f:
                f.write(line + "\n")
