"""State runtime global untuk satu sesi CLI (engagement, laluan, tetapan)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .audit import AuditLog

if TYPE_CHECKING:
    from .scope import Engagement


@dataclass
class Runtime:
    engagement: "Engagement | None" = None
    code_root: Path | None = None
    files_root: Path | None = None
    sandbox_dir: Path = Path("workspace/sandbox")
    auto_approve: bool = False
    max_tool_output: int = 6000
    cfg: dict = field(default_factory=dict)
    audit: AuditLog = field(default_factory=AuditLog)


RT = Runtime()
