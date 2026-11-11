"""Pelaksana proses luaran: allowlist binari, tiada shell, timeout."""
import shutil
import subprocess
import sys
from pathlib import Path

from ..runtime import RT

ALLOWED_BINARIES = {"nmap", "nuclei", "semgrep", "bandit"}


def run_proc(args: list[str], timeout: int = 600, cwd=None) -> subprocess.CompletedProcess:
    if args[0] not in ALLOWED_BINARIES:
        raise PermissionError(f"Binari '{args[0]}' tiada dalam allowlist")
    # cari dalam venv semasa dahulu (semgrep/bandit dipasang di sana), kemudian PATH
    exe = shutil.which(args[0], path=str(Path(sys.executable).parent)) or shutil.which(args[0])
    if not exe:
        raise FileNotFoundError(f"'{args[0]}' tidak dijumpai dalam PATH - pasang dahulu (lihat README)")
    RT.audit.log("exec", argv=args)
    try:
        return subprocess.run(
            [exe, *args[1:]],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, cwd=cwd,
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError(f"'{args[0]}' melebihi had masa {timeout}s") from e
