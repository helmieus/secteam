"""Alat analisis fail/binari untuk Spy: strings extraction + maklumat fail. Baca sahaja."""
import re
import subprocess
from pathlib import Path

from langchain_core.tools import tool

from .common import guarded

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
MAX_READ = 20 * 1024 * 1024  # 20MB


def _path(p: str) -> Path:
    fp = Path(p).expanduser()
    if not fp.is_absolute():
        fp = (Path.cwd() / fp)
    fp = fp.resolve()
    if not fp.exists() or not fp.is_file():
        raise FileNotFoundError(f"Fail tidak wujud: {p}")
    if fp.stat().st_size > MAX_READ:
        raise ValueError(f"Fail terlalu besar (>{MAX_READ // (1024*1024)}MB) untuk dianalisis sekali gus.")
    return fp


@tool
@guarded
def file_info(path: str) -> str:
    """Identify a file: size, type (via `file`), and a hex preview of the first 64 bytes.
    Use for binary analysis (magic bytes, format) before extracting strings."""
    fp = _path(path)
    head = fp.read_bytes()[:64]
    hexs = " ".join(f"{b:02x}" for b in head)
    try:
        ftype = subprocess.run(["file", "-b", str(fp)], capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:  # noqa: BLE001
        ftype = "(perintah 'file' tidak tersedia)"
    return f"path: {fp}\nsize: {fp.stat().st_size} B\ntype: {ftype}\nhex[0:64]: {hexs}"


@tool
@guarded
def extract_strings(path: str, min_len: int = 4, max_results: int = 300) -> str:
    """Extract printable ASCII strings (length >= min_len) from a binary or data file.
    Returns up to max_results strings. Useful for finding endpoints, secrets, URLs, format markers."""
    fp = _path(path)
    data = fp.read_bytes()
    found = [m.group().decode("ascii", "replace") for m in PRINTABLE.finditer(data) if len(m.group()) >= max(4, min_len)]
    uniq = list(dict.fromkeys(found))[:max(1, min(max_results, 1000))]
    return f"{len(uniq)} strings unik daripada {fp.name} ({len(data)} B):\n" + "\n".join(uniq)


INSPECT_TOOLS = [file_info, extract_strings]
