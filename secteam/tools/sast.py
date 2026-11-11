"""Alat code audit. Akses fail dihadkan kepada root --code."""
import json
import re
from collections import Counter
from pathlib import Path

from langchain_core.tools import tool

from ..runtime import RT
from .common import guarded
from .shell import run_proc

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
    ".idea", ".vscode", "vendor", "target", ".next", ".tox",
}
SEV_ORDER = {"ERROR": 0, "HIGH": 0, "WARNING": 1, "MEDIUM": 1, "INFO": 2, "LOW": 2}


def _root() -> Path:
    if RT.code_root is None:
        raise ValueError("Tiada root kod diberi (guna --code).")
    return RT.code_root


def _resolve(rel: str) -> Path:
    root = _root()
    p = (root / rel).resolve()
    if not p.is_relative_to(root):
        raise PermissionError("Laluan di luar root audit.")
    return p


def _rel(p) -> str:
    try:
        return str(Path(p).resolve().relative_to(_root()))
    except ValueError:
        return str(p)


def _iter_files(base: Path, glob: str):
    root = _root()
    for p in base.rglob(glob):
        if p.is_file() and not any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            yield p


@tool
@guarded
def list_files(subdir: str = ".", glob: str = "*") -> str:
    """List source files under the audit root (relative paths, sizes) plus a language summary."""
    files = list(_iter_files(_resolve(subdir), glob))
    langs = Counter(p.suffix.lower() or "(tiada)" for p in files)
    head = f"{len(files)} fail. Sambungan: " + ", ".join(f"{k}:{v}" for k, v in langs.most_common(12))
    body = "\n".join(f"{_rel(p)} ({p.stat().st_size} B)" for p in files[:400])
    more = f"\n... dan {len(files) - 400} lagi" if len(files) > 400 else ""
    return f"{head}\n{body}{more}"


@tool
@guarded
def read_file(path: str, start_line: int = 1, end_line: int = 200) -> str:
    """Read a source file (relative to audit root) with line numbers. Max 400 lines per call."""
    p = _resolve(path)
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, start_line)
    end = min(len(lines), end_line, start + 399)
    out = "\n".join(f"{i:5d}| {lines[i - 1]}" for i in range(start, end + 1))
    return f"{_rel(p)} (baris {start}-{end} daripada {len(lines)})\n{out}"


@tool
@guarded
def search_code(pattern: str, glob: str = "*") -> str:
    """Regex search across source files (e.g. 'exec\\(|eval\\(', 'password\\s*='). Returns up to 80 hits."""
    rx = re.compile(pattern)
    hits = []
    for p in _iter_files(_root(), glob):
        if p.stat().st_size > 1_000_000:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                hits.append(f"{_rel(p)}:{n}: {line.strip()[:200]}")
                if len(hits) >= 80:
                    return "\n".join(hits) + "\n...[had 80 hit]"
    return "\n".join(hits) or "Tiada padanan."


@tool
@guarded
def run_semgrep(subdir: str = ".") -> str:
    """Run Semgrep static analysis on the audit root (or a subdirectory). Returns findings sorted by severity."""
    target = _resolve(subdir)
    args = ["semgrep", "scan", "--json", "--quiet", "--metrics", "off"]
    for c in RT.cfg.get("semgrep_configs", ["p/default"]):
        args += ["--config", c]
    args.append(str(target))
    p = run_proc(args, timeout=1800)
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        return f"Output semgrep tidak boleh dihurai.\n{p.stderr[-2000:]}"
    res = sorted(data.get("results", []), key=lambda r: SEV_ORDER.get(r["extra"].get("severity", "INFO"), 3))
    out = [
        f"[{r['extra'].get('severity')}] {r['check_id']}\n    {_rel(r['path'])}:{r['start']['line']} - "
        f"{r['extra'].get('message', '').strip()[:300]}"
        for r in res[:60]
    ]
    errs = len(data.get("errors", []))
    return f"{len(res)} penemuan semgrep ({errs} ralat parse).\n" + "\n".join(out)


@tool
@guarded
def run_bandit(subdir: str = ".") -> str:
    """Run Bandit (Python security linter) on the audit root or a subdirectory."""
    target = _resolve(subdir)
    p = run_proc(["bandit", "-r", str(target), "-f", "json", "-q"], timeout=1200)
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        return f"Output bandit tidak boleh dihurai.\n{p.stderr[-2000:]}"
    res = sorted(data.get("results", []), key=lambda r: SEV_ORDER.get(r.get("issue_severity", "LOW"), 3))
    out = [
        f"[{r['issue_severity']}/{r['issue_confidence']}] {r['test_id']} {_rel(r['filename'])}:{r['line_number']}"
        f" - {r['issue_text']}"
        for r in res[:60]
    ]
    return f"{len(res)} penemuan bandit.\n" + "\n".join(out)


SAST_TOOLS = [list_files, read_file, search_code, run_semgrep, run_bandit]
