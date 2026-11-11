"""CLI secteam."""
from __future__ import annotations

import datetime as dt
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.panel import Panel
from rich.table import Table

from .audit import AuditLog
from .config import DEFAULT_CONFIG, load_config
from .runtime import RT
from .scope import Engagement, ScopeError
from .ui import console

app = typer.Typer(help="Pasukan AI security research (LangGraph + Ollama).", no_args_is_help=True)

EngOpt = typer.Option(None, "--engagement", "-e", help="Fail YAML engagement (wajib untuk recon/scan).")
CodeOpt = typer.Option(None, "--code", "-c", help="Direktori kod sumber untuk diaudit.")
FilesOpt = typer.Option(None, "--files", "-f", help="Direktori fail cabaran CTF.")
AutoOpt = typer.Option(False, "--auto-approve", help="Luluskan tindakan aktif secara automatik (BERHATI-HATI).")
StepsOpt = typer.Option(None, "--max-steps", help="Override had langkah supervisor.")
CfgOpt = typer.Option(DEFAULT_CONFIG, "--config", help="Fail konfigurasi.")


def _setup(cfg_path: Path, engagement: Optional[Path], code: Optional[Path], files: Optional[Path],
           auto_approve: bool) -> dict:
    cfg = load_config(cfg_path)
    paths = cfg.get("paths", {})
    RT.cfg = cfg
    RT.audit = AuditLog(paths.get("logs", "logs"))
    RT.sandbox_dir = Path(paths.get("sandbox", "workspace/sandbox")).resolve()
    RT.max_tool_output = cfg.get("orchestration", {}).get("max_tool_output_chars", 6000)
    RT.auto_approve = auto_approve

    if engagement:
        eng = Engagement.load(engagement)
        RT.engagement = eng
        style = "green" if eng.is_active() else "red"
        console.print(Panel(eng.summary(), title="Engagement", border_style=style))
        if not eng.is_active():
            console.print("[red]Engagement tidak aktif - semua aktiviti recon akan ditolak.[/]")
    if code:
        if not code.is_dir():
            raise typer.BadParameter(f"{code} bukan direktori")
        RT.code_root = code.resolve()
    if files:
        if not files.is_dir():
            raise typer.BadParameter(f"{files} bukan direktori")
        RT.files_root = files.resolve()
    if auto_approve and RT.engagement:
        console.print("[bold red]AMARAN:[/] --auto-approve aktif; scan akan berjalan tanpa pengesahan.")
    RT.audit.log("session_start", engagement=getattr(RT.engagement, "path", None),
                 code=str(RT.code_root), files=str(RT.files_root), auto_approve=auto_approve)
    return cfg


def _context() -> str:
    parts = []
    if RT.engagement:
        parts.append(RT.engagement.summary())
    else:
        parts.append("No engagement loaded: active recon/scanning is NOT authorized.")
    if RT.code_root:
        parts.append(f"Source code available for audit at: {RT.code_root}")
    if RT.files_root:
        parts.append(f"CTF challenge files available at: {RT.files_root}")
    return "\n".join(parts)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:40] or "laporan"


def _ollama_models(cfg: dict) -> set[str]:
    base = cfg.get("ollama", {}).get("base_url", "http://localhost:11434")
    try:
        tags = httpx.get(f"{base}/api/tags", timeout=5).json()
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Ollama tidak boleh dihubungi di {base}[/] ({e}). Pastikan Ollama berjalan.")
        raise typer.Exit(1)
    names = {m["name"] for m in tags.get("models", [])}
    return names | {n.removesuffix(":latest") for n in names}


def _preflight_models(cfg: dict) -> None:
    """Pastikan setiap model wujud; jika tiada, jatuh balik ke model default (dengan amaran)."""
    have = _ollama_models(cfg)
    models = cfg.setdefault("models", {})
    default = models.get("default", "qwen2.5:7b")
    if default not in have:
        console.print(f"[red]Model default '{default}' tiada.[/] Jalankan: [bold]ollama pull {default}[/]")
        raise typer.Exit(1)
    for role, m in list(models.items()):
        if m not in have:
            console.print(f"[yellow]Model '{m}' untuk {role} tiada -> guna '{default}'. "
                          f"(ollama pull {m} untuk guna model asal)[/]")
            models[role] = default


def _execute(task: str, cfg: dict, max_steps: Optional[int]) -> None:
    from .graph import available_specialists, build_graph  # import lewat: lebih pantas untuk --help

    _preflight_models(cfg)
    if max_steps:
        cfg.setdefault("orchestration", {})["max_steps"] = max_steps
    members = available_specialists()
    console.print(f"[bold]Pasukan:[/] {', '.join(members)}  |  [bold]Tugasan:[/] {task}")
    graph = build_graph(cfg, members)
    state = {"task": task, "context": _context(), "findings": [], "next": "",
             "instruction": "", "steps": 0, "report": ""}
    findings: list[dict] = []
    report = ""
    for update in graph.stream(state, {"recursion_limit": 200}, stream_mode="updates"):
        for _node, val in update.items():
            if not val:
                continue
            findings += val.get("findings", [])
            report = val.get("report") or report

    out_dir = Path(cfg.get("paths", {}).get("reports", "reports"))
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{dt.datetime.now():%Y%m%d-%H%M%S}-{_slug(task)}"
    (out_dir / f"{stem}.md").write_text(report, encoding="utf-8")
    (out_dir / f"{stem}-findings.json").write_text(
        json.dumps({"task": task, "context": state["context"], "findings": findings}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    RT.audit.log("session_end", report=str(out_dir / f"{stem}.md"))
    console.rule("[bold green]Selesai[/]")
    console.print(f"Laporan: [bold]{out_dir / (stem + '.md')}[/]\nBukti mentah: {out_dir / (stem + '-findings.json')}")


@app.command()
def run(task: str = typer.Argument(..., help="Tugasan dalam bahasa biasa."),
        engagement: Optional[Path] = EngOpt, code: Optional[Path] = CodeOpt, files: Optional[Path] = FilesOpt,
        auto_approve: bool = AutoOpt, max_steps: Optional[int] = StepsOpt, config: Path = CfgOpt):
    """Jalankan pasukan penuh: supervisor akan mengagih kerja kepada pakar yang sesuai."""
    cfg = _setup(config, engagement, code, files, auto_approve)
    _execute(task, cfg, max_steps)


@app.command()
def audit(path: Path = typer.Argument(..., help="Direktori kod sumber."),
          focus: str = typer.Option("", help="Fokus tambahan, cth. 'authentication dan SQL'."),
          max_steps: Optional[int] = StepsOpt, config: Path = CfgOpt):
    """Audit keselamatan kod sumber (SAST + semakan manual + CVE dependency)."""
    cfg = _setup(config, None, path, None, False)
    task = ("Perform a thorough security code audit of the provided source code. Find and verify "
            "vulnerabilities, check dependencies for known CVEs, and prioritise by severity.")
    _execute(task + (f" Focus: {focus}" if focus else ""), cfg, max_steps)


@app.command()
def cve(query: str = typer.Argument(..., help="ID CVE, produk, atau soalan threat intel."),
        config: Path = CfgOpt):
    """Analisis threat intel untuk CVE / produk."""
    cfg = _setup(config, None, None, None, False)
    _execute(f"Threat intelligence analysis: {query}. Assess severity, exploitation status and mitigation.",
             cfg, 3)


@app.command()
def ctf(challenge: str = typer.Argument(..., help="Penerangan cabaran CTF (boleh termasuk ciphertext)."),
        files: Optional[Path] = FilesOpt, auto_approve: bool = AutoOpt, config: Path = CfgOpt):
    """Selesaikan cabaran CTF."""
    cfg = _setup(config, None, None, files, auto_approve)
    _execute(f"Solve this CTF challenge and recover the flag:\n{challenge}", cfg, 4)


@app.command("check-scope")
def check_scope(engagement: Path = typer.Argument(...), target: str = typer.Argument(...),
                activity: str = typer.Option("port_scan", help="passive_recon|web_probe|port_scan|vuln_scan")):
    """Uji sama ada target dibenarkan oleh fail engagement (tanpa menjalankan apa-apa)."""
    eng = Engagement.load(engagement)
    try:
        norm = eng.check(target, activity)
        console.print(f"[green]DIBENARKAN[/] {norm} untuk {activity}")
    except ScopeError as e:
        console.print(f"[red]DITOLAK[/] {e}")
        raise typer.Exit(1)


@app.command()
def doctor(config: Path = CfgOpt):
    """Semak Ollama, model dan alat luaran."""
    cfg = load_config(config)
    base = cfg.get("ollama", {}).get("base_url", "http://localhost:11434")
    table = Table(title="secteam doctor")
    table.add_column("Komponen")
    table.add_column("Status")
    try:
        tags = httpx.get(f"{base}/api/tags", timeout=5).json()
        have = {m["name"] for m in tags.get("models", [])}
        table.add_row("Ollama", f"[green]OK[/] {base}")
        for m in sorted(set(cfg.get("models", {}).values())):
            ok = m in have or f"{m}:latest" in have
            table.add_row(f"model {m}", "[green]ada[/]" if ok else f"[red]tiada[/] -> ollama pull {m}")
    except Exception as e:  # noqa: BLE001
        table.add_row("Ollama", f"[red]tidak boleh dihubungi[/] ({e})")
    for b, why in [("nmap", "recon port_scan"), ("nuclei", "recon vuln_scan"),
                   ("semgrep", "code audit"), ("bandit", "code audit Python")]:
        found = shutil.which(b, path=str(Path(sys.executable).parent)) or shutil.which(b)
        table.add_row(b, "[green]ada[/]" if found else f"[yellow]tiada[/] (pilihan: {why})")
    console.print(table)


if __name__ == "__main__":
    app()
