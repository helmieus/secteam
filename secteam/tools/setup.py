"""Alat sokongan untuk agent: pasang tool yang diperlukan, baiki sendiri bila gagal, dan minta input manusia.
Semua jalan di HOST (VM pentest) dan perlu kelulusan + audit. Untuk SETUP/DIAGNOSIS/LOCAL sahaja -
serang target melalui tool khusus (netexec/ssh_exec/http_request), jangan arahan merosakkan/DoS."""
import subprocess
import sys

from langchain_core.tools import tool

from .common import guarded, request_human_input, require_approval

_BAD = set(";|&`$<>\n")


@tool
@guarded
def install_tool(package: str, manager: str = "apt") -> str:
    """Install a tool/package you need to continue (e.g. hydra, gobuster, smbclient, seclists, or a pip
    library like impacket). manager: 'apt' | 'pip' | 'pipx'. If it FAILS, the error output is returned -
    read it, then adjust the package name or manager and retry, or use run_shell to fix a missing dependency
    (add a repo, install build deps, etc.). Requires approval."""
    pkg = package.strip()
    if not pkg or _BAD & set(pkg):
        raise ValueError("nama pakej tidak sah (aksara shell tidak dibenarkan)")
    mgr = manager.strip().lower()
    require_approval("install_tool", f"{mgr} install {pkg}")
    if mgr == "apt":
        subprocess.run(["sudo", "apt-get", "update", "-q"], capture_output=True, text=True, timeout=180)
        cmd = ["sudo", "apt-get", "install", "-y", "-q", pkg]
    elif mgr == "pip":
        cmd = [sys.executable, "-m", "pip", "install", pkg]
    elif mgr == "pipx":
        cmd = ["python3", "-m", "pipx", "install", pkg]
    else:
        raise ValueError("manager mesti 'apt', 'pip' atau 'pipx'")
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
    tail = (p.stdout[-1200:] + "\n" + p.stderr[-1800:]).strip()
    status = "BERJAYA" if p.returncode == 0 else f"GAGAL (exit {p.returncode})"
    return f"[{status}] {mgr} install {pkg}\n{tail}"


@tool
@guarded
def run_shell(command: str, timeout: int = 120) -> str:
    """Run a shell command on THIS host (the pentest VM) to set up tooling, diagnose/fix a failed install,
    check the environment (which / ldd / apt-cache / pip show), or prepare files. Returns stdout+stderr.
    For SETUP, DIAGNOSIS and LOCAL operations only - attack the target through netexec/ssh_exec/http_request,
    and NEVER run destructive or denial-of-service commands. Requires approval."""
    require_approval("run_shell", command[:200])
    p = subprocess.run(command, shell=True, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=max(1, min(timeout, 600)))
    out = p.stdout.strip()
    if p.stderr.strip():
        out += "\n[stderr]\n" + p.stderr.strip()
    return f"exit={p.returncode}\n{out}"[:8000]


# ask_human SENGAJA bukan @guarded: elak jawapan (boleh jadi password/OTP) direkod dalam audit tool_result.
@tool
def ask_human(question: str, secret: bool = False) -> str:
    """Ask the human operator for information you need to continue: a password, an OTP / 2FA code, an API
    token, a missing detail, or a decision. Returns their typed answer. Use ONLY when you genuinely need
    something that only the human can provide. Set secret=True for passwords/OTP (input is hidden and not
    logged). In non-interactive mode this returns a notice that no human is available."""
    return request_human_input(question, secret)


SETUP_TOOLS = [install_tool, run_shell, ask_human]
