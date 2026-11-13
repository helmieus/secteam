"""Alat akses/eksploitasi aktif untuk Operator: sahkan kredential + LAKSANA arahan atas target.
AUTHORIZED pentest / CTF (cth. HackTheBox) sahaja. Setiap tindakan perlu kelulusan + audit; jangan DoS.
Jalankan secteam dalam VM yang bersambung ke rangkaian sasaran yang dibenarkan sahaja."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

from langchain_core.tools import tool

from .common import guarded, require_approval

NXC_PROTOCOLS = ("smb", "winrm", "ssh", "rdp", "ldap", "mssql", "ftp", "wmi", "nfs", "vnc")
EXEC_PROTOCOLS = ("smb", "winrm", "ssh", "mssql", "wmi")  # yang menyokong -x (laksana arahan)


def _nxc_bin() -> str:
    for cand in (
        shutil.which("nxc"),
        shutil.which("netexec"),
        str(Path.home() / ".local/bin/nxc"),
        str(Path.home() / ".local/bin/netexec"),
    ):
        if cand and Path(cand).exists():
            return cand
    raise FileNotFoundError("netexec (nxc) tidak dipasang. Pasang: pipx install netexec")


@tool
@guarded
def netexec(protocol: str, host: str, username: str = "", password: str = "",
            command: str = "", powershell: bool = False, extra: str = "") -> str:
    """Authenticate to a target and OPTIONALLY execute a command, via netexec (nxc).
    protocol: smb | winrm | ssh | rdp | ldap | mssql | ftp | wmi | vnc | nfs.
    With username+password it validates the credentials (look for '[+]' = success, '(Pwn3d!)' = admin).
    With `command` (on smb/winrm/ssh/mssql/wmi) it RUNS that command on the target and returns the output -
    use this to gain access with found credentials, enumerate, and read flag files (e.g. command='type
    C:\\Users\\Public\\user.txt' or 'whoami /all'). powershell=True runs it via PowerShell (-X) on Windows.
    Requires approval. Authorized targets only; never use for denial of service."""
    proto = protocol.strip().lower()
    if proto not in NXC_PROTOCOLS:
        raise ValueError(f"protocol mesti salah satu: {', '.join(NXC_PROTOCOLS)}")
    if command and proto not in EXEC_PROTOCOLS:
        raise ValueError(f"'{proto}' tak menyokong laksana arahan; guna smb/winrm/ssh/mssql/wmi.")
    args = [_nxc_bin(), proto, host]
    if username:
        args += ["-u", username]
    if password:
        args += ["-p", password]
    if command:
        args += (["-X", command] if powershell else ["-x", command])
    if extra:
        args += extra.split()
    detail = " ".join(args).replace(password, "***") if password else " ".join(args)
    require_approval("netexec", detail)
    p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=300)
    out = p.stdout.strip()
    if p.stderr.strip():
        out += "\n[stderr]\n" + p.stderr.strip()[-1500:]
    return out or f"(tiada output, exit={p.returncode})"


@tool
@guarded
def ssh_exec(host: str, command: str, username: str, password: str = "",
             key_path: str = "", port: int = 22) -> str:
    """SSH into a target and run ONE command, returning stdout/stderr. Use found credentials (password or
    private key) to get a shell on a Linux host, enumerate, attempt privilege escalation, and read files
    (e.g. command='cat ~/user.txt' or 'sudo -l'). Requires approval. Authorized targets only; no DoS."""
    import paramiko  # noqa: PLC0415

    require_approval("ssh_exec", f"{username}@{host}:{port} $ {command[:160]}")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, port=int(port), username=username, timeout=20,
                  allow_agent=False, look_for_keys=False, banner_timeout=20, auth_timeout=20)
    if key_path:
        kwargs["key_filename"] = os.path.expanduser(key_path)
    if password:
        kwargs["password"] = password
    try:
        client.connect(**kwargs)
        _in, _out, _err = client.exec_command(command, timeout=60)
        out = _out.read().decode("utf-8", "replace").strip()
        err = _err.read().decode("utf-8", "replace").strip()
    finally:
        client.close()
    res = f"$ {command}\n{out}"
    if err:
        res += "\n[stderr]\n" + err[-1500:]
    return res or f"$ {command}\n(tiada output)"


ACCESS_TOOLS = [netexec, ssh_exec]
