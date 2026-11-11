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
    """Laluan relatif kepada root audit. Nama root sendiri / laluan mutlak root dianggap '.'.
    Laluan yang tidak wujud ialah RALAT (bukan imbasan kosong senyap yang memberi '0 isu')."""
    root = _root()
    rel = (rel or ".").strip().strip("/\\") or "."
    if rel == root.name:
        return root
    p = Path(rel)
    p = (p if p.is_absolute() else root / p).resolve()
    if not p.is_relative_to(root):
        raise PermissionError(f"Laluan di luar root audit ({root}).")
    if not p.exists():
        raise FileNotFoundError(
            f"'{rel}' tidak wujud dalam root audit {root}. Guna laluan RELATIF kepada root, "
            f"cth. '.' untuk keseluruhan projek atau 'app.py'."
        )
    return p


def _rel(p) -> str:
    try:
        r = str(Path(p).resolve().relative_to(_root()))
        return "" if r == "." else r
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
        f"[{r['extra'].get('severity')}] {r['check_id'].split('.')[-1]} {_rel(r['path'])}:{r['start']['line']}"
        f" - {r['extra'].get('message', '').strip()[:120]}"
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


# ---------------------------------------------------------------- scan_code (gabungan)

CATEGORIES = [  # (kategori, kata kunci dalam rule id / test id)
    ("SQL Injection", ("sql", "B608")),
    ("Command Injection", ("subprocess", "command", "shell", "os-system", "B602", "B605", "B607", "B609")),
    ("Server-Side Template Injection / XSS", ("template", "ssti", "B701", "B703", "B704")),
    ("Cross-Site Scripting", ("xss", "raw-html", "html")),
    ("Path Traversal", ("path-traversal", "traversal")),
    ("Insecure Deserialization", ("deserial", "pickle", "yaml-load", "marshal", "B301", "B506")),
    ("Binding to All Interfaces", ("bad_host", "bind_all", "B104")),
    ("Debug Mode Enabled", ("debug", "B201")),
    ("Hardcoded Secret", ("hardcoded_password", "hardcoded-password", "secret", "password", "api-key",
                          "B105", "B106", "B107")),
    ("SSRF", ("ssrf",)),
    ("Weak Cryptography", ("md5", "sha1", "crypto", "B303", "B304", "B324", "B311")),
    ("Insecure TLS", ("verify", "ssl", "tls", "B501", "B502", "B503")),
    ("Code Injection (eval/exec)", ("eval", "exec", "B102", "B307")),
]
REMEDIATION = {  # cadangan pembaikan tetap (lebih boleh dipercayai daripada model 7B)
    "SQL Injection": "Guna parameterised query, cth. cursor.execute('... WHERE u = ? AND p = ?', (user, pw)); "
                     "jangan bina SQL dengan f-string/concat. Simpan kata laluan sebagai hash (bcrypt/argon2).",
    "Command Injection": "Elak shell=True; guna subprocess.run(['ping', '-c', '1', host], shell=False) dan "
                         "validasi input dengan allowlist (cth. ipaddress.ip_address(host)).",
    "Server-Side Template Injection / XSS": "Jangan bina template daripada input pengguna. Guna "
                         "render_template('hello.html', name=name) dengan autoescape, atau markupsafe.escape(name).",
    "Cross-Site Scripting": "Escape output (markupsafe.escape / autoescape Jinja2 melalui render_template); "
                            "tambah Content-Security-Policy.",
    "Path Traversal": "Guna werkzeug.utils.safe_join(BASE_DIR, fname) atau send_from_directory(); tolak '..' dan "
                      "laluan mutlak; secure_filename() untuk nama fail.",
    "Insecure Deserialization": "JANGAN deserialize data tidak dipercayai dengan pickle/marshal (tiada cara "
                                "selamat). Guna JSON + validasi skema; untuk YAML guna yaml.safe_load().",
    "Hardcoded Secret": "Pindahkan rahsia ke environment variable / secret manager; putar (rotate) rahsia yang "
                        "telah terdedah dalam repo/sejarah git.",
    "Debug Mode Enabled": "Matikan debug=True dalam produksi (debugger Werkzeug membenarkan pelaksanaan kod); "
                          "kawal melalui FLASK_DEBUG/env.",
    "Binding to All Interfaces": "Bind ke 127.0.0.1 dan letak di belakang reverse proxy (nginx) jika perlu akses luar.",
    "SSRF": "Allowlist domain/IP destinasi; sekat alamat dalaman (169.254.169.254, 10/8, 127/8).",
    "Weak Cryptography": "Guna SHA-256+/HMAC untuk integriti, bcrypt/argon2 untuk kata laluan, secrets untuk token.",
    "Insecure TLS": "Jangan matikan pengesahan sijil (verify=True); guna CA bundle yang betul.",
    "Code Injection (eval/exec)": "Buang eval/exec pada input; guna ast.literal_eval atau parser khusus.",
}
NOISE_IDS = {"B403", "B404", "B110", "B112", "B101"}  # import sahaja / try-except-pass / assert
SEV_RANK = {"HIGH": 3, "ERROR": 3, "MEDIUM": 2, "WARNING": 2, "LOW": 1, "INFO": 1}
SEV_NAME = {3: "HIGH", 2: "MEDIUM", 1: "LOW"}


def _category(rule: str) -> str:
    low = rule.lower()
    for cat, keys in CATEGORIES:
        if any(k.lower() in low for k in keys):
            return cat
    return "Lain-lain"


def _semgrep_raw(target: Path) -> list[dict]:
    args = ["semgrep", "scan", "--json", "--quiet", "--metrics", "off"]
    for c in RT.cfg.get("semgrep_configs", ["p/default"]):
        args += ["--config", c]
    p = run_proc(args + [str(target)], timeout=1800)
    out = []
    for r in json.loads(p.stdout or "{}").get("results", []):
        out.append({"tool": "semgrep", "rule": r["check_id"].split(".")[-1], "file": _rel(r["path"]),
                    "line": r["start"]["line"], "sev": SEV_RANK.get(r["extra"].get("severity", "INFO"), 1),
                    "cat": _category(r["check_id"])})
    return out


def _bandit_raw(target: Path) -> list[dict]:
    p = run_proc(["bandit", "-r", str(target), "-f", "json", "-q"], timeout=1200)
    out = []
    for r in json.loads(p.stdout or "{}").get("results", []):
        if r["test_id"] in NOISE_IDS:
            continue
        out.append({"tool": "bandit", "rule": f"{r['test_id']}:{r['test_name']}", "file": _rel(r["filename"]),
                    "line": r["line_number"], "sev": SEV_RANK.get(r["issue_severity"], 1),
                    "cat": _category(f"{r['test_id']} {r['test_name']}")})
    return out


def _snippet(rel: str, line: int) -> str:
    try:
        lines = (_root() / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[line - 1].strip()[:160]
    except (OSError, IndexError):
        return ""


def _merge(hits: list[dict]) -> list[dict]:
    """Gabung hit dengan kategori + fail sama dan baris berdekatan (<=5) menjadi satu isu."""
    issues: list[dict] = []
    for h in sorted(hits, key=lambda h: (h["cat"], h["file"], h["line"])):
        last = issues[-1] if issues else None
        if last and last["cat"] == h["cat"] and last["file"] == h["file"] and h["line"] - last["end"] <= 5:
            last["end"] = max(last["end"], h["line"])
            if h["sev"] >= last["sev"]:
                last["sev"], last["key_line"] = h["sev"], h["line"]
            last["rules"].add(f"{h['tool']}:{h['rule']}")
        else:
            issues.append({"cat": h["cat"], "file": h["file"], "start": h["line"], "end": h["line"],
                           "key_line": h["line"], "sev": h["sev"], "rules": {f"{h['tool']}:{h['rule']}"}})
    # isu yang dikesan oleh dua alat lebih meyakinkan
    for i in issues:
        i["tools"] = {r.split(":")[0] for r in i["rules"]}
    return sorted(issues, key=lambda i: (-i["sev"], -len(i["tools"]), i["file"], i["start"]))


def _parse_manifests(root: Path) -> list[tuple[str, str, str, str]]:
    """(ecosystem, package, version, file) daripada requirements*.txt dan package.json."""
    deps = []
    for req in _iter_files(root, "requirements*.txt"):
        for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
            if m:
                deps.append(("PyPI", m.group(1), m.group(2), _rel(req)))
    for pj in _iter_files(root, "package.json"):
        try:
            data = json.loads(pj.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for sect in ("dependencies", "devDependencies"):
            for name, ver in (data.get(sect) or {}).items():
                v = str(ver).lstrip("^~=v ")
                if re.match(r"^\d+(\.\d+)*$", v):
                    deps.append(("npm", name, v, _rel(pj)))
    return deps[:40]


def _osv(eco: str, name: str, version: str) -> list[dict]:
    import httpx  # noqa: PLC0415

    r = httpx.post("https://api.osv.dev/v1/query",
                   json={"package": {"name": name, "ecosystem": eco}, "version": version}, timeout=30)
    r.raise_for_status()
    return r.json().get("vulns", [])


@tool
@guarded
def scan_code(subdir: str = ".") -> str:
    """PREFERRED first step for code audits. Runs Semgrep + Bandit + dependency vulnerability check
    (OSV for requirements.txt / package.json) in one call, de-duplicates and groups findings by
    vulnerability class and location, and shows the offending code line as evidence."""
    target = _resolve(subdir)
    n_files = sum(1 for _ in _iter_files(target, "*")) if target.is_dir() else 1
    if n_files == 0:
        raise FileNotFoundError(f"Tiada fail untuk diimbas dalam {_rel(target) or '.'}.")
    hits, notes = [], []
    for name, fn in (("semgrep", _semgrep_raw), ("bandit", _bandit_raw)):
        try:
            hits += fn(target)
        except Exception as e:  # noqa: BLE001
            notes.append(f"{name}: {type(e).__name__}: {e}")
    issues = _merge(hits)
    counts = {s: sum(1 for i in issues if i["sev"] == s) for s in (3, 2, 1)}
    lines = [f"RINGKASAN KOD ({n_files} fail diimbas di '{_rel(target) or '.'}'): {len(issues)} isu unik "
             f"(HIGH {counts[3]}, MEDIUM {counts[2]}, LOW {counts[1]})"]
    for n, i in enumerate(issues, 1):
        loc = f"{i['file']}:{i['start']}" + (f"-{i['end']}" if i["end"] != i["start"] else "")
        tools_ = "+".join(sorted(i["tools"]))
        lines.append(f"C{n}. [{SEV_NAME[i['sev']]}] {i['cat']} - {loc}  (dikesan oleh {tools_})")
        lines.append(f"     > L{i['key_line']}: {_snippet(i['file'], i['key_line'])}")
        if i["cat"] in REMEDIATION:
            lines.append(f"     Pembaikan: {REMEDIATION[i['cat']]}")
    deps = _parse_manifests(target)
    if deps:
        lines.append(f"\nDEPENDENCY ({len(deps)} pakej dengan versi tetap):")
        n_vuln = 0
        for eco, name, ver, src in deps:
            try:
                vulns = _osv(eco, name, ver)
            except Exception as e:  # noqa: BLE001
                lines.append(f"  {name}=={ver}: semakan OSV gagal ({e})")
                continue
            if not vulns:
                continue
            n_vuln += 1
            cves = sorted({a for v in vulns for a in v.get("aliases", []) if a.startswith("CVE-")})
            fixed = sorted({e["fixed"] for v in vulns for a in v.get("affected", []) for rg in a.get("ranges", [])
                            for e in rg.get("events", []) if "fixed" in e},
                           key=lambda s: [int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", s)])
            summaries = "; ".join(dict.fromkeys(v.get("summary", "")[:70] for v in vulns if v.get("summary")))
            lines.append(f"D{n_vuln}. {name}=={ver} ({src}): {len(vulns)} vulnerability; "
                         f"CVE: {', '.join(cves[:6]) or '-'}{' ...' if len(cves) > 6 else ''}")
            lines.append(f"     Jenis: {summaries[:300]}")
            lines.append(f"     Pembaikan: naik taraf ke {name}>={fixed[-1] if fixed else '(versi terkini)'} "
                         f"(versi terendah yang membaiki SEMUA isu di atas)")
        if n_vuln == 0:
            lines.append("  Tiada vulnerability diketahui.")
    if notes:
        lines.append("\nNota alat: " + "; ".join(notes))
    return "\n".join(lines)


SAST_TOOLS = [scan_code, list_files, read_file, search_code, run_semgrep, run_bandit]
