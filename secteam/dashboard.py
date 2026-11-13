"""Dashboard web tempatan untuk memvisualkan aktiviti agent daripada audit log.

Pelayan stdlib (tiada dependency), bind ke 127.0.0.1 sahaja kerana log mengandungi data engagement.
"""
from __future__ import annotations

import datetime as dt
import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

WEB_DIR = Path(__file__).parent / "web"
RUNNING_IDLE_SECONDS = 300  # sesi tanpa session_end dan tiada aktiviti > 5 minit dianggap terhenti

# Untuk log lama yang tiada medan 'agent' pada panggilan alat
TOOL_AGENT = {
    **{t: "spy" for t in ("dns_lookup", "rdap_lookup", "http_probe", "port_scan", "web_search",
                          "file_info", "extract_strings")},
    **{t: "analyst" for t in ("cve_lookup", "cve_search", "osv_lookup", "kev_recent", "scan_code",
                              "list_files", "read_file", "search_code", "run_semgrep", "run_bandit")},
    **{t: "operator" for t in ("vuln_scan", "http_request", "run_python", "netexec", "ssh_exec")},
}


def _epoch(rec: dict) -> float:
    if "t" in rec:
        return float(rec["t"])
    try:
        return dt.datetime.fromisoformat(rec["ts"]).timestamp()
    except (KeyError, ValueError):
        return 0.0


def load_sessions(log_dir: Path) -> dict[str, list[dict]]:
    """Baca semua audit-*.jsonl dan kumpulkan rekod mengikut sesi.
    Rekod lama tanpa 'session' dimasukkan ke dalam sesi session_start terakhir."""
    sessions: dict[str, list[dict]] = {}
    current = None
    for path in sorted(log_dir.glob("audit-*.jsonl")):
        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rec["t"] = _epoch(rec)
                rec["_src"] = f"{path.name}:{lineno}"  # rujukan bukti: fail log + nombor baris
                sid = rec.get("session")
                if rec.get("event") == "session_start":
                    sid = sid or f"legacy-{rec.get('ts', '')}"
                    current = sid
                sid = sid or current
                if not sid:
                    continue
                if rec.get("event") in ("tool_call", "tool_result", "tool_error", "scope_denied",
                                        "tool_cancelled") and not rec.get("agent"):
                    rec["agent"] = TOOL_AGENT.get(rec.get("tool", ""), "?")
                sessions.setdefault(sid, []).append(rec)
    return sessions


def summarize(sid: str, evs: list[dict]) -> dict:
    first = evs[0]
    start = next((e for e in evs if e["event"] == "session_start"), first)
    end = next((e for e in evs if e["event"] == "session_end"), None)
    task_ev = next((e for e in evs if e["event"] == "task"), None)
    last_t = max(e["t"] for e in evs)
    if end:
        status = "selesai"
    elif time.time() - last_t < RUNNING_IDLE_SECONDS:
        status = "berjalan"
    else:
        status = "terhenti"
    members = (task_ev or {}).get("members") or sorted({
        e.get("next") for e in evs if e["event"] == "supervisor_decision" and e.get("next") != "reporter"
    } - {None})
    task = (task_ev or {}).get("task")
    if not task and end and end.get("report"):  # sesi lama: teka daripada nama fail laporan
        task = Path(end["report"]).stem.split("-", 2)[-1].replace("-", " ") + " (dari nama laporan)"
    count = lambda name: sum(1 for e in evs if e["event"] == name)  # noqa: E731
    return {
        "id": sid,
        "start": start["t"], "start_ts": start.get("ts"),
        "end": end["t"] if end else None,
        "last": last_t,
        "status": status,
        "task": task or "(tugasan tidak direkodkan)",
        "members": members,
        "engagement": start.get("engagement_name") or start.get("engagement"),
        "code": start.get("code") if start.get("code") not in ("None", "") else None,
        "files": start.get("files") if start.get("files") not in ("None", "") else None,
        "auto_approve": start.get("auto_approve", False),
        "report": end.get("report") if end else None,
        "stats": {
            "decisions": count("supervisor_decision"),
            "tool_calls": count("tool_call"),
            "errors": count("tool_error"),
            "scope_denied": count("scope_denied"),
            "approvals": count("approval_request"),
            "loop_guard": count("loop_guard"),
            "unverified": sum(1 for e in evs if e["event"] == "specialist_result"
                              and (e.get("unverified") or "[TIDAK DISAHKAN]" in (e.get("result") or ""))),
        },
    }


class Handler(BaseHTTPRequestHandler):
    log_dir: Path = Path("logs")
    reports_dir: Path = Path("reports")
    default_theme: str = "trace"

    def log_message(self, *_):  # senyapkan log akses
        pass

    def _send(self, body: bytes, ctype: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status: int = 200) -> None:
        self._send(json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"),
                   "application/json; charset=utf-8", status)

    def do_GET(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        q = parse_qs(url.query)
        try:
            if url.path in ("/", "/index.html", "/trace"):
                page = "springfield.html" if self.default_theme == "springfield" and url.path == "/" else "index.html"
                self._send((WEB_DIR / page).read_bytes(), "text/html; charset=utf-8")
            elif url.path in ("/springfield", "/simpsons"):
                self._send((WEB_DIR / "springfield.html").read_bytes(), "text/html; charset=utf-8")
            elif url.path == "/api/sessions":
                sessions = load_sessions(self.log_dir)
                out = sorted((summarize(s, e) for s, e in sessions.items()), key=lambda s: s["start"], reverse=True)
                self._json(out)
            elif url.path == "/api/session":
                sid = (q.get("id") or [""])[0]
                evs = load_sessions(self.log_dir).get(sid)
                if not evs:
                    self._json({"error": "sesi tidak dijumpai"}, HTTPStatus.NOT_FOUND)
                    return
                self._json({"summary": summarize(sid, evs), "events": evs})
            elif url.path == "/api/report":
                rel = (q.get("path") or [""])[0]
                p = Path(rel).resolve()
                root = self.reports_dir.resolve()
                if not p.is_relative_to(root) or p.suffix not in (".md", ".json") or not p.exists():
                    self._json({"error": "laporan tidak sah"}, HTTPStatus.BAD_REQUEST)
                    return
                self._send(p.read_bytes(), "text/plain; charset=utf-8")
            else:
                self._json({"error": "tidak dijumpai"}, HTTPStatus.NOT_FOUND)
        except (BrokenPipeError, ConnectionResetError):
            pass


def serve(port: int, log_dir: Path, reports_dir: Path, theme: str = "trace") -> ThreadingHTTPServer:
    Handler.log_dir = log_dir
    Handler.reports_dir = reports_dir
    Handler.default_theme = theme
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)
