"""Alat recon untuk Spy. Scope guard dibuang (operator arah sendiri); tindakan aktif kekal perlu kelulusan."""
import json
import re
import socket
from urllib.parse import urlparse

import httpx
from langchain_core.tools import tool

from .common import guarded, require_approval
from .shell import run_proc

PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
SEVERITIES = ("info", "low", "medium", "high", "critical")
SECURITY_HEADERS = (
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
)
UA = {"User-Agent": "secteam-authorized-assessment/0.1"}


def _host(target: str) -> str:
    """Ambil host bersih daripada URL / host:port / IP (tanpa semakan skop)."""
    t = (target or "").strip()
    if not t or t.startswith("-"):
        raise ValueError(f"Target tidak sah: {target!r}")
    if "://" in t or "/" not in t:
        parsed = urlparse(t if "://" in t else "//" + t)
        return (parsed.hostname or t).rstrip(".")
    return t


@tool
@guarded
def dns_lookup(host: str) -> str:
    """Resolve DNS (A/AAAA records) for a hostname. Passive and low impact."""
    h = _host(host)
    ips = sorted({i[4][0] for i in socket.getaddrinfo(h, None)})
    return f"{h} -> {', '.join(ips) or 'tiada rekod'}"


@tool
@guarded
def rdap_lookup(domain: str) -> str:
    """Get domain registration data (RDAP/WHOIS: registrar, dates, nameservers) for a domain."""
    d = _host(domain)
    r = httpx.get(f"https://rdap.org/domain/{d}", follow_redirects=True, timeout=20, headers=UA)
    r.raise_for_status()
    j = r.json()
    events = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}
    ns = [n.get("ldhName") for n in j.get("nameservers", [])]
    roles = []
    for ent in j.get("entities", []):
        vcard = ent.get("vcardArray", [None, []])[1]
        fn = next((v[3] for v in vcard if v and v[0] == "fn"), ent.get("handle"))
        roles.append(f"{'/'.join(ent.get('roles', []))}: {fn}")
    return json.dumps(
        {"domain": d, "status": j.get("status"), "events": events, "nameservers": ns, "entities": roles},
        indent=1, ensure_ascii=False,
    )


@tool
@guarded
def http_probe(url: str) -> str:
    """Send ONE GET request to a URL and report status, redirect, server banner, technology,
    security headers present/missing, cookie flags and page title. Does not follow redirects."""
    if "://" not in url:
        url = "http://" + url
    with httpx.Client(follow_redirects=False, timeout=15, verify=False, headers=UA) as c:
        r = c.get(url)
    h = r.headers
    title = re.search(r"<title[^>]*>(.*?)</title>", r.text[:20000], re.I | re.S)
    lines = [
        f"URL: {url}",
        f"Status: {r.status_code}",
        f"Location: {h.get('location', '-')}",
        f"Server: {h.get('server', '-')} | X-Powered-By: {h.get('x-powered-by', '-')}",
        f"Title: {title.group(1).strip()[:120] if title else '-'}",
        "Security headers:",
    ]
    for name in SECURITY_HEADERS:
        lines.append(f"  {name}: {h.get(name, 'TIADA')}")
    for ck in h.get_list("set-cookie"):
        flags = [f for f in ("secure", "httponly", "samesite") if f in ck.lower()]
        lines.append(f"Cookie {ck.split('=')[0]}: flags={flags or 'TIADA'}")
    return "\n".join(lines)


@tool
@guarded
def port_scan(target: str, ports: str = "top100", service_detection: bool = True) -> str:
    """TCP connect port scan (nmap -sT) of a host or CIDR, for service detection / endpoint discovery.
    ports: 'top100', 'top1000', or a list like '22,80,443,8000-8100'.
    service_detection=True adds version detection (-sV). Requires human approval."""
    args = ["nmap", "-Pn", "-sT", "-T3", "--max-retries", "2", "--host-timeout", "15m"]
    if ports in ("top100", "top1000"):
        args += ["--top-ports", ports[3:]]
    elif PORTS_RE.match(ports):
        args += ["-p", ports]
    else:
        raise ValueError("Format ports tidak sah. Guna 'top100', 'top1000' atau '22,80,8000-8100'.")
    if service_detection:
        args.append("-sV")
    args.append(_host(target))
    require_approval("port_scan", " ".join(args))
    p = run_proc(args, timeout=1800)
    return p.stdout + (f"\n[stderr]\n{p.stderr[-1500:]}" if p.returncode else "")


@tool
@guarded
def vuln_scan(target: str, severity: str = "medium,high,critical") -> str:
    """Run nuclei vulnerability templates (rate limited) against a URL or host to verify weaknesses.
    severity: comma list from info,low,medium,high,critical. Requires human approval."""
    sev = [s.strip() for s in severity.split(",") if s.strip() in SEVERITIES] or ["medium", "high", "critical"]
    args = [
        "nuclei", "-target", target.strip(), "-severity", ",".join(sev),
        "-rate-limit", "50", "-jsonl", "-silent", "-no-color", "-disable-update-check",
    ]
    require_approval("vuln_scan", " ".join(args))
    p = run_proc(args, timeout=3600)
    results = []
    for line in p.stdout.splitlines():
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = j.get("info", {})
        results.append(
            f"[{info.get('severity', '?').upper()}] {j.get('template-id')} - {info.get('name')}\n"
            f"    matched: {j.get('matched-at')}  extracted: {j.get('extracted-results') or '-'}"
        )
    if not results:
        return "Tiada penemuan nuclei." + (f"\n[stderr]\n{p.stderr[-1500:]}" if p.stderr else "")
    return f"{len(results)} penemuan:\n" + "\n".join(results)


RECON_TOOLS = [dns_lookup, rdap_lookup, http_probe, port_scan, vuln_scan]
