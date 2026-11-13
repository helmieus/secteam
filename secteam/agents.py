"""Definisi agent pakar + subgraph ReAct (model <-> alat) untuk setiap agent."""
from __future__ import annotations

import json
import re
import uuid

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_ollama import ChatOllama
from langgraph.errors import GraphRecursionError
from langgraph.graph import START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

from .config import model_for
from .tools import ANALYST_TOOLS, OPERATOR_TOOLS, SPY_TOOLS
from .ui import console

COMMON_RULES = """
Rules (mandatory):
- You are part of an AUTHORIZED security research team. Act only within the provided scope.
- Gather evidence with tools. NEVER invent findings, CVE IDs, versions, file contents or tool output.
- If a tool returns [DITOLAK - LUAR SKOP] or [DIBATALKAN], do not try to work around it; report it.
- If a tool/binary you need is missing, install it with install_tool (apt/pip/pipx). If the install FAILS,
  read the error and fix it yourself: retry with the correct package name/manager, or use run_shell to add a
  repository or install a missing dependency, then try again.
- If you need information that only the human operator has - a password, an OTP / 2FA code, a token, or a
  decision - call ask_human (secret=True for passwords/OTP). NEVER guess or fabricate such values.
- Prefer the least intrusive action that answers the question.
- When finished, reply WITHOUT calling tools, with a concise summary:
  for each finding: title, severity (Critical/High/Medium/Low/Info), evidence (file:line, URL, tool output),
  impact, and recommended fix. Clearly label anything unverified as "HYPOTHESIS".
"""

SPECIALISTS: dict[str, dict] = {
    "spy": {
        "description": "Perisik: gathers raw intel - network (nmap service detection), web (tech stack & "
                       "endpoint discovery), OSINT (web_search), and binary analysis (strings). No exploitation.",
        "tools": SPY_TOOLS,
        "prompt": """You are the Spy (Perisik) - reconnaissance and intelligence gathering.
Collect as much raw, factual data as possible WITHOUT active attacks that would damage the target.

Tasks:
1. Gather facts and raw data about the target.
2. Make NO assumptions or speculation - that is the Analyst's job.
3. Do NOT attempt exploitation.
4. Give precise, structured, complete data.
5. Use the provided tools with correct parameters.

Focus:
- Network: port_scan (service + version detection), dns_lookup, rdap_lookup.
- Web: technology stack and endpoint discovery (http_probe, web_search).
- Software/binary: file_info then extract_strings.

NEVER scan or guess a target that was not explicitly given in your assignment (no default ranges like
192.168.1.0/24). If no target was provided, do not call any scan tool - say a target is required.

OUTPUT: structured facts (prefer a JSON-like block) that the Analyst can process directly.
Only report what the tools actually returned; never invent data, versions or URLs.""",
    },
    "analyst": {
        "description": "Penyelidik Kerentanan: analyses the Spy's data, correlates it, maps CVEs (NVD/OSV/KEV), "
                       "audits code (semgrep/bandit), and produces testable hypotheses with confidence scores.",
        "tools": ANALYST_TOOLS,
        "prompt": """You are the Analyst (Penyelidik Kerentanan / Vulnerability Researcher) in a Red Team.

Tasks:
1. Analyse the Spy's data carefully.
2. Connect the data points to find correlations.
3. Identify potential vulnerabilities based on:
   - CVE database (cve_lookup / cve_search / osv_lookup / kev_recent)
   - Known attack patterns
   - Security best-practice violations
   - Code logic flaws (scan_code / read_file / search_code)
4. Give TESTABLE (actionable) hypotheses.
5. Assign a confidence score (0.0 - 1.0) to each hypothesis.

Thinking per domain:
- DOM XSS: bypass techniques (innerText/innerHTML, event handlers, gadget chains).
- Network: CVE matching and misconfigurations; map exposed services to exec paths (WinRM 5985, SMB 445,
  SSH 22, MSSQL 1433) that the Operator can use with found credentials.
- Web app (http service, login/API): auth bypass, default/guessable creds, IDOR, API enumeration, info leaks.
  A booking/reference code + a person's name are almost always WEB app inputs (log in / look up a record),
  not an OS password - hypothesise using them against the web service, and deriving OS usernames from the name.
- Reverse engineering: buffer overflow, memory corruption, binary exploitation.

OUTPUT: list hypotheses from HIGHEST to LOWEST confidence, each with a concrete suggested test for the
Operator. Only cite CVEs, versions and evidence that appear in actual tool output - never invent them.""",
    },
    "operator": {
        "description": "Exploit Operator: takes the Analyst's hypotheses and verifies them actively - crafted "
                       "HTTP requests (http_request), Python PoCs (run_python), nuclei (vuln_scan). Approval-gated.",
        "tools": OPERATOR_TOOLS,
        "prompt": """You are the Operator (Exploit Operator) in a Red Team. You ACTIVELY exploit and gain
access - you DO the work with real tools, you do not just advise or suggest tools.

Your tools:
- netexec: validate credentials AND run commands on a target over smb / winrm / ssh / mssql / wmi.
  Use found creds to authenticate ('[+]' = valid login, '(Pwn3d!)' = admin/exec) and to execute commands
  (read files, whoami, enumerate). Windows exec: command='whoami /all' or 'type <path>' (powershell=True for
  PowerShell).
- ssh_exec: get a shell on a Linux host and run commands (enumerate, sudo -l, privesc, read files).
- http_request: craft and inject HTTP payloads for web exploitation.
- run_python: write and run a custom PoC/exploit in Python (httpx available).
- vuln_scan: confirm a weakness with nuclei.

Method:
1. Take the Analyst's top hypothesis and ACTUALLY perform the exploit/access attempt with the right tool
   (a real command / real payload against the real target).
2. If it fails: READ the error, ADJUST (creds, path, protocol, encoding), and retry (about 5 attempts).
3. On access success: enumerate further and capture PROOF of access.
   - CTF / HackTheBox (testing): read and report the flag files. Common locations:
     Windows: C:\\Users\\<user>\\Desktop\\user.txt, C:\\Users\\Administrator\\Desktop\\root.txt
     Linux:   /home/<user>/user.txt, /root/root.txt. Then escalate to reach root.txt / Administrator.
   - Real engagement (NO flags exist): prove impact with MINIMAL evidence (whoami/id, hostname, and that you
     can reach a sensitive resource). Do NOT exfiltrate, read in bulk, alter or damage real client data;
     prioritise findings by business risk.
4. DOCUMENT the real Proof of Concept: the EXACT commands you ran and their actual output.

Credentials & protocols:
- When you have or find credentials, try them across ALL exec protocols with netexec - winrm, smb, wmi,
  mssql, ssh - not just one. Derive username formats from a person's name: 'First Last' -> flast, f.last,
  first.last, firstlast, first.
Web services (a port shows http, or http_request returns a page):
- Enumerate with http_request: FOLLOW redirects (e.g. to /login), probe /api, /swagger, /robots.txt; test
  for authentication bypass, default/guessable credentials, IDOR, and info leaks in responses.
- A booking / reference code plus a name usually belongs to a WEB app (log in / look up a record), not an
  OS login - use it against the web service first.

Rules:
- NEVER perform denial of service; do not damage the target.
- Use only credentials and targets given to you or found by the team - never invent creds, hosts or flags.
- If an action is [DIBATALKAN] or [DITOLAK], report it; do not try to work around it.

OUTPUT: status (SUCCESS / FAILED), the exact commands + output as PoC, any flags captured, and the lesson
learned. A result or flag is ONLY valid if it appears verbatim in real tool output - never fabricate it.""",
    },
}


def clean_text(content) -> str:
    if isinstance(content, list):
        content = "".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in content)
    return re.sub(r"<think>.*?</think>", "", str(content or ""), flags=re.S).strip()


def make_llm(cfg: dict, role: str, json_mode: bool = False) -> ChatOllama:
    o = cfg.get("ollama", {})
    kwargs = dict(
        model=model_for(cfg, role),
        base_url=o.get("base_url", "http://localhost:11434"),
        temperature=o.get("temperature", 0.2),
        num_ctx=o.get("num_ctx", 16384),
        num_predict=o.get("num_predict", 2048),   # elak model 7B mengulang teks tanpa henti
        repeat_penalty=o.get("repeat_penalty", 1.1),
        keep_alive=o.get("keep_alive", "30m"),
    )
    if json_mode:
        kwargs["format"] = "json"
    return ChatOllama(**kwargs)


REFLECT_PROMPT = """You just finished a security task as the {role} specialist.
Extract 0 to 2 REUSABLE, GENERALISABLE techniques you (or a teammate in this role) could apply to FUTURE,
DIFFERENT tasks - a growing playbook. Think "how to approach X", not one-off facts.

STRICT rules:
- Only GENERAL methods/heuristics/tool-usage patterns. NOT findings about this specific target.
- NEVER include target names, IPs, hostnames, client names, flags, hashes, secrets, or a claim that a
  specific CVE affects a specific product (those go stale). Techniques only.
- Only extract a lesson if the work actually demonstrated it (grounded in tool output), not speculation.
- If nothing reusable was learned, return an empty list.

Return ONLY JSON: {{"skills": [{{"title": "...", "trigger": "keywords when this applies", "lesson": "the technique in 1-2 sentences"}}]}}"""


def reflect_skills(cfg: dict, role: str, task: str, result: str) -> list[dict]:
    """Minta model distil 0-2 skill generalisasi daripada kerja pakar. Pulangkan senarai dict."""
    llm = make_llm(cfg, role, json_mode=True)
    msg = HumanMessage(f"TASK:\n{task}\n\nWHAT YOU DID AND FOUND:\n{result[:4000]}")
    try:
        raw = clean_text(llm.invoke([SystemMessage(REFLECT_PROMPT.format(role=role)), msg]).content)
    except Exception:  # noqa: BLE001 - refleksi tak boleh runtuhkan run
        return []
    data = None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = next((o for o in _iter_json_objects(raw) if isinstance(o, dict) and "skills" in o), None)
    skills = data.get("skills", []) if isinstance(data, dict) else []
    out = []
    for s in skills[:2]:
        if isinstance(s, dict) and s.get("title") and s.get("lesson"):
            out.append({"title": str(s["title"]), "trigger": str(s.get("trigger", "")), "lesson": str(s["lesson"])})
    return out


def _iter_json_objects(text: str):
    """Cari objek JSON {...} dalam teks (termasuk dalam blok ```json)."""
    dec = json.JSONDecoder()
    i = text.find("{")
    while i != -1:
        try:
            obj, end = dec.raw_decode(text, i)
            yield obj
            i = text.find("{", end)
        except json.JSONDecodeError:
            i = text.find("{", i + 1)


def recover_text_tool_calls(msg: AIMessage, tool_names: set[str]) -> AIMessage:
    """Sesetengah model (cth. qwen2.5-coder) menulis tool call sebagai teks JSON dan bukan tool_calls
    berstruktur. Tukar teks itu kepada tool_calls sebenar supaya alat benar-benar dijalankan."""
    if msg.tool_calls or not isinstance(msg.content, str):
        return msg
    calls = []
    for obj in _iter_json_objects(msg.content):
        if not isinstance(obj, dict):
            continue
        name = obj.get("name") or obj.get("tool") or (obj.get("function") or {}).get("name")
        args = obj.get("arguments", obj.get("parameters", obj.get("args", {})))
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        if name in tool_names and isinstance(args, dict):
            calls.append({"name": name, "args": args, "id": f"call_{uuid.uuid4().hex[:12]}", "type": "tool_call"})
    if not calls:
        return msg
    return AIMessage(content="", tool_calls=calls, id=msg.id)


def _call_key(tc: dict) -> str:
    return tc["name"] + json.dumps(tc.get("args", {}), sort_keys=True).lower()


def build_specialist(cfg: dict, name: str):
    spec = SPECIALISTS[name]
    base_llm = make_llm(cfg, name)
    llm = base_llm.bind_tools(spec["tools"])
    system = SystemMessage(spec["prompt"] + "\n" + COMMON_RULES)
    tool_names = {t.name for t in spec["tools"]}
    max_parallel = cfg.get("orchestration", {}).get("max_parallel_tool_calls", 4)

    def call_model(state: MessagesState):
        msgs = [system, *state["messages"]]
        resp = recover_text_tool_calls(llm.invoke(msgs), tool_names)
        if not resp.tool_calls:
            return {"messages": [resp]}
        # buang panggilan yang sudah dibuat sebelum ini / pendua dalam giliran yang sama, dan hadkan bilangan
        done = {_call_key(tc) for m in state["messages"] if isinstance(m, AIMessage) for tc in m.tool_calls}
        fresh, seen = [], set()
        for tc in resp.tool_calls:
            k = _call_key(tc)
            if k not in done and k not in seen:
                seen.add(k)
                fresh.append(tc)
        dropped = len(resp.tool_calls) - len(fresh[:max_parallel])
        if dropped:
            console.print(f"    [dim]({dropped} panggilan alat pendua/berlebihan diabaikan)[/]")
        if fresh:
            return {"messages": [AIMessage(content=resp.content, tool_calls=fresh[:max_parallel], id=resp.id)]}
        # semua panggilan ialah ulangan -> paksa model menulis ringkasan akhir tanpa alat
        final = base_llm.invoke(msgs + [HumanMessage(
            "You already have the results of these tool calls above. Do NOT call tools again. "
            "Write your final summary now, using only facts from the tool outputs.")])
        return {"messages": [AIMessage(content=clean_text(final.content), id=resp.id)]}

    g = StateGraph(MessagesState)
    g.add_node("model", call_model)
    g.add_node("tools", ToolNode(spec["tools"]))
    g.add_edge(START, "model")
    g.add_conditional_edges("model", tools_condition)
    g.add_edge("tools", "model")
    return g.compile()


def _show(agent: str, m) -> None:
    if isinstance(m, AIMessage) and m.tool_calls:
        for tc in m.tool_calls:
            args = str(tc.get("args"))
            console.print(f"  [magenta]{agent}[/] -> [bold]{tc['name']}[/]({args[:140]})")
    elif isinstance(m, ToolMessage):
        first = str(m.content).strip().splitlines()[:1]
        console.print(f"    [dim]{(first[0] if first else '')[:160]}[/]")


def run_specialist(subgraph, agent: str, message: str, max_rounds: int) -> str:
    msgs: list = []
    seen = 1  # langkau HumanMessage awal
    note = ""
    try:
        for state in subgraph.stream(
            {"messages": [HumanMessage(message)]},
            {"recursion_limit": max_rounds * 2 + 1},
            stream_mode="values",
        ):
            msgs = state["messages"]
            for m in msgs[seen:]:
                _show(agent, m)
            seen = len(msgs)
    except GraphRecursionError:
        note = "\n\n[Nota: had pusingan alat dicapai; hasil mungkin tidak lengkap.]"

    tool_text = "\n".join(str(m.content) for m in msgs if isinstance(m, ToolMessage))
    for m in reversed(msgs):
        if isinstance(m, AIMessage):
            text = clean_text(m.content)
            if text:
                return text + note + verify_claims(text, tool_text)
    tool_out = [clean_text(m.content)[:1500] for m in msgs if isinstance(m, ToolMessage)][-3:]
    return "Agent tidak menghasilkan ringkasan. Output alat terakhir:\n" + "\n---\n".join(tool_out) + note


FLAG_CLAIM_RE = re.compile(r"[A-Za-z0-9_]{1,16}\{[^\s{}]{1,120}\}")
CVE_CLAIM_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def verify_claims(text: str, tool_text: str) -> str:
    """Semak setiap flag / CVE yang didakwa agent benar-benar muncul dalam output alat.
    Model kecil kerap merosakkan data semasa menyalin atau mereka-reka jawapan."""
    lines = []
    for f in dict.fromkeys(FLAG_CLAIM_RE.findall(text)):
        if f in tool_text:
            lines.append(f"[DISAHKAN] Flag '{f}' muncul dalam output alat.")
        else:
            lines.append(f"[TIDAK DISAHKAN] Flag '{f}' TIADA dalam mana-mana output alat - kemungkinan "
                         f"rekaan/salinan rosak oleh model. JANGAN laporkan sebagai jawapan.")
    upper_tools = tool_text.upper()
    bad_cves = [c for c in dict.fromkeys(c.upper() for c in CVE_CLAIM_RE.findall(text)) if c not in upper_tools]
    if bad_cves:
        lines.append(f"[TIDAK DISAHKAN] CVE tiada dalam output alat: {', '.join(bad_cves)} - mungkin rekaan.")
    return ("\n\n--- Semakan bukti automatik ---\n" + "\n".join(lines)) if lines else ""
