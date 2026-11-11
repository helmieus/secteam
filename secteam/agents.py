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
from .tools import CTF_TOOLS, INTEL_TOOLS, RECON_TOOLS, SAST_TOOLS
from .tools.intel import osv_lookup
from .ui import console

COMMON_RULES = """
Rules (mandatory):
- You are part of an AUTHORIZED security research team. Act only within the provided scope.
- Gather evidence with tools. NEVER invent findings, CVE IDs, versions, file contents or tool output.
- If a tool returns [DITOLAK - LUAR SKOP] or [DIBATALKAN], do not try to work around it; report it.
- Prefer the least intrusive action that answers the question.
- When finished, reply WITHOUT calling tools, with a concise summary:
  for each finding: title, severity (Critical/High/Medium/Low/Info), evidence (file:line, URL, tool output),
  impact, and recommended fix. Clearly label anything unverified as "HYPOTHESIS".
"""

SPECIALISTS: dict[str, dict] = {
    "recon": {
        "description": "Recon & pentest on in-scope targets: DNS/RDAP, HTTP probing, nmap port scan, nuclei vuln scan.",
        "tools": RECON_TOOLS,
        "prompt": """You are the Recon & Penetration Testing specialist.
Methodology: passive first (dns_lookup, rdap_lookup) -> port_scan (start with top100) ->
http_probe on discovered web ports -> vuln_scan only on confirmed web services and only if needed.
Interpret results: exposed services, outdated versions, missing security headers, misconfigurations.
Map service versions to likely CVEs as HYPOTHESES for the threat_intel specialist to verify.""",
    },
    "code_auditor": {
        "description": "Source code security audit (SAST): semgrep, bandit, manual review of risky code, dependency CVEs.",
        "tools": [*SAST_TOOLS, osv_lookup],
        "prompt": """You are the Code Security Auditor.
Methodology: list_files to understand the project -> run_semgrep (and run_bandit for Python) ->
search_code for hot spots (auth, SQL, command exec, deserialization, file paths, SSRF, templates,
hardcoded secrets, weak crypto) -> read_file to VERIFY each candidate in context.
Discard false positives explicitly. Check dependency manifests (requirements.txt, package.json, ...)
with osv_lookup for pinned versions. Cite file:line for every finding.""",
    },
    "threat_intel": {
        "description": "Threat intelligence: CVE details, CVSS/EPSS/CISA-KEV prioritisation, package vulnerabilities, recent exploited CVEs.",
        "tools": INTEL_TOOLS,
        "prompt": """You are the Threat Intelligence analyst.
Use cve_lookup / cve_search / osv_lookup / kev_recent. Prioritise by: in CISA KEV > high EPSS > CVSS.
State affected and fixed versions when known, and concrete mitigation/patch guidance.
Only cite CVE IDs that appear in tool output.""",
    },
    "ctf_solver": {
        "description": "CTF challenge solving: crypto, encoding, forensics files, scripting; finds the flag.",
        "tools": CTF_TOOLS,
        "prompt": """You are the CTF Solver.
First identify the category (crypto, encoding, forensics, web, rev, misc). Inspect files with
list_ctf_files / file_inspect. Try cheap transformations first (decode auto, caesar, xor), then
write focused Python with run_python (print intermediate values). Explain the reasoning chain and
report the flag exactly as recovered. Never guess a flag.""",
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


def build_specialist(cfg: dict, name: str):
    spec = SPECIALISTS[name]
    llm = make_llm(cfg, name).bind_tools(spec["tools"])
    system = SystemMessage(spec["prompt"] + "\n" + COMMON_RULES)
    tool_names = {t.name for t in spec["tools"]}

    def call_model(state: MessagesState):
        resp = llm.invoke([system, *state["messages"]])
        return {"messages": [recover_text_tool_calls(resp, tool_names)]}

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

    for m in reversed(msgs):
        if isinstance(m, AIMessage):
            text = clean_text(m.content)
            if text:
                return text + note
    tool_out = [clean_text(m.content)[:1500] for m in msgs if isinstance(m, ToolMessage)][-3:]
    return "Agent tidak menghasilkan ringkasan. Output alat terakhir:\n" + "\n---\n".join(tool_out) + note
