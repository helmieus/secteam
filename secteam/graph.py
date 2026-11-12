"""Graph orkestrasi: supervisor -> pakar -> supervisor ... -> reporter."""
from __future__ import annotations

import json
import operator
import re
import time
from typing import Annotated, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

from .agents import SPECIALISTS, build_specialist, clean_text, make_llm, reflect_skills, run_specialist
from .memory import SkillStore
from .runtime import RT
from .ui import console


class TeamState(TypedDict):
    task: str
    context: str
    findings: Annotated[list[dict], operator.add]
    next: str
    instruction: str
    steps: int
    report: str


SUPERVISOR_PROMPT = """You are the lead of an AUTHORIZED security research team. Decide the single next step.

Available team members:
__MEMBERS__
- reporter: writes the final report and ends the job. Choose it when the task is answered,
  when no member can make further progress, or when findings are sufficient.

Rules:
- Assign ONE member at a time with a concrete, specific instruction (targets, files, CVE IDs, what to look for).
- Build on findings so far; never repeat an assignment that was already done.
- Hand off between specialists only when it adds NEW information (e.g. service versions from recon ->
  threat_intel to verify CVEs).
- threat_intel is ONLY for a specific CVE id / product+version / package+version. Never send it generic
  vulnerability classes ("sql injection") or open questions ("what is X", "research Y", "how does Z work").
- For any open-ended "what is / research / find info about / how does it work" question about a tool,
  technique, concept or product (e.g. "php2shell", "what is SSTI"), assign the RESEARCHER, not threat_intel.
- code_auditor's scan already includes dependency CVEs. Once code_auditor has reported findings with
  file:line evidence, the audit is DONE -> choose reporter. Each member may be used at most twice.
- Only assign members listed above.
- Findings may end with an automatic evidence check. A CVE marked [TIDAK DISAHKAN] is NOT confirmed:
  either assign another attempt (e.g. verify the exact product+version against threat_intel) or go to reporter.
  Never treat an unverified claim as the answer.

Respond with ONLY a JSON object:
{"next": "<member name>", "instruction": "<specific instruction>", "reason": "<one short sentence>"}"""

REPORTER_PROMPT = """You are the report writer of a security research team. Write the final report in __LANG__,
in Markdown. Use ONLY information present in the findings; do not invent anything. Keep tool-verified
facts separate from hypotheses. Findings end with an automatic evidence check: anything marked
[TIDAK DISAHKAN] must NOT be presented as an answer or confirmed finding - list it only under caveats
as unverified. Only items marked [DISAHKAN] (or quoted from tool output) may be stated as results.

Structure:
# <Report title>
## Ringkasan Eksekutif
## Skop & Kebenaran   (engagement details if any, targets/code/files examined)
## Metodologi         (which specialists and tools were used)
## Penemuan           (table: ID | Tajuk | Severity | Status (Disahkan/Hipotesis); then one subsection per
                       finding with Bukti, Impak, Cadangan Pembaikan)
## Langkah Seterusnya
## Had & Kaveat       (what was not tested, limitations of automated/LLM analysis)"""


def _summarise_findings(findings: list[dict], per_item: int) -> str:
    if not findings:
        return "(none yet)"
    return "\n\n".join(
        f"### Step {i} - {f['agent']}\nAssignment: {f['instruction']}\nResult:\n{f['result'][:per_item]}"
        for i, f in enumerate(findings, 1)
    )


def _parse_decision(text: str, valid: set[str]) -> dict:
    text = clean_text(text)
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        try:
            d = json.loads(m.group(0)) if m else {}
        except json.JSONDecodeError:
            d = {}
    nxt = str(d.get("next", "")).strip().lower()
    if nxt not in valid:
        nxt = "reporter"
    return {"next": nxt, "instruction": str(d.get("instruction", "")), "reason": str(d.get("reason", ""))}


def _similar(a: str, b: str) -> float:
    wa, wb = set(re.findall(r"\w+", a.lower())), set(re.findall(r"\w+", b.lower()))
    return len(wa & wb) / max(len(wa | wb), 1)


def loop_guard(decision: dict, findings: list[dict], max_per_agent: int) -> str | None:
    """Pulangkan sebab jika keputusan Lead ialah ulangan (agent terlalu kerap / arahan hampir sama)."""
    nxt = decision["next"]
    if nxt == "reporter":
        return None
    prev = [f["instruction"] for f in findings if f["agent"] == nxt]
    if len(prev) >= max_per_agent:
        return f"{nxt} sudah dipanggil {len(prev)} kali (had {max_per_agent})"
    for p in prev:
        if _similar(decision["instruction"], p) >= 0.6:
            return f"arahan kepada {nxt} hampir sama dengan tugasan terdahulu"
    return None


def available_specialists() -> list[str]:
    names = ["researcher", "threat_intel"]
    if RT.engagement is not None:
        names.insert(0, "recon")
    if RT.code_root is not None:
        names.insert(0, "code_auditor")
    return names


def build_graph(cfg: dict, members: list[str] | None = None):
    members = members or available_specialists()
    orch = cfg.get("orchestration", {})
    max_steps = orch.get("max_steps", 8)
    max_rounds = orch.get("max_tool_rounds", 12)
    max_per_agent = orch.get("max_calls_per_agent", 2)
    lang = cfg.get("report_language", "Bahasa Melayu")

    mem_cfg = cfg.get("memory", {})
    mem = SkillStore(mem_cfg.get("dir", "memory"), mem_cfg.get("max_per_agent", 60)) \
        if mem_cfg.get("enabled", True) else None
    mem_k = mem_cfg.get("recall_k", 3)
    mem_reflect = mem_cfg.get("reflect", True)

    sup_llm = make_llm(cfg, "supervisor", json_mode=True)
    rep_llm = make_llm(cfg, "reporter")
    member_text = "\n".join(f"- {n}: {SPECIALISTS[n]['description']}" for n in members)
    sup_system = SystemMessage(SUPERVISOR_PROMPT.replace("__MEMBERS__", member_text))
    valid = {*members, "reporter"}

    def supervisor(state: TeamState):
        if state["steps"] >= max_steps:
            console.print(f"[yellow]Had {max_steps} langkah dicapai -> reporter[/]")
            return {"next": "reporter", "instruction": ""}
        human = HumanMessage(
            f"TASK:\n{state['task']}\n\nCONTEXT:\n{state['context']}\n\n"
            f"FINDINGS SO FAR ({len(state['findings'])} steps, {max_steps - state['steps']} remaining):\n"
            f"{_summarise_findings(state['findings'], 2500)}"
        )
        t0 = time.perf_counter()
        d = _parse_decision(sup_llm.invoke([sup_system, human]).content, valid)
        ms = int((time.perf_counter() - t0) * 1000)
        why = loop_guard(d, state["findings"], max_per_agent)
        if why:
            console.print(f"[yellow]Pengawal gelung: {why} -> reporter[/]")
            RT.audit.log("loop_guard", reason=why, blocked=d)
            d = {"next": "reporter", "instruction": "", "reason": f"loop guard: {why}"}
        RT.audit.log("supervisor_decision", step=state["steps"] + 1, ms=ms, **d)
        console.rule(f"[bold cyan]Lead -> {d['next']}[/]")
        if d["instruction"]:
            console.print(f"[cyan]Arahan:[/] {d['instruction']}\n[dim]Sebab: {d['reason']}[/]")
        return {"next": d["next"], "instruction": d["instruction"], "steps": state["steps"] + 1}

    def make_specialist_node(name: str):
        sub = build_specialist(cfg, name)

        def node(state: TeamState):
            assignment = state["instruction"] or state["task"]
            # BACA: suntik playbook (skill relevan dari run lepas) ke dalam tugasan pakar
            playbook = ""
            recalled: list[dict] = []
            if mem is not None:
                recalled = mem.recall(name, f"{state['task']} {assignment}", mem_k)
                playbook = mem.format_playbook(recalled)
            msg = (
                (playbook + "\n\n" if playbook else "")
                + f"Overall task: {state['task']}\n\nContext:\n{state['context']}\n\n"
                f"Your assignment from the lead:\n{assignment}\n\n"
                f"Relevant findings from teammates:\n{_summarise_findings(state['findings'], 3500)}"
            )
            RT.audit.agent = name
            RT.audit.log("specialist_start", instruction=state["instruction"],
                         playbook=[s["title"] for s in recalled] or None)
            try:
                result = run_specialist(sub, name, msg, max_rounds)
            finally:
                RT.audit.agent = None
            unverified = "[TIDAK DISAHKAN]" in result
            RT.audit.log("specialist_result", agent=name, chars=len(result), result=result[:8000],
                         unverified=unverified)
            # TULIS: belajar skill generalisasi - hanya jika hasil tidak ditanda tak sah
            if mem is not None and mem_reflect and not unverified:
                if recalled:
                    mem.bump_uses(name, [s["title"] for s in recalled])
                for sk in reflect_skills(cfg, name, assignment, result):
                    saved = mem.remember(name, sk["title"], sk["trigger"], sk["lesson"])
                    if saved:
                        RT.audit.log("skill_learned", agent=name, title=saved)
                        console.print(f"  [dim]playbook {name}: +{saved}[/]")
            return {"findings": [{"agent": name, "instruction": state["instruction"], "result": result}]}

        return node

    def reporter(state: TeamState):
        console.rule("[bold green]Menulis laporan[/]")
        RT.audit.log("reporter_start", agent="reporter")
        t0 = time.perf_counter()
        system = SystemMessage(REPORTER_PROMPT.replace("__LANG__", lang))
        human = HumanMessage(
            f"TASK:\n{state['task']}\n\nCONTEXT:\n{state['context']}\n\n"
            f"FINDINGS:\n{_summarise_findings(state['findings'], 4000)}"
        )
        report = clean_text(rep_llm.invoke([system, human]).content)
        RT.audit.log("reporter_done", agent="reporter", chars=len(report),
                     ms=int((time.perf_counter() - t0) * 1000))
        return {"report": report}

    g = StateGraph(TeamState)
    g.add_node("supervisor", supervisor)
    for name in members:
        g.add_node(name, make_specialist_node(name))
        g.add_edge(name, "supervisor")
    g.add_node("reporter", reporter)
    g.add_edge(START, "supervisor")
    g.add_conditional_edges("supervisor", lambda s: s["next"], {n: n for n in valid})
    g.add_edge("reporter", END)
    return g.compile()
