"""Graph orkestrasi: supervisor -> pakar -> supervisor ... -> reporter."""
from __future__ import annotations

import json
import operator
import re
from typing import Annotated, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

from .agents import SPECIALISTS, build_specialist, clean_text, make_llm, run_specialist
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
- Hand off between specialists when useful (e.g. service versions from recon -> threat_intel to verify CVEs;
  dependency versions from code_auditor -> threat_intel).
- Only assign members listed above.

Respond with ONLY a JSON object:
{"next": "<member name>", "instruction": "<specific instruction>", "reason": "<one short sentence>"}"""

REPORTER_PROMPT = """You are the report writer of a security research team. Write the final report in __LANG__,
in Markdown. Use ONLY information present in the findings; do not invent anything. Keep tool-verified
facts separate from hypotheses.

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


def available_specialists() -> list[str]:
    names = ["threat_intel", "ctf_solver"]
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
    lang = cfg.get("report_language", "Bahasa Melayu")

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
            f"{_summarise_findings(state['findings'], 1500)}"
        )
        d = _parse_decision(sup_llm.invoke([sup_system, human]).content, valid)
        RT.audit.log("supervisor_decision", **d)
        console.rule(f"[bold cyan]Lead -> {d['next']}[/]")
        if d["instruction"]:
            console.print(f"[cyan]Arahan:[/] {d['instruction']}\n[dim]Sebab: {d['reason']}[/]")
        return {"next": d["next"], "instruction": d["instruction"], "steps": state["steps"] + 1}

    def make_specialist_node(name: str):
        sub = build_specialist(cfg, name)

        def node(state: TeamState):
            msg = (
                f"Overall task: {state['task']}\n\nContext:\n{state['context']}\n\n"
                f"Your assignment from the lead:\n{state['instruction'] or state['task']}\n\n"
                f"Relevant findings from teammates:\n{_summarise_findings(state['findings'], 800)}"
            )
            result = run_specialist(sub, name, msg, max_rounds)
            RT.audit.log("specialist_result", agent=name, chars=len(result))
            return {"findings": [{"agent": name, "instruction": state["instruction"], "result": result}]}

        return node

    def reporter(state: TeamState):
        console.rule("[bold green]Menulis laporan[/]")
        system = SystemMessage(REPORTER_PROMPT.replace("__LANG__", lang))
        human = HumanMessage(
            f"TASK:\n{state['task']}\n\nCONTEXT:\n{state['context']}\n\n"
            f"FINDINGS:\n{_summarise_findings(state['findings'], 4000)}"
        )
        return {"report": clean_text(rep_llm.invoke([system, human]).content)}

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
