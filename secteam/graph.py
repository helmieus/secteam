"""Graph orkestrasi: supervisor -> pakar -> supervisor ... -> reporter."""
from __future__ import annotations

import json
import operator
import re
import time
from typing import Annotated, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

from .agents import (
    SPECIALISTS,
    _iter_json_objects,
    build_specialist,
    clean_text,
    make_llm,
    reflect_skills,
    run_specialist,
)
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


SUPERVISOR_PROMPT = """You are the Red Team Lead (Ketua Pasukan). Direct the team and decide the single next step.

Available team members:
__MEMBERS__
- reporter: end the assignment and give the operator a short BRIEFING of the findings. You do NOT write
  the full formal report here - the operator reviews the briefing and requests the full report separately.
  Choose it when the hypotheses have been verified, when no member can progress, or when findings are sufficient.

The pipeline is: Spy (gather raw intel) -> Analyst (correlate data, rank vulnerabilities as testable
hypotheses with confidence) -> Operator (actively verify/exploit the top hypotheses).

Rules:
- Assign ONE member at a time with a concrete, specific instruction (targets, files, which hypothesis).
- NEVER invent, assume or guess a target (IP, host, URL, CIDR, port). Use ONLY targets explicitly given by
  the operator or already present in the findings/context. If a task needs a target and none is available,
  choose reporter and state that a target is required - do NOT make one up (never default to 192.168.x.x etc.).
- Enforce the Rules of Engagement / scope shown in the context; prioritise by risk (Critical > High > Medium > Low).
- Build on findings so far; never repeat an assignment that was already done.
- spy only gathers data (no exploitation). analyst turns data into ranked, testable hypotheses - never send
  it exploitation work. operator verifies hypotheses actively (approval-gated) - give it ONE hypothesis + test.
- Do not send the operator until the analyst has produced at least one concrete hypothesis.
- If the objective is to EXPLOIT, keep driving: after the analyst ranks hypotheses, assign the operator to
  ACTUALLY exploit (gain access, run commands) and capture proof - a CTF/HackTheBox flag (user.txt, root.txt)
  when testing, or in a real engagement MINIMAL proof-of-access/impact (never exfiltrate real client data) -
  then escalate. Do NOT end at hypotheses or recommendations while the operator still has promising,
  untried vectors or credentials to test.
- Each member may be used at most twice. Only assign members listed above.
- Findings may end with an automatic evidence check. A result/CVE marked [TIDAK DISAHKAN] is NOT confirmed:
  either assign another attempt or go to reporter. Never treat an unverified claim as the answer.

Respond with ONLY a JSON object:
{"next": "<member name>", "instruction": "<specific instruction>", "reason": "<one short sentence>"}"""

REPORTER_PROMPT = """You are the Red Team Lead writing the final Web Application Security Assessment (WASA)
report in the company's standard format. Write prose in __LANG__, but keep SECTION TITLES and FIELD LABELS
in English (company standard). Use ONLY information in the findings; do not invent anything.
Findings end with an automatic evidence check: items marked [TIDAK DISAHKAN] are NOT confirmed - present
them as Hypotheses only, never as proven. Only [DISAHKAN] / tool-quoted items are confirmed results.

Produce Markdown in EXACTLY this structure:

# <Client / Application> - Web Application Security Assessment Report

## 1. INTRODUCTION
Purpose of the assessment and intended AUDIENCE.

## 2. ASSESSMENT ACTIVITIES
- **Overview:** objective of the exercise.
- **Point of Attack:** External / Internal.
- **Target:** the assessed URL(s) / host(s) from the findings.
- **Scope of Work:** what was tested.
- **Tools Used:** list only the tools the team actually used (from the findings).

## 3. SEVERITY RATING DEFINITION
Short table: Critical / High / Medium / Low / Info and what each means.

## 4. SUMMARY OF FINDINGS
One sentence: "A total of N target(s) was tested and produced X Critical, Y High, Z Medium, W Low."
Then a table: No | Vulnerability | Severity | Status (Disahkan / Hipotesis).

## 5. FINDINGS
Group by severity, HIGHEST first (Critical -> High -> Medium -> Low). For EACH finding use this EXACT field
template (keep labels in English):
### <FINDING NAME IN CAPS>
- **Severity:** <Critical/High/Medium/Low> - <Disahkan / Hipotesis>
- **Point of Attack:** External / Internal
- **CVE / CWE:** <CWE-id - name; CVE id ONLY if it appears in tool output>
- **CVSS:** <score + rating (+ vector if derivable), else "Estimated">
- **OWASP Top 10:** <A0x:2021 - category>
- **ISO/IEC 27001:** <relevant Annex A control(s)>
- **Root Cause:** <one line>
- **Description:** <from evidence>
- **Impact:** <from evidence>
- **Proof of Concept:** <reproducible steps / request / tool output - ONLY from the Operator's VERIFIED
  work; if not verified, write "Not verified - hypothesis, PoC pending">
- **Recommendation:** <concrete fix>
- **References:** <CWE / OWASP URLs>
- **Affected Host / Port:** <target : port / protocol>

## 6. CONCLUSION
Overall risk posture and recommended next steps.

Rules:
- CWE / OWASP / ISO mappings MAY be derived from the vulnerability class (standard classifications).
- But Description, Impact, Proof of Concept, Affected Host and CVE ids MUST come from the actual findings /
  tool output - never fabricate a PoC. If the Operator did not verify it, mark the finding Hipotesis.
- Output clean Markdown (fenced code blocks for requests/output), ready for a client report and a Jekyll blog.
- Admin sections (cover page, Revision History, Document Approval, Table of Contents, Acceptance Verification)
  are added later from the company template - do NOT fabricate approver names, dates or signatures."""

BRIEF_PROMPT = """You are the Red Team Lead giving a SHORT briefing to the operator - NOT a formal report.
In __LANG__, concisely present what the team found so far:
- Per specialist (Spy / Analyst / Operator): the KEY results in bullet points.
- Clearly separate VERIFIED results ([DISAHKAN] or quoted from tool output) from HYPOTHESIS / [TIDAK DISAHKAN].
- State what is NOT yet done, and any decision you need from the operator.
Keep it short (a briefing, not a document). Do NOT write the formal report sections.
End with exactly: "Jalankan `secteam report` bila anda berpuas hati untuk laporan penuh." """


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
    # Pasukan Red Team tetap: Spy -> Analyst -> Operator (Leader orkestrasi + tulis laporan).
    return ["spy", "analyst", "operator"]


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
        # 'run' berhenti dengan TAKLIMAT (briefing), bukan laporan penuh. Laporan penuh dijana
        # secara berasingan oleh 'secteam report' bila operator berpuas hati.
        console.rule("[bold green]Taklimat pasukan[/]")
        RT.audit.log("brief_start", agent="leader")
        t0 = time.perf_counter()
        system = SystemMessage(BRIEF_PROMPT.replace("__LANG__", lang))
        human = HumanMessage(
            f"TASK:\n{state['task']}\n\nCONTEXT:\n{state['context']}\n\n"
            f"FINDINGS:\n{_summarise_findings(state['findings'], 4000)}"
        )
        brief = clean_text(rep_llm.invoke([system, human]).content)
        RT.audit.log("brief_done", agent="leader", chars=len(brief),
                     ms=int((time.perf_counter() - t0) * 1000))
        return {"report": brief}

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


TRIAGE_PROMPT = """You are the Red Team Lead chatting with the operator. Classify their latest message.
Return ONLY JSON: {"mode": "converse" | "task", "reply": "<text>"}

Decision:
1. Does the message tell you to DO something (scan, pentest, test, audit, exploit, check, probe, enumerate,
   ping, lookup, research) AND name a target (a domain, IP, URL or host such as google.com, 10.0.0.1,
   http://x, or a CVE id)? -> "task", leave "reply" empty. The target is already given; do NOT ask again.
2. Is it a greeting, small talk, "who/what are you", "what can you do", thanks, or any question that is not
   an instruction to act? -> "converse", put a short direct answer (in __LANG__) in "reply" as the lead.
3. Does it ask you to act but names NO target, and none exists in the context? -> "converse", and in "reply"
   ASK the operator for the exact target.

Rules:
- If a target is clearly present in the message, it is ALWAYS a "task" - never ask for a target you were given.
- NEVER invent a target (e.g. never assume 192.168.1.0/24).
- A purely casual or meta question is never a task."""


def triage(cfg: dict, user: str, context: str) -> dict:
    """Asingkan borak/soalan (converse) daripada tugasan sebenar (task) dalam mod chat.
    Elak pasukan dijalankan untuk mesej biasa + elak Leader reka sasaran."""
    lang = cfg.get("report_language", "Bahasa Melayu")
    llm = make_llm(cfg, "supervisor", json_mode=True)
    sys = SystemMessage(TRIAGE_PROMPT.replace("__LANG__", lang))
    human = HumanMessage(f"CONTEXT (targets/findings known so far):\n{context[:2000]}\n\nOPERATOR MESSAGE:\n{user}")
    try:
        raw = clean_text(llm.invoke([sys, human]).content)
        d = json.loads(raw) if raw.startswith("{") else next(
            (o for o in _iter_json_objects(raw) if isinstance(o, dict)), {})
    except Exception:  # noqa: BLE001
        d = {}
    mode = str(d.get("mode", "task")).strip().lower()
    if mode not in ("converse", "task"):
        mode = "task"
    return {"mode": mode, "reply": str(d.get("reply", ""))}


def write_full_report(cfg: dict, task: str, context: str, findings: list[dict]) -> str:
    """Jana laporan penuh (format company) daripada findings sesi - dipanggil oleh 'secteam report'
    bila operator berpuas hati dengan taklimat. Berasingan daripada graf 'run'."""
    # Laporan rasmi klien = English (padan format company WASA), walaupun taklimat dalam Bahasa Melayu.
    rep_llm = make_llm(cfg, "reporter")
    system = SystemMessage(REPORTER_PROMPT.replace("__LANG__", "English"))
    human = HumanMessage(
        f"TASK:\n{task}\n\nCONTEXT:\n{context}\n\nFINDINGS:\n{_summarise_findings(findings, 4000)}"
    )
    return clean_text(rep_llm.invoke([system, human]).content)
