"""Memori skill per-pakar: playbook teknik boleh guna semula yang berkembang antara run.

Reka bentuk keselamatan:
- Simpan TEKNIK generalisasi, bukan fakta mudah basi atau data klien.
- Penapis buang apa-apa yang nampak khusus-sasaran (IP, flag, sasaran engagement, rahsia).
- JSONL boleh baca manusia -> mudah disemak & dibuang.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import threading
from pathlib import Path

# Corak yang menandakan data khusus (JANGAN simpan ke memori kongsi)
_BLOCK = [
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),                 # alamat IPv4
    re.compile(r"\b[a-zA-Z0-9_]{1,16}\{[^}\n]{1,200}\}"),       # flag: wgmy{...}, flag{...}
    re.compile(r"\b[A-Fa-f0-9]{24,}\b"),                        # blob hex panjang (hash/kunci)
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),                # blob base64 panjang
    re.compile(r"\b(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S+", re.I),
]
_WORD = re.compile(r"[a-zA-Z0-9]{3,}")


def _tokens(text: str) -> set[str]:
    return {w.lower() for w in _WORD.findall(text or "")}


def looks_specific(text: str) -> bool:
    """True jika teks mengandungi data khusus-sasaran yang tak patut masuk memori kongsi."""
    return any(p.search(text or "") for p in _BLOCK)


class SkillStore:
    """Stor skill per-pakar. Satu fail JSONL setiap pakar di bawah `dir`."""

    def __init__(self, dir: Path | str = "memory", max_per_agent: int = 60) -> None:
        self.dir = Path(dir)
        self.max = max_per_agent
        self._lock = threading.Lock()

    def _path(self, agent: str) -> Path:
        safe = re.sub(r"[^a-z0-9_]+", "_", agent.lower())
        return self.dir / f"{safe}.jsonl"

    def all(self, agent: str) -> list[dict]:
        p = self._path(agent)
        if not p.exists():
            return []
        out = []
        for line in p.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def recall(self, agent: str, query: str, k: int = 3) -> list[dict]:
        """Skill paling relevan dengan query (pertindihan kata kunci trigger+title)."""
        q = _tokens(query)
        if not q:
            return []
        scored = []
        for s in self.all(agent):
            kw = _tokens(s.get("trigger", "") + " " + s.get("title", ""))
            overlap = len(q & kw)
            if overlap:
                scored.append((overlap + 0.1 * s.get("uses", 0), s))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored[:k]]

    def remember(self, agent: str, title: str, trigger: str, lesson: str) -> str | None:
        """Tambah skill. Pulangkan tajuk jika disimpan, atau None jika ditolak/pendua.
        Menolak apa-apa yang nampak khusus-sasaran, dan nyahpendua ikut tajuk."""
        title, trigger, lesson = title.strip(), trigger.strip(), lesson.strip()
        if not title or not lesson:
            return None
        if any(looks_specific(x) for x in (title, trigger, lesson)):
            return None
        with self._lock:
            existing = self.all(agent)
            tset = _tokens(title)
            for s in existing:
                if len(tset & _tokens(s.get("title", ""))) >= max(2, len(tset) - 1):
                    return None  # pendua / hampir sama
            skill = {"title": title[:120], "trigger": trigger[:200], "lesson": lesson[:600],
                     "added": dt.date.today().isoformat(), "uses": 0}
            existing.append(skill)
            # had saiz: buang yang paling jarang guna & lama
            existing.sort(key=lambda s: (s.get("uses", 0), s.get("added", "")))
            existing = existing[-self.max:]
            self._write(agent, existing)
            return skill["title"]

    def bump_uses(self, agent: str, titles: list[str]) -> None:
        if not titles:
            return
        tset = {t.lower() for t in titles}
        with self._lock:
            skills = self.all(agent)
            for s in skills:
                if s.get("title", "").lower() in tset:
                    s["uses"] = s.get("uses", 0) + 1
            if skills:
                self._write(agent, skills)

    def _write(self, agent: str, skills: list[dict]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self._path(agent).with_suffix(".tmp")
        tmp.write_text("\n".join(json.dumps(s, ensure_ascii=False) for s in skills) + "\n", encoding="utf-8")
        tmp.replace(self._path(agent))

    def format_playbook(self, skills: list[dict]) -> str:
        if not skills:
            return ""
        lines = ["# Your playbook (lessons learned in past runs - apply ONLY if relevant to this task):"]
        for s in skills:
            lines.append(f"- [{s['title']}] {s['lesson']}")
        return "\n".join(lines)
