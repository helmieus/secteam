"""Alat carian web untuk pakar 'researcher'. Tiga pembekal (auto ikut kunci dalam environment):
  - Tavily  (TAVILY_API_KEY)  - terbaik untuk LLM, pulangkan kandungan ringkas + sumber
  - Brave   (BRAVE_API_KEY)
  - DuckDuckGo (tiada kunci, pustaka ddgs) - lalai

Anti-halusinasi: alat pulangkan hasil bernombor dengan URL sebenar. Pakar jawab dari hasil ini sahaja
dan rujuk sumber [n]; URL tak boleh direka oleh model."""
from __future__ import annotations

import os

import httpx
from langchain_core.tools import tool

from .common import guarded


def _provider() -> str:
    if os.environ.get("TAVILY_API_KEY"):
        return "tavily"
    if os.environ.get("BRAVE_API_KEY"):
        return "brave"
    return "ddg"


def _tavily(query: str, n: int) -> list[dict]:
    r = httpx.post("https://api.tavily.com/search", timeout=25, json={
        "api_key": os.environ["TAVILY_API_KEY"], "query": query, "max_results": n, "search_depth": "basic"})
    r.raise_for_status()
    return [{"title": x.get("title", ""), "url": x.get("url", ""), "snippet": (x.get("content") or "")[:600]}
            for x in r.json().get("results", [])]


def _brave(query: str, n: int) -> list[dict]:
    r = httpx.get("https://api.search.brave.com/res/v1/web/search", timeout=25,
                  params={"q": query, "count": n},
                  headers={"X-Subscription-Token": os.environ["BRAVE_API_KEY"], "Accept": "application/json"})
    r.raise_for_status()
    return [{"title": x.get("title", ""), "url": x.get("url", ""), "snippet": (x.get("description") or "")[:600]}
            for x in r.json().get("web", {}).get("results", [])]


def _ddg(query: str, n: int) -> list[dict]:
    from ddgs import DDGS  # import lewat supaya kegagalan pustaka tak merosakkan import modul
    out = []
    with DDGS() as ddgs:
        for x in ddgs.text(query, max_results=n, region="my-en"):
            out.append({"title": x.get("title", ""), "url": x.get("href") or x.get("url") or "",
                        "snippet": (x.get("body") or "")[:600]})
    return out


@tool
@guarded
def web_search(query: str, max_results: int = 6) -> str:
    """Search the public web and return numbered results (title, snippet, real URL) for a query.
    Use this to research tools, techniques, concepts, products or current information that is NOT a CVE.
    Answer only from these results and cite the source number [n]; never invent URLs or facts."""
    n = max(1, min(max_results, 10))
    p = _provider()
    fn = {"tavily": _tavily, "brave": _brave, "ddg": _ddg}[p]
    results = fn(query, n)
    if not results:
        return (f"[{p}] Tiada hasil carian untuk {query!r}. Mungkin had kadar atau tiada maklumat. "
                f"Laporkan yang anda tak jumpa maklumat; JANGAN reka jawapan.")
    lines = [f"Carian ({p}) untuk {query!r} - {len(results)} hasil:"]
    for i, r in enumerate(results, 1):
        lines.append(f"[{i}] {r['title']}\n    {r['snippet']}\n    sumber: {r['url']}")
    return "\n".join(lines)


RESEARCH_TOOLS = [web_search]
