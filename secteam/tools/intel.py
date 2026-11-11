"""Alat threat intel: NVD, EPSS (FIRST), CISA KEV, OSV."""
import datetime as dt
import os
import re

import httpx
from langchain_core.tools import tool

from .common import guarded

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
OSV_URL = "https://api.osv.dev/v1/query"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

_kev_cache: dict | None = None


def _nvd(params: dict) -> dict:
    headers = {}
    if key := os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = key
    r = httpx.get(NVD_URL, params=params, headers=headers, timeout=40)
    r.raise_for_status()
    return r.json()


def _kev() -> dict:
    global _kev_cache
    if _kev_cache is None:
        r = httpx.get(KEV_URL, timeout=40)
        r.raise_for_status()
        _kev_cache = {v["cveID"]: v for v in r.json().get("vulnerabilities", [])}
    return _kev_cache


def _epss(cve_id: str) -> str:
    try:
        r = httpx.get(EPSS_URL, params={"cve": cve_id}, timeout=20)
        d = r.json().get("data", [])
        if d:
            return f"EPSS {float(d[0]['epss']):.4f} (persentil {float(d[0]['percentile']):.2%})"
    except Exception:  # noqa: BLE001
        pass
    return "EPSS: tiada data"


def _cvss(metrics: dict) -> str:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            d = m["cvssData"]
            sev = d.get("baseSeverity") or m.get("baseSeverity", "")
            return f"{key.replace('cvssMetric', 'CVSS ')}: {d.get('baseScore')} {sev} ({d.get('vectorString')})"
    return "CVSS: belum dinilai"


def _fmt_cve(c: dict, refs: int = 8) -> str:
    desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
    cwes = sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])})
    lines = [
        f"{c['id']} (terbit {c.get('published', '')[:10]}, status {c.get('vulnStatus')})",
        _cvss(c.get("metrics", {})),
        f"CWE: {', '.join(cwes) or '-'}",
        f"Penerangan: {desc}",
    ]
    if refs:
        lines.append("Rujukan: " + " | ".join(r["url"] for r in c.get("references", [])[:refs]))
    return "\n".join(lines)


@tool
@guarded
def cve_lookup(cve_id: str) -> str:
    """Full details for one CVE: CVSS, CWE, description, references, EPSS exploit probability,
    and whether it is in CISA Known Exploited Vulnerabilities (KEV)."""
    cve_id = cve_id.strip().upper()
    if not CVE_RE.match(cve_id):
        raise ValueError("Format mesti CVE-YYYY-NNNN")
    vulns = _nvd({"cveId": cve_id}).get("vulnerabilities", [])
    if not vulns:
        return f"{cve_id} tidak dijumpai dalam NVD."
    out = [_fmt_cve(vulns[0]["cve"]), _epss(cve_id)]
    kev = _kev().get(cve_id)
    if kev:
        out.append(
            f"CISA KEV: YA (ditambah {kev['dateAdded']}, ransomware: {kev.get('knownRansomwareCampaignUse')}). "
            f"Tindakan: {kev.get('requiredAction')}"
        )
    else:
        out.append("CISA KEV: tidak tersenarai")
    return "\n".join(out)


@tool
@guarded
def cve_search(keyword: str, max_results: int = 10) -> str:
    """Search NVD for CVEs by keyword (product/vendor/technology, e.g. 'apache struts', 'fortios ssl vpn')."""
    n = max(1, min(max_results, 20))
    data = _nvd({"keywordSearch": keyword, "resultsPerPage": n})
    vulns = data.get("vulnerabilities", [])
    total = data.get("totalResults", 0)
    body = "\n\n".join(_fmt_cve(v["cve"], refs=0)[:700] for v in vulns)
    return f"{total} hasil (papar {len(vulns)}):\n\n{body}"


@tool
@guarded
def osv_lookup(package: str, ecosystem: str, version: str = "") -> str:
    """Check an open-source package version for known vulnerabilities via OSV.dev.
    ecosystem: PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Packagist, ..."""
    body: dict = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        body["version"] = version
    r = httpx.post(OSV_URL, json=body, timeout=30)
    r.raise_for_status()
    vulns = r.json().get("vulns", [])
    if not vulns:
        return f"Tiada vulnerability diketahui untuk {ecosystem}/{package} {version}".strip()
    out = []
    for v in vulns[:30]:
        aliases = ",".join(a for a in v.get("aliases", []) if a.startswith("CVE")) or "-"
        fixed = sorted({
            e["fixed"] for a in v.get("affected", []) for rg in a.get("ranges", [])
            for e in rg.get("events", []) if "fixed" in e
        })
        out.append(f"{v['id']} ({aliases}) fixed: {', '.join(fixed) or '?'} - {v.get('summary', '')[:160]}")
    return f"{len(vulns)} vulnerability untuk {package} {version}:\n" + "\n".join(out)


@tool
@guarded
def kev_recent(days: int = 30) -> str:
    """List CVEs added to CISA Known Exploited Vulnerabilities catalog in the last N days."""
    cutoff = dt.date.today() - dt.timedelta(days=max(1, min(days, 365)))
    rows = [v for v in _kev().values() if dt.date.fromisoformat(v["dateAdded"]) >= cutoff]
    rows.sort(key=lambda v: v["dateAdded"], reverse=True)
    out = [
        f"{v['dateAdded']} {v['cveID']} {v['vendorProject']} {v['product']} - {v['vulnerabilityName']}"
        for v in rows[:60]
    ]
    return f"{len(rows)} entri KEV sejak {cutoff}:\n" + "\n".join(out)


INTEL_TOOLS = [cve_lookup, cve_search, osv_lookup, kev_recent]
