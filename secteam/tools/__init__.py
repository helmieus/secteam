"""Kumpulan alat ikut peranan Red Team: Spy / Analyst / Operator."""
from .exploit import http_request, run_python
from .inspect import extract_strings, file_info
from .intel import cve_lookup, cve_search, kev_recent, osv_lookup
from .recon import dns_lookup, http_probe, port_scan, rdap_lookup, vuln_scan
from .research import web_search
from .sast import list_files, read_file, scan_code, search_code

# Spy (Perisik): kumpul data mentah - rangkaian, web, OSINT, binari. Pasif + imbasan perkhidmatan.
SPY_TOOLS = [dns_lookup, rdap_lookup, http_probe, port_scan, web_search, file_info, extract_strings]

# Analyst (Penyelidik kerentanan): analisis atas meja - CVE, OSV, KEV, audit kod. Tak sentuh sasaran.
ANALYST_TOOLS = [cve_lookup, cve_search, osv_lookup, kev_recent, scan_code, list_files, read_file, search_code]

# Operator (Exploit): sahkan hipotesis secara aktif - nuclei, permintaan bertulis-tangan, PoC Python.
OPERATOR_TOOLS = [vuln_scan, http_request, run_python]

__all__ = ["SPY_TOOLS", "ANALYST_TOOLS", "OPERATOR_TOOLS"]
