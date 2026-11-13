"""Kumpulan alat ikut peranan Red Team: Spy / Analyst / Operator."""
from .access import netexec, ssh_exec
from .exploit import http_request, run_python
from .inspect import extract_strings, file_info
from .intel import cve_lookup, cve_search, kev_recent, osv_lookup
from .recon import dns_lookup, http_probe, port_scan, rdap_lookup, vuln_scan
from .research import web_search
from .sast import list_files, read_file, scan_code, search_code
from .setup import SETUP_TOOLS, ask_human, install_tool, run_shell  # dikongsi semua agent

# Spy (Perisik): kumpul data mentah - rangkaian, web, OSINT, binari. Pasif + imbasan perkhidmatan.
SPY_TOOLS = [dns_lookup, rdap_lookup, http_probe, port_scan, web_search, file_info, extract_strings, *SETUP_TOOLS]

# Analyst (Penyelidik kerentanan): analisis atas meja - CVE, OSV, KEV, audit kod. Tak sentuh sasaran.
ANALYST_TOOLS = [cve_lookup, cve_search, osv_lookup, kev_recent, scan_code, list_files, read_file,
                 search_code, *SETUP_TOOLS]

# Operator (Exploit): eksploitasi aktif - nuclei, HTTP payload, PoC Python, DAN akses jauh bercredential
# (netexec: SMB/WinRM/SSH/MSSQL exec; ssh_exec: shell Linux) untuk pijak masuk + tangkap flag.
OPERATOR_TOOLS = [vuln_scan, http_request, run_python, netexec, ssh_exec, *SETUP_TOOLS]

# Solver (mod ejen-tunggal): satu agent dengan toolkit penuh + run_shell (universal) untuk solve/exploit
# target end-to-end sendiri (recon -> exploit -> flag/privesc), gaya Claude Code tapi atas model tempatan.
SOLVER_TOOLS = [port_scan, http_probe, http_request, web_search, cve_lookup, netexec, ssh_exec,
                run_python, vuln_scan, run_shell, install_tool, ask_human]

__all__ = ["SPY_TOOLS", "ANALYST_TOOLS", "OPERATOR_TOOLS", "SETUP_TOOLS", "SOLVER_TOOLS"]
