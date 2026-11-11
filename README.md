# secteam — Pasukan AI Security Research (open-source)

Orkestrasi multi-agent menggunakan **LangGraph** + **Ollama** (model lokal). Lead/supervisor
mengagih kerja kepada pakar, pakar guna alat sebenar, dan reporter tulis laporan Markdown.

```
                 ┌────────────────────┐
  tugasan ─────► │ Supervisor (Lead)  │◄───────────────────────────┐
                 └─────────┬──────────┘                            │
   ┌────────────┬──────────┼───────────┬────────────┬───────────┐ │ hasil
   ▼            ▼          ▼           ▼            ▼           ▼ │
 recon    code_auditor  threat_intel  researcher  ctf_solver     │
 dns/rdap,  semgrep,     NVD, EPSS,    carian web  decode, xor,   │
 http_probe,bandit,      CISA KEV,     (Tavily/    file_inspect,  │
 nmap,      read/search, OSV           Brave/DDG)  run_python     │
 nuclei     OSV                        + sumber                   │
   └────────────┴──────────┬───────────┴────────────┴───────────┘ │
                           ▼                                       │
                      Reporter ──► reports/*.md + *-findings.json ─┘
```

Setiap pakar ialah subgraph ReAct (model ↔ alat) dengan had pusingan sendiri.

## Lapisan keselamatan

| Lapisan | Apa yang berlaku |
|---|---|
| **Fail engagement** | Recon/scan hanya aktif jika `--engagement` dimuatkan: klien, siapa beri kebenaran, no. rujukan, tempoh sah. |
| **Scope guard** | Setiap target disemak terhadap `include`/`exclude` (CIDR & wildcard domain). Hostname yang resolve ke IP dikecualikan akan ditolak. |
| **Activity allowlist** | `passive_recon`, `web_probe`, `port_scan`, `vuln_scan`. Mana-mana yang tak disenaraikan ditolak. |
| **Kelulusan manusia** | `port_scan`, `vuln_scan`, `run_python` minta pengesahan `y/N` (kecuali `--auto-approve`). |
| **Tiada shell bebas** | Hanya binari allowlist (`nmap`, `nuclei`, `semgrep`, `bandit`) dengan argumen yang dibina oleh kod, bukan oleh model. |
| **Audit log** | Semua keputusan supervisor, panggilan alat, penolakan skop dan kelulusan ke `logs/audit-YYYYMMDD.jsonl`. |
| **Akses fail terhad** | Code auditor hanya boleh baca dalam `--code`; CTF hanya dalam `--files`. |

> Gunakan hanya pada sistem yang anda miliki atau ada **kebenaran bertulis**. Scan tanpa kebenaran
> ialah kesalahan di bawah Akta Jenayah Komputer 1997 (Malaysia) dan undang-undang setara.

## Pemasangan (Windows)

```powershell
# 1. Python & Ollama
winget install Python.Python.3.12
winget install Ollama.Ollama
# (buka terminal baru selepas pasang)

# 2. Model (≈4.7 GB setiap satu, muat dalam 8 GB VRAM)
ollama pull qwen2.5:7b
ollama pull qwen2.5-coder:7b

# 3. Projek
cd C:\Users\User\Documents\AI
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
pip install -e ".[sast]"        # pilihan: semgrep + bandit

# 4. Alat recon (pilihan)
winget install Insecure.Nmap     # termasuk Npcap
# nuclei: muat turun binari dari github.com/projectdiscovery/nuclei/releases, letak dalam PATH

# 5. Semak
secteam doctor
```

Pilihan: tetapkan `$env:NVD_API_KEY` (percuma dari nvd.nist.gov) supaya had kadar NVD lebih tinggi.

## Penggunaan

```powershell
# Threat intel (CVE spesifik, dari NVD/EPSS/KEV)
secteam cve CVE-2024-3400
secteam run "Apakah CVE yang dieksploitasi aktif bulan ini yang melibatkan VPN appliance?"

# Research maklumat am (carian web + sumber) - untuk soalan "apa itu X", bukan CVE
secteam research "apa itu php2shell"
secteam research "macam mana SSTI dieksploitasi dalam Jinja2"

# Code audit
secteam audit C:\projek\webapp --focus "authentication dan SQL injection"

# CTF
secteam ctf "Ciphertext: Gur synt vf pgs{ebg13_vf_rnfl}"
secteam ctf "Fail misteri, cari flag" --files .\challenges\forensics1

# Pentest lab (perlu engagement)
secteam check-scope engagements\example-lab.yaml 192.168.56.101
secteam run "Lakukan penilaian keselamatan ke atas 192.168.56.101" -e engagements\example-lab.yaml

# Gabungan: audit kod + semak servis yang menjalankan kod itu
secteam run "Audit kod ini dan sahkan sama ada servis di 192.168.56.101 terdedah" `
  -c C:\projek\webapp -e engagements\example-lab.yaml
```

Output: `reports\<masa>-<tugasan>.md` (laporan) dan `-findings.json` (bukti mentah setiap pakar).

### Carian web (pakar `researcher`)

`secteam research` (dan `run` untuk soalan "apa itu X") guna carian web dan menjawab **hanya dari hasil
carian, dengan URL sumber sebenar** dalam laporan. Pembekal dipilih automatik ikut kunci dalam environment:

- **DuckDuckGo** — lalai, tiada kunci, terus jalan (kadang kena had kadar bila kerap).
- **Tavily** — lebih dipercayai, percuma ~1000/bulan: `setx TAVILY_API_KEY "tvly-..."` (buka terminal baru selepas itu).
- **Brave** — percuma ~2000/bulan: `setx BRAVE_API_KEY "BSA-..."`.

Researcher melaporkan apa yang ada di web; kualiti bergantung pada sumber. Sentiasa klik URL sumber dalam
laporan untuk sahkan — ini BUKAN threat_intel (yang guna NVD untuk CVE spesifik).

Tanpa aktifkan venv: guna pelancar `.\secteam <arahan>` dari folder projek (fail `secteam.cmd`).

## Dashboard aktiviti agent

```powershell
.\secteam dashboard            # buka http://127.0.0.1:8765 dalam pelayar
```

- **Senarai sesi**: setiap run, dengan status (selesai / berjalan / terhenti), tempoh, bilangan alat, amaran.
- **Garis masa**: swimlane Lead / setiap pakar / Reporter; bar nipis = panggilan alat (merah = ralat/ditolak).
  Klik bar untuk lompat ke langkah tersebut.
- **Langkah demi langkah**: keputusan Lead (arahan + sebab) → setiap panggilan alat (klik untuk lihat argumen
  & output) → ringkasan agent dengan tanda **[DISAHKAN]** / **[TIDAK DISAHKAN]**.
- Dikemas kini secara langsung setiap 2.5 saat semasa run berjalan; biarkan ia terbuka dalam tab lain.
- Hanya bind ke `127.0.0.1` (log mengandungi data engagement). Sumber data: `logs\audit-*.jsonl`.

## Konfigurasi (`config.yaml`)

- `models.*`: model untuk setiap peranan. Model mesti menyokong **tool calling** di Ollama
  (qwen2.5, qwen2.5-coder, qwen3, llama3.1, mistral-nemo, ...).
- **8 GB VRAM:** dua model 7B tak muat serentak, jadi Ollama akan swap setiap kali peranan bertukar.
  Untuk kelajuan, set semua peranan ke satu model.
- Model 14B (cth. `qwen2.5:14b`, ~9 GB) akan offload sebahagian ke CPU: lebih pintar, lebih perlahan.
- `orchestration.max_steps` / `max_tool_rounds`: had untuk elak gelung tanpa henti.

## Menambah pakar baru

1. Tulis alat dalam `secteam/tools/<nama>.py` dengan `@tool` + `@guarded` (dan `_eng().check()` +
   `require_approval()` untuk apa-apa yang menyentuh target).
2. Daftar dalam `SPECIALISTS` di `secteam/agents.py` (description, tools, prompt).
3. Tambah nama ke `available_specialists()` dalam `secteam/graph.py`.

## Had yang perlu diketahui

- Model 7B boleh berhalusinasi. Semak bukti dalam `-findings.json` sebelum percaya laporan.
  Prompt memaksa label "HYPOTHESIS" untuk perkara yang belum disahkan, tapi itu bukan jaminan.
- `run_python` (CTF) **bukan sandbox sebenar**: ia jalan sebagai user anda, cuma dengan kelulusan dan
  timeout. Untuk fail CTF yang tidak dipercayai, jalankan secteam dalam VM/WSL/Docker.
- `http_probe` guna `verify=False` (TLS tidak disahkan) kerana target lab biasanya self-signed.
