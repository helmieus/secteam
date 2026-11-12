# secteam — Pasukan AI Security Research (open-source)

Orkestrasi multi-agent **Red Team** menggunakan **LangGraph** + **Ollama** (model lokal). **Leader**
(Ketua Pasukan) mengagih kerja mengikut pipeline Spy → Analyst → Operator, dan Leader sendiri menulis
laporan akhir (Markdown).

```
                 ┌────────────────────┐
  tugasan ─────► │   Leader (Ketua)   │◄───────────────────────────┐
                 └─────────┬──────────┘                            │ hasil
        ┌────────────┬─────┴──────┬──────────────┐                 │
        ▼            ▼            ▼               │                 │
      Spy ───────► Analyst ───► Operator         │                 │
  risik mentah   analisis +   sahkan/exploit     │                 │
  nmap, dns,     korelasi,    aktif: http_request│                 │
  rdap, http,    CVE/OSV/KEV, run_python (PoC),  │                 │
  web_search,    audit kod,   nuclei vuln_scan   │                 │
  strings        hipotesis    (perlu kelulusan)  │                 │
        └────────────┴────────────┴──────────────┘                 │
                           ▼                                        │
         Leader tulis laporan ──► reports/*.md + *-findings.json ──┘
```

Pipeline: **Spy** kumpul data mentah (tiada serangan) → **Analyst** korelasi + hasilkan hipotesis boleh
diuji dengan skor keyakinan → **Operator** sahkan/exploit secara aktif (gated kelulusan) → **Leader**
prioriti ikut risiko & tulis laporan. Setiap ahli ialah subgraph ReAct (model ↔ alat) dengan had pusingan.

## Lapisan keselamatan

> **Nota:** scope guard automatik (fail engagement wajib + semakan include/exclude) telah **dibuang** —
> operator (anda) mengarahkan sasaran sendiri. `--engagement` masih boleh dimuatkan sebagai metadata
> kebenaran untuk laporan, tetapi tidak lagi menyekat sasaran. Lapisan keselamatan yang kekal:

| Lapisan | Apa yang berlaku |
|---|---|
| **Kelulusan manusia** | Tindakan aktif (`port_scan`, `vuln_scan`, `http_request`, `run_python`) minta pengesahan `y/N` (kecuali `--auto-approve`). Dalam mod bukan-interaktif ia **auto-ditolak**. |
| **Audit log** | Semua keputusan Leader, panggilan alat, permintaan & kelulusan direkod ke `logs/audit-YYYYMMDD.jsonl`. |
| **Operator mengarah** | Spy/Analyst tidak menyerang; hanya Operator melakukan tindakan aktif, satu hipotesis pada satu masa, tiada DoS. |
| **Sandbox pelaksanaan** | `run_python` jalan terasing (`python -I`) dalam `workspace/sandbox`. Jalankan secteam dalam **VM** (ia melaksanakan exploit sebenar). |
| **Akses fail audit** | Alat audit kod Analyst hanya baca dalam `--code`. |

> Gunakan hanya pada sistem yang anda miliki atau ada **kebenaran bertulis**. Tanpa scope guard automatik,
> tanggungjawab memastikan sasaran dibenarkan kini sepenuhnya pada anda. Scan/exploit tanpa kebenaran ialah
> kesalahan di bawah Akta Jenayah Komputer 1997 (Malaysia) dan undang-undang setara.

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

# Research / OSINT (carian web + sumber, oleh Spy) - soalan "apa itu X"
secteam research "apa itu php2shell"
secteam research "macam mana SSTI dieksploitasi dalam Jinja2"

# Code audit (oleh Analyst)
secteam audit C:\projek\webapp --focus "authentication dan SQL injection"

# Pentest penuh: Spy -> Analyst -> Operator -> Leader tulis laporan.
# Operator minta kelulusan y/N untuk setiap tindakan aktif (scan/exploit).
secteam run "Lakukan penilaian keselamatan ke atas http://192.168.56.101"

# Hands-off pada sasaran yang anda ADA kebenaran (langkau prompt kelulusan):
secteam run "Pentest http://192.168.56.101" --auto-approve

# Gabungan: audit kod + sahkan servis yang menjalankan kod itu
secteam run "Audit kod ini dan sahkan sama ada servis di 192.168.56.101 terdedah" -c C:\projek\webapp
```

Output: `reports\<masa>-<tugasan>.md` (laporan) dan `-findings.json` (bukti mentah setiap ahli).

### Carian web / OSINT (alat `web_search`, oleh Spy)

`secteam research` (dan Spy dalam `run`) guna carian web dan menjawab **hanya dari hasil carian, dengan
URL sumber sebenar**. Pembekal dipilih automatik ikut kunci dalam environment:

- **DuckDuckGo** — lalai, tiada kunci, terus jalan (kadang kena had kadar bila kerap).
- **Tavily** — lebih dipercayai, percuma ~1000/bulan: `setx TAVILY_API_KEY "tvly-..."` (buka terminal baru selepas itu).
- **Brave** — percuma ~2000/bulan: `setx BRAVE_API_KEY "BSA-..."`.

Spy melaporkan apa yang ada di web; kualiti bergantung pada sumber. Untuk CVE spesifik, Analyst guna NVD/OSV
(bukan carian web).

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

## Memori skill (playbook)

Setiap pakar membina **playbook** teknik boleh guna semula yang berkembang antara run — supaya pasukan
"belajar" dari masa ke masa (penting kerana cybersecurity sentiasa berubah).

```powershell
.\secteam skills                 # lihat playbook semua pakar
.\secteam skills analyst         # satu ahli sahaja (spy/analyst/operator)
.\secteam skills --forget        # kosongkan semua playbook
```

Cara ia bekerja:
- Selepas setiap tugasan, pakar mereflek dan menyimpan 0-2 **teknik generalisasi** (cth. "untuk rantaian
  finding HIGH, sahkan input sampai ke baris itu dulu"). Pada run akan datang, skill yang relevan disuntik ke dalam tugasan pakar.
- **Guardrail keselamatan:** hanya teknik disimpan, BUKAN fakta mudah basi atau data klien. Penapis menolak
  apa-apa yang mengandungi IP, flag, hash, rahsia, atau sasaran engagement. Skill hanya dipelajari daripada
  hasil yang **tidak** ditanda `[TIDAK DISAHKAN]`.
- Disimpan sebagai JSONL boleh baca di `memory/<pakar>.jsonl` — semak dan buang bila-bila.
- Tetapan dalam `config.yaml` bawah `memory:` (set `enabled: false` untuk matikan, `reflect: false` untuk
  langkau langkah pembelajaran dan jadi lebih laju).

> Memori ini **global** (merentas engagement), jadi ia sengaja hanya simpan teknik umum. Data khusus setiap
> engagement kekal dalam `reports/` sahaja, tidak pernah masuk playbook.

## Konfigurasi (`config.yaml`)

- `models.*`: model untuk setiap peranan. Model mesti menyokong **tool calling** di Ollama
  (qwen2.5, qwen2.5-coder, qwen3, llama3.1, mistral-nemo, ...).
- **8 GB VRAM:** dua model 7B tak muat serentak, jadi Ollama akan swap setiap kali peranan bertukar.
  Untuk kelajuan, set semua peranan ke satu model.
- Model 14B (cth. `qwen2.5:14b`, ~9 GB) akan offload sebahagian ke CPU: lebih pintar, lebih perlahan.
- `orchestration.max_steps` / `max_tool_rounds`: had untuk elak gelung tanpa henti.

## Menambah ahli / alat baru

1. Tulis alat dalam `secteam/tools/<nama>.py` dengan `@tool` + `@guarded` (dan `require_approval()`
   untuk tindakan aktif yang menyentuh target). Masukkan ke kumpulan `SPY_TOOLS` / `ANALYST_TOOLS` /
   `OPERATOR_TOOLS` dalam `secteam/tools/__init__.py`.
2. Daftar ahli dalam `SPECIALISTS` di `secteam/agents.py` (description, tools, prompt).
3. Tambah nama ke `available_specialists()` dalam `secteam/graph.py` dan peta `TOOL_AGENT` di `dashboard.py`.

## Had yang perlu diketahui

- Model 7B boleh berhalusinasi. Semak bukti dalam `-findings.json` sebelum percaya laporan.
  Prompt memaksa label "HYPOTHESIS" untuk perkara yang belum disahkan, tapi itu bukan jaminan.
- `http_probe` guna `verify=False` (TLS tidak disahkan) kerana target lab biasanya self-signed.
