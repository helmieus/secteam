"""Alat CTF: decode, bruteforce klasik, inspeksi fail, dan pelaksanaan Python (perlu kelulusan)."""
import base64
import binascii
import codecs
import hashlib
import re
import string
import subprocess
import sys
import urllib.parse
import uuid
from pathlib import Path

from langchain_core.tools import tool

from ..runtime import RT
from .common import guarded, require_approval

FREQ = {  # frekuensi huruf Inggeris (%), ruang dianggarkan
    "e": 12.7, "t": 9.1, "a": 8.2, "o": 7.5, "i": 7.0, "n": 6.7, "s": 6.3, "h": 6.1, "r": 6.0,
    "d": 4.3, "l": 4.0, "c": 2.8, "u": 2.8, "m": 2.4, "w": 2.4, "f": 2.2, "g": 2.0, "y": 2.0,
    "p": 1.9, "b": 1.5, "v": 1.0, "k": 0.8, "j": 0.2, "x": 0.2, "q": 0.1, "z": 0.1, " ": 13.0,
    "_": 4.0,
}
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,12}\{[ -~]+\}")


def _english_score(b: bytes) -> float:
    """Skor kebolehbacaan: 0 jika ada bait tak boleh cetak berlebihan; huruf kecil biasa dapat skor
    tinggi, huruf besar separuh, bonus besar untuk corak flag{...}."""
    if not b:
        return 0.0
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b)
    if printable < 0.9:
        return printable
    freq = 0.0
    for c in b:
        ch = chr(c)
        freq += FREQ.get(ch, FREQ.get(ch.lower(), 0) * 0.4)
    score = printable + freq / len(b) / 4
    if FLAG_RE.search(b):
        score += 3
    return score


def _files_root() -> Path:
    if RT.files_root is None:
        raise ValueError("Tiada direktori fail CTF diberi (guna --files).")
    return RT.files_root


def _resolve_file(path: str) -> Path:
    root = _files_root()
    p = (root / path).resolve()
    if not p.is_relative_to(root):
        raise PermissionError("Laluan di luar direktori fail CTF.")
    return p


@tool
@guarded
def list_ctf_files() -> str:
    """List challenge files provided for the CTF (relative path, size, absolute path for scripts)."""
    root = _files_root()
    files = [p for p in root.rglob("*") if p.is_file()]
    return "\n".join(f"{p.relative_to(root)} ({p.stat().st_size} B) abs={p}" for p in files[:200]) or "Tiada fail."


@tool
@guarded
def file_inspect(path: str) -> str:
    """Inspect a challenge file: size, sha256, magic bytes (hex), and printable strings (min length 5)."""
    p = _resolve_file(path)
    data = p.read_bytes()
    strings_ = re.findall(rb"[\x20-\x7e]{5,}", data)
    flaggy = [s.decode() for s in strings_ if re.search(rb"(?i)flag|ctf\{|\{.*\}", s)]
    return "\n".join([
        f"{p.name}: {len(data)} B, sha256={hashlib.sha256(data).hexdigest()}",
        f"magic: {data[:16].hex(' ')}",
        f"strings mencurigakan: {flaggy[:20] or '-'}",
        f"{len(strings_)} strings, 60 pertama:",
        *[s.decode()[:120] for s in strings_[:60]],
    ])


def _decode_one(data: str, enc: str) -> str:
    s = data.strip()
    if enc == "base64":
        return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
    if enc == "base32":
        return base64.b32decode(s + "=" * (-len(s) % 8)).decode("utf-8", "replace")
    if enc == "base85":
        return base64.b85decode(s).decode("utf-8", "replace")
    if enc == "hex":
        return binascii.unhexlify(re.sub(r"[^0-9a-fA-F]", "", s)).decode("utf-8", "replace")
    if enc == "url":
        return urllib.parse.unquote(s)
    if enc == "rot13":
        return codecs.decode(s, "rot13")
    if enc == "binary":
        bits = re.sub(r"[^01]", "", s)
        return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8)).decode("utf-8", "replace")
    if enc == "decimal":
        return bytes(int(x) for x in re.findall(r"\d+", s)).decode("utf-8", "replace")
    raise ValueError(f"encoding tidak disokong: {enc}")


ENCODINGS = ("base64", "base32", "base85", "hex", "url", "rot13", "binary", "decimal")


def _candidates(data: str) -> list[tuple[float, str, str]]:
    """Semua decode yang menghasilkan teks boleh cetak, disusun ikut skor."""
    out = []
    for enc in ENCODINGS:
        if enc == "rot13":  # rot13 sentiasa 'berjaya'; hanya berguna jika hasilnya lebih Inggeris
            continue
        try:
            res = _decode_one(data, enc)
        except Exception:  # noqa: BLE001
            continue
        if not res or res.strip() == data.strip() or "�" in res:
            continue
        b = res.encode("utf-8", "replace")
        printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b)
        if printable >= 0.95:
            out.append((_english_score(b), enc, res))
    rot = codecs.decode(data, "rot13")
    if _english_score(rot.encode()) > _english_score(data.encode()) + 0.3:
        out.append((_english_score(rot.encode()), "rot13", rot))
    return sorted(out, reverse=True)


@tool
@guarded
def decode(data: str, encoding: str = "auto") -> str:
    """Decode data. encoding: auto, base64, base32, base85, hex, url, rot13, binary, decimal.
    'auto' tries every encoding AND follows multiple layers (e.g. base64 -> hex -> text),
    showing each layer. If the final layer is still unreadable bytes, try xor_bruteforce on the hex."""
    if encoding != "auto":
        return _decode_one(data, encoding)
    lines = []
    first = _candidates(data)
    if not first:
        return "Tiada decode yang menghasilkan teks boleh cetak. Cuba xor_bruteforce (jika hex) atau run_python."
    for score, enc, res in first[:4]:
        lines.append(f"[{enc}] (skor {score:.2f}) {res[:300]}")
    # ikut rantaian lapisan menggunakan calon terbaik
    _, enc, cur = first[0]
    chain = [enc]
    for _ in range(5):
        nxt = _candidates(cur)
        if not nxt:
            break
        _, enc, cur = nxt[0]
        chain.append(enc)
    if len(chain) > 1:
        lines.append(f"\nRantaian lapisan: {' -> '.join(chain)}\nHasil akhir: {cur[:400]}")
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", cur.strip()):
        lines.append("Hasil akhir ialah hex yang tidak boleh dibaca terus -> cuba xor_bruteforce pada hex ini.")
    return "\n".join(lines)


@tool
@guarded
def caesar_bruteforce(text: str) -> str:
    """Try all 25 Caesar shifts on alphabetic text."""
    lower, upper = string.ascii_lowercase, string.ascii_uppercase
    out = []
    for k in range(1, 26):
        table = str.maketrans(lower + upper, lower[k:] + lower[:k] + upper[k:] + upper[:k])
        out.append(f"shift {k:2d}: {text.translate(table)[:200]}")
    return "\n".join(out)


@tool
@guarded
def xor_bruteforce(hex_data: str) -> str:
    """Brute force single-byte XOR on hex-encoded data; returns top 5 candidates by readability."""
    data = binascii.unhexlify(re.sub(r"[^0-9a-fA-F]", "", hex_data))
    cands = []
    for k in range(256):
        dec = bytes(b ^ k for b in data)
        cands.append((_english_score(dec), k, dec))
    cands.sort(reverse=True)
    return "\n".join(f"key=0x{k:02x} skor={s:.2f}: {d[:200]!r}" for s, k, d in cands[:5])


HASH_TYPES = {
    32: "MD5 / NTLM / MD4", 40: "SHA-1 / RIPEMD-160", 56: "SHA-224 / SHA3-224",
    64: "SHA-256 / SHA3-256 / BLAKE2s", 96: "SHA-384", 128: "SHA-512 / SHA3-512 / BLAKE2b",
}


@tool
@guarded
def hash_identify(hash_value: str) -> str:
    """Guess the hash algorithm from format and length."""
    h = hash_value.strip()
    prefixes = {
        "$2a$": "bcrypt", "$2b$": "bcrypt", "$2y$": "bcrypt", "$argon2": "Argon2",
        "$6$": "sha512crypt", "$5$": "sha256crypt", "$1$": "md5crypt", "$y$": "yescrypt",
    }
    for pre, name in prefixes.items():
        if h.startswith(pre):
            return f"Kemungkinan: {name}"
    if re.fullmatch(r"[0-9a-fA-F]+", h):
        return f"Hex {len(h)} aksara -> kemungkinan: {HASH_TYPES.get(len(h), 'tidak diketahui')}"
    return "Format tidak dikenali (mungkin base64-encoded atau format khusus)."


@tool
@guarded
def run_python(code: str) -> str:
    """Execute a Python 3 script for CTF solving (crypto math, parsing, decoding). Runs in the
    sandbox directory with a 60s timeout. Print results to stdout. Requires human approval."""
    sandbox = RT.sandbox_dir
    sandbox.mkdir(parents=True, exist_ok=True)
    script = sandbox / f"ctf_{uuid.uuid4().hex[:8]}.py"
    script.write_text(code, encoding="utf-8")
    preview = code if len(code) < 1500 else code[:1500] + "\n...[dipotong]"
    require_approval("run_python", f"{script}\n---\n{preview}\n---")
    try:
        p = subprocess.run(
            [sys.executable, "-I", str(script)], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=60, cwd=sandbox,
        )
    except subprocess.TimeoutExpired:
        return "[RALAT] skrip melebihi 60s"
    return f"exit={p.returncode}\n[stdout]\n{p.stdout}\n[stderr]\n{p.stderr[-2000:]}"


CTF_TOOLS = [list_ctf_files, file_inspect, decode, caesar_bruteforce, xor_bruteforce, hash_identify, run_python]
