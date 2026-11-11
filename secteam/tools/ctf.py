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


def _decode_bytes(data: str, enc: str) -> bytes:
    s = data.strip()
    if enc == "base64":
        if not re.fullmatch(r"[A-Za-z0-9+/=\s_-]+", s):
            raise ValueError("bukan base64")
        s = s.replace("-", "+").replace("_", "/")
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
    if enc == "base32":
        return base64.b32decode(s.upper() + "=" * (-len(s) % 8))
    if enc == "base85":
        return base64.b85decode(s)
    if enc == "hex":
        h = re.sub(r"(0x|\\x|[\s:,])", "", s)
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", h):
            raise ValueError("bukan hex")
        return binascii.unhexlify(h)
    if enc == "url":
        if "%" not in s:
            raise ValueError("bukan url-encoded")
        return urllib.parse.unquote_to_bytes(s)
    if enc == "rot13":
        return codecs.decode(s, "rot13").encode()
    if enc == "binary":
        bits = re.sub(r"\s", "", s)
        if not re.fullmatch(r"[01]+", bits) or len(bits) % 8:
            raise ValueError("bukan binari")
        return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
    if enc == "decimal":
        nums = re.findall(r"\d+", s)
        if not nums or any(int(x) > 255 for x in nums):
            raise ValueError("bukan senarai desimal bait")
        return bytes(int(x) for x in nums)
    raise ValueError(f"encoding tidak disokong: {enc}")


def _decode_one(data: str, enc: str) -> str:
    return _decode_bytes(data, enc).decode("utf-8", "replace")


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


def _is_printable(b: bytes) -> bool:
    return bool(b) and sum(32 <= c < 127 or c in (9, 10, 13) for c in b) / len(b) >= 0.95


def _expand(node: bytes) -> list[tuple[str, bytes]]:
    """Semua transformasi satu langkah daripada satu nod."""
    out = []
    if _is_printable(node):
        s = node.decode("latin-1")
        for enc in ENCODINGS:
            try:
                b = _decode_bytes(s, enc)
            except Exception:  # noqa: BLE001
                continue
            if b and b != node:
                out.append((enc, b))
    # XOR satu bait: ambil 2 kunci terbaik jika hasilnya boleh cetak
    best = sorted(((_english_score(bytes(c ^ k for c in node)), k) for k in range(1, 256)), reverse=True)[:2]
    for _, k in best:
        dec = bytes(c ^ k for c in node)
        if _is_printable(dec):
            out.append((f"xor(0x{k:02x})", dec))
    return out


KNOWN_PREFIXES = {
    b"flag", b"ctf", b"picoctf", b"htb", b"thm", b"ductf", b"uiuctf", b"csictf", b"hacktheflag",
    b"flg", b"key", b"secret", b"ictf", b"wgmy", b"lagctf", b"sherpa",
}
FLAG_BODY_RE = re.compile(rb"^[A-Za-z0-9_\-!@#$%.?+]{3,}$")


def _flag_quality(flag: bytes, chain: list[str]) -> float:
    """Skor keyakinan calon flag: awalan dikenali, isi bersih, mudah dibaca, rantaian pendek."""
    prefix, _, body = flag.partition(b"{")
    body = body[:-1]
    score = 0.0
    if prefix.lower() in KNOWN_PREFIXES:
        score += 3
    elif prefix.isalpha() and prefix.islower() and len(prefix) >= 3:
        score += 0.5
    if FLAG_BODY_RE.match(body):
        score += 2
    else:
        score -= 2
    letters = sum(chr(c).isalpha() for c in body) / max(len(body), 1)
    score += letters + _english_score(body) / 3
    score -= 0.3 * len(chain)
    return score


def _roots_from(data: str, path: str) -> list[bytes]:
    roots: list[bytes] = []
    if path:
        raw = _resolve_file(path).read_bytes()
        roots.append(raw.strip())
        if _is_printable(raw):  # fail teks: setiap token panjang juga calon
            roots += [t for t in raw.split() if len(t) >= 8]
    if data:
        roots.append(data.strip().encode("latin-1", "replace"))
    seen, uniq = set(), []
    for r in roots:
        if r and r not in seen:
            seen.add(r)
            uniq.append(r)
    return uniq


@tool
@guarded
def auto_solve(path: str = "", data: str = "", max_depth: int = 5) -> str:
    """PREFERRED first step for encoding/crypto CTF challenges. Reads the challenge file directly
    (path relative to the CTF files dir) and/or raw data, then searches every chain of decodings
    (base64, base32, base85, hex, url, binary, decimal, rot13) and single-byte XOR, up to max_depth
    layers, reporting any flag-like string with the exact transformation chain. Pass the file path
    instead of copying data yourself."""
    if not path and not data:
        raise ValueError("Beri 'path' (fail cabaran) atau 'data'.")
    max_depth = max(1, min(max_depth, 6))
    roots = _roots_from(data, path)
    queue = [(r, []) for r in roots]
    seen = set(roots)
    flags: dict[bytes, list[str]] = {}
    readable: list[tuple[float, list[str], bytes]] = []
    expanded = 0
    while queue and expanded < 400:
        node, chain = queue.pop(0)
        expanded += 1
        for m in FLAG_RE.finditer(node):
            flags.setdefault(m.group(0), chain)
        if chain and _is_printable(node):
            readable.append((_english_score(node), chain, node))
        if len(chain) >= max_depth:
            continue
        for name, nxt in _expand(node):
            if nxt not in seen and len(nxt) >= 4:
                seen.add(nxt)
                queue.append((nxt, chain + [name]))
    ranked = sorted(((_flag_quality(f, c), f, c) for f, c in flags.items()), key=lambda x: x[0], reverse=True)
    ranked = [r for r in ranked if r[0] >= 2.0]
    if ranked:
        q, best, chain = ranked[0]
        lines = [
            f"FLAG DIJUMPAI: {best.decode('latin-1')}",
            f"  rantaian: {' -> '.join(chain) or '(teks asal)'}  (skor keyakinan {q:.1f})",
        ]
        if len(ranked) > 1:
            lines.append("Calon lain (keyakinan lebih rendah):")
            lines += [f"  {f.decode('latin-1')}  <- {' -> '.join(c)}  ({s:.1f})" for s, f, c in ranked[1:4]]
        return "\n".join(lines)
    readable.sort(key=lambda x: x[0], reverse=True)
    lines = [f"Tiada corak flag dijumpai ({expanded} nod diperiksa). Calon paling boleh dibaca:"]
    for score, chain, node in readable[:6]:
        lines.append(f"  [{' -> '.join(chain)}] skor {score:.2f}: {node[:150].decode('latin-1')}")
    lines.append("Cadangan: cuba run_python untuk cipher lain (vigenere, xor berbilang bait, RSA, ...).")
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


CTF_TOOLS = [auto_solve, list_ctf_files, file_inspect, decode, caesar_bruteforce, xor_bruteforce, hash_identify, run_python]
