"""Automasi GUI/RDP untuk box yang perlukan interaksi desktop (cth. kiosk escape).
Pada VM headless: Xvfb (skrin maya) + xfreerdp (sesi RDP) + tesseract OCR (agent 'baca' skrin sebagai
teks + koordinat) + xdotool (klik/taip). AUTHORIZED sahaja. Sambungan sesi perlu kelulusan + audit.

Aliran untuk agent: gui_rdp_connect -> gui_screenshot (baca skrin) -> gui_click/gui_click_text/gui_type/
gui_key (bertindak) -> gui_screenshot lagi (lihat keadaan baharu) -> ulang sehingga objektif tercapai."""
import os
import shutil
import subprocess
import time
from pathlib import Path

from langchain_core.tools import tool

from ..runtime import RT
from .common import guarded, require_approval

_DISPLAY = ":99"
_SHOT = Path("/tmp/secteam-gui.png")
_SESSION: dict = {"xvfb": None, "rdp": None, "size": "1280x800"}


def _env() -> dict:
    e = dict(os.environ)
    e["DISPLAY"] = _DISPLAY
    return e


def _need(bin_: str) -> str:
    p = shutil.which(bin_)
    if not p:
        raise FileNotFoundError(f"'{bin_}' tidak dipasang (modul GUI perlukan freerdp2-x11/xvfb/xdotool/"
                                f"tesseract/imagemagick).")
    return p


def _xdotool(*args: str) -> str:
    p = subprocess.run([_need("xdotool"), *args], capture_output=True, text=True, env=_env(), timeout=30)
    return (p.stdout + p.stderr).strip()


def _ocr() -> list[dict]:
    """Tangkap skrin + OCR -> senarai {text, cx, cy, conf}."""
    subprocess.run([_need("import"), "-window", "root", str(_SHOT)], env=_env(),
                   capture_output=True, timeout=30)
    p = subprocess.run([_need("tesseract"), str(_SHOT), "stdout", "tsv"],
                       capture_output=True, text=True, timeout=40)
    out = []
    for line in p.stdout.splitlines()[1:]:
        c = line.split("\t")
        if len(c) >= 12 and c[11].strip():
            try:
                left, top, w, h, conf = int(c[6]), int(c[7]), int(c[8]), int(c[9]), float(c[10])
            except ValueError:
                continue
            if conf < 40:
                continue
            out.append({"text": c[11], "cx": left + w // 2, "cy": top + h // 2, "conf": conf})
    return out


@tool
@guarded
def gui_rdp_connect(host: str, username: str, password: str = "", width: int = 1280, height: int = 800) -> str:
    """Open an RDP GUI session to a host inside a virtual screen (for boxes needing desktop interaction,
    e.g. kiosk escape). After connecting, use gui_screenshot to read the screen. Requires approval."""
    require_approval("gui_rdp_connect", f"RDP {username}@{host}")
    _SESSION["size"] = f"{int(width)}x{int(height)}"
    # bersihkan sesi lama
    subprocess.run(["pkill", "-f", f"Xvfb {_DISPLAY}"], capture_output=True)
    subprocess.run(["pkill", "-f", "xfreerdp"], capture_output=True)
    time.sleep(1)
    _SESSION["xvfb"] = subprocess.Popen(
        [_need("Xvfb"), _DISPLAY, "-screen", "0", f"{_SESSION['size']}x24", "-ac"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    xf = _need("xfreerdp")
    args = [xf, f"/v:{host}", f"/u:{username}", "/cert:ignore", f"/size:{_SESSION['size']}",
            "/log-level:ERROR", "+clipboard", "-grab-keyboard"]
    if password:
        args.append(f"/p:{password}")
    _SESSION["rdp"] = subprocess.Popen(args, env=_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(10)
    if _SESSION["rdp"].poll() is not None:
        return f"[GAGAL] xfreerdp keluar awal (exit {_SESSION['rdp'].returncode}). Semak host/creds/port 3389."
    items = _ocr()
    txt = " | ".join(i["text"] for i in items[:40])
    return f"RDP sesi dibuka ke {host} ({_SESSION['size']}). Teks skrin awal (OCR):\n{txt or '(kosong/memuat)'}"


@tool
@guarded
def gui_screenshot() -> str:
    """Capture the current RDP screen and OCR it. Returns visible text with approximate (x,y) coordinates
    you can click. Call this after every action to see the new state."""
    items = _ocr()
    if not items:
        return "(tiada teks dikesan; skrin mungkin memuat, grafik, atau kosong)"
    lines = [f"PNG: {_SHOT}", f"{len(items)} elemen teks:"]
    lines += [f"  ({i['cx']},{i['cy']}) {i['text']}" for i in items[:60]]
    return "\n".join(lines)


@tool
@guarded
def gui_click(x: int, y: int, double: bool = False, button: int = 1) -> str:
    """Click at pixel (x,y) on the RDP screen. double=True for double-click. button 1=left,3=right."""
    _xdotool("mousemove", str(int(x)), str(int(y)))
    _xdotool("click", "--repeat", "2" if double else "1", str(int(button)))
    return f"klik ({x},{y}){' x2' if double else ''}"


@tool
@guarded
def gui_click_text(text: str, double: bool = False) -> str:
    """Find on-screen text (via OCR) and click its center. Easier than pixel coords for buttons/links."""
    items = _ocr()
    hit = next((i for i in items if text.lower() in i["text"].lower()), None)
    if not hit:
        avail = ", ".join(i["text"] for i in items[:30])
        return f"[TIDAK JUMPA] '{text}' tiada di skrin. Teks ada: {avail}"
    _xdotool("mousemove", str(hit["cx"]), str(hit["cy"]))
    _xdotool("click", "--repeat", "2" if double else "1", "1")
    return f"klik '{hit['text']}' di ({hit['cx']},{hit['cy']})"


@tool
@guarded
def gui_type(text: str) -> str:
    """Type text into the focused field on the RDP screen."""
    _xdotool("type", "--delay", "40", text)
    return f"taip: {text[:60]}"


@tool
@guarded
def gui_key(keys: str) -> str:
    """Press a key or combo on the RDP screen (xdotool syntax), e.g. 'Return', 'ctrl+l', 'alt+F4', 'Escape',
    'super' (Windows key). Use ctrl+l to focus a browser address bar."""
    _xdotool("key", keys)
    return f"kekunci: {keys}"


@tool
@guarded
def gui_disconnect() -> str:
    """Close the RDP session and virtual screen."""
    for key in ("rdp", "xvfb"):
        proc = _SESSION.get(key)
        if proc and proc.poll() is None:
            proc.terminate()
    subprocess.run(["pkill", "-f", "xfreerdp"], capture_output=True)
    subprocess.run(["pkill", "-f", f"Xvfb {_DISPLAY}"], capture_output=True)
    _SESSION["rdp"] = _SESSION["xvfb"] = None
    return "sesi RDP ditutup"


GUI_TOOLS = [gui_rdp_connect, gui_screenshot, gui_click, gui_click_text, gui_type, gui_key, gui_disconnect]
