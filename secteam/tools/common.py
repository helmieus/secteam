"""Pembalut keselamatan untuk semua alat: audit, tangkap ralat, potong output, kelulusan."""
import functools
import sys
import threading

from rich.prompt import Confirm

from ..runtime import RT
from ..scope import ScopeError
from ..ui import console

_approval_lock = threading.Lock()


class ApprovalDenied(Exception):
    pass


def truncate(text: str, limit: int | None = None) -> str:
    limit = limit or RT.max_tool_output
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[dipotong, {len(text) - limit} aksara lagi]"


def require_approval(action: str, detail: str) -> None:
    """Minta kelulusan manusia untuk tindakan aktif. Raise ApprovalDenied jika ditolak."""
    with _approval_lock:
        RT.audit.log("approval_request", action=action, detail=detail)
        if RT.auto_approve:
            console.print(f"[yellow]auto-approve[/] {action}: {detail}")
            RT.audit.log("approval_granted", action=action, auto=True)
            return
        if not sys.stdin or not sys.stdin.isatty():
            RT.audit.log("approval_denied", action=action, reason="non-interactive")
            raise ApprovalDenied(f"'{action}' memerlukan kelulusan tetapi tiada terminal interaktif.")
        console.print(f"\n[bold yellow]Kelulusan diperlukan[/] - {action}\n  [cyan]{detail}[/]")
        if Confirm.ask("Benarkan?", default=False):
            RT.audit.log("approval_granted", action=action, auto=False)
            return
        RT.audit.log("approval_denied", action=action)
        raise ApprovalDenied(f"Operator tidak meluluskan '{action}'.")


def guarded(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        name = fn.__name__
        RT.audit.log("tool_call", tool=name, args=kwargs or list(args))
        try:
            out = fn(*args, **kwargs)
        except ScopeError as e:
            RT.audit.log("scope_denied", tool=name, reason=str(e))
            return f"[DITOLAK - LUAR SKOP] {e} Jangan cuba memintas; laporkan kepada lead."
        except ApprovalDenied as e:
            return f"[DIBATALKAN] {e}"
        except Exception as e:  # noqa: BLE001 - pulangkan ralat kepada model
            RT.audit.log("tool_error", tool=name, error=f"{type(e).__name__}: {e}")
            return f"[RALAT] {type(e).__name__}: {e}"
        out = truncate(str(out))
        RT.audit.log("tool_result", tool=name, chars=len(out))
        return out

    return wrapper
