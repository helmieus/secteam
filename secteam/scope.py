"""Scope guard: setiap aktiviti aktif mesti melalui Engagement.check()."""
from __future__ import annotations

import datetime as dt
import fnmatch
import ipaddress
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

ACTIVITIES = {"passive_recon", "web_probe", "port_scan", "vuln_scan"}
REQUIRED_FIELDS = (
    "name", "client", "authorized_by", "authorization_ref",
    "valid_from", "valid_until", "scope", "allowed_activities",
)


class ScopeError(Exception):
    """Target atau aktiviti di luar skop engagement."""


def _as_date(v) -> dt.date:
    if isinstance(v, dt.datetime):
        return v.date()
    if isinstance(v, dt.date):
        return v
    return dt.date.fromisoformat(str(v))


def _parse_net(p: str):
    try:
        return ipaddress.ip_network(p, strict=False)
    except ValueError:
        return None


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _resolve(host: str) -> set[str]:
    try:
        return {i[4][0] for i in socket.getaddrinfo(host, None)}
    except OSError:
        return set()


def normalize_target(target: str) -> str:
    """Tukar URL / host:port / IP / CIDR kepada host atau rangkaian kanonik."""
    t = target.strip()
    if not t or t.startswith("-"):
        raise ScopeError(f"Target tidak sah: {target!r}")
    try:
        if "/" in t and "://" not in t:
            return str(ipaddress.ip_network(t, strict=False))
        return str(ipaddress.ip_address(t))
    except ValueError:
        pass
    parsed = urlparse(t if "://" in t else "//" + t)
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        raise ScopeError(f"Tidak dapat menghurai host daripada {target!r}")
    return host


@dataclass
class Engagement:
    name: str
    client: str
    authorized_by: str
    authorization_ref: str
    valid_from: dt.date
    valid_until: dt.date
    include: list[str]
    exclude: list[str]
    allowed_activities: set[str]
    notes: str = ""
    path: str = ""

    @classmethod
    def load(cls, path: Path | str) -> "Engagement":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        missing = [k for k in REQUIRED_FIELDS if not data.get(k)]
        if missing:
            raise ValueError(f"Fail engagement tiada medan wajib: {', '.join(missing)}")
        scope = data["scope"] or {}
        include = [str(x) for x in scope.get("include") or []]
        if not include:
            raise ValueError("scope.include tidak boleh kosong")
        acts = {str(a) for a in data["allowed_activities"]}
        unknown = acts - ACTIVITIES
        if unknown:
            raise ValueError(f"Aktiviti tidak dikenali: {', '.join(sorted(unknown))}")
        eng = cls(
            name=str(data["name"]),
            client=str(data["client"]),
            authorized_by=str(data["authorized_by"]),
            authorization_ref=str(data["authorization_ref"]),
            valid_from=_as_date(data["valid_from"]),
            valid_until=_as_date(data["valid_until"]),
            include=include,
            exclude=[str(x) for x in scope.get("exclude") or []],
            allowed_activities=acts,
            notes=str(data.get("notes") or ""),
            path=str(path),
        )
        if eng.valid_until < eng.valid_from:
            raise ValueError("valid_until lebih awal daripada valid_from")
        return eng

    def is_active(self, today: dt.date | None = None) -> bool:
        today = today or dt.date.today()
        return self.valid_from <= today <= self.valid_until

    @staticmethod
    def _host_matches(host: str, patterns: list[str]) -> bool:
        ip = ipaddress.ip_address(host) if _is_ip(host) else None
        for p in patterns:
            net = _parse_net(p)
            if net is not None:
                if ip is not None and ip in net:
                    return True
            elif ip is None and fnmatch.fnmatchcase(host, p.lower()):
                return True
        return False

    def check(self, target: str, activity: str) -> str:
        """Pulangkan target ternormal jika dibenarkan, atau raise ScopeError."""
        if activity not in ACTIVITIES:
            raise ScopeError(f"Aktiviti tidak dikenali: {activity}")
        if not self.is_active():
            raise ScopeError(
                f"Engagement '{self.name}' tidak aktif (sah {self.valid_from} hingga {self.valid_until})."
            )
        if activity not in self.allowed_activities:
            raise ScopeError(f"Aktiviti '{activity}' tidak dibenarkan dalam engagement ini.")

        norm = normalize_target(target)

        if "/" in norm:  # julat rangkaian
            net = ipaddress.ip_network(norm)
            inc = [n for n in map(_parse_net, self.include) if n and n.version == net.version]
            exc = [n for n in map(_parse_net, self.exclude) if n and n.version == net.version]
            if not any(net.subnet_of(n) for n in inc):
                raise ScopeError(f"Julat {norm} bukan subset skop include.")
            if any(net.overlaps(n) for n in exc):
                raise ScopeError(f"Julat {norm} bertindih dengan exclude; kecilkan julat atau senaraikan host.")
            return norm

        if self._host_matches(norm, self.exclude):
            raise ScopeError(f"'{norm}' disenaraikan dalam exclude.")
        if not self._host_matches(norm, self.include):
            raise ScopeError(f"'{norm}' tiada dalam skop include.")
        if not _is_ip(norm):
            bad = [ip for ip in _resolve(norm) if self._host_matches(ip, self.exclude)]
            if bad:
                raise ScopeError(f"'{norm}' resolve ke IP yang dikecualikan: {', '.join(bad)}")
        return norm

    def summary(self) -> str:
        status = "AKTIF" if self.is_active() else "TIDAK AKTIF"
        return (
            f"Engagement: {self.name} [{status}]\n"
            f"Klien: {self.client} | Dibenarkan oleh: {self.authorized_by} | Ruj: {self.authorization_ref}\n"
            f"Tempoh: {self.valid_from} hingga {self.valid_until}\n"
            f"Skop include: {', '.join(self.include)}\n"
            f"Skop exclude: {', '.join(self.exclude) or '-'}\n"
            f"Aktiviti dibenarkan: {', '.join(sorted(self.allowed_activities))}"
        )
