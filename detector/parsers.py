"""Parsers plugaveis.

Cada formato de log vira um LoginEvent normalizado. Para dar suporte a um
formato novo, escreva uma funcao `str -> LoginEvent | None` e registre em
PARSERS. O resto do sistema nao precisa saber de onde o evento veio.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from itertools import chain
from typing import Callable, Optional

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass(frozen=True)
class LoginEvent:
    """Uma tentativa de autenticacao, ja normalizada."""

    timestamp: datetime
    ip: str
    username: str
    success: bool
    raw: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "ip": self.ip,
            "username": self.username,
            "success": self.success,
        }


# --------------------------------------------------------------------------
# Parser 1: syslog do sshd (/var/log/auth.log)
# --------------------------------------------------------------------------

_SYSLOG_TS = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})"
)

_SSH_PATTERNS: list[tuple] = [
    (re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) "
        r"from (?P<ip>[0-9a-fA-F.:]+) port"
    ), False),
    (re.compile(
        r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"
    ), False),
    (re.compile(
        r"authentication failure;.*rhost=(?P<ip>[0-9a-fA-F.:]+)\s+user=(?P<user>\S+)"
    ), False),
    (re.compile(
        r"Accepted (?:password|publickey) for (?P<user>\S+) "
        r"from (?P<ip>[0-9a-fA-F.:]+) port"
    ), True),
]


def parse_syslog_timestamp(line: str, year: int) -> datetime | None:
    """O syslog classico nao grava o ano, por isso ele vem de fora."""
    m = _SYSLOG_TS.match(line)
    if not m:
        return None
    month = MONTHS.get(m.group("mon"))
    if month is None:
        return None
    try:
        return datetime(
            year, month, int(m.group("day")),
            int(m.group("hh")), int(m.group("mm")), int(m.group("ss")),
        )
    except ValueError:
        return None


def parse_ssh_line(line: str, year: int) -> LoginEvent | None:
    ts = parse_syslog_timestamp(line, year)
    if ts is None:
        return None
    for pattern, success in _SSH_PATTERNS:
        m = pattern.search(line)
        if m:
            return LoginEvent(
                timestamp=ts,
                ip=m.group("ip"),
                username=m.group("user"),
                success=success,
                raw=line.rstrip("\n"),
            )
    return None


# --------------------------------------------------------------------------
# Parser 2: JSON Lines (logs de aplicacao)
# --------------------------------------------------------------------------

_TS_KEYS = ("timestamp", "ts", "time", "@timestamp", "datetime")
_IP_KEYS = ("ip", "source_ip", "src_ip", "client_ip", "remote_addr")
_USER_KEYS = ("user", "username", "login", "account", "email")
_OK_KEYS = ("success", "ok", "authenticated")
_RESULT_KEYS = ("result", "outcome", "status", "event")

_TRUTHY = {"success", "ok", "accepted", "allowed", "granted", "login_success"}
_FALSY = {"failure", "failed", "denied", "rejected", "invalid", "login_failed"}


def _first(record: dict, keys: Iterable[str]):
    for key in keys:
        if key in record and record[key] is not None:
            return record[key]
    return None


def _parse_timestamp(value) -> datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    # Descarta o fuso para manter todas as comparacoes homogeneas.
    return dt.replace(tzinfo=None)


def _parse_success(record: dict) -> bool | None:
    raw = _first(record, _OK_KEYS)
    if isinstance(raw, bool):
        return raw
    raw = _first(record, _RESULT_KEYS)
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in _TRUTHY:
            return True
        if text in _FALSY:
            return False
    return None


def parse_json_line(line: str, year: int) -> LoginEvent | None:
    line = line.strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(record, dict):
        return None

    ts = _parse_timestamp(_first(record, _TS_KEYS))
    ip = _first(record, _IP_KEYS)
    success = _parse_success(record)
    if ts is None or ip is None or success is None:
        return None

    user = _first(record, _USER_KEYS) or "<desconhecido>"
    return LoginEvent(
        timestamp=ts,
        ip=str(ip),
        username=str(user),
        success=success,
        raw=line,
    )


# --------------------------------------------------------------------------
# Registro e deteccao automatica de formato
# --------------------------------------------------------------------------

ParserFn = Callable[[str, int], Optional[LoginEvent]]

PARSERS: dict = {
    "ssh": parse_ssh_line,
    "json": parse_json_line,
}


def detect_format(lines: Iterable[str], sample_size: int = 40) -> str:
    """Olha as primeiras linhas e chuta o formato."""
    for i, line in enumerate(lines):
        if i >= sample_size:
            break
        stripped = line.strip()
        if stripped.startswith("{"):
            return "json"
        if _SYSLOG_TS.match(stripped):
            return "ssh"
    return "ssh"


def _resolve_format(
    lines: Iterator[str], sample_size: int = 40
) -> tuple[str, Iterator[str]]:
    """Decide o formato olhando o minimo de linhas possivel.

    Devolve (formato, iterador_reconstituido). Nao materializa a entrada:
    em modo --follow a stream nunca termina, e um list() aqui travaria o
    programa para sempre, sem nunca emitir um alerta.
    """
    buffered: list[str] = []
    for line in lines:
        buffered.append(line)
        stripped = line.strip()
        if stripped.startswith("{"):
            return "json", chain(buffered, lines)
        if _SYSLOG_TS.match(stripped):
            return "ssh", chain(buffered, lines)
        if len(buffered) >= sample_size:
            break
    return "ssh", chain(buffered, lines)


def parse_lines(
    lines: Iterable[str],
    fmt: str = "auto",
    year: int | None = None,
) -> Iterator[LoginEvent]:
    """Converte linhas cruas em LoginEvents, ignorando o que nao casar."""
    year = year or datetime.now().year
    lines = iter(lines)

    if fmt == "auto":
        fmt, lines = _resolve_format(lines)

    if fmt not in PARSERS:
        raise ValueError(
            f"formato desconhecido: {fmt!r} "
            f"(disponiveis: {', '.join(sorted(PARSERS))}, auto)"
        )

    parser = PARSERS[fmt]
    for line in lines:
        event = parser(line, year)
        if event is not None:
            yield event
