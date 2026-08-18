"""Saida: texto para humano, JSON para maquina, webhook para alertar."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

from .detection import Alert

RESET = "\033[0m"
COLORS = {
    "critical": "\033[1;97;41m",  # branco em fundo vermelho
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
}
DIM = "\033[2m"


def use_color(stream=sys.stdout) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def format_text(alert: Alert, color: bool = False, show_evidence: bool = True) -> str:
    tag = f"[{alert.severity.upper()}]"
    if color:
        tag = f"{COLORS.get(alert.severity, '')}{tag}{RESET}"

    ts = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    head = f"{tag} {ts}  {alert.kind}  {alert.message}"

    if not show_evidence or not alert.evidence:
        return head

    lines = [head]
    for item in alert.evidence:
        prefix = f"{DIM}    | " if color else "    | "
        suffix = RESET if color else ""
        lines.append(f"{prefix}{item}{suffix}")
    return "\n".join(lines)


def format_json(alert: Alert, include_evidence: bool = True) -> str:
    data = alert.to_dict()
    if not include_evidence:
        data.pop("evidence", None)
    return json.dumps(data, ensure_ascii=False)


def summary(alerts: list[Alert], events_seen: int) -> str:
    if not alerts:
        return f"\nNenhum alerta. {events_seen} eventos analisados."

    by_kind: dict = {}
    by_sev: dict = {}
    for a in alerts:
        by_kind[a.kind] = by_kind.get(a.kind, 0) + 1
        by_sev[a.severity] = by_sev.get(a.severity, 0) + 1

    parts = [
        "",
        "-" * 60,
        f"{len(alerts)} alertas em {events_seen} eventos analisados",
        "  por tipo:      " + ", ".join(
            f"{k}={v}" for k, v in sorted(by_kind.items())
        ),
        "  por severidade: " + ", ".join(
            f"{k}={v}" for k, v in sorted(by_sev.items())
        ),
    ]
    return "\n".join(parts)


def send_webhook(alert: Alert, url: str, timeout: float = 5.0) -> str | None:
    """Formato compativel com Discord e Slack. Devolve o erro, ou None."""
    payload = {
        "content": f"[{alert.severity.upper()}] {alert.message}",
        "text": f"[{alert.severity.upper()}] {alert.message}",
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return None
    except (urllib.error.URLError, OSError) as exc:
        return str(exc)
