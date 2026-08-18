"""Motor de deteccao.

A ideia central e uma janela deslizante: guardamos apenas as falhas dos
ultimos N segundos e reavaliamos as regras a cada evento novo. O uso de
memoria fica constante mesmo lendo um log gigante ou uma stream infinita.

O relogio usado e sempre o do evento, nunca o da maquina. Rodar sobre um log
de tres anos atras produz o mesmo resultado que rodar ao vivo, e os testes
ficam deterministicos.

Regras:

  brute_force  um IP acumula muitas falhas na janela
  spraying     um IP testa muitos usuarios diferentes na janela
  distributed  um usuario e atacado a partir de muitos IPs diferentes
  compromise   um login da certo logo depois de uma rajada de falhas
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .parsers import LoginEvent

MAX_EVIDENCE = 5


@dataclass
class Thresholds:
    """Todos os botoes de ajuste num lugar so."""

    window_seconds: int = 60
    failures_per_ip: int = 5
    users_per_ip: int = 5
    ips_per_user: int = 5
    cooldown_seconds: int = 300

    def validate(self) -> None:
        for name in (
            "window_seconds", "failures_per_ip",
            "users_per_ip", "ips_per_user",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} precisa ser >= 1")
        if self.cooldown_seconds < 0:
            raise ValueError("cooldown_seconds nao pode ser negativo")


@dataclass
class Alert:
    kind: str
    severity: str
    timestamp: datetime
    message: str
    count: int
    window_seconds: int
    ip: str | None = None
    username: str | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "ip": self.ip,
            "username": self.username,
            "count": self.count,
            "window_seconds": self.window_seconds,
            "message": self.message,
            "evidence": self.evidence,
        }


SEVERITY_RANK = {"medium": 1, "high": 2, "critical": 3}


def _severity(count: int, threshold: int) -> str:
    if count >= threshold * 3:
        return "critical"
    if count >= threshold * 2:
        return "high"
    return "medium"


class Detector:
    """Consome LoginEvents em ordem cronologica e devolve alertas."""

    def __init__(self, thresholds: Thresholds | None = None):
        self.t = thresholds or Thresholds()
        self.t.validate()
        self._window = timedelta(seconds=self.t.window_seconds)
        self._cooldown = timedelta(seconds=self.t.cooldown_seconds)

        self._fails_by_ip: dict[str, deque[LoginEvent]] = defaultdict(deque)
        self._fails_by_user: dict[str, deque[LoginEvent]] = defaultdict(deque)
        self._last_alert: dict[tuple[str, str], tuple[datetime, str]] = {}

        self.events_seen = 0
        self.alerts_raised = 0

    # -- utilidades internas ------------------------------------------------

    def _prune(self, bucket: deque[LoginEvent], now: datetime) -> None:
        cutoff = now - self._window
        while bucket and bucket[0].timestamp < cutoff:
            bucket.popleft()

    def _should_emit(
        self, kind: str, key: str, now: datetime, severity: str
    ) -> bool:
        """Controla o barulho sem esconder um ataque que esta piorando.

        O cooldown evita 200 alertas identicos para a mesma rajada. Mas se a
        severidade sobe (medium -> high -> critical), o alerta passa mesmo
        dentro do silencio: escalada e justamente o que o analista precisa
        ver na hora.
        """
        entry = self._last_alert.get((kind, key))
        rank = SEVERITY_RANK.get(severity, 0)

        if entry is None:
            self._last_alert[(kind, key)] = (now, severity)
            return True

        last_time, last_severity = entry
        escalou = rank > SEVERITY_RANK.get(last_severity, 0)
        expirou = now - last_time >= self._cooldown

        if escalou or expirou or self._cooldown.total_seconds() == 0:
            self._last_alert[(kind, key)] = (now, severity)
            return True
        return False

    @staticmethod
    def _evidence(events: Iterable[LoginEvent]) -> list[str]:
        items = list(events)[-MAX_EVIDENCE:]
        return [e.raw or str(e.to_dict()) for e in items]

    # -- API principal ------------------------------------------------------

    def feed(self, event: LoginEvent) -> list[Alert]:
        """Processa um evento e devolve os alertas que ele disparou."""
        self.events_seen += 1
        alerts: list[Alert] = []
        now = event.timestamp

        if event.success:
            alerts.extend(self._check_compromise(event, now))
        else:
            ip_fails = self._fails_by_ip[event.ip]
            ip_fails.append(event)
            self._prune(ip_fails, now)

            user_fails = self._fails_by_user[event.username]
            user_fails.append(event)
            self._prune(user_fails, now)

            alerts.extend(self._check_brute_force(event, ip_fails, now))
            alerts.extend(self._check_spraying(event, ip_fails, now))
            alerts.extend(self._check_distributed(event, user_fails, now))

        self.alerts_raised += len(alerts)
        return alerts

    def run(self, events: Iterable[LoginEvent]) -> Iterator[Alert]:
        for event in events:
            yield from self.feed(event)

    # -- regras -------------------------------------------------------------

    def _check_brute_force(
        self, event: LoginEvent, ip_fails: deque[LoginEvent], now: datetime
    ) -> list[Alert]:
        count = len(ip_fails)
        if count < self.t.failures_per_ip:
            return []
        severity = _severity(count, self.t.failures_per_ip)
        if not self._should_emit("brute_force", event.ip, now, severity):
            return []
        return [Alert(
            kind="brute_force",
            severity=severity,
            timestamp=now,
            ip=event.ip,
            username=event.username,
            count=count,
            window_seconds=self.t.window_seconds,
            message=(
                f"{count} falhas de login vindas de {event.ip} "
                f"em {self.t.window_seconds}s"
            ),
            evidence=self._evidence(ip_fails),
        )]

    def _check_spraying(
        self, event: LoginEvent, ip_fails: deque[LoginEvent], now: datetime
    ) -> list[Alert]:
        users = {e.username for e in ip_fails}
        if len(users) < self.t.users_per_ip:
            return []
        severity = _severity(len(users), self.t.users_per_ip)
        if not self._should_emit("spraying", event.ip, now, severity):
            return []
        amostra = ", ".join(sorted(users)[:5])
        return [Alert(
            kind="spraying",
            severity=severity,
            timestamp=now,
            ip=event.ip,
            username=None,
            count=len(users),
            window_seconds=self.t.window_seconds,
            message=(
                f"{event.ip} tentou {len(users)} usuarios distintos "
                f"em {self.t.window_seconds}s (alvos: {amostra})"
            ),
            evidence=self._evidence(ip_fails),
        )]

    def _check_distributed(
        self, event: LoginEvent, user_fails: deque[LoginEvent], now: datetime
    ) -> list[Alert]:
        ips = {e.ip for e in user_fails}
        if len(ips) < self.t.ips_per_user:
            return []
        severity = _severity(len(ips), self.t.ips_per_user)
        if not self._should_emit("distributed", event.username, now, severity):
            return []
        return [Alert(
            kind="distributed",
            severity=severity,
            timestamp=now,
            ip=None,
            username=event.username,
            count=len(ips),
            window_seconds=self.t.window_seconds,
            message=(
                f"usuario '{event.username}' atacado por {len(ips)} IPs "
                f"distintos em {self.t.window_seconds}s"
            ),
            evidence=self._evidence(user_fails),
        )]

    def _check_compromise(
        self, event: LoginEvent, now: datetime
    ) -> list[Alert]:
        """Sucesso logo depois de uma rajada de falhas do mesmo IP."""
        ip_fails = self._fails_by_ip.get(event.ip)
        if not ip_fails:
            return []
        self._prune(ip_fails, now)
        count = len(ip_fails)
        if count < self.t.failures_per_ip:
            return []
        # Zera para nao repetir o alerta a cada login seguinte da sessao.
        ip_fails.clear()
        return [Alert(
            kind="compromise",
            severity="critical",
            timestamp=now,
            ip=event.ip,
            username=event.username,
            count=count,
            window_seconds=self.t.window_seconds,
            message=(
                f"LOGIN BEM-SUCEDIDO de {event.ip} como '{event.username}' "
                f"apos {count} falhas - possivel comprometimento"
            ),
            evidence=[event.raw or str(event.to_dict())],
        )]
