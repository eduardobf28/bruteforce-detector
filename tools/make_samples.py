"""Gera os logs de exemplo do repositorio.

Os IPs usados sao das faixas reservadas para documentacao (RFC 5737):
192.0.2.0/24, 198.51.100.0/24 e 203.0.113.0/24. Nunca coloque IPs reais
em arquivo de exemplo de um repo publico.

Rode: python tools/make_samples.py
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(1337)  # saida reproduzivel

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_logs"
BASE = datetime(2026, 8, 17, 3, 0, 0)

USERS = ["eduardo", "deploy", "postgres", "ubuntu", "www-data"]
SPRAY_USERS = [
    "admin", "root", "test", "guest", "oracle",
    "jenkins", "backup", "ftpuser",
]
BOTNET = [f"198.51.100.{n}" for n in (11, 24, 37, 48, 59, 61, 72)]

ssh_lines: list[tuple[datetime, str]] = []
json_rows: list[tuple[datetime, dict]] = []


def ssh(offset: float, template: str) -> None:
    ts = BASE + timedelta(seconds=offset)
    stamp = ts.strftime("%b %d %H:%M:%S")
    pid = random.randint(10000, 99999)
    ssh_lines.append((ts, f"{stamp} srv-web-01 sshd[{pid}]: {template}"))


def jrow(offset: float, ip: str, user: str, ok: bool) -> None:
    ts = BASE + timedelta(seconds=offset)
    json_rows.append((ts, {
        "timestamp": ts.isoformat(),
        "level": "info" if ok else "warning",
        "service": "auth-api",
        "event": "login_success" if ok else "login_failed",
        "username": user,
        "source_ip": ip,
        "user_agent": "Mozilla/5.0",
    }))


# --------------------------------------------------------------------------
# Cenario 0 - trafego normal, o ruido de fundo que NAO deve alertar
# --------------------------------------------------------------------------
for i in range(12):
    t = i * 47
    user = random.choice(USERS)
    ip = f"192.0.2.{random.choice([10, 15, 20])}"
    porta = random.randint(40000, 60000)
    if random.random() < 0.25:
        ssh(t, f"Failed password for {user} from {ip} port {porta} ssh2")
    else:
        ssh(t + 2, f"Accepted password for {user} from {ip} port {porta} ssh2")

# --------------------------------------------------------------------------
# Cenario 1 - brute force classico: 1 IP, 1 usuario, muita velocidade
# --------------------------------------------------------------------------
for i in range(14):
    ssh(600 + i * 3, f"Failed password for root from 203.0.113.45 port {41000 + i} ssh2")

# --------------------------------------------------------------------------
# Cenario 2 - password spraying: 1 IP, 1 tentativa por usuario, devagar
# --------------------------------------------------------------------------
for i, user in enumerate(SPRAY_USERS):
    ssh(900 + i * 6, f"Failed password for invalid user {user} "
        f"from 203.0.113.99 port {45000 + i} ssh2")

# --------------------------------------------------------------------------
# Cenario 3 - distribuido: varios IPs contra o mesmo usuario
# --------------------------------------------------------------------------
for i, ip in enumerate(BOTNET):
    ssh(1200 + i * 7, f"Failed password for admin from {ip} port {50000 + i} ssh2")

# --------------------------------------------------------------------------
# Cenario 4 - comprometimento: rajada de falhas e depois um sucesso
# --------------------------------------------------------------------------
for i in range(8):
    ssh(1500 + i * 4, f"Failed password for deploy from 192.0.2.66 port {52000 + i} ssh2")
ssh(1536, "Accepted password for deploy from 192.0.2.66 port 52099 ssh2")

# --------------------------------------------------------------------------
# Log JSON da aplicacao: trafego normal + brute force + spraying
# --------------------------------------------------------------------------
for i in range(10):
    jrow(i * 30, f"192.0.2.{10 + i % 4}", random.choice(USERS), ok=True)

for i in range(11):
    jrow(400 + i * 4, "203.0.113.201", "eduardo@exemplo.com", ok=False)

for i, user in enumerate(SPRAY_USERS):
    jrow(700 + i * 5, "203.0.113.202", f"{user}@exemplo.com", ok=False)

for i in range(6):
    jrow(1000 + i * 5, "192.0.2.77", "postgres", ok=False)
jrow(1032, "192.0.2.77", "postgres", ok=True)


def main() -> None:
    SAMPLES.mkdir(exist_ok=True)

    ssh_lines.sort(key=lambda r: r[0])
    (SAMPLES / "auth.log").write_text(
        "\n".join(line for _, line in ssh_lines) + "\n", encoding="utf-8"
    )

    json_rows.sort(key=lambda r: r[0])
    (SAMPLES / "api.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for _, row in json_rows) + "\n",
        encoding="utf-8",
    )

    print(f"auth.log   {len(ssh_lines)} linhas")
    print(f"api.jsonl  {len(json_rows)} linhas")


if __name__ == "__main__":
    main()
