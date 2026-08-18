"""Interface de linha de comando."""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TextIO

from . import __version__
from .detection import Alert, Detector, Thresholds
from .output import format_json, format_text, send_webhook, summary, use_color
from .parsers import PARSERS, parse_lines

EXIT_OK = 0
EXIT_ALERTS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="detector",
        description=(
            "Detecta brute force, password spraying e ataques distribuidos "
            "em logs de autenticacao."
        ),
        epilog=(
            "exemplos:\n"
            "  detector sample_logs/auth.log\n"
            "  detector sample_logs/api.jsonl --format json --output json\n"
            "  detector /var/log/auth.log --follow --threshold 3\n"
            "  cat auth.log | detector -\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "logfile",
        help="arquivo de log a analisar, ou '-' para ler do stdin",
    )
    p.add_argument(
        "--format",
        choices=[*sorted(PARSERS), "auto"],
        default="auto",
        help="formato do log (padrao: auto)",
    )
    p.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="formato da saida (padrao: text)",
    )

    g = p.add_argument_group("limiares de deteccao")
    g.add_argument("--window", type=int, default=60, metavar="SEG",
                   help="tamanho da janela deslizante (padrao: 60)")
    g.add_argument("--threshold", type=int, default=5, metavar="N",
                   help="falhas do mesmo IP para brute force (padrao: 5)")
    g.add_argument("--spray-users", type=int, default=5, metavar="N",
                   help="usuarios distintos por IP para spraying (padrao: 5)")
    g.add_argument("--distributed-ips", type=int, default=5, metavar="N",
                   help="IPs distintos por usuario para distribuido (padrao: 5)")
    g.add_argument("--cooldown", type=int, default=300, metavar="SEG",
                   help="silencio entre alertas repetidos, 0 desliga (padrao: 300)")

    e = p.add_argument_group("extras")
    e.add_argument("--follow", action="store_true",
                   help="acompanha o arquivo em tempo real, tipo tail -f")
    e.add_argument("--webhook", metavar="URL",
                   help="envia cada alerta para um webhook Discord/Slack")
    e.add_argument("--year", type=int, metavar="AAAA",
                   help="ano dos logs syslog, que nao gravam o ano")
    e.add_argument("--no-evidence", action="store_true",
                   help="omite as linhas de evidencia na saida de texto")
    e.add_argument("--quiet", action="store_true",
                   help="so os alertas, sem o resumo final")
    e.add_argument("--version", action="version",
                   version=f"detector {__version__}")
    return p


def follow_file(path: Path, poll: float = 0.5) -> Iterator[str]:
    """Igual a `tail -f`: le ate o fim e depois espera por linhas novas."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)  # pula para o fim
        while True:
            line = fh.readline()
            if line:
                yield line
            else:
                time.sleep(poll)


def emit(
    alert: Alert,
    args: argparse.Namespace,
    color: bool,
    stream: TextIO,
) -> None:
    if args.output == "json":
        print(
            format_json(alert, include_evidence=not args.no_evidence),
            file=stream,
            flush=True,
        )
    else:
        print(
            format_text(alert, color=color, show_evidence=not args.no_evidence),
            file=stream,
            flush=True,
        )
    if args.webhook:
        err = send_webhook(alert, args.webhook)
        if err:
            print(f"aviso: webhook falhou: {err}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        thresholds = Thresholds(
            window_seconds=args.window,
            failures_per_ip=args.threshold,
            users_per_ip=args.spray_users,
            ips_per_user=args.distributed_ips,
            cooldown_seconds=args.cooldown,
        )
        detector = Detector(thresholds)
    except ValueError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Fonte das linhas
    if args.logfile == "-":
        if args.follow:
            print("erro: --follow nao funciona com stdin", file=sys.stderr)
            return EXIT_ERROR
        lines: Iterator[str] = iter(sys.stdin)
    else:
        path = Path(args.logfile)
        if not path.is_file():
            print(f"erro: arquivo nao encontrado: {path}", file=sys.stderr)
            return EXIT_ERROR
        if args.follow:
            lines = follow_file(path)
        else:
            lines = iter(
                path.read_text(encoding="utf-8", errors="replace").splitlines()
            )

    color = args.output == "text" and use_color()
    collected: list[Alert] = []

    try:
        events = parse_lines(lines, fmt=args.format, year=args.year)
        for alert in detector.run(events):
            collected.append(alert)
            emit(alert, args, color, sys.stdout)
    except ValueError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\ninterrompido.", file=sys.stderr)
    except BrokenPipeError:
        # Acontece em `detector log | head`. O consumidor fechou o cano;
        # sair em silencio e o comportamento correto de um utilitario Unix.
        return _exit_on_broken_pipe()

    if not args.quiet and args.output == "text":
        try:
            print(summary(collected, detector.events_seen))
        except BrokenPipeError:
            return _exit_on_broken_pipe()

    return EXIT_ALERTS if collected else EXIT_OK


def _exit_on_broken_pipe() -> int:
    """Evita o 'Exception ignored' que o Python imprime ao encerrar."""
    with contextlib.suppress(BrokenPipeError):
        sys.stdout.close()
    os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
