"""Testes do detector.

Tudo usa horario de evento explicito, entao nada depende do relogio da
maquina nem de sleep. A suite roda em milissegundos e nunca fica instavel.
"""

from datetime import datetime, timedelta

import pytest

from detector.detection import Detector, Thresholds
from detector.parsers import (
    LoginEvent,
    detect_format,
    parse_json_line,
    parse_lines,
    parse_ssh_line,
)

T0 = datetime(2026, 8, 17, 3, 0, 0)


def ev(offset_seconds, ip="203.0.113.10", user="root", success=False):
    return LoginEvent(
        timestamp=T0 + timedelta(seconds=offset_seconds),
        ip=ip,
        username=user,
        success=success,
    )


def kinds(alerts):
    return [a.kind for a in alerts]


# ---------------------------------------------------------------- parsers

class TestParserSSH:
    def test_falha_de_senha(self):
        linha = ("Aug 17 03:10:00 srv sshd[123]: Failed password for root "
                 "from 203.0.113.45 port 41000 ssh2")
        e = parse_ssh_line(linha, 2026)
        assert e is not None
        assert e.ip == "203.0.113.45"
        assert e.username == "root"
        assert e.success is False
        assert e.timestamp == datetime(2026, 8, 17, 3, 10, 0)

    def test_usuario_invalido(self):
        linha = ("Aug 17 03:10:00 srv sshd[123]: Failed password for invalid "
                 "user admin from 203.0.113.45 port 41000 ssh2")
        e = parse_ssh_line(linha, 2026)
        assert e is not None and e.username == "admin" and e.success is False

    def test_login_aceito(self):
        linha = ("Aug 17 03:10:00 srv sshd[123]: Accepted password for eduardo "
                 "from 192.0.2.10 port 41000 ssh2")
        e = parse_ssh_line(linha, 2026)
        assert e is not None and e.success is True and e.username == "eduardo"

    def test_chave_publica(self):
        linha = ("Aug 17 03:10:00 srv sshd[123]: Accepted publickey for deploy "
                 "from 192.0.2.10 port 41000 ssh2")
        e = parse_ssh_line(linha, 2026)
        assert e is not None and e.success is True

    def test_ipv6(self):
        linha = ("Aug 17 03:10:00 srv sshd[123]: Failed password for root "
                 "from 2001:db8::1 port 41000 ssh2")
        e = parse_ssh_line(linha, 2026)
        assert e is not None and e.ip == "2001:db8::1"

    def test_linha_irrelevante_vira_none(self):
        assert parse_ssh_line("Aug 17 03:10:00 srv cron[1]: job started", 2026) is None
        assert parse_ssh_line("lixo qualquer", 2026) is None
        assert parse_ssh_line("", 2026) is None

    def test_ano_vem_de_fora(self):
        linha = ("Aug 17 03:10:00 srv sshd[1]: Failed password for root "
                 "from 203.0.113.45 port 41000 ssh2")
        assert parse_ssh_line(linha, 2023).timestamp.year == 2023


class TestParserJSON:
    def test_campos_padrao(self):
        linha = ('{"timestamp": "2026-08-17T03:10:00", "source_ip": "203.0.113.1",'
                 ' "username": "admin", "event": "login_failed"}')
        e = parse_json_line(linha, 2026)
        assert e is not None
        assert e.ip == "203.0.113.1" and e.username == "admin"
        assert e.success is False

    def test_nomes_alternativos_de_campo(self):
        linha = ('{"ts": "2026-08-17T03:10:00", "client_ip": "203.0.113.1",'
                 ' "login": "bob", "success": true}')
        e = parse_json_line(linha, 2026)
        assert e is not None and e.success is True and e.username == "bob"

    def test_timezone_e_removido(self):
        linha = ('{"timestamp": "2026-08-17T03:10:00Z", "ip": "203.0.113.1",'
                 ' "user": "x", "success": false}')
        e = parse_json_line(linha, 2026)
        assert e is not None and e.timestamp.tzinfo is None

    def test_json_invalido_ou_incompleto(self):
        assert parse_json_line("{quebrado", 2026) is None
        assert parse_json_line('{"ip": "1.2.3.4"}', 2026) is None
        assert parse_json_line("[1,2,3]", 2026) is None
        assert parse_json_line("", 2026) is None


class TestDeteccaoDeFormato:
    def test_reconhece_json(self):
        assert detect_format(['{"a": 1}']) == "json"

    def test_reconhece_syslog(self):
        assert detect_format(["Aug 17 03:10:00 srv sshd[1]: oi"]) == "ssh"

    def test_parse_lines_rejeita_formato_bobo(self):
        with pytest.raises(ValueError):
            list(parse_lines(["x"], fmt="xml"))


# -------------------------------------------------------------- deteccoes

class TestBruteForce:
    def test_dispara_no_limiar(self):
        d = Detector(Thresholds(window_seconds=60, failures_per_ip=5))
        alerts = []
        for i in range(5):
            alerts += d.feed(ev(i))
        assert kinds(alerts) == ["brute_force"]
        assert alerts[0].count == 5

    def test_nao_dispara_abaixo_do_limiar(self):
        d = Detector(Thresholds(window_seconds=60, failures_per_ip=5))
        alerts = []
        for i in range(4):
            alerts += d.feed(ev(i))
        assert alerts == []

    def test_janela_expira(self):
        """5 falhas espalhadas em 5 minutos nao sao um ataque."""
        d = Detector(Thresholds(window_seconds=60, failures_per_ip=5))
        alerts = []
        for i in range(5):
            alerts += d.feed(ev(i * 61))
        assert alerts == []

    def test_ips_diferentes_nao_somam(self):
        d = Detector(Thresholds(window_seconds=60, failures_per_ip=5))
        alerts = []
        for i in range(5):
            alerts += d.feed(ev(i, ip=f"203.0.113.{i}"))
        assert "brute_force" not in kinds(alerts)

    def test_sucessos_nao_contam(self):
        d = Detector(Thresholds(window_seconds=60, failures_per_ip=3))
        alerts = []
        for i in range(6):
            alerts += d.feed(ev(i, success=True))
        assert alerts == []


class TestCooldownEEscalada:
    def test_cooldown_segura_repeticao(self):
        d = Detector(Thresholds(window_seconds=300, failures_per_ip=5,
                                cooldown_seconds=300))
        alerts = []
        for i in range(7):
            alerts += d.feed(ev(i))
        # 5a falha alerta; 6a e 7a ainda sao "medium", entao ficam quietas
        assert len(alerts) == 1

    def test_escalada_fura_o_cooldown(self):
        d = Detector(Thresholds(window_seconds=300, failures_per_ip=5,
                                cooldown_seconds=300))
        alerts = []
        for i in range(15):
            alerts += d.feed(ev(i))
        sev = [a.severity for a in alerts]
        assert sev == ["medium", "high", "critical"]

    def test_cooldown_zero_alerta_sempre(self):
        d = Detector(Thresholds(window_seconds=300, failures_per_ip=5,
                                cooldown_seconds=0))
        alerts = []
        for i in range(7):
            alerts += d.feed(ev(i))
        assert len(alerts) == 3


class TestSpraying:
    def test_um_ip_muitos_usuarios(self):
        d = Detector(Thresholds(window_seconds=60, failures_per_ip=99,
                                users_per_ip=5))
        alerts = []
        for i, user in enumerate(["a", "b", "c", "d", "e"]):
            alerts += d.feed(ev(i, user=user))
        assert kinds(alerts) == ["spraying"]

    def test_mesmo_usuario_repetido_nao_e_spraying(self):
        d = Detector(Thresholds(window_seconds=60, failures_per_ip=99,
                                users_per_ip=3))
        alerts = []
        for i in range(10):
            alerts += d.feed(ev(i, user="root"))
        assert alerts == []


class TestDistribuido:
    def test_muitos_ips_um_usuario(self):
        d = Detector(Thresholds(window_seconds=60, failures_per_ip=99,
                                users_per_ip=99, ips_per_user=5))
        alerts = []
        for i in range(5):
            alerts += d.feed(ev(i, ip=f"198.51.100.{i}", user="admin"))
        assert kinds(alerts) == ["distributed"]
        assert alerts[0].username == "admin"


class TestComprometimento:
    def test_sucesso_depois_de_rajada(self):
        d = Detector(Thresholds(window_seconds=60, failures_per_ip=5))
        alerts = []
        for i in range(6):
            alerts += d.feed(ev(i))
        alerts += d.feed(ev(7, success=True))
        assert kinds(alerts)[-1] == "compromise"
        assert alerts[-1].severity == "critical"

    def test_sucesso_limpo_nao_alerta(self):
        d = Detector(Thresholds(window_seconds=60, failures_per_ip=5))
        assert d.feed(ev(0, success=True)) == []

    def test_sucesso_fora_da_janela_nao_alerta(self):
        d = Detector(Thresholds(window_seconds=60, failures_per_ip=5))
        for i in range(6):
            d.feed(ev(i))
        assert d.feed(ev(500, success=True)) == []

    def test_nao_repete_para_a_mesma_sessao(self):
        d = Detector(Thresholds(window_seconds=60, failures_per_ip=5))
        for i in range(6):
            d.feed(ev(i))
        primeiro = d.feed(ev(7, success=True))
        segundo = d.feed(ev(8, success=True))
        assert len(primeiro) == 1 and segundo == []


class TestConfiguracao:
    @pytest.mark.parametrize("campo", [
        "window_seconds", "failures_per_ip", "users_per_ip", "ips_per_user",
    ])
    def test_limiar_zero_e_rejeitado(self, campo):
        t = Thresholds(**{campo: 0})
        with pytest.raises(ValueError):
            t.validate()

    def test_cooldown_negativo_e_rejeitado(self):
        with pytest.raises(ValueError):
            Thresholds(cooldown_seconds=-1).validate()


class TestIntegracao:
    def test_trafego_limpo_nao_gera_nada(self):
        """O teste mais importante: ruido normal nao pode virar alerta."""
        d = Detector()
        alerts = []
        for i in range(50):
            alerts += d.feed(ev(i * 120, ip=f"192.0.2.{i % 5}",
                                user="eduardo", success=True))
        assert alerts == []

    def test_contadores(self):
        d = Detector(Thresholds(failures_per_ip=5))
        for i in range(5):
            d.feed(ev(i))
        assert d.events_seen == 5
        assert d.alerts_raised == 1


class TestStreamInfinita:
    """Regressao: --follow com --format auto travava para sempre.

    A auto-deteccao antiga fazia list(lines) para inspecionar o inicio do
    arquivo. Numa stream que nunca termina (tail -f), isso nunca retornava
    e o detector ficava mudo. A deteccao agora e preguicosa.
    """

    def test_auto_nao_consome_stream_infinita(self):
        from itertools import islice

        def infinita():
            i = 0
            while True:
                yield (f"Aug 17 03:{i // 60 % 60:02d}:{i % 60:02d} srv sshd[1]: "
                       f"Failed password for root from 203.0.113.45 port 41000 ssh2")
                i += 1

        eventos = list(islice(parse_lines(infinita(), fmt="auto"), 3))
        assert len(eventos) == 3
        assert all(e.ip == "203.0.113.45" for e in eventos)

    def test_auto_preserva_a_primeira_linha(self):
        """A linha usada para detectar o formato nao pode ser descartada."""
        linhas = [
            "Aug 17 03:10:00 srv sshd[1]: Failed password for root "
            "from 203.0.113.45 port 41000 ssh2",
            "Aug 17 03:10:01 srv sshd[2]: Failed password for root "
            "from 203.0.113.45 port 41001 ssh2",
        ]
        assert len(list(parse_lines(linhas, fmt="auto", year=2026))) == 2

    def test_auto_com_lixo_antes_do_log(self):
        linhas = [
            "### cabecalho irrelevante",
            "",
            '{"timestamp": "2026-08-17T03:10:00", "ip": "203.0.113.1", '
            '"user": "admin", "success": false}',
        ]
        eventos = list(parse_lines(linhas, fmt="auto", year=2026))
        assert len(eventos) == 1 and eventos[0].username == "admin"
