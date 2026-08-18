# Detector de Brute Force em Logs

[![CI](https://github.com/eduardobf28/bruteforce-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/eduardobf28/bruteforce-detector/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Analisa logs de autenticação e identifica ataques de força bruta, *password
spraying* e tentativas distribuídas — em arquivos históricos ou em tempo real.

Sem dependências externas. Python 3.9+ e a biblioteca padrão.

```
[MEDIUM]   2026-08-17 03:10:12  brute_force  5 falhas de login vindas de 203.0.113.45 em 60s
[HIGH]     2026-08-17 03:10:27  brute_force  10 falhas de login vindas de 203.0.113.45 em 60s
[MEDIUM]   2026-08-17 03:15:24  spraying     203.0.113.99 tentou 5 usuarios distintos em 60s
[MEDIUM]   2026-08-17 03:20:28  distributed  usuario 'admin' atacado por 5 IPs distintos em 60s
[CRITICAL] 2026-08-17 03:25:36  compromise   LOGIN BEM-SUCEDIDO de 192.0.2.66 apos 8 falhas
```

## O problema

Um `grep "Failed password" auth.log | wc -l` responde *quantas* falhas
existem. Não responde o que importa:

- essas 200 falhas são um ataque ou três meses de gente esquecendo a senha?
- alguém está testando **uma senha contra 500 usuários**? Isso quase não
  aparece na contagem por IP, porque cada usuário sofre uma única tentativa.
- depois da rajada de falhas, **alguém entrou?**

Este projeto responde as três.

## Rodando em 30 segundos

```bash
git clone https://github.com/eduardobf28/bruteforce-detector
cd bruteforce-detector
python -m detector sample_logs/auth.log --year 2026
```

O repositório já vem com logs sintéticos contendo os quatro cenários de
ataque, então dá pra ver o resultado sem configurar nada.

Instalação como comando de sistema:

```bash
pip install -e .
detector sample_logs/auth.log --year 2026
```

## As quatro regras

| Regra | O que procura | Por que importa |
|---|---|---|
| `brute_force` | muitas falhas do mesmo IP na janela | ataque clássico, ruidoso |
| `spraying` | um IP tentando muitos usuários diferentes | escapa de bloqueio por conta |
| `distributed` | muitos IPs contra o mesmo usuário | botnet diluindo a origem |
| `compromise` | login aceito logo após rajada de falhas | o ataque **funcionou** |

A regra `spraying` é a que costuma passar despercebida. Um atacante que testa
`Senha123` contra 500 contas gera uma tentativa por conta — nenhum limite por
usuário dispara, e a contagem por IP fica diluída. O que denuncia é a
**variedade de alvos**, não o volume.

E `compromise` é a de maior valor operacional: as outras dizem que tentaram,
essa diz que conseguiram.

## Uso

```bash
detector <arquivo|-> [opções]
```

| Opção | Padrão | Descrição |
|---|---|---|
| `--format {ssh,json,auto}` | `auto` | formato do log |
| `--output {text,json}` | `text` | saída legível ou para máquina |
| `--window SEG` | 60 | tamanho da janela deslizante |
| `--threshold N` | 5 | falhas por IP para `brute_force` |
| `--spray-users N` | 5 | usuários distintos para `spraying` |
| `--distributed-ips N` | 5 | IPs distintos para `distributed` |
| `--cooldown SEG` | 300 | silêncio entre alertas repetidos (0 desliga) |
| `--follow` | — | acompanha o arquivo ao vivo, tipo `tail -f` |
| `--webhook URL` | — | envia alertas para Discord/Slack |
| `--year AAAA` | ano atual | ano dos logs syslog, que não gravam o ano |

Exemplos:

```bash
# monitoramento ao vivo com limiar agressivo
detector /var/log/auth.log --follow --threshold 3 --window 30

# log JSON de aplicação, saída para um SIEM
detector api.jsonl --output json --no-evidence > alertas.jsonl

# via pipe
journalctl -u ssh --no-pager | detector -
```

**Código de saída:** `0` sem alertas, `1` com alertas, `2` em erro. Serve pra
usar direto em cron ou pipeline de CI.

## Decisões de projeto

**Janela deslizante em vez de contagem total.** O detector guarda apenas as
falhas dos últimos N segundos, então o consumo de memória fica constante mesmo
lendo um log de vários GB ou uma stream infinita.

**O relógio é o do evento, nunca o da máquina.** Rodar sobre um log de três
anos atrás produz exatamente o mesmo resultado que rodar ao vivo. Isso também
torna os testes determinísticos: nenhum `sleep`, nenhuma flakiness.

**Datetimes naive de propósito.** O sistema compara horário de log com horário
de log; misturar objetos *aware* e *naive* quebraria as comparações. Por isso
a regra `DTZ` do linter está fora do conjunto selecionado — é escolha
consciente, não descuido.

**Cooldown com escalada.** Sem cooldown, um ataque de 500 tentativas gera 500
alertas idênticos e o analista para de ler. Mas um cooldown burro esconde um
ataque que está piorando. A solução: o silêncio vale para repetição, mas
**alertas de severidade maior furam o cooldown**. Por isso o exemplo lá em
cima mostra `MEDIUM` em 5 falhas e `HIGH` em 10, do mesmo IP.

**Parsers plugáveis.** Adicionar um formato é escrever uma função
`str -> LoginEvent | None` e registrá-la em `PARSERS`. O motor de detecção
nunca soube de que formato o evento veio.

## Arquitetura

```
detector/
├── parsers.py     formatos crus  ->  LoginEvent normalizado
├── detection.py   LoginEvent     ->  Alert (janelas deslizantes)
├── output.py      Alert          ->  texto, JSON ou webhook
└── cli.py         argumentos, leitura de arquivo, modo --follow
```

Fluxo de dados em uma linha: **linha de log → `LoginEvent` → janela → regra →
`Alert` → saída.** Cada camada só conhece a vizinha.

## Testes

```bash
pip install -e ".[dev]"
pytest -v
```

39 testes cobrindo os parsers, cada regra, expiração de janela, cooldown,
escalada de severidade e validação de configuração.

O teste mais importante é o de **falso positivo**: tráfego normal, com logins
legítimos e falhas ocasionais espalhadas no tempo, não pode gerar nenhum
alerta. Detector que grita o tempo todo é detector que ninguém usa.

## Limitações conhecidas

Vale saber antes de apontar isso para produção:

- **Estado só em memória.** Reiniciar o processo zera as janelas. Para uso
  real, persistir em Redis ou SQLite.
- **Assume ordem cronológica.** Logs fora de ordem ou de várias máquinas
  intercalados podem gerar contagem imprecisa.
- **Não bloqueia nada.** Detecta e alerta; a resposta (fail2ban, regra de
  firewall) fica de fora do escopo de propósito.
- **Sem geolocalização nem reputação de IP.** Enriquecer com AbuseIPDB
  reduziria bastante o ruído.

## Próximos passos

- [ ] Persistência de estado entre reinícios
- [ ] Parser de logs do nginx e do IIS
- [ ] Enriquecimento com reputação de IP (AbuseIPDB)
- [ ] Exportar métricas no formato Prometheus
- [ ] Empacotamento em container

## O que eu aprendi

Duas coisas mudaram o projeto no meio do caminho.

A primeira foi perceber que **detectar é fácil, calibrar é difícil**. A versão
inicial disparava em qualquer coisa. O trabalho de verdade foi separar ataque
de ruído, e daí nasceram a janela deslizante e o teste de falso positivo.

A segunda foi o cooldown. Implementei, achei que estava pronto, e aí rodei nos
logs de exemplo: um IP com 14 falhas gerava um único alerta `MEDIUM`, porque
o silêncio engolia a escalada. O alerta estava tecnicamente correto e
operacionalmente inútil. A regra de deixar a severidade furar o cooldown veio
daí — e é o tipo de detalhe que só aparece quando você olha a saída de
verdade, em vez de confiar que o código faz o que você imaginou.

A terceira apareceu no fim, e foi a mais instrutiva. Testei o `--follow`
apontando para um arquivo e escrevendo linhas de ataque nele em paralelo:
nenhum alerta. O processo rodava, não travava visivelmente, não dava erro —
simplesmente ficava mudo. A causa era a auto-detecção de formato, que fazia
`list(lines)` para inspecionar o começo do arquivo. Em modo `tail -f` a
stream nunca termina, então esse `list()` nunca retornava. O bug só existia
na combinação `--follow` com `--format auto`, que é justamente a forma como
qualquer pessoa usaria a ferramenta em produção. A lição: "o comando rodou
sem erro" não é o mesmo que "o comando funcionou". O teste de regressão
`test_auto_nao_consome_stream_infinita` existe para que ele não volte.

## Licença

MIT.
