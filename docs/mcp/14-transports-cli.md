# S14 — Legacy-SSE, stdio-мост, CLI

> Вход: [`00-contract.md`](00-contract.md) + этот файл + `HANDOFF.md` + скил `mcp`.
> Сессия про **совместимость с живыми клиентами**. Streamable HTTP из S1
> понимают не все: часть сборок LM Studio умеет только legacy-SSE, часть
> клиентов — только stdio. Плюс `zapret-gui mcp …` для отладки по SSH.

## Что прочитать (≈22K)

- `api/logs.py` — **образец SSE в этом проекте** (keep-alive, закрытие по
  разрыву клиента): `grep -n "sse\|yield\|keep\|15"`.
- `core/cli.py` — целиком по структуре (`grep -n "COMMANDS\|def cmd_\|argparse"`)
  и один существующий подкоманд-обработчик как образец.
- `core/mcp/server.py` (S1) — диспетчер, который мост переиспользует.
- `core/mcp/registry.py` (S2) — для `zapret-gui mcp tools|call`.

## Что написать

```
core/mcp/session.py    — сессии и очереди сообщений (нужно только для legacy-SSE)
api/mcp.py             — дополнить: GET /api/mcp/sse, POST /api/mcp/messages
core/cli.py            — подкоманда mcp (+ в COMMANDS)
```

### 1. Legacy-SSE (флаг `mcp.transports.sse`, по умолчанию выключен)

- `GET /api/mcp/sse` отдаёт `event: endpoint` с
  `/api/mcp/messages?session=<id>`;
- `POST /api/mcp/messages` → `202 Accepted`, ответы уходят в SSE-поток;
- держать не более `mcp.limits.max_sessions` сессий, keep-alive пингом раз в
  15 с (как в `api/logs.py`);
- **сессии закрываются по разрыву клиента** — иначе на роутере со 128 МБ
  накопятся мёртвые очереди. Это пункт 1 приёмки фичи целиком (§17 плана).

Здесь же появляется настоящая рассылка `notifications/tools/list_changed`
при смене разрешений (для stateless HTTP она сводилась к корректному
`tools/list`).

### 2. stdio-мост

`zapret-gui mcp --stdio` — читает JSON-RPC построчно из stdin, пишет в
stdout. Два режима:

- **локальный** (по умолчанию): вызывает диспетчер `core/mcp/server.py`
  напрямую, без HTTP — это главный сценарий «клиент пришёл по SSH»;
- **прокси** (`--url`, `--token`): проксирует в HTTP-точку другого
  экземпляра.

Требования: одна строка — один JSON-RPC объект; ничего постороннего в
stdout (логи — только в stderr, иначе клиент захлебнётся); EOF на stdin —
корректное завершение.

### 3. CLI (`core/cli.py`)

```
zapret-gui mcp status                 # включён, адрес, разрешения, число инструментов
zapret-gui mcp token show|rotate
zapret-gui mcp tools [--json]         # список инструментов с описаниями
zapret-gui mcp call <tool> '<json>'   # локальный вызов (для отладки)
zapret-gui mcp stdio [--url … --token …]
zapret-gui mcp audit [--limit 50]     # журнал вызовов, включая shell-команды
zapret-gui mcp code list|diff|rollback [<snapshot_id>]
zapret-gui mcp code export-patch > /tmp/local.patch
```

`mcp code …` работает только если S13 сделана; иначе подкоманда честно
говорит, что самоправка недоступна в этой сборке, — не выдумывать заглушек.

**`token show` печатает токен в терминал** — это осознанно (иначе его не
скопировать по SSH), но в выводе должно быть предупреждение, а в историю
shell он попадёт: упомянуть это в README (S16).

## Тесты

| Файл | Что фиксирует |
|---|---|
| `tests/test_mcp_stdio.py` | мост читает/пишет JSON-RPC построчно; батч; мусор в stdin → `-32700` и мост не падает; EOF завершает; в stdout нет ничего, кроме JSON |
| `tests/test_mcp_transport.py` (дополнить) | SSE отдаёт `event: endpoint` и доставляет ответ; `POST /api/mcp/messages` → 202; лимит `max_sessions`; разрыв клиента чистит сессию |
| `tests/test_mcp_cli.py` | `status`/`tools`/`call` на подменённом реестре; `token rotate` меняет токен и пишет его в конфиг; `call` с неверным JSON даёт понятную ошибку |

## Приёмка

- LM Studio подключается — HTTP или SSE (проверить обе ветки на живом
  клиенте, это смысл сессии).
- `zapret-gui mcp stdio` работает по SSH: клиент на ноутбуке ходит в роутер
  через `ssh router zapret-gui mcp --stdio`.
- Включение/выключение SSE не требует перезапуска GUI.
- Во время открытой SSE-сессии GUI остаётся отзывчивым.

## Грабли

- **Bottle и стриминг.** Посмотри, как это уже сделано в `api/logs.py`, и не
  изобретай второй способ: с WSGI-сервером проекта работает не всякий.
- **Мёртвые SSE-сессии — утечка памяти на роутере.** Таймаут неактивности +
  чистка по разрыву обязательны.
- **stdout моста священен.** Любой `print()` для отладки ломает протокол;
  отлаживай через stderr.
- **`token rotate` рвёт подключённых клиентов** — так и должно быть, но
  вывод обязан об этом предупредить.

## Оставить следующим

`HANDOFF.md` + скил: какие транспорты включаются какими флагами, формат
команд CLI, что проверено на живых клиентах и что нет (S16 гоняет приёмку
целиком).
