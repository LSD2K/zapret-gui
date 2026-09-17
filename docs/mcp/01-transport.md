# S1 — Транспорт и протокол

> Вход: [`00-contract.md`](00-contract.md) + этот файл + `HANDOFF.md`.
> Цель сессии: `claude mcp add` подключается к роутеру, `tools/list` и
> `tools/call` работают, 401/403/405 корректны. Инструментов пока два —
> они нужны как «подопытные», настоящий реестр делает S2.

## Что прочитать (≈20K, не больше)

- `api/__init__.py` целиком — как регистрируются роуты (`register_routes`).
- Один существующий модуль API как образец стиля: `api/status.py`
  (маленький) — целиком.
- `core/config_manager.py` — **точечно**: `grep -n "DEFAULT_CONFIG\|def get\|def set\|0o600\|_merge" core/config_manager.py`, затем нужные диапазоны.
- `tests/_wsgi_client.py` целиком — как тесты ходят в приложение без сети.
- Один тест API как образец: `tests/test_api_status.py` (или ближайший
  существующий `tests/test_api_*.py`).
- `core/version.py` — `GUI_VERSION`.
- `grep -n "cors_origins\|check_auth\|Authorization\|Basic" app.py api/__init__.py` —
  как устроена текущая авторизация GUI и CORS.

## Что написать

```
core/mcp/__init__.py
core/mcp/server.py     — диспетчер JSON-RPC
core/mcp/auth.py       — токен, Origin-check, bind, рейт-лимит, ротация
core/mcp/schema.py     — сборка JSON Schema + мини-валидатор аргументов
api/mcp.py             — Bottle-роуты
```

Изменить: `api/__init__.py` (зарегистрировать `api.mcp`),
`core/config_manager.py` (секция `mcp` в `DEFAULT_CONFIG`).

### 1. Протокол (`core/mcp/server.py`)

`PROTOCOL_VERSION = "2025-06-18"`. В `initialize` отвечаем версией клиента,
если поддерживаем её, иначе своей.

| Метод | Замечания |
|---|---|
| `initialize` | `capabilities`: `tools.listChanged=true`, `resources.listChanged=true`, `prompts.listChanged=false`, `logging`; `serverInfo = {name: "zapret-gui", version: GUI_VERSION}`. Дополнительно сообщаем модели её разрешения — чтобы она говорила «вот что я бы изменил», а не пробовала вслепую |
| `notifications/initialized` | ответа не требует |
| `ping` | пустой результат |
| `tools/list` | список зависит от разрешений; поддержать `cursor` |
| `tools/call` | результат — `{content, structuredContent, isError}` (см. контракт §3) |
| `resources/list`, `resources/read`, `resources/templates/list` | в S1 — пустые списки, но методы отвечают (не `-32601`) |
| `prompts/list`, `prompts/get` | то же |
| `notifications/tools/list_changed` | для stateless HTTP — просто корректный `tools/list`; рассылка появится с SSE (S14) |
| `logging/setLevel` | опционально |

Коды ошибок: `-32700` parse, `-32600` invalid request, `-32601` method not
found, `-32602` invalid params, `-32603` internal. **Ошибка инструмента —
не ошибка JSON-RPC** (контракт §3). Поддержать батч (массив запросов);
уведомление (без `id`) ответа не порождает.

### 2. HTTP-слой (`api/mcp.py`)

- Точка доступа обслуживается **тем же веб-сервером**, что и GUI: адрес,
  порт, TLS и bind — это `gui.host`/`gui.port`. При `gui.host=127.0.0.1`
  MCP доступен только с роутера — нормальный и самый безопасный режим.
- `POST /api/mcp` — тело один объект или батч, `Content-Type: application/json`,
  ответ `application/json`.
- Заголовок `MCP-Protocol-Version` на не-`initialize` запросах: неизвестная
  версия → `400` с пояснением.
- `GET /api/mcp` → `405` + `Allow: POST` и **понятный текст**, что это не
  ошибка, а свойство транспорта без SSE.
- `DELETE /api/mcp` → `405` тем же образом.
- `GET /api/mcp/info` → метаданные для UI (включён ли, разрешения, версия,
  сколько инструментов) — **без токена, но только с локального адреса**.
- Выдавать `Mcp-Session-Id` и принимать обратно, но состояние сервера от
  него **не зависит** (stateless — проще и надёжнее на роутере).

### 3. Авторизация (`core/mcp/auth.py`)

1. Bearer-токен: `secrets.token_hex(32)` (64 символа), хранится в
   `settings.json → mcp.token`, сравнение через `hmac.compare_digest`.
   **Пустой токен ⇒ MCP выключен** (401 всем). Проверить, что
   `config_manager` кладёт файл с правами `0600`.
2. Токен действует **только** на `/api/mcp*`: на любом другом маршруте API
   он отклоняется.
3. `mcp.allow_gui_auth` — разрешить вместо токена обычную Basic-авторизацию
   GUI (тогда MCP-доступ равен доступу к GUI; предупреждение — забота S15).
4. `Origin`: если заголовок есть — он должен быть в `gui.cors_origins` либо
   localhost-подобным, иначе `403`. Это защита от DNS-rebinding, требование
   спеки для локальных серверов.
5. `mcp.bind`: `inherit` (по умолчанию) или `local` — при `local` отдавать
   `403` всем, кроме `127.0.0.1`/`::1`.
6. Рейт-лимит `mcp.limits.calls_per_minute` на токен → `429`.
7. **Отказы логируются со сворачиванием**: одна строка раз в 30 секунд со
   счётчиком, иначе перебор токена забьёт лог. **Токен не пишется в лог
   никогда** — ни предъявленный, ни настроенный.

### 4. Мини-валидатор (`core/mcp/schema.py`)

~150 строк stdlib: `type` (object/array/string/integer/number/boolean),
`required`, `enum`, `minimum`/`maximum`, `minItems`/`maxItems`, `properties`,
`items`. Неверный аргумент → `-32602` с указанием поля и ожидаемого типа
(текстом, который модель сможет исправить). Никакого `jsonschema`.

### 5. Секция `mcp` в `DEFAULT_CONFIG`

Взять словарь из §6 плана (`grep -n '"mcp": {' -A 60 docs/mcp-server-plan.md`)
**с одной поправкой, зафиксированной в `HANDOFF.md`:** в `permissions` завести
сразу **все 11** ключей со значением `False` — `control`, `strategies_write`,
`config_write`, `probes`, `experiments`, `tunnels_write`, `dangerous`,
`shell_readonly`, `shell_full`, `self_edit`, `self_edit_core`. В §6 плана
последних четырёх нет, но они есть в §5; если завести их позже, разойдутся
`tools/list`, счётчики инструментов и сторож writable-путей.

Ключ `mcp.allow_gui_auth` (bool, `False`) в §6 плана тоже не выписан —
завести здесь же.

### 6. Два инструмента-заглушки

`ping_tool` не нужен. Нужны два настоящих, но простых, чтобы было на чём
проверить `tools/call` и форму ответа: `system_status` (сводка из
`core/system_info.py` + что запущено) и `nfqws_status` (pid/uptime/argv из
`nfqws_manager.get_status()`). Оба — read-only, без `scope`-проверки (её
вводит S2). **Регистрировать их временно, прямо в `server.py`** — в S2 они
переедут в `core/mcp/tools/status.py` под декоратор `@tool`.

## Тесты (в этой же сессии)

| Файл | Что фиксирует |
|---|---|
| `tests/test_mcp_protocol.py` | `initialize` → capabilities/serverInfo; `tools/list`; `tools/call`; батч; коды `-32700/-32600/-32601/-32602`; ошибка инструмента приходит как `isError`, а не как JSON-RPC ошибка |
| `tests/test_mcp_transport.py` | `GET /api/mcp` → 405 + `Allow: POST`; неподдерживаемый `MCP-Protocol-Version` → 400; `GET /api/mcp/info` доступен локально без токена и недоступен снаружи |
| `tests/test_mcp_auth.py` | нет токена → 401; неверный токен → 401; чужой `Origin` → 403; `bind=local` + внешний IP → 403; рейт-лимит → 429; токен не открывает другие роуты API |
| `tests/test_mcp_schema.py` | мини-валидатор: типы, `required`, `enum`, диапазоны; неверный аргумент даёт `-32602` с именем поля |

Прогон: `python3 -m pytest tests/test_mcp_*.py -q`, затем весь `tests/` и
`make lint`.

## Приёмка

- `claude mcp add --transport http zapret-gui http://<ip>:8080/api/mcp --header "Authorization: Bearer <token>"`
  подключается, клиент видит два инструмента и вызывает их.
- MCP выключен по умолчанию, токен пуст, все 11 разрешений `false`.
- Существующие роуты и тесты не затронуты (`python3 -m pytest tests/ -q`).

## Грабли

- **Не заводить своё хранилище настроек.** Секция `mcp` живёт в общем
  `settings.json` через `config_manager`, включая права `0600`.
- **Не делать сервер stateful.** `Mcp-Session-Id` выдаём и принимаем, но
  никакой логики на нём не строим: роутер перезагружается чаще, чем
  хочется.
- **Не отвечать `-32601` на `resources/*` и `prompts/*`** — клиенты
  опрашивают их при подключении и ругаются в лог; пустой список честнее.
- Bottle отдаёт тело как байты — следить за `Content-Length` и UTF-8 в
  русских текстах ошибок.

## Оставить следующим

`HANDOFF.md`: точные сигнатуры `server.dispatch()`, `auth.check()`, формат
ответа `tools/call`, где именно в `api/__init__.py` подключён роут, как
тесты поднимают приложение. Скила `mcp` ещё нет — его заводит S2.
