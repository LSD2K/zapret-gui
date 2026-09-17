# MCP: эстафета между сессиями

> Одна страница, которую **каждая сессия перезаписывает в конце**. Следующая
> сессия читает её вместо того, чтобы реконструировать состояние по диффам.
> Держать в пределах ~120 строк: это не журнал, а снимок «где мы сейчас».
>
> Шаблон записи — в конце файла.

---

## Состояние: после S1 (транспорт и протокол)

**Дата:** 2026-09-17 · **Ветка/PR:** `claude/nice-dijkstra-idateo`

### Сделано

- `core/mcp/schema.py` (≈300) — мини-валидатор JSON Schema и
  `normalize_tool_schema()`. Поддержано: `type` (в т.ч. список),
  `required`, `enum`, `minimum/maximum`, `minLength/maxLength/pattern`,
  `minItems/maxItems`, `properties`, `items`, `default`,
  `additionalProperties: false`. Остального (`anyOf`, `$ref`, `format`)
  **нет намеренно**.
- `core/mcp/server.py` (≈560) — диспетчер JSON-RPC + временный реестр
  инструментов + два инструмента S1 (`system_status`, `nfqws_status`).
- `core/mcp/auth.py` (≈330) — bind → Origin → токен → рейт-лимит,
  `settings()`/`permissions()`, сворачивание отказов.
- `api/mcp.py` (≈260) — `POST /api/mcp`, `GET/DELETE` → 405, `GET
  /api/mcp/info`, класс `_Headers`.
- `core/config_manager.py` — секция `mcp` в `DEFAULT_CONFIG`.
- `api/__init__.py` — `reg_mcp(app)` последним, после `reg_dns_routing`.
- `app.py` — врезка в `_security_gate`: запрос на `/api/mcp*` с верным
  Bearer проходит мимо Basic-гейта GUI.
- `tests/_wsgi_client.py` — `make_environ`/`_call` принимают `headers` и
  `remote_addr`; добавлен `client.request()` → `(код, заголовки, тело)`.
- тесты: `test_mcp_schema.py` (20), `test_mcp_protocol.py` (36),
  `test_mcp_transport.py` (22), `test_mcp_auth.py` (36) — **114 зелёных**;
  весь `tests/` — 2943 passed, 1 skipped; `make lint` чист.

### Зафиксированные контракты

**Диспетчер.** `server.dispatch(payload, ctx=None) -> dict | list | None`.
`payload` — уже разобранный JSON (объект или батч); `None` в ответе значит
«только уведомления, отвечать нечем» → HTTP 202. Нечитаемое тело:
`server.parse_error(detail) -> dict` (код `-32700`, `id: null`).

`ctx` — словарь: `permissions` (dict), `session_id`, `subject`
(`"token"`/`"gui"`), `protocol_version`. **Если `ctx["permissions"]` нет —
берутся из конфига**; в тестах это удобно, в рантайме их всегда кладёт
`api/mcp.py`.

**Реестр (временный, S2 заменяет на `@tool`).**
`register_tool(name, handler, *, description, title="", schema=None,
scope=None, mutating=False)`; `get_tool`, `all_tools()`,
`available_tools(perms)`, `scope_allowed(spec, perms)`.
`ToolSpec.to_wire()` отдаёт `{name, title, description, inputSchema,
annotations, _meta["zapret-gui"]={scope, mutating}}`.
Инструмент **без `scope`** — чтение, доступен всегда. `handler(args: dict)
-> dict`; в ответ дописываются `ok` (если не задан) и `elapsed_ms`.

**Ответ `tools/call`** — `server.tool_result(payload: dict, is_error=False)`:
`{content:[{type:"text", text:<тот же JSON строкой>}], structuredContent,
isError}`. Это **единственная точка сериализации результата** — сюда S2
встраивает `core/mcp/redact.py`, и сюда же уже встроена обрезка по
`mcp.limits.response_kb`.

**Авторизация.** `auth.check(*, method, remote_addr, headers, auth_pair=None,
count_call=True) -> AuthDecision(ok, status, error, headers, subject,
reason)`. `headers` — любой объект с `.get(name, default)`.
Ещё наружу: `auth.settings()` (секция `mcp` поверх дефолтов — **всегда
полная**, можно читать без `default=`), `auth.permissions()`,
`auth.is_enabled()`, `auth.generate_token()`, `auth.token_is_valid(header)`,
`auth.is_local_address(addr)`, `auth.origin_allowed(origin, host)`,
`auth.reset_rate_limit()` (для тестов).

**Валидатор.** `schema.validate(value, schema, field="args")` → копия с
подставленными `default`; бросает `schema.SchemaError(message, field,
expected)` с `.to_error_data()` для `error.data`.

**Роут.** `api/mcp.py::register(app)`, подключён в `api/__init__.py`
последним. `api/v1_compat.py` автоматически делает алиас `/api/v1/mcp`
(только POST — он зеркалит первый метод пути).

**Тесты поднимают приложение** через `tests/_wsgi_client.py`:
`WSGIClient(build_test_app())` — только API; `app_module.create_app()` —
приложение целиком (нужно, если проверяется гейт из `app.py`).
Конфиг в тестах — глобальный синглтон: `get_config_manager().set(...)` в
`setUp` и откат в `tearDown`, плюс `auth.reset_rate_limit()`.

### Следующий шаг

**S2** — [`02-registry.md`](02-registry.md): настоящий реестр `@tool`,
разрешения, `core/mcp/redact.py`, скил `.claude/skills/mcp/SKILL.md`.
Подключаться так:

1. Декоратор `@tool` пишется поверх `register_tool()` — сигнатура уже
   совпадает с формой из контракта §3.
2. `system_status` и `nfqws_status` переезжают из «временных инструментов
   S1» (низ `core/mcp/server.py`, после разделителя) в
   `core/mcp/tools/status.py` **без изменения поведения** — на них
   завязаны `test_mcp_protocol.py` и `test_mcp_transport.py`. Убрать вызов
   `register_builtin_tools()` внизу `server.py`.
3. Редактирование секретов встраивается в `server.tool_result()` — одна
   точка, менять её вызывающих не надо.

### Что оказалось не так, как написано в задании

1. **`config_manager` не ставит `0600` явно** — права получаются сами:
   `safe_io.atomic_write_bytes()` пишет через `tempfile.mkstemp()` (тот
   создаёт файл с `0600`), а `os.replace()` переносит inode вместе с
   правами. Менять ничего не стали, но **зафиксировали тестом**
   (`test_mcp_auth.py::TestTokenStorage`): иначе замена `mkstemp` на
   `open()` когда-нибудь тихо откроет `settings.json` с токеном всем.
2. **Пришлось тронуть `app.py`** (в задании его нет). Глобальный
   `before_request`-гейт при `gui.auth_enabled=true` отдавал 401 любому
   MCP-клиенту ещё до `auth.check`: у того нет Basic-кред, только Bearer.
   Врезка пускает `/api/mcp*` с верным токеном дальше — и только их.
3. **`tests/_wsgi_client.py` не умел заголовки и `REMOTE_ADDR`** — без
   них не проверить ни `Authorization`, ни `Origin`, ни `bind=local`.
   Добавлено обратносовместимо (`headers=`, `remote_addr=`,
   `client.request()`); старые вызовы не тронуты.
4. **Найден и исправлен баг, к MCP отношения не имеющий:** `bottle`
   декодирует заголовок как latin-1 → utf-8 и бросает `UnicodeError` на
   мусорных байтах → 500. Для `/api/mcp` это 500 вместо 401 от одного
   неверного байта в токене. Лечится классом `_Headers` в `api/mcp.py`
   (S12/S13 стоит переиспользовать его, а не `request.headers`).
5. **`Content-Type` проверяется мягко:** пустой — пропускаем, заданный и
   не `application/json` — `415`. Спека требует `application/json`, но
   часть клиентов не шлёт заголовок вовсе.

### Грабли

- **`-32601` на `resources/*` и `prompts/*` — это не «пока не сделано», а
  сломанное подключение.** Клиенты опрашивают их сразу после
  `initialize`. Отвечаем пустыми списками; `resources/read` — `-32002`.
- **Рейт-лимит считается только после успешной авторизации.** Иначе
  перебор токена снаружи выбивает квоту у легального клиента — отказ в
  обслуживании без единого угаданного токена (тест есть).
- **Порядок проверок — часть безопасности, а не вкусовщина.** `bind` и
  `Origin` идут раньше токена: иначе чужой сайт узнаёт по коду ответа,
  верен ли токен.
- **Тело ответа — байты.** `json.dumps(..., ensure_ascii=False).encode()`:
  вернёшь `str` с кириллицей — `Content-Length` разъедется с
  содержимым, и клиент получит обрезанный JSON (тест есть).
- **Обрезка большого ответа не режет JSON посередине** — отдаётся
  валидный объект `{truncated: true, size_bytes, limit_bytes, hint}`.
  Обрубок клиент не разберёт и не поймёт, что произошло.
- **`bool` — подтип `int`.** В валидаторе `True` намеренно не проходит
  как `integer`/`number`, иначе `repeats: true` доедет до движка.
- **Реестр глобальный.** Тест, регистрирующий свой инструмент, обязан
  убрать его в `finally` (`server._REGISTRY.pop(name, None)`), иначе
  ломается тест счётчика инструментов в `/api/mcp/info`.

---

## Шаблон записи (перезаписывать, не дописывать)

```markdown
## Состояние: после SNN (<название сессии>)

**Дата:** YYYY-MM-DD · **Ветка/PR:** <ссылка>

### Сделано
- <файл> — <что в нём теперь есть> (<строк>)
- тесты: <какие файлы, что фиксируют>, прогон зелёный

### Зафиксированные контракты
- <имя> — <сигнатура/формат, который следующие сессии обязаны соблюдать>

### Следующий шаг
**SNN+1** — <файл задания>: <первое, за что браться>, <где подключиться к
написанному>.

### Что оказалось не так, как написано в задании
- <расхождение> → <принятое решение и где оно записано>

### Грабли
- <то, на что потрачено время и что не видно из кода>
```
