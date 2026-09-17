# MCP: эстафета между сессиями

> Одна страница, которую **каждая сессия перезаписывает в конце**. Следующая
> сессия читает её вместо того, чтобы реконструировать состояние по диффам.
> Держать в пределах ~120 строк: это не журнал, а снимок «где мы сейчас».
>
> Шаблон записи — в конце файла.

---

## Состояние: после S2 (реестр, разрешения, секреты)

**Дата:** 2026-09-17 · **Ветка/PR:** `claude/zen-fermat-zyyjgm`

### Сделано

- `core/mcp/registry.py` (≈420) — `@tool`, проверки объявления,
  автозагрузка `core/mcp/tools/*` через `pkgutil`, `call()`,
  `tool_result()` (маскировка + обрезка), `scope_counts()`.
- `core/mcp/permissions.py` (≈390) — 11 разрешений, зависимости,
  `allowed/denial/describe`, граница записи настроек
  (`is_writable`, `why_not_writable`, `writable_paths`,
  `non_writable_paths`, `ENUMS`).
- `core/mcp/redact.py` (≈190) — маска по ключам, URL подписок,
  `redact_text()` для сырого текста.
- `core/mcp/tools/{__init__,status,config,logs}.py` — четыре
  read-only инструмента-эталона.
- `core/mcp/server.py` — реестр вырезан, остались методы протокола и
  псевдонимы (`register_tool`, `all_tools`, `tool_result`, `_REGISTRY`…).
- `api/mcp.py` — `/api/mcp/info` отдаёт `permissions_effective`,
  `permissions_info`, `tools_by_scope`.
- `core/config_manager.py` — `ConfigManager.effective()`.
- `core/log_buffer.py` — `get_filtered(source=, since=)`, `get_sources()`.
- `.claude/skills/mcp/SKILL.md` + `python3 tools/gen_agent_index.py`.
- тесты: `test_mcp_permissions.py` (21), `test_mcp_redaction.py` (13),
  `test_mcp_tool_counts.py` (8, включая автозагрузку),
  `test_mcp_writable_paths.py` (8), `test_mcp_tools.py` (21),
  `test_mcp_schema.py` (+13) — **всего по `test_mcp_*` 198 зелёных**;
  весь `tests/` — 3028 passed, 1 skipped; `make lint` чист.

### Зафиксированные контракты

**Объявление инструмента.**

```python
from core.mcp.registry import tool

@tool(name="logs_tail", scope="read", mutating=False, title="…",
      description="EN / RU, ≤300", schema={"type": "object", …})
def logs_tail(args: dict) -> dict: ...
```

`scope` — `"read"` или ключ из `permissions.PERMISSIONS`; хранится как
`None` для чтения. `mutating=True` при `scope="read"` — `ToolError`.
Модуль кладётся в `core/mcp/tools/`, **нигде не перечисляется**.

**Вызов.** `registry.call(name, args, perms) -> dict` (готовый результат
`tools/call`). Бросает `registry.UnknownTool` и `schema.SchemaError` —
обе ловит `server._m_tools_call` и превращает в `-32602`. Всё остальное
(нет разрешения, падение обработчика) — `isError` внутри результата.

**Сериализация ровно одна** — `registry.tool_result(payload, is_error)`:
`redact.redact()` → `json.dumps` → обрезка по `mcp.limits.response_kb`.
`server.tool_result` — псевдоним, вызывающих менять не надо.

**Разрешения.** `permissions.allowed(scope, perms)`,
`permissions.denial(scope, perms)` (`{ok, error, permission, requires,
missing, hint}`), `effective()`, `describe()`, `normalize()`.
`REQUIRES = {"experiments": ("control", "probes"), "self_edit_core":
("self_edit",)}`.

**Запись настроек** (для S6): `permissions.is_writable(path)` — только
листья внутри `WRITABLE_SECTIONS`, минус `DENY_PATHS`,
`DENY_PATH_PREFIXES`, `DENY_KEY_RE` (расположения) и секретные ключи.
`writable_paths()` отдаёт `{path, type, value, default, enum?}` — это
готовый ответ `config_writable_paths`. Сейчас writable 43 пути, все
перечислены в `tests/test_mcp_writable_paths.py::WRITABLE`.

**Маскировка.** `redact.redact(payload)` — по ключам (`SECRET_KEY_RE`),
URL под `URL_KEY_RE` → `https://host/…`, строки под `TEXT_KEYS`
(`stdout`, `stderr`, `message`, `command`…) — ещё и `redact_text()`.
S12/S13: сырой текст класть под ключ из `TEXT_KEYS` либо звать
`redact.redact_text()` явно.

**Счётчик инструментов — контракт.** `tests/test_mcp_tool_counts.py`
держит таблицу `BY_SCOPE` (сейчас `read: 4`, остальные `0`). **Каждая
следующая сессия правит её, добавляя свои инструменты** — это не
формальность: цифра, изменившаяся не в той строке, означает инструмент,
опубликованный не под тем разрешением.

**Форма ответа инструмента** (эталон — `core/mcp/tools/*.py`): `ok`,
при ошибке `error` + `hint`, у списков `items`/`count`/`truncated`,
«нет данных» — честный ответ и что есть рядом (`available`, `sources`).

### Следующий шаг

**S3** — [`03-resources.md`](03-resources.md): ресурсы, `docs_get`,
`config_describe`, промты. Подключаться так:

1. `server._m_resources_list` / `_m_resources_read` / `_m_prompts_*` —
   сейчас честные пустые списки, наполнять их там же.
2. Новые инструменты (`docs_get`, `config_describe`) — файлом в
   `core/mcp/tools/`, по образцу `tools/config.py`.
3. `config_describe` берёт `permissions.writable_paths()` — ответ уже
   содержит тип, текущее значение и `ENUMS`.
4. После добавления инструментов — поправить `BY_SCOPE` в
   `tests/test_mcp_tool_counts.py` и таблицу в
   `.claude/skills/mcp/SKILL.md`.

S4/S5/S6/S12 не зависят от S3 и могут идти параллельно — реестр готов.

### Что оказалось не так, как написано в задании

1. **Секций `lists.*` и `install.*` в конфиге нет.** Задание называло их
   среди writable-поддеревьев; в `DEFAULT_CONFIG` таких секций не
   существует (списки живут файлами, пути к ним — в `zapret.*`, и они
   закрыты как расположения). Whitelist содержит девять реально
   существующих секций.
2. **`register_tool()` из S1 оставлен** (низкий уровень, мягкие
   умолчания) — на нём держатся тесты S1, регистрирующие временные
   инструменты. Строгая проверка `scope`/`mutating` — в декораторе
   `@tool`, все настоящие инструменты объявляются только им.
3. **Пришлось тронуть `core/config_manager.py` и `core/log_buffer.py`**
   (в задании их нет). `ConfigManager.effective()` — иначе `config_get`
   отдавал бы пустое дерево везде, где менеджер не загружен (CLI,
   тесты), и модель считала бы настройки отсутствующими.
   `get_filtered(source=, since=)` — иначе хвост журнала пришлось бы
   фильтровать на стороне модели, тратя её контекст. Обе правки
   обратносовместимы и доступны теперь UI/CLI.
4. **`test_mcp_writable_paths.py` написан здесь, а не отдан в S6** —
   модель путей готова, сторож получился бесплатно.
5. **Аудит вызовов не делался** — его место в S6 (JSONL + снимки для
   `mcp_undo_last`). Сейчас в реестре только строки в лог-буфере:
   `debug` на успешный вызов, `warning` на отклонённый.

### Грабли

- **Служебное поле со словом `key` маскируется.** `_keys` в ответе
  `config_get` уезжало моделью как `"***"`: `redact` не знает, что поле
  наше. Отсюда `_fields`. То же ждёт любое `*_key`, `*_token` в
  служебных структурах.
- **Метку времени нельзя округлять.** Модель возвращает `ts` в `since`,
  чтобы дочитать хвост: округление вниз (было `round(ts, 3)`) отдаёт
  последнюю запись второй раз, вверх — теряет соседнюю. Отдаём как есть.
- **Тест, считающий записи в общем лог-буфере, нестабилен.** В него
  пишут фоновые потоки других тестов и сама строка аудита вызова:
  фильтруйте по своему `source`, а не по `nfqws`/`mcp`.
- **Тест, регистрирующий инструмент, обязан убирать ТОЛЬКО своё.**
  Безусловный `_REGISTRY.pop(name)` в `finally` выносит настоящий
  инструмент, если тест проверял дубликат по его имени.
- **Автозагрузка и `importlib.invalidate_caches()`.** Модуль, положенный
  в `core/mcp/tools/` уже после старта процесса, без сброса кеша
  импортёра не виден — `load_tools(force=True)` это делает.
- **Ленивая загрузка ставит флаг только после успеха.** Иначе упавший
  импорт одного модуля инструментов оставил бы реестр наполовину
  собранным и «загруженным».
- **`scope_allowed` спрашивает `permissions.allowed()`**, а не
  `perms.get(scope)`: иначе `experiments` без `control`/`probes` был бы
  доступен, хотя его зависимости не выполнены.
- **Новый скил требует записи в `docs/upstream.json`.** Сторож
  `tests/test_upstream_manifest.py` падает на скиле без апстрима.
  Для `mcp` записан не чужой код, а **ревизия спеки** (`2025-06-18`,
  она же `server.PROTOCOL_VERSION`), и `mentions` требуют, чтобы её
  дословно упоминали скил и `core/mcp/server.py`.

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
