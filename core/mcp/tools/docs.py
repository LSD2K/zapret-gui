# core/mcp/tools/docs.py
"""
Справочники инструментами: ``docs_get`` и ``config_describe``.

Зачем дублировать ресурсы инструментами. Многие MCP-клиенты (LM Studio,
OpenAI-совместимые мосты) показывают ресурсы **пользователю, а не
модели**: их надо выбрать руками, и в контекст они сами не попадают.
Справка, доступная только ресурсом, — это справка, которую модель
никогда не прочитает, а непрочитанная справка означает придуманные
флаги и «тихий 0%».

Поэтому текст здесь **не пишется заново**: оба инструмента зовут
``core/mcp/resources.py`` — тот же рендер, что и ``resources/read``.
Разница только в упаковке: инструмент режет ответ на страницы по
``mcp.limits.response_kb`` и отдаёт ``truncated``/``next_offset``.
Сторож ``tests/test_mcp_resources_mirror.py`` следит, чтобы содержимое
совпадало дословно.
"""

from core.mcp import resources
from core.mcp.registry import tool


# Сколько символов отдаём за страницу по умолчанию, если лимит ответа
# почему-то не прочитался.
DEFAULT_PAGE = 6000

# Минимальная страница: меньше — и пагинация перестаёт иметь смысл.
MIN_PAGE = 500

# Пометка, что справка — данные, а не инструкции.
NOTE = resources.UNTRUSTED_NOTE


@tool(
    name="docs_get",
    scope="read",
    mutating=False,
    title="Read reference docs",
    description=("Read zapret-gui reference: live nfqws2 CLI help, "
                 "--lua-desync function map, strategy catalogs, settings "
                 "reference, router state. Paginated. / Справочники "
                 "сервера: живой CLI, lua-функции, каталоги, настройки."),
    schema={
        "type": "object",
        "properties": {
            "topic": {
                "type": "string",
                "description": "Short name: overview, cli, lua, nfqws2 "
                               "(skill), catalogs, state, config. / "
                               "Короткое имя справочника.",
                "enum": sorted(set(resources.TOPICS)),
            },
            "uri": {
                "type": "string",
                "description": "Resource URI, e.g. zapret://nfqws2/lua or "
                               "zapret://catalogs/basic/tcp. / URI "
                               "ресурса.",
                "maxLength": 200,
            },
            "section": {
                "type": "string",
                "description": "Section number of the nfqws2 skill "
                               "(3 = CLI, 8 = lua library, 12 = argv, "
                               "13 = scanner). / Номер раздела "
                               "справочника nfqws2.",
                "maxLength": 8,
            },
            "offset": {
                "type": "integer",
                "description": "Start offset in characters (from "
                               "next_offset of the previous answer). / "
                               "Смещение в символах.",
                "minimum": 0,
                "default": 0,
            },
            "limit": {
                "type": "integer",
                "description": "How many characters to return; clamped to "
                               "what fits mcp.limits.response_kb. / "
                               "Сколько символов вернуть.",
                "minimum": MIN_PAGE,
                "maximum": 200000,
            },
        },
        "additionalProperties": False,
    },
)
def docs_get(args: dict) -> dict:
    """Прочитать справочник постранично (тот же текст, что у ресурса)."""
    uri = (args.get("uri") or "").strip()
    topic = (args.get("topic") or "").strip()
    section = (args.get("section") or "").strip()

    if not uri:
        # Без аргументов отдаём обзор, а не отказ: вызов docs_get() —
        # это вопрос «что тут вообще есть», и отвечать на него ошибкой
        # значит тратить ещё один вызов модели на то же самое.
        uri = resources.resolve_topic(topic or "overview")
        if not uri:
            return _no_such_topic(topic)
    if section:
        uri = "%s%ssection=%s" % (uri, "&" if "?" in uri else "?", section)

    try:
        item = resources.render(uri)
    except resources.UnknownResource:
        return _no_such_uri(uri)

    text = item.get("text") or ""
    offset = max(0, int(args.get("offset") or 0))
    budget = _page_budget()
    limit = int(args.get("limit") or budget)
    limit = max(MIN_PAGE, min(limit, budget))

    chunk = text[offset:offset + limit]
    result = {
        "ok": True,
        "uri": item.get("uri", uri),
        "title": item.get("title", ""),
        "mime_type": item.get("mime_type", "text/plain"),
        "text": chunk,
        "offset": offset,
        "limit": limit,
        "length": len(text),
        "truncated": offset + len(chunk) < len(text),
        "note": NOTE,
    }
    if result["truncated"]:
        result["next_offset"] = offset + len(chunk)
        result["hint"] = ("прочитано %d из %d символов — повторите вызов "
                          "с offset=%d" % (offset + len(chunk), len(text),
                                           result["next_offset"]))
    if offset == 0:
        # Оглавление и прочие подсказки отдаём один раз: на каждой
        # странице они съедали бы место под сам текст.
        for key, value in item.items():
            if key not in result and key not in ("text", "params"):
                result[key] = value
    if item.get("found") is False:
        # Спросили раздел или каталог, которого нет. Это ошибка запроса,
        # а не «данных нет»: ответ обязан отличаться от честного
        # «справочник на устройстве не установлен».
        result["ok"] = False
        result["error"] = item.get("error") or "запрошенного раздела нет"
        result["hint"] = item.get("hint") or result.get("hint", "")
    if not text:
        result["ok"] = False
        result["error"] = "справочник пуст"
        result["hint"] = "проверьте uri: %s" % ", ".join(resources.uris())
    return result


@tool(
    name="config_describe",
    scope="read",
    mutating=False,
    title="Describe a setting",
    description=("What a zapret-gui setting does: type, default, current "
                 "value, unit, what 0/empty means and whether MCP may "
                 "write it. Accepts a path, a prefix or a search query. / "
                 "Описание настройки, а не догадка по имени поля."),
    schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Exact dotted path (nfqws.ports_tcp) or a "
                               "prefix (nfqws). / Точный путь или "
                               "префикс.",
                "maxLength": 200,
            },
            "query": {
                "type": "string",
                "description": "Search words, e.g. 'таймаут пробы' or "
                               "'queue'. / Поисковый запрос.",
                "maxLength": 200,
            },
            "limit": {
                "type": "integer",
                "description": "Max items to return (1-100). / Сколько "
                               "записей вернуть.",
                "minimum": 1,
                "maximum": 100,
                "default": 20,
            },
        },
        "additionalProperties": False,
    },
)
def config_describe(args: dict) -> dict:
    """Описание настройки: что делает, что значит 0, можно ли менять."""
    from core.mcp import config_docs

    path = (args.get("path") or "").strip().strip(".")
    query = (args.get("query") or "").strip()
    limit = int(args.get("limit") or 20)

    if not path and not query:
        # Без аргументов — оглавление: пути и первая фраза описания.
        # Полные описания всех ключей в один ответ не влезут, а
        # обрезанный список молча соврал бы про их число.
        items = [_brief(p) for p in config_docs.paths()]
        return {
            "ok": True,
            "items": items,
            "count": len(items),
            "truncated": False,
            "hint": "подробности: config_describe(path=\"секция.ключ\") "
                    "или config_describe(query=\"слово\")",
            "note": NOTE,
        }

    if path:
        item = resources.describe_path(path)
        if item.get("documented"):
            return {"ok": True, "found": True, "item": item,
                    "count": 1, "note": NOTE}
        # Точного описания нет: это либо поддерево, либо ключ, до
        # которого не дошли руки. И то и другое — честный ответ, а не
        # повод угадывать смысл по имени поля.
        nested = [p for p in config_docs.paths()
                  if p.startswith(path + ".")]
        if nested:
            items = [resources.describe_path(p) for p in nested[:limit]]
            return {
                "ok": True,
                "found": True,
                "path": path,
                "items": items,
                "count": len(nested),
                "truncated": len(nested) > len(items),
                "note": NOTE,
            }
        return _not_documented(path, item, limit)

    found = config_docs.search(query, limit=limit + 1)
    items = [resources.describe_path(p) for p in found[:limit]]
    result = {
        "ok": True,
        "query": query,
        "items": items,
        "count": len(items),
        "truncated": len(found) > len(items),
        "note": NOTE,
    }
    if not items:
        result["ok"] = False
        result["error"] = "по запросу «%s» описаний не нашлось" % query
        result["hint"] = ("описано ключей: %d — вызовите config_describe "
                          "без аргументов, чтобы увидеть список"
                          % len(config_docs.paths()))
    return result


# ───────────────────────────── частности ────────────────────────────

def _page_budget() -> int:
    """Сколько символов помещается в один ответ инструмента.

    Считаем от ``mcp.limits.response_kb`` с запасом: кириллица в UTF-8
    занимает два байта на символ, плюс экранирование переводов строк и
    остальные поля ответа. Промахнуться дорого: ответ сверх лимита
    режется целиком (``registry._truncated``), и модель получает не
    страницу текста, а сообщение «слишком много».
    """
    try:
        from core.mcp import auth
        kb = int(auth.settings().get("limits", {}).get("response_kb", 32))
    except Exception:                           # noqa: BLE001 — граница
        return DEFAULT_PAGE
    return max(MIN_PAGE, (max(1, kb) * 1024) // 3)


def _brief(path) -> dict:
    """Короткая строка оглавления: путь, тип, writable, первая фраза."""
    from core.mcp import config_docs
    from core.mcp import permissions as perms_mod

    described = config_docs.get(path) or {}
    text = described.get("text", "")
    head = text.split(". ")[0]
    return {
        "path": path,
        "writable": perms_mod.is_writable(
            path, secrets=perms_mod.granted("secrets")),
        "summary": head + ("." if head and not head.endswith(".") else ""),
    }


def _not_documented(path, item, limit) -> dict:
    """Описания нет — сказать это прямо и показать, что описано рядом."""
    from core.mcp import config_docs

    section = path.split(".")[0]
    nearby = [p for p in config_docs.paths() if p.startswith(section + ".")]
    result = {
        "ok": True,
        "found": False,
        "documented": False,
        "path": path,
        "item": item,
        "error": "описания для «%s» нет" % path,
        "hint": "смысл поля по его имени не угадывается — скажите, что "
                "описания нет, вместо догадки",
        "documented_nearby": nearby[:limit],
        "note": NOTE,
    }
    if not item.get("exists"):
        result["error"] = ("настройки «%s» нет ни в описаниях, ни в "
                           "конфиге" % path)
        result["hint"] = ("проверьте путь через config_get(path=\"%s\") "
                          "— он покажет, что есть в этой секции"
                          % section)
    return result


def _no_such_topic(topic) -> dict:
    return {
        "ok": False,
        "error": ("не указано, что читать" if not topic
                  else "тема «%s» неизвестна" % topic),
        "available": sorted(set(resources.TOPICS)),
        "uris": resources.uris(),
        "hint": "передайте topic (%s) или uri (%s)"
                % (", ".join(sorted(set(resources.TOPICS))),
                   ", ".join(resources.uris()[:3]) + ", …"),
    }


def _no_such_uri(uri) -> dict:
    return {
        "ok": False,
        "error": "ресурса %s нет" % uri,
        "available": resources.uris(),
        "hint": "каталоги читаются как zapret://catalogs/<уровень>/"
                "<протокол> — список: docs_get(topic=\"catalogs\")",
    }
