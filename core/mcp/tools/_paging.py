# core/mcp/tools/_paging.py
"""
Одна форма списка на все инструменты MCP.

Модуль с подчёркиванием — реестр такие пропускает (``load_tools``), это
не инструмент, а общий кусок упаковки.

Зачем он есть. Модель читает ответы десятками, и каждый разнобой в
именах полей она тратит на догадки: там был ``count`` или ``total``,
здесь ``next_offset`` или ``offset+limit``, а тут список просто обрезан
и об этом никто не сказал. Поэтому окно и его описание собираются
**одной функцией**, а не повторяются в девяти инструментах, где одно
из девяти рано или поздно разойдётся с остальными.

Контракт списка (соблюдают все инструменты S4 и дальше):

``items``
    Окно записей — уже отфильтрованное и отсортированное.
``total``
    Сколько записей подошло под фильтр **всего**, а не сколько отдано.
``count``
    Сколько в ``items``.
``offset`` / ``limit``
    Окно, которое отдано.
``truncated``
    Есть ли что-то за окном. При ``True`` добавляется ``next_offset``.

Само окно берётся ``slice`` по уже готовому списку: менеджеры отдают
списки целиком, и «ленивая» пагинация здесь была бы враньём — данные
всё равно прочитаны. Исключение — каталоги (``CatalogManager
.find_entries``) и хостлисты: там окно режется в менеджере, и сюда
приезжают уже ``(окно, total)``.

**Окно ужимается под лимит ответа.** ``limit=100`` записей каталога — это
40 КБ, то есть больше ``mcp.limits.response_kb``, а ответ сверх лимита
реестр заменяет ЦЕЛИКОМ на «слишком много» (``registry._truncated``):
модель получает не страницу данных, а сообщение об ошибке и тратит ещё
один вызов. Поэтому :func:`page` меряет собранный ответ и выкидывает
лишние записи с конца, пока он не поместится, — честно отмечая это
``truncated`` и ``shrunk_to_fit``.
"""

import json


# Потолок окна по умолчанию. Больше сотни записей в одном ответе модель
# всё равно не прочитает, а лимит ответа (`mcp.limits.response_kb`)
# срежет их целиком — вместе с полями, объясняющими, что произошло.
MAX_LIMIT = 100
DEFAULT_LIMIT = 25

# Какую долю лимита ответа занимает окно. Остаток — на поля вокруг
# него (подсказки, фильтры, сводки) и на запас: редактирование секретов
# и сериализация считаются реестром уже после нас.
BUDGET_SHARE = 0.85

# Если лимит почему-то не прочитался.
DEFAULT_BUDGET = 24 * 1024


def limits(args, default=DEFAULT_LIMIT, maximum=MAX_LIMIT):
    """``(offset, limit)`` из аргументов инструмента, с потолком."""
    offset = max(0, int(args.get("offset") or 0))
    limit = int(args.get("limit") or default)
    return offset, max(1, min(limit, maximum))


def page(items, offset, limit, total=None, **extra) -> dict:
    """Окно списка в общей форме (см. контракт в docstring модуля).

    Args:
        items: либо весь список (тогда окно режется здесь), либо уже
               готовое окно — тогда ``total`` обязателен.
        total: сколько записей подошло под фильтр всего.
    """
    if total is None:
        total = len(items)
        window = list(items[offset:offset + limit])
    else:
        window = list(items)

    result = _assemble(window, offset, limit, int(total), extra)
    return _fit(result, offset, limit, int(total), extra)


def _assemble(window, offset, limit, total, extra) -> dict:
    """Собрать ответ-страницу из готового окна."""
    result = {
        "ok": True,
        "items": window,
        "total": total,
        "count": len(window),
        "offset": offset,
        "limit": limit,
        "truncated": offset + len(window) < total,
    }
    if result["truncated"]:
        result["next_offset"] = offset + len(window)
        result["hint"] = ("показано %d из %d — повторите вызов с offset=%d"
                          % (offset + len(window), total,
                             result["next_offset"]))
    result.update(extra)
    return result


def _fit(result, offset, limit, total, extra) -> dict:
    """Ужать окно до лимита ответа, если собранное в него не влезло.

    Ищем максимальное число записей делением пополам, а не отбрасыванием
    по одной: сериализация сотни записей каталога не бесплатна, а
    вызовов получилось бы столько же, сколько лишних записей.
    """
    budget = response_budget()
    if _size(result) <= budget:
        return result

    items = result["items"]
    low, high = 0, len(items)
    best = _assemble([], offset, limit, total, extra)
    while low <= high:
        middle = (low + high) // 2
        candidate = _assemble(items[:middle], offset, limit, total, extra)
        if _size(candidate) <= budget:
            best = candidate
            low = middle + 1
        else:
            high = middle - 1

    kept = best["count"]
    best["shrunk_to_fit"] = True
    best["requested_limit"] = limit
    if kept:
        best["hint"] = ("в ответ поместилось %d записей из %d запрошенных "
                        "(лимит mcp.limits.response_kb) — продолжите с "
                        "offset=%d" % (kept, len(items), offset + kept))
    else:
        # Даже одна запись не влезла: это не «сузьте окно», это «сузьте
        # запрос», и врать про next_offset здесь нельзя.
        best["hint"] = ("даже одна запись не помещается в "
                        "mcp.limits.response_kb — увеличьте лимит "
                        "ответа или сузьте запрос фильтрами")
    return best


def response_budget() -> int:
    """Сколько байт можно занять окном (доля ``mcp.limits.response_kb``)."""
    try:
        from core.mcp import auth
        kb = int(auth.settings().get("limits", {}).get("response_kb", 32))
    except Exception:                           # noqa: BLE001 — граница
        return DEFAULT_BUDGET
    return max(2048, int(max(1, kb) * 1024 * BUDGET_SHARE))


def _size(payload) -> int:
    return len(json.dumps(payload, ensure_ascii=False,
                          default=str).encode("utf-8"))


def empty(reason, hint="", **extra) -> dict:
    """Пустой список с объяснением, а не молчаливый ``items: []``.

    «Ничего не нашлось» и «искать было негде» — разные ответы, и модель
    обязана их различать: на первый она меняет фильтр, на второй —
    чинит устройство.
    """
    result = page([], 0, DEFAULT_LIMIT, total=0)
    result["reason"] = reason
    if hint:
        result["hint"] = hint
    result.update(extra)
    return result


def unavailable(what, reason, hint="") -> dict:
    """Честное «на этом устройстве этого нет».

    ``ok`` остаётся ``True``: отсутствие бинарника или каталога — это
    ответ на вопрос, а не ошибка вызова. ``isError`` здесь заставил бы
    модель переспрашивать то же самое другими словами.
    """
    result = empty(reason, hint)
    result["available"] = False
    result["what"] = what
    return result
