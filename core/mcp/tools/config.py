# core/mcp/tools/config.py
"""
Чтение настроек GUI (``settings.json``).

Отдаём **редактированное** дерево: секреты режет единая
``core/mcp/redact.py`` на сериализации результата, здесь о них думать
не надо. Что можно менять — видно сразу, в поле ``writable``: модель
не должна узнавать о запрете, уже предложив изменение (записывать
умеет S6, модель путей — ``core/mcp/permissions.py``).
"""

from core.mcp import permissions as perms_mod
from core.mcp.registry import tool


# Глубже этого дерево не разворачиваем даже по запросу: ответ читает
# модель с ограниченным контекстом.
MAX_DEPTH = 6

# Чем заменяется поддерево, до которого не хватило глубины.
#
# Имя поля намеренно НЕ содержит «key»: под этот корень подпадает
# маскировка секретов (``redact.SECRET_KEY_RE``), и служебное поле
# ``_keys`` уехало бы модели как ``"***"``.
CUT_FIELD = "_fields"


@tool(
    name="config_get",
    scope="read",
    mutating=False,
    title="Read settings",
    description=("Read zapret-gui settings (secrets redacted): whole tree "
                 "or one dotted path, with a writable flag telling what "
                 "config_set may change. / Прочитать настройки GUI по "
                 "точечному пути."),
    schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Dotted path, e.g. nfqws.ports_tcp. Empty "
                               "= whole tree. / Точечный путь; пусто — всё "
                               "дерево.",
                "maxLength": 200,
                "default": "",
            },
            "depth": {
                "type": "integer",
                "description": "How many nesting levels to expand (1-6). "
                               "/ Сколько уровней вложенности раскрыть.",
                "minimum": 1,
                "maximum": MAX_DEPTH,
                "default": 2,
            },
        },
        "additionalProperties": False,
    },
)
def config_get(args: dict) -> dict:
    """Прочитать настройки целиком или по точечному пути.

    Берём `effective()`, а не `get_all()`: ключ, которого ещё нет в
    `settings.json`, всё равно действует — из дефолтов, — и модель
    должна видеть то же, что действует.
    """
    from core.config_manager import get_config_manager

    path = (args.get("path") or "").strip().strip(".")
    depth = int(args.get("depth") or 2)
    parts = perms_mod.split_path(path)

    node = get_config_manager().effective()
    walked = []
    for key in parts:
        if not isinstance(node, dict) or key not in node:
            return _not_found(path, walked, node)
        node = node[key]
        walked.append(key)

    cut = []
    value = _limit_depth(node, depth, path, cut)
    writable = perms_mod.is_writable(path) if parts else False
    result = {
        "ok": True,
        "path": path,
        "type": _json_type(node),
        "value": value,
        "writable": writable,
        "truncated": bool(cut),
    }
    if not writable:
        result["writable_reason"] = (
            perms_mod.why_not_writable(path) if parts else
            "корень дерева: запись идёт по путям вида «секция.ключ»")
    if cut:
        result["hint"] = ("свёрнуто поддеревьев: %d — запросите их "
                          "отдельно (path=%s) или увеличьте depth"
                          % (len(cut), cut[0]))
    return result


# ───────────────────────────── частности ────────────────────────────

def _not_found(path, walked, node) -> dict:
    """Путь не найден — показать, что есть рядом, а не просто отказать."""
    available = sorted(node.keys()) if isinstance(node, dict) else []
    where = ".".join(walked) or "корень"
    return {
        "ok": False,
        "error": "путь «%s» в настройках не найден" % path,
        "path": path,
        "available": available[:60],
        "hint": "в «%s» есть: %s" % (where, ", ".join(available[:20])
                                     or "ничего"),
    }


def _limit_depth(node, depth, prefix, cut):
    """Свернуть слишком глубокие поддеревья в список их ключей.

    Обрезаем **по структуре, а не по длине текста**: список ключей
    говорит модели, что там лежит и каким путём это дочитать, а
    обрубленная строка — не говорит ничего.
    """
    if not isinstance(node, dict):
        return node
    if depth <= 0:
        cut.append(prefix or "<корень>")
        return {CUT_FIELD: sorted(node.keys()), "_truncated": True}
    out = {}
    for key, value in node.items():
        child = "%s.%s" % (prefix, key) if prefix else key
        out[key] = _limit_depth(value, depth - 1, child, cut)
    return out


def _json_type(value) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "null"
