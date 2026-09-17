# core/mcp/schema.py
"""
Мини-валидатор JSON Schema для аргументов MCP-инструментов.

Зачем свой. Схемы инструментов уезжают модели в ``tools/list``, и она
присылает аргументы обратно — их нельзя брать на веру. Готовые
валидаторы (``jsonschema``, ``pydantic``) на роутер не ставятся:
там ``python3-light`` и только stdlib. Поэтому здесь поддержано ровно
то подмножество Draft-07, которым описываются наши инструменты:

  ``type``       — object | array | string | integer | number | boolean |
                   null (или список вариантов);
  ``required``   — обязательные ключи объекта;
  ``properties`` — схемы полей, ``items`` — схема элементов массива;
  ``enum``       — допустимые значения;
  ``minimum`` / ``maximum``         — диапазон чисел;
  ``minLength`` / ``maxLength`` / ``pattern`` — строки;
  ``minItems`` / ``maxItems``       — длина массива;
  ``default``    — подставляется, если ключа нет;
  ``additionalProperties: false``   — запрет лишних ключей.

Всё остальное (``anyOf``, ``$ref``, ``format``, ``patternProperties``)
намеренно НЕ поддержано: в схеме инструмента такому не место, а тихо
проигнорированное правило хуже отсутствующего. Неизвестные ключи схемы
игнорируются — они безвредны и уезжают модели как подсказка.

Текст ошибки читает модель, а не человек: он всегда называет **поле** и
**что от него ждут**, чтобы следующий вызов был исправлен без догадок.
"""

import re


# Типы, которые понимает валидатор. Всё, чего здесь нет, — ошибка схемы,
# а не аргумента: ловится тестом реестра, а не в рантайме у клиента.
KNOWN_TYPES = frozenset((
    "object", "array", "string", "integer", "number", "boolean", "null",
))


class SchemaError(ValueError):
    """Аргументы не соответствуют схеме инструмента.

    ``field``    — путь до поля (``args.variants[0].name``),
    ``expected`` — короткое описание ожидания («integer», «one of: a, b»).
    Оба уезжают в ``data`` JSON-RPC-ошибки ``-32602``.
    """

    def __init__(self, message: str, field: str = "", expected: str = ""):
        super().__init__(message)
        self.message = message
        self.field = field
        self.expected = expected

    def to_error_data(self) -> dict:
        """Машиночитаемая часть ошибки для ``error.data``."""
        data = {"field": self.field}
        if self.expected:
            data["expected"] = self.expected
        return data


def normalize_tool_schema(schema) -> dict:
    """Привести схему инструмента к виду, который ждёт клиент MCP.

    ``inputSchema`` в спеке — всегда объект с ``properties``: клиенты
    (в том числе Claude Desktop) на схеме без ``type: object`` рисуют
    инструмент без аргументов. Поэтому недостающее достраиваем здесь, а
    не в каждом объявлении инструмента.
    """
    if not isinstance(schema, dict):
        schema = {}
    out = dict(schema)
    out.setdefault("type", "object")
    if out["type"] == "object":
        props = out.get("properties")
        out["properties"] = dict(props) if isinstance(props, dict) else {}
        req = out.get("required")
        if isinstance(req, list) and req:
            out["required"] = list(req)
        else:
            out.pop("required", None)
    return out


def validate(value, schema, field: str = "args"):
    """Проверить ``value`` по ``schema``; вернуть нормализованную копию.

    Нормализация — это только подстановка ``default`` для отсутствующих
    полей объекта. Типы не приводятся: строка «60» вместо числа 60 —
    ошибка, и модель должна её увидеть, а не получить молчаливое
    приведение с неожиданным результатом.

    Бросает :class:`SchemaError`.
    """
    if not isinstance(schema, dict) or not schema:
        return value

    types = schema.get("type")
    if types is not None:
        wanted = [types] if isinstance(types, str) else list(types)
        if not any(_type_matches(value, t) for t in wanted):
            raise SchemaError(
                "поле '%s': ожидается %s, получено %s"
                % (field, " или ".join(wanted), _type_name(value)),
                field=field, expected=" или ".join(wanted),
            )

    if "enum" in schema:
        allowed = schema["enum"]
        if isinstance(allowed, list) and value not in allowed:
            listed = ", ".join(_short(v) for v in allowed)
            raise SchemaError(
                "поле '%s': допустимые значения — %s (получено %s)"
                % (field, listed, _short(value)),
                field=field, expected="one of: " + listed,
            )

    if isinstance(value, bool):
        # bool — подтип int в Python: до числовых проверок не допускаем,
        # иначе True прошёл бы как 1 в minimum/maximum.
        pass
    elif isinstance(value, (int, float)):
        _check_number(value, schema, field)
    elif isinstance(value, str):
        _check_string(value, schema, field)

    if isinstance(value, list):
        return _check_array(value, schema, field)

    if isinstance(value, dict):
        return _check_object(value, schema, field)

    return value


# ───────────────────────────── частности ─────────────────────────────

def _check_number(value, schema, field):
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    if isinstance(minimum, (int, float)) and value < minimum:
        raise SchemaError(
            "поле '%s': значение %s меньше минимума %s"
            % (field, value, minimum),
            field=field, expected=">= %s" % minimum,
        )
    if isinstance(maximum, (int, float)) and value > maximum:
        raise SchemaError(
            "поле '%s': значение %s больше максимума %s"
            % (field, value, maximum),
            field=field, expected="<= %s" % maximum,
        )


def _check_string(value, schema, field):
    min_len = schema.get("minLength")
    max_len = schema.get("maxLength")
    if isinstance(min_len, int) and len(value) < min_len:
        raise SchemaError(
            "поле '%s': строка короче %d символов" % (field, min_len),
            field=field, expected="minLength=%d" % min_len,
        )
    if isinstance(max_len, int) and len(value) > max_len:
        raise SchemaError(
            "поле '%s': строка длиннее %d символов" % (field, max_len),
            field=field, expected="maxLength=%d" % max_len,
        )
    pattern = schema.get("pattern")
    if isinstance(pattern, str) and pattern:
        try:
            ok = re.search(pattern, value) is not None
        except re.error:
            ok = True  # битый pattern в схеме — не вина аргумента
        if not ok:
            raise SchemaError(
                "поле '%s': значение не подходит под шаблон %s"
                % (field, pattern),
                field=field, expected="pattern=%s" % pattern,
            )


def _check_array(value, schema, field):
    min_items = schema.get("minItems")
    max_items = schema.get("maxItems")
    if isinstance(min_items, int) and len(value) < min_items:
        raise SchemaError(
            "поле '%s': нужно минимум %d элементов (получено %d)"
            % (field, min_items, len(value)),
            field=field, expected="minItems=%d" % min_items,
        )
    if isinstance(max_items, int) and len(value) > max_items:
        raise SchemaError(
            "поле '%s': не больше %d элементов (получено %d)"
            % (field, max_items, len(value)),
            field=field, expected="maxItems=%d" % max_items,
        )
    item_schema = schema.get("items")
    if not isinstance(item_schema, dict):
        return value
    return [validate(item, item_schema, "%s[%d]" % (field, i))
            for i, item in enumerate(value)]


def _check_object(value, schema, field):
    props = schema.get("properties")
    props = props if isinstance(props, dict) else {}

    required = schema.get("required")
    if isinstance(required, list):
        for key in required:
            if key not in value:
                raise SchemaError(
                    "поле '%s.%s': обязательный аргумент не передан"
                    % (field, key),
                    field="%s.%s" % (field, key),
                    expected=_expected_of(props.get(key)),
                )

    if schema.get("additionalProperties") is False:
        extra = [k for k in value if k not in props]
        if extra:
            known = ", ".join(sorted(props)) or "нет"
            raise SchemaError(
                "поле '%s': неизвестные аргументы: %s (допустимы: %s)"
                % (field, ", ".join(sorted(extra)), known),
                field=field, expected="one of: " + known,
            )

    out = dict(value)
    for key, sub in props.items():
        if not isinstance(sub, dict):
            continue
        if key in out:
            out[key] = validate(out[key], sub, "%s.%s" % (field, key))
        elif "default" in sub:
            out[key] = sub["default"]
    return out


def _type_matches(value, type_name: str) -> bool:
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "integer":
        # bool — подтип int, но True не является целым аргументом.
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_name == "null":
        return value is None
    return False


def _type_name(value) -> str:
    """Имя типа значения в терминах JSON Schema — для текста ошибки."""
    if value is None:
        return "null"
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
    return type(value).__name__


def _expected_of(sub) -> str:
    if not isinstance(sub, dict):
        return ""
    t = sub.get("type")
    if isinstance(t, str):
        return t
    if isinstance(t, list):
        return " или ".join(str(x) for x in t)
    return ""


def _short(value, limit: int = 40) -> str:
    """Короткое представление значения для текста ошибки."""
    text = repr(value)
    return text if len(text) <= limit else text[:limit - 1] + "…"
