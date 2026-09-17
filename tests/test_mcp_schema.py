# tests/test_mcp_schema.py
"""
Мини-валидатор JSON Schema (core/mcp/schema.py).

Схемы инструментов уезжают модели, аргументы приходят обратно — и
приходят как попало. Здесь зафиксировано, что именно валидатор ловит и
что он пишет в ошибке: текст читает модель, поэтому он обязан называть
поле и ожидаемый тип, иначе следующая попытка будет такой же неверной.
"""

import unittest

from core.mcp import schema as s


class TestTypes(unittest.TestCase):

    def test_scalar_types(self):
        s.validate("x", {"type": "string"})
        s.validate(5, {"type": "integer"})
        s.validate(5.5, {"type": "number"})
        s.validate(True, {"type": "boolean"})
        s.validate(None, {"type": "null"})
        s.validate([], {"type": "array"})
        s.validate({}, {"type": "object"})

    def test_wrong_type_names_field_and_expectation(self):
        with self.assertRaises(s.SchemaError) as ctx:
            s.validate("60", {"type": "integer"}, "args.limit")
        err = ctx.exception
        self.assertEqual(err.field, "args.limit")
        self.assertEqual(err.expected, "integer")
        self.assertIn("args.limit", err.message)
        self.assertIn("integer", err.message)
        self.assertIn("string", err.message)   # что пришло на самом деле

    def test_bool_is_not_integer(self):
        # bool — подтип int в Python; для схемы это разные типы, иначе
        # True молча проезжает в поле «сколько повторов».
        with self.assertRaises(s.SchemaError):
            s.validate(True, {"type": "integer"})
        with self.assertRaises(s.SchemaError):
            s.validate(True, {"type": "number"})

    def test_integer_accepted_as_number(self):
        s.validate(5, {"type": "number"})

    def test_type_list(self):
        s.validate(None, {"type": ["string", "null"]})
        s.validate("a", {"type": ["string", "null"]})
        with self.assertRaises(s.SchemaError):
            s.validate(1, {"type": ["string", "null"]})


class TestConstraints(unittest.TestCase):

    def test_enum(self):
        sch = {"type": "string", "enum": ["tcp", "udp"]}
        s.validate("tcp", sch)
        with self.assertRaises(s.SchemaError) as ctx:
            s.validate("sctp", sch, "args.proto")
        self.assertIn("args.proto", ctx.exception.message)
        self.assertIn("tcp", ctx.exception.message)

    def test_minimum_maximum(self):
        sch = {"type": "integer", "minimum": 1, "maximum": 200}
        s.validate(1, sch)
        s.validate(200, sch)
        with self.assertRaises(s.SchemaError):
            s.validate(0, sch)
        with self.assertRaises(s.SchemaError):
            s.validate(201, sch)

    def test_string_length_and_pattern(self):
        with self.assertRaises(s.SchemaError):
            s.validate("", {"type": "string", "minLength": 1})
        with self.assertRaises(s.SchemaError):
            s.validate("abcd", {"type": "string", "maxLength": 3})
        with self.assertRaises(s.SchemaError):
            s.validate("zz", {"type": "string", "pattern": "^[0-9]+$"})
        s.validate("42", {"type": "string", "pattern": "^[0-9]+$"})

    def test_min_max_items(self):
        sch = {"type": "array", "minItems": 1, "maxItems": 2}
        s.validate([1], sch)
        with self.assertRaises(s.SchemaError):
            s.validate([], sch)
        with self.assertRaises(s.SchemaError):
            s.validate([1, 2, 3], sch)

    def test_items_validated_with_index_in_field(self):
        sch = {"type": "array", "items": {"type": "string"}}
        with self.assertRaises(s.SchemaError) as ctx:
            s.validate(["a", 2], sch, "args.targets")
        self.assertEqual(ctx.exception.field, "args.targets[1]")


class TestObjects(unittest.TestCase):

    SCHEMA = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "default": 50},
        },
        "required": ["name"],
    }

    def test_required_missing(self):
        with self.assertRaises(s.SchemaError) as ctx:
            s.validate({}, self.SCHEMA, "arguments")
        self.assertEqual(ctx.exception.field, "arguments.name")
        self.assertIn("обязательный", ctx.exception.message)

    def test_defaults_are_filled(self):
        out = s.validate({"name": "a"}, self.SCHEMA)
        self.assertEqual(out["limit"], 50)

    def test_defaults_do_not_override_given(self):
        out = s.validate({"name": "a", "limit": 7}, self.SCHEMA)
        self.assertEqual(out["limit"], 7)

    def test_nested_field_path(self):
        sch = {"type": "object", "properties": {
            "opts": {"type": "object", "properties": {
                "ttl": {"type": "integer"}}}}}
        with self.assertRaises(s.SchemaError) as ctx:
            s.validate({"opts": {"ttl": "x"}}, sch, "arguments")
        self.assertEqual(ctx.exception.field, "arguments.opts.ttl")

    def test_additional_properties_rejected_when_forbidden(self):
        sch = {"type": "object", "properties": {"a": {"type": "string"}},
               "additionalProperties": False}
        with self.assertRaises(s.SchemaError) as ctx:
            s.validate({"a": "x", "b": 1}, sch, "arguments")
        self.assertIn("b", ctx.exception.message)
        # Подсказываем, что вообще допустимо, — иначе модели нечем
        # исправиться.
        self.assertIn("a", ctx.exception.message)

    def test_additional_properties_allowed_by_default(self):
        sch = {"type": "object", "properties": {"a": {"type": "string"}}}
        out = s.validate({"a": "x", "b": 1}, sch)
        self.assertEqual(out["b"], 1)

    def test_input_is_not_mutated(self):
        src = {"name": "a"}
        s.validate(src, self.SCHEMA)
        self.assertNotIn("limit", src)


class TestNormalize(unittest.TestCase):

    def test_empty_schema_becomes_object(self):
        out = s.normalize_tool_schema(None)
        self.assertEqual(out["type"], "object")
        self.assertEqual(out["properties"], {})

    def test_empty_required_dropped(self):
        # "required": [] ломает часть клиентов; пустому списку в схеме
        # делать нечего.
        out = s.normalize_tool_schema({"type": "object", "required": []})
        self.assertNotIn("required", out)

    def test_existing_schema_preserved(self):
        src = {"type": "object",
               "properties": {"a": {"type": "string"}},
               "required": ["a"]}
        out = s.normalize_tool_schema(src)
        self.assertEqual(out["required"], ["a"])
        self.assertIn("a", out["properties"])


class TestToolDeclarations(unittest.TestCase):
    """Каждый инструмент в реестре объявлен по правилам контракта §3.

    Проверяется то, что уезжает модели и чего не видно на глаз: схема,
    которую валидатор не разберёт; описание на полстраницы, съедающее
    её контекст; забытый `scope`, открывающий инструмент всем.
    """

    def setUp(self):
        from core.mcp import registry
        self.registry = registry
        self.tools = registry.all_tools()

    def test_registry_is_not_empty(self):
        self.assertGreaterEqual(len(self.tools), 4)

    def test_names_are_snake_case(self):
        for spec in self.tools:
            with self.subTest(tool=spec.name):
                self.assertRegex(spec.name, self.registry.NAME_RE)

    def test_descriptions_are_short_and_bilingual(self):
        # Описание читает модель: английский нужен ей, русский — нам,
        # и оно уезжает целиком в каждый tools/list.
        for spec in self.tools:
            with self.subTest(tool=spec.name):
                self.assertTrue(spec.description.strip())
                self.assertLessEqual(len(spec.description),
                                     self.registry.MAX_DESCRIPTION)
                self.assertTrue(any("a" <= c.lower() <= "z"
                                    for c in spec.description),
                                "нет английской части")
                self.assertTrue(any("а" <= c.lower() <= "я"
                                    for c in spec.description),
                                "нет русской части")

    def test_scope_and_mutating_are_declared(self):
        from core.mcp import permissions as perms
        for spec in self.tools:
            with self.subTest(tool=spec.name):
                self.assertTrue(spec.scope is None
                                or spec.scope in perms.SCOPES)
                self.assertIsInstance(spec.mutating, bool)
                if spec.mutating:
                    self.assertIsNotNone(
                        spec.scope,
                        "мутирующий инструмент без scope доступен всем")

    def test_schema_is_an_object_the_validator_understands(self):
        for spec in self.tools:
            with self.subTest(tool=spec.name):
                self.assertEqual(spec.schema["type"], "object")
                self.assertIsInstance(spec.schema["properties"], dict)
                for key, sub in spec.schema["properties"].items():
                    kind = sub.get("type")
                    kinds = [kind] if isinstance(kind, str) else list(kind
                                                                      or ())
                    for one in kinds:
                        self.assertIn(one, s.KNOWN_TYPES,
                                      "%s.%s: тип %r валидатор не знает"
                                      % (spec.name, key, one))

    def test_empty_arguments_pass_validation(self):
        # Клиент вправе не передать arguments вовсе; инструмент с
        # обязательными полями обязан объявить их в required.
        for spec in self.tools:
            with self.subTest(tool=spec.name):
                if spec.schema.get("required"):
                    continue
                s.validate({}, spec.schema, "arguments")


class TestDeclarationIsCheckedAtImport(unittest.TestCase):
    """Неверное объявление — исключение, а не тихая регистрация.

    Инструмент, зарегистрировавшийся «как-нибудь», уедет модели и будет
    ею вызван: ошибку надо получить на импорте, у себя, а не в чужом
    клиенте.
    """

    def setUp(self):
        from core.mcp import registry
        self.registry = registry
        registry.load_tools()

    def declare(self, **kwargs):
        """Объявить инструмент и убрать за собой.

        Убираем ТОЛЬКО то, что добавили сами: проверка дубликата зовёт
        declare() с именем настоящего инструмента, и безусловный pop()
        вынес бы его из реестра для всех последующих тестов.
        """
        options = {"name": "test_decl_tool", "scope": "read",
                   "mutating": False, "description": "test / тест",
                   "schema": {"type": "object", "properties": {}}}
        options.update(kwargs)
        existed = options["name"] in self.registry._REGISTRY
        try:
            self.registry.tool(**options)(lambda args: {"ok": True})
        finally:
            if not existed:
                self.registry._REGISTRY.pop(options["name"], None)

    def test_valid_declaration_passes(self):
        self.declare()

    def test_name_must_be_snake_case(self):
        for bad in ("ConfigGet", "config-get", "2fast", "config__get"):
            with self.subTest(name=bad):
                with self.assertRaises(self.registry.ToolError):
                    self.declare(name=bad)

    def test_description_is_required_and_bounded(self):
        with self.assertRaises(self.registry.ToolError):
            self.declare(description="")
        with self.assertRaises(self.registry.ToolError):
            self.declare(description="x" * 301)

    def test_scope_and_mutating_are_mandatory(self):
        with self.assertRaises(self.registry.ToolError):
            self.registry.tool(name="test_decl_tool",
                               description="t / т")(lambda args: {})
        with self.assertRaises(self.registry.ToolError):
            self.declare(scope="конечно_можно")

    def test_mutating_tool_cannot_be_read_scope(self):
        with self.assertRaises(self.registry.ToolError):
            self.declare(mutating=True)
        with self.assertRaises(self.registry.ToolError):
            self.declare(scope=None, mutating=True)

    def test_broken_schema_is_caught(self):
        with self.assertRaises(self.registry.ToolError):
            self.declare(schema={"type": "obj"})
        with self.assertRaises(self.registry.ToolError):
            self.declare(schema={"type": "object",
                                 "properties": {"a": {"type": "str"}}})
        with self.assertRaises(self.registry.ToolError):
            self.declare(schema={"type": "object", "properties": {},
                                 "required": ["a"]})

    def test_duplicate_name_is_refused(self):
        with self.assertRaises(self.registry.ToolError):
            self.declare(name="config_get")


if __name__ == "__main__":
    unittest.main()
