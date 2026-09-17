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


if __name__ == "__main__":
    unittest.main()
