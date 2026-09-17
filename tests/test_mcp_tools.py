# tests/test_mcp_tools.py
"""
Четыре эталонных инструмента S2 (core/mcp/tools/*).

Их форму копируют все следующие сессии, поэтому здесь зафиксировано не
столько «работает», сколько **как именно устроен ответ**: одинаковые
имена полей, одинаковая обработка «нет данных», лимиты и обрезка.
Разнобой в этих мелочах модель тратит на догадки, а мы — на объяснения
в каждом следующем задании.
"""

import unittest

from core.config_manager import get_config_manager
from core.log_buffer import get_log_buffer, log
from core.mcp import registry


def call(name, args=None):
    """Вызов инструмента с правами только на чтение."""
    return registry.call(name, args or {}, {})["structuredContent"]


class TestCommonShape(unittest.TestCase):

    def test_every_read_tool_answers_ok_and_elapsed(self):
        for spec in registry.available_tools({}):
            if spec.schema.get("required"):
                continue
            with self.subTest(tool=spec.name):
                payload = call(spec.name)
                self.assertTrue(payload["ok"])
                self.assertIsInstance(payload["elapsed_ms"], int)


class TestSystemStatus(unittest.TestCase):

    def test_summary_fields(self):
        payload = call("system_status")
        self.assertIn("system", payload)
        self.assertIn("gui_version", payload)
        self.assertIn("engines", payload)
        self.assertIn("nfqws", payload["engines"])

    def test_unavailable_engine_is_none_not_a_crash(self):
        # На устройстве может не быть половины движков — сводка обязана
        # собраться всё равно.
        engines = call("system_status")["engines"]
        for name, value in engines.items():
            with self.subTest(engine=name):
                self.assertIsInstance(value, (bool, int, type(None)))


class TestNfqwsStatus(unittest.TestCase):

    def test_state_fields(self):
        payload = call("nfqws_status")
        self.assertIn("running", payload)
        self.assertIn("strategy", payload)
        self.assertIn("name", payload["strategy"])


class TestConfigGet(unittest.TestCase):

    def test_whole_tree_by_default(self):
        payload = call("config_get")
        self.assertEqual(payload["path"], "")
        self.assertIn("nfqws", payload["value"])

    def test_dotted_path(self):
        payload = call("config_get", {"path": "nfqws.ports_tcp"})
        self.assertEqual(payload["type"], "string")
        self.assertTrue(payload["writable"])

    def test_defaults_are_visible_without_a_saved_file(self):
        # Ключ, которого нет в settings.json, всё равно действует —
        # модель должна видеть то, что действует.
        payload = call("config_get", {"path": "mcp.limits.response_kb"})
        self.assertEqual(payload["value"], 32)

    def test_writable_flag_and_reason(self):
        payload = call("config_get", {"path": "nfqws.queue_num"})
        self.assertFalse(payload["writable"])
        self.assertIn("перехват", payload["writable_reason"])

    def test_depth_folds_subtrees_into_field_lists(self):
        payload = call("config_get", {"path": "mcp", "depth": 1})
        self.assertTrue(payload["truncated"])
        folded = payload["value"]["limits"]
        self.assertIn("response_kb", folded["_fields"])
        self.assertTrue(folded["_truncated"])
        self.assertIn("depth", payload["hint"])

    def test_unknown_path_shows_what_is_nearby(self):
        payload = call("config_get", {"path": "nfqws.нетакого"})
        self.assertFalse(payload["ok"])
        self.assertIn("не найден", payload["error"])
        self.assertIn("ports_tcp", payload["available"])
        self.assertIn("ports_tcp", payload["hint"])

    def test_depth_is_bounded_by_the_schema(self):
        from core.mcp import schema as schema_mod
        spec = registry.get_tool("config_get")
        with self.assertRaises(schema_mod.SchemaError):
            registry.call("config_get", {"depth": 99}, {})
        self.assertEqual(spec.schema["properties"]["depth"]["maximum"], 6)


class TestLogsTail(unittest.TestCase):

    # Свои источники, а не «nfqws»/«mcp»: журнал глобальный, в него
    # пишут и фоновые потоки других тестов, и строка аудита самого
    # вызова. Тест, считающий записи в общем буфере, однажды упадёт не
    # по своей вине.
    SRC = "test-logs-tail"
    OTHER = "test-logs-other"

    def setUp(self):
        self.buffer = get_log_buffer()
        self.buffer.clear()
        log.info("первая запись", source=self.SRC)
        log.error("вторая запись, ошибка", source=self.SRC)
        log.warning("третья запись", source=self.SRC)
        log.info("чужая запись", source=self.OTHER)

    def tearDown(self):
        self.buffer.clear()

    def tail(self, **args):
        args.setdefault("source", self.SRC)
        return call("logs_tail", args)

    def test_tail_is_compact(self):
        payload = self.tail(limit=10)
        self.assertEqual(payload["count"], 3)
        item = payload["items"][0]
        self.assertEqual(sorted(item),
                         ["level", "message", "source", "time", "ts"])

    def test_filter_by_source(self):
        self.assertEqual(self.tail()["count"], 3)
        self.assertEqual(self.tail(source=self.OTHER)["count"], 1)

    def test_filter_by_minimum_level(self):
        payload = self.tail(level="ERROR")
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["items"][0]["level"], "ERROR")

    def test_filter_by_substring(self):
        self.assertEqual(self.tail(search="ошибка")["count"], 1)

    def test_filter_by_time(self):
        newest = max(item["ts"] for item in self.tail()["items"])
        self.assertEqual(self.tail(since=newest)["count"], 0)

    def test_limit_is_respected_and_marked(self):
        payload = self.tail(limit=1)
        self.assertEqual(payload["count"], 1)
        self.assertTrue(payload["truncated"])
        # Вернулись последние, а не первые: интересен хвост.
        self.assertIn("третья", payload["items"][0]["message"])

    def test_empty_result_says_what_is_nearby(self):
        payload = self.tail(source="нет-такого")
        self.assertEqual(payload["count"], 0)
        self.assertIn(self.SRC, payload["sources"])
        self.assertIn(self.SRC, payload["hint"])

    def test_long_line_is_clipped(self):
        self.buffer.clear()
        log.info("x" * 5000, source=self.SRC)
        message = self.tail()["items"][0]["message"]
        self.assertLessEqual(len(message), 400)
        self.assertTrue(message.endswith("…"))

    def test_log_is_marked_as_untrusted(self):
        # Модель обязана видеть, что содержимое журнала — данные, а не
        # инструкции: имена доменов и вывод движка приходят извне.
        self.assertIn("untrusted", self.tail()["note"])


class TestConfigIsolation(unittest.TestCase):
    """config_get не меняет конфиг и не отдаёт ссылку на него."""

    def test_value_is_a_copy(self):
        cfg = get_config_manager()
        saved = cfg.get("filter", "mode")
        try:
            payload = call("config_get", {"path": "filter"})
            payload["value"]["mode"] = "испорчено"
            self.assertEqual(cfg.get("filter", "mode"), saved)
        finally:
            if saved is not None:
                cfg.set("filter", "mode", saved)


if __name__ == "__main__":
    unittest.main()
