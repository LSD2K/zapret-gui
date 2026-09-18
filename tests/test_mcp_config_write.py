# tests/test_mcp_config_write.py
"""
Запись настроек через MCP: что принимается, что отклоняется и как.

Главное, что здесь зафиксировано, — **отказ должен быть полезным**.
Модель, получившая «нельзя», пробует соседний путь и тратит на это
вызовы; отказ обязан назвать причину, показать саму настройку и
инструмент, который перечисляет разрешённое.

Второе по важности — **список заменяется целиком**. Самая дорогая
ошибка модели здесь звучит как «добавь домен в healthcheck.services»:
прочитав задачу буквально, она пришлёт список из одного элемента и
сотрёт остальные. Поэтому прежнее значение возвращается в ответе
целиком, а в описании инструмента написано, что список именно
заменяется.

Настройки пишутся в ВРЕМЕННЫЙ каталог: тест, трогающий настоящий
settings.json, портит устройство, на котором его запустили.
"""

import json
import os
import shutil
import tempfile
import unittest

from core.mcp import registry


WRITE = {"config_write": True}


class Sandbox:
    """Временный каталог настроек (и журнала MCP) на время теста."""

    def __init__(self, case):
        import core.config_manager as cm

        self.dir = tempfile.mkdtemp(prefix="mcp-config-write-")
        case.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

        saved = cm._config_manager
        case.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()

        # Журнал и снимки лежат рядом с settings.json — этот же каталог.
        before = os.environ.get("ZAPRET_GUI_CONFIG_DIR")
        case.addCleanup(_restore_env, before)
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = self.dir

    @property
    def settings(self) -> dict:
        with open(os.path.join(self.dir, "settings.json"),
                  encoding="utf-8") as f:
            return json.load(f)


def _restore_env(value):
    if value is None:
        os.environ.pop("ZAPRET_GUI_CONFIG_DIR", None)
    else:
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = value


def call(name, args=None, perms=None):
    """Вызов инструмента; по умолчанию — с разрешением на запись.

    ``perms={}`` — это «ничего не разрешено», а не «по умолчанию»:
    пустой словарь ложен, и `perms or WRITE` тихо выдавал бы права там,
    где тест проверяет именно отказ.
    """
    return registry.call(name, args or {},
                         WRITE if perms is None else perms)


def data(name, args=None, perms=None):
    return call(name, args, perms)["structuredContent"]


class TestRefusals(unittest.TestCase):
    """Отказ обязан объяснять, почему и что можно вместо этого."""

    def setUp(self):
        self.box = Sandbox(self)

    def assert_refused(self, path, value):
        answer = call("config_set", {"path": path, "value": value})
        payload = answer["structuredContent"]
        self.assertTrue(answer["isError"], path)
        self.assertFalse(payload["ok"])
        self.assertFalse(payload.get("writable", False))
        self.assertTrue(payload.get("reason"),
                        "отказ без причины: %s" % path)
        self.assertIn("config_writable_paths", payload.get("hint", ""))
        return payload

    def test_section_outside_the_whitelist(self):
        payload = self.assert_refused("gui.port", 8081)
        self.assertIn("gui", payload["reason"])
        self.assertIn("sections", payload)

    def test_mcp_section_is_never_writable(self):
        # Модель не расширяет собственные права — даже при config_write.
        self.assert_refused("mcp.permissions.shell_full", True)
        self.assert_refused("mcp.token", "deadbeef")
        self.assertFalse(
            self.box.settings.get("mcp", {}).get("permissions", {})
            .get("shell_full", False))

    def test_deny_field_inside_a_writable_section(self):
        payload = self.assert_refused("nfqws.queue_num", 201)
        self.assertIn("перехват", payload["reason"])

    def test_paths_and_locations_are_closed(self):
        self.assert_refused("logging.file_path", "/tmp/z.log")

    def test_writing_a_whole_section_is_refused(self):
        self.assert_refused("nfqws", {"ports_tcp": "80"})

    def test_missing_intermediate_node(self):
        # «a.b.c» с несуществующим промежуточным узлом выглядит как лист
        # внутри разрешённой секции — и всё равно не принимается.
        payload = self.assert_refused("nfqws.nope.deep", 1)
        self.assertIn("нет", payload["reason"])
        self.assertNotIn("nope", self.box.settings.get("nfqws", {}))

    def test_dotted_tricks_do_not_open_a_path(self):
        for path in ("nfqws..queue_num", ".nfqws.queue_num",
                     "nfqws.queue_num.", "nfqws.ports_tcp.x"):
            with self.subTest(path=path):
                self.assert_refused(path, 7)

    def test_type_is_checked_against_the_default(self):
        payload = data("config_set", {"path": "nfqws.ports_tcp",
                                      "value": 443})
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["type"], "string")
        self.assertIn("config_describe", payload["hint"])
        self.assertEqual(self.box.settings["nfqws"]["ports_tcp"],
                         data("config_get",
                              {"path": "nfqws.ports_tcp"})["value"])

    def test_boolean_is_not_an_integer(self):
        payload = data("config_set", {"path": "nfqws.debug", "value": 1})
        self.assertFalse(payload["ok"])
        payload = data("config_set", {"path": "logging.max_entries",
                                      "value": True})
        self.assertFalse(payload["ok"])

    def test_enum_values_are_checked(self):
        payload = data("config_set", {"path": "filter.mode",
                                      "value": "nonsense"})
        self.assertFalse(payload["ok"])
        self.assertIn("autohostlist", payload["enum"])

    def test_without_permission_the_tool_says_which_one(self):
        answer = call("config_set", {"path": "nfqws.debug", "value": True},
                      perms={})
        self.assertTrue(answer["isError"])
        payload = answer["structuredContent"]
        self.assertEqual(payload["permission"], "config_write")
        self.assertIn("config_write", payload["hint"])


class TestWrites(unittest.TestCase):

    def setUp(self):
        self.box = Sandbox(self)

    def test_answer_is_a_diff_and_the_value_lands_on_disk(self):
        before = data("config_get", {"path": "nfqws.ports_tcp"})["value"]
        payload = data("config_set", {"path": "nfqws.ports_tcp",
                                      "value": "80,443,8443"})
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["before"], before)
        self.assertEqual(payload["after"], "80,443,8443")
        self.assertTrue(payload["changed"])
        self.assertTrue(payload["saved"])
        self.assertEqual(self.box.settings["nfqws"]["ports_tcp"],
                         "80,443,8443")

    def test_unchanged_value_is_not_written(self):
        current = data("config_get", {"path": "nfqws.debug"})["value"]
        payload = data("config_set", {"path": "nfqws.debug",
                                      "value": current})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["changed"])
        self.assertFalse(payload["saved"])

    def test_list_is_replaced_whole_and_the_old_one_comes_back(self):
        before = data("config_get",
                      {"path": "healthcheck.services"})["value"]
        self.assertGreater(len(before), 1, "нужен список из нескольких")
        payload = data("config_set", {"path": "healthcheck.services",
                                      "value": ["youtube"]})
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["is_list"])
        self.assertTrue(payload["replaced"])
        # Прежний список возвращается ЦЕЛИКОМ: это единственный способ
        # собрать его обратно, не делая второго вызова.
        self.assertEqual(payload["before"], before)
        self.assertIn("ЦЕЛИКОМ", payload["hint"])
        self.assertEqual(self.box.settings["healthcheck"]["services"],
                         ["youtube"])

    def test_description_tells_the_model_to_send_the_whole_list(self):
        # Единственное место, где формулировка описания важнее кода:
        # модель читает его ДО первого вызова.
        spec = registry.get_tool("config_set")
        text = spec.description.lower()
        self.assertIn("replaced", text)
        self.assertIn("целиком", text)

    def test_enum_value_from_the_list_is_accepted(self):
        payload = data("config_set", {"path": "filter.mode",
                                      "value": "hostlist"})
        self.assertTrue(payload["ok"])
        self.assertEqual(self.box.settings["filter"]["mode"], "hostlist")

    def test_null_default_accepts_a_string(self):
        # strategy.current_id дефолта не имеет: тип задаёт значение.
        payload = data("config_set", {"path": "strategy.current_name",
                                      "value": "мой профиль"})
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["after"], "мой профиль")

    def test_logging_is_applied_live(self):
        # Запись, которая начнёт действовать после перезапуска GUI, —
        # это запись наполовину: поднять уровень лога модели нужно
        # здесь и сейчас, иначе воспроизводить проблему нечем.
        from core.log_buffer import LEVELS, get_log_buffer

        # Буфер логов — глобальный: вернуть его как было обязаны мы,
        # иначе соседние тесты получат чужой уровень персистентности.
        buffer = get_log_buffer()
        saved = buffer.get_persistent_status()
        names = {spec["priority"]: name for name, spec in LEVELS.items()}
        self.addCleanup(buffer.set_persistent, saved["enabled"],
                        saved["path"],
                        names.get(saved["min_priority"], "WARNING"),
                        saved["max_size"])

        payload = data("config_set", {"path": "logging.persist_min_level",
                                      "value": "ERROR"})
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["applied_live"], "logging")
        self.assertEqual(buffer.get_persistent_status()["min_priority"],
                         LEVELS["ERROR"]["priority"])

    def test_oversized_value_is_refused(self):
        payload = data("config_set", {
            "path": "healthcheck.custom_domains",
            "value": ["x" * 64 for _ in range(1000)]})
        self.assertFalse(payload["ok"])
        self.assertIn("hostlist", payload["hint"])


class TestWritablePaths(unittest.TestCase):

    def setUp(self):
        self.box = Sandbox(self)

    def test_lists_paths_with_type_and_value(self):
        payload = data("config_writable_paths", {"limit": 100}, perms={})
        self.assertTrue(payload["ok"])
        self.assertGreater(payload["total"], 10)
        for item in payload["items"]:
            with self.subTest(path=item["path"]):
                self.assertIn("type", item)
                self.assertIn("value", item)
                self.assertIn("default", item)

    def test_every_listed_path_is_actually_writable(self):
        from core.mcp import permissions as perms

        payload = data("config_writable_paths", {"limit": 100}, perms={})
        for item in payload["items"]:
            self.assertTrue(perms.is_writable(item["path"]), item["path"])

    def test_enum_is_shown_where_it_exists(self):
        payload = data("config_writable_paths",
                       {"search": "filter.mode"}, perms={})
        self.assertEqual(payload["count"], 1)
        self.assertIn("none", payload["items"][0]["enum"])

    def test_unknown_section_answers_with_a_reason(self):
        payload = data("config_writable_paths", {"section": "gui"},
                       perms={})
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["count"], 0)
        self.assertIn("gui", payload["reason"])
        self.assertIn("nfqws", payload["hint"])


if __name__ == "__main__":
    unittest.main()
