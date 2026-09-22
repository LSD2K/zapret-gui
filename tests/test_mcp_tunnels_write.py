# tests/test_mcp_tunnels_write.py
"""
Запуск туннелей и правка их конфигов через MCP.

Разрешение `tunnels_write` существовало с S2 и не открывало ни одного
инструмента: модель читала `tunnels_status` и останавливалась. Здесь
стережём то, из-за чего оно наконец что-то значит.

**Логика — в `core/tunnels_control.py`, а не в `tools/`.** Шесть
движков поднимаются шестью разными способами, и каждый из них уже
написан внутри HTTP-обработчиков `api/*.py`. Вторая реализация значила
бы, что «поднял из GUI» и «поднял из MCP» — разные вещи (в первую
очередь: переживёт ли туннель перезагрузку). Поэтому тесты зовут
именно этот слой, подменяя менеджеры.

**Отказ обязан называть, что есть.** «Конфига нет» без перечня имён
модель повторяет с другой опечаткой.

**Конфиг пишется целиком и оставляет снимок** — иначе `mcp_undo_last`
для туннелей не работает.

Настоящие движки здесь не запускаются: их менеджеры подменены.
"""

import unittest

from core import tunnels_control as control
from core.mcp import registry


WRITE = {"tunnels_write": True}


class FakeManager:
    """Менеджер движка: помнит, что у него просили."""

    def __init__(self, configs=None, fail=False):
        self.configs = configs or [{"name": "main", "path": "/tmp/main.json"}]
        self.calls = []
        self.fail = fail
        self.saved = {}

    def _answer(self, action, name):
        self.calls.append((action, name))
        if self.fail:
            return {"ok": False, "error": "движок отказался"}
        return {"ok": True, "name": name}

    def up(self, name):
        return self._answer("up", name)

    def down(self, name):
        return self._answer("down", name)

    def restart(self, name):
        return self._answer("restart", name)

    def list_configs(self):
        return list(self.configs)

    def get_config(self, name):
        if name in self.saved:
            return {"name": name, "path": "/tmp/%s" % name,
                    "text": self.saved[name]}
        for cfg in self.configs:
            if cfg["name"] == name:
                return {"name": name, "path": cfg["path"],
                        "text": cfg.get("text", "{}\n")}
        raise FileNotFoundError(name)

    def save_config(self, name, text=None, **kwargs):
        self.saved[name] = text if text is not None else kwargs.get("text")
        self.calls.append(("save", name))
        return {"ok": True, "name": name, "path": "/tmp/%s" % name}


class Base(unittest.TestCase):

    def setUp(self):
        registry.load_tools()
        self.manager = FakeManager()
        self.patch_engine("singbox", self.manager)

    def patch_engine(self, engine, manager):
        """Подменить адаптер движка в core/tunnels_control."""
        saved = control._ACTIONS[engine]
        self.addCleanup(control._ACTIONS.__setitem__, engine, saved)

        def handler(name, action):
            target = control._name(name)
            return getattr(manager, action)(target)

        control._ACTIONS[engine] = handler

        # Конфиги читаются/пишутся отдельным путём (config_get/_save),
        # у него свои импорты — подменяем и их.
        import core.singbox_manager as sb

        saved_getter = sb.get_singbox_manager
        self.addCleanup(setattr, sb, "get_singbox_manager", saved_getter)
        sb.get_singbox_manager = lambda: manager

        saved_instances = control.instances
        self.addCleanup(setattr, control, "instances", saved_instances)
        control.instances = lambda eng: [c["name"]
                                         for c in manager.list_configs()]

    def data(self, name, args=None, perms=None):
        return registry.call(name, args or {},
                             WRITE if perms is None else perms
                             )["structuredContent"]


class TestPermission(unittest.TestCase):

    TOOLS = ("tunnel_up", "tunnel_down", "tunnel_restart",
             "tunnel_config_get", "tunnel_config_save",
             "subscription_refresh", "pool_refresh")

    def setUp(self):
        registry.load_tools()

    def test_not_published_without_the_permission(self):
        names = {spec.name for spec in registry.available_tools({})}
        for tool in self.TOOLS:
            with self.subTest(tool=tool):
                self.assertNotIn(tool, names)

    def test_calling_by_name_is_refused(self):
        for tool in self.TOOLS:
            with self.subTest(tool=tool):
                answer = registry.call(
                    tool, {"engine": "singbox", "name": "main",
                           "text": "{}"}, {})
                self.assertTrue(answer["isError"])
                self.assertEqual(
                    answer["structuredContent"]["permission"],
                    "tunnels_write")


class TestUpDown(Base):

    def test_up_calls_the_engine(self):
        payload = self.data("tunnel_up", {"engine": "singbox",
                                          "name": "main"})
        self.assertTrue(payload["ok"])
        self.assertEqual(self.manager.calls, [("up", "main")])
        self.assertEqual(payload["reverse"], "tunnel_down")

    def test_down_warns_about_routes(self):
        payload = self.data("tunnel_down", {"engine": "singbox",
                                            "name": "main"})
        self.assertTrue(payload["ok"])
        # Погашенный туннель оставляет маршруты, которые в него вели, —
        # и трафик по ним перестаёт идти куда бы то ни было.
        self.assertIn("маршруты", payload["hint"])

    def test_restart_is_how_a_config_change_takes_effect(self):
        self.data("tunnel_restart", {"engine": "singbox", "name": "main"})
        self.assertEqual(self.manager.calls, [("restart", "main")])

    def test_unknown_engine_lists_the_known_ones(self):
        payload = self.data("tunnel_up", {"engine": "singbox"},
                            perms=WRITE)
        # Имя обязательно для всех, кроме opera: «подними sing-box»
        # без имени означало бы «подними наугад один из конфигов».
        self.assertFalse(payload["ok"])
        self.assertIn("known_names", payload)

    def test_unknown_name_lists_what_there_is(self):
        saved = control._ACTIONS["singbox"]

        def failing(name, action):
            raise control.EngineError("конфига «%s» нет" % name)

        control._ACTIONS["singbox"] = failing
        self.addCleanup(control._ACTIONS.__setitem__, "singbox", saved)

        payload = self.data("tunnel_up", {"engine": "singbox",
                                          "name": "nope"})
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["known_names"], ["main"])

    def test_engine_refusal_points_at_the_status_tool(self):
        self.manager.fail = True
        payload = self.data("tunnel_up", {"engine": "singbox",
                                          "name": "main"})
        self.assertFalse(payload["ok"])
        self.assertIn("tunnels_status", payload["hint"])


class TestConfig(Base):

    def test_reads_the_text(self):
        self.manager.configs = [{"name": "main", "path": "/tmp/main.json",
                                 "text": "{\"log\": {}}\n"}]
        payload = self.data("tunnel_config_get",
                            {"engine": "singbox", "name": "main"})
        self.assertTrue(payload["ok"])
        self.assertIn("log", payload["text"])
        self.assertTrue(payload["redacted"])

    def test_engines_without_a_config_file_are_refused_by_schema(self):
        # usque/tgproxy/opera конфига-файла не имеют: enum схемы их не
        # принимает, и объяснение приходит ещё до менеджера — ошибкой
        # протокола, с перечнем допустимых значений.
        from core.mcp import schema as schema_mod

        with self.assertRaises(schema_mod.SchemaError) as ctx:
            registry.call("tunnel_config_get",
                          {"engine": "opera", "name": "x"}, WRITE)
        self.assertIn("singbox", str(ctx.exception))

    def test_save_replaces_and_leaves_a_snapshot(self):
        payload = self.data("tunnel_config_save",
                            {"engine": "singbox", "name": "main",
                             "text": "{\"new\": true}\n"})
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["changed"])
        self.assertIsNotNone(payload["undo"])
        self.assertIn("tunnel_restart", payload["hint"])
        self.assertIn("new", self.manager.saved["main"])

    def test_empty_config_is_refused(self):
        payload = self.data("tunnel_config_save",
                            {"engine": "singbox", "name": "main",
                             "text": "   "})
        self.assertFalse(payload["ok"])
        self.assertIn("пуст", payload["error"])

    def test_restart_after_save(self):
        self.data("tunnel_config_save",
                  {"engine": "singbox", "name": "main",
                   "text": "{\"a\": 1}\n", "restart": True})
        self.assertIn(("restart", "main"), self.manager.calls)


class TestControlLayer(unittest.TestCase):
    """Сам `core/tunnels_control.py`, мимо MCP."""

    def test_unknown_engine(self):
        with self.assertRaises(control.EngineError) as ctx:
            control.up("nosuchengine")
        self.assertIn("известные", str(ctx.exception))

    def test_engine_without_config_files(self):
        with self.assertRaises(control.EngineError) as ctx:
            control.config_get("usque", "x")
        self.assertIn("конфига-файла", str(ctx.exception))

    def test_names_with_slashes_are_refused(self):
        for bad in ("../../etc/passwd", "a/b", "..", ""):
            with self.subTest(name=bad):
                with self.assertRaises(control.EngineError):
                    control._name(bad)

    def test_oversized_config_is_refused(self):
        with self.assertRaises(control.EngineError) as ctx:
            control.config_save("singbox", "main",
                                "x" * (control.MAX_CONFIG_BYTES + 1))
        self.assertIn("великоват", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
