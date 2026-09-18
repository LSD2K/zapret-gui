# tests/test_mcp_strategies_write.py
"""
Правка user-стратегий через MCP: CRUD, границы имени, снимок и откат.

Что здесь важно зафиксировать:

**Встроенную стратегию не переписать и не удалить.** Она приходит из
каталога и восстановится при следующей загрузке; молчаливая
«перезапись» означала бы, что модель считает правку сохранённой, а она
исчезла.

**Имя проверяется ДО менеджера.** ``StrategyManager`` санитизирует id,
заменяя недопустимые символы на ``_``: «../../etc/passwd» превратился
бы в существующий файл со странным именем вместо честного отказа.

**Каждая правка кладёт снимок.** Без него ``mcp_undo_last`` для
стратегий не работает вовсе — а мутирующий инструмент без отката
нарушает инвариант §5.4 контракта.

Стратегии и журнал пишутся во ВРЕМЕННЫЙ каталог: тест, трогающий
config/strategies/user, портит репозиторий, в котором его запустили.
"""

import os
import shutil
import tempfile
import unittest

from core.mcp import audit
from core.mcp import registry


WRITE = {"strategies_write": True}

MINIMAL = {
    "id": "mcp-test",
    "name": "Тестовая",
    "profiles": [{"id": "p1", "args": "--dpi-desync=fake"}],
}


class Sandbox(unittest.TestCase):
    """Временные каталоги стратегий и настроек на время теста."""

    def setUp(self):
        import core.config_manager as cm
        import core.strategy_builder as sb

        registry.load_tools()

        self.dir = tempfile.mkdtemp(prefix="mcp-strategies-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

        saved_cfg = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved_cfg)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()

        # Журнал и снимки MCP лежат рядом с settings.json.
        before = os.environ.get("ZAPRET_GUI_CONFIG_DIR")
        self.addCleanup(_restore_env, before)
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = self.dir

        # Менеджер стратегий — со своим base_dir и без каталогов: в
        # тесте нас интересуют user-стратегии, а не 700 builtin.
        manager = sb.StrategyManager(base_dir=os.path.join(self.dir,
                                                           "strategies"))
        manager._loaded = True
        self.manager = manager
        saved_factory = sb.get_strategy_manager
        self.addCleanup(setattr, sb, "get_strategy_manager", saved_factory)
        sb.get_strategy_manager = lambda: manager

        # Валидацию через живой nfqws2 подменяем: бинарника здесь нет, а
        # ходить за ним на каждый вызов — секунды на пустом месте.
        import core.mcp.tools.strategies as tools

        saved_dry = tools._dry_run
        self.addCleanup(setattr, tools, "_dry_run", saved_dry)
        tools._dry_run = lambda m, s: {"available": False,
                                       "reason": "бинарника нет"}

    def call(self, name, args=None, perms=None):
        return registry.call(name, args or {},
                             WRITE if perms is None else perms)

    def data(self, name, args=None, perms=None):
        return self.call(name, args, perms)["structuredContent"]


def _restore_env(value):
    if value is None:
        os.environ.pop("ZAPRET_GUI_CONFIG_DIR", None)
    else:
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = value


class TestPermission(unittest.TestCase):

    def setUp(self):
        registry.load_tools()

    def test_not_listed_without_permission(self):
        names = {spec.name for spec in registry.available_tools({})}
        self.assertNotIn("strategy_save", names)
        self.assertNotIn("strategy_delete", names)

    def test_calling_by_name_is_refused(self):
        answer = registry.call("strategy_save", dict(MINIMAL), {})
        self.assertTrue(answer["isError"])
        self.assertEqual(answer["structuredContent"]["permission"],
                         "strategies_write")


class TestSave(Sandbox):

    def test_creates_and_returns_a_diff(self):
        payload = self.data("strategy_save", dict(MINIMAL))
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["created"])
        self.assertIsNone(payload["before"])
        self.assertEqual(payload["after"]["id"], "mcp-test")
        self.assertEqual(payload["profiles"], 1)
        self.assertIn("strategy_apply", payload["hint"])
        self.assertIsNotNone(self.manager.get_strategy("mcp-test"))

    def test_saving_does_not_apply(self):
        # «Записать файл» и «пустить это в трафик» — разные права, и
        # модель обязана видеть, что второго не произошло.
        self.data("strategy_save", dict(MINIMAL))
        import core.config_manager as cm
        self.assertIsNone(cm.get_config_manager().get("strategy",
                                                      "current_id"))

    def test_overwrite_says_the_profiles_are_replaced(self):
        self.data("strategy_save", dict(MINIMAL))
        second = dict(MINIMAL)
        second["profiles"] = [{"id": "p2", "args": "--dpi-desync=split2"}]
        payload = self.data("strategy_save", second)
        self.assertTrue(payload["replaced"])
        self.assertIn("ЦЕЛИКОМ", payload["hint"])
        # Прежняя версия отдаётся целиком: собрать её обратно можно без
        # второго вызова.
        self.assertEqual(payload["before"]["profiles"][0]["id"], "p1")
        self.assertEqual(len(self.manager.get_strategy("mcp-test")
                             ["profiles"]), 1)

    def test_keeps_fields_the_model_did_not_send(self):
        first = dict(MINIMAL)
        first["description"] = "зачем она нужна"
        self.data("strategy_save", first)
        self.data("strategy_save", dict(MINIMAL))
        self.assertEqual(self.manager.get_strategy("mcp-test")
                         ["description"], "зачем она нужна")

    def test_path_traversal_in_id_is_refused(self):
        for bad in ("../../etc/passwd", "a/b", "..", "with space", ".",
                    "", "стратегия"):
            with self.subTest(id=bad):
                payload = self.data("strategy_save",
                                    dict(MINIMAL, id=bad))
                self.assertFalse(payload["ok"])
                self.assertIn("id", payload["error"])
                self.assertFalse(os.listdir(
                    os.path.join(self.dir, "strategies", "user"))
                    if os.path.isdir(os.path.join(self.dir, "strategies",
                                                  "user")) else [])

    def test_too_long_id_is_a_schema_error(self):
        # Длину режет схема, до обработчика такой вызов не доходит: это
        # ошибка протокола (-32602), а не отказ инструмента.
        import core.mcp.schema as schema_mod

        with self.assertRaises(schema_mod.SchemaError):
            registry.call("strategy_save", dict(MINIMAL, id="x" * 65),
                          WRITE)

    def test_builtin_is_refused(self):
        self.manager._cache["shipped"] = {
            "id": "shipped", "name": "Из каталога", "is_builtin": True,
            "profiles": [],
        }
        payload = self.data("strategy_save", dict(MINIMAL, id="shipped"))
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["is_builtin"])
        self.assertIn("другим id", payload["hint"])

    def test_size_limit(self):
        import core.mcp.tools.strategies as tools

        huge = dict(MINIMAL)
        huge["profiles"] = [{"id": "p1", "args": "x" * 7000},
                            {"id": "p2", "args": "y" * 7000},
                            {"id": "p3", "args": "z" * 7000}]
        saved = tools.MAX_STRATEGY_BYTES
        self.addCleanup(setattr, tools, "MAX_STRATEGY_BYTES", saved)
        tools.MAX_STRATEGY_BYTES = 1024
        payload = self.data("strategy_save", huge)
        self.assertFalse(payload["ok"])
        self.assertIn("великовата", payload["error"])
        self.assertIsNone(self.manager.get_strategy("mcp-test"))

    def test_validation_is_reported_but_does_not_block(self):
        import core.mcp.tools.strategies as tools

        tools._dry_run = lambda m, s: {"available": True, "ok": False,
                                       "output": "unknown option"}
        payload = self.data("strategy_save", dict(MINIMAL))
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["validation"]["ok"])
        self.assertIsNotNone(self.manager.get_strategy("mcp-test"))


class TestDelete(Sandbox):

    def test_deletes_and_snapshots(self):
        self.data("strategy_save", dict(MINIMAL))
        payload = self.data("strategy_delete", {"id": "mcp-test"})
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["deleted"])
        self.assertEqual(payload["before"]["id"], "mcp-test")
        self.assertIsNone(self.manager.get_strategy("mcp-test"))

    def test_unknown_id(self):
        payload = self.data("strategy_delete", {"id": "nope"})
        self.assertFalse(payload["ok"])
        self.assertIn("strategy_list", payload["hint"])

    def test_builtin_is_refused(self):
        self.manager._cache["shipped"] = {
            "id": "shipped", "name": "Из каталога", "is_builtin": True,
            "profiles": [],
        }
        payload = self.data("strategy_delete", {"id": "shipped"})
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["is_builtin"])

    def test_active_strategy_is_reset_and_said_so(self):
        import core.config_manager as cm

        self.data("strategy_save", dict(MINIMAL))
        cfg = cm.get_config_manager()
        cfg.set("strategy", "current_id", "mcp-test")
        cfg.set("strategy", "favorites", ["mcp-test", "other"])
        cfg.save()

        payload = self.data("strategy_delete", {"id": "mcp-test"})
        self.assertTrue(payload["was_active"])
        # Удалить активную — не то же самое, что выключить обход.
        self.assertIn("движок", payload["hint"])
        self.assertIsNone(cfg.get("strategy", "current_id"))
        self.assertEqual(cfg.get("strategy", "favorites"), ["other"])

    def test_path_traversal_is_refused(self):
        payload = self.data("strategy_delete", {"id": "../../settings"})
        self.assertFalse(payload["ok"])
        self.assertIn("id", payload["error"])


class TestUndo(Sandbox):
    """`mcp_undo_last` обязан отменять и сохранение, и удаление."""

    def undo(self):
        return registry.call("mcp_undo_last", {},
                             WRITE)["structuredContent"]

    def test_snapshot_is_written(self):
        payload = self.data("strategy_save", dict(MINIMAL))
        self.assertEqual(payload["undo"]["kind"], audit.KIND_STRATEGY)
        self.assertEqual(payload["undo"]["target"], "mcp-test")

    def test_undo_of_a_create_deletes(self):
        self.data("strategy_save", dict(MINIMAL))
        result = self.undo()
        self.assertTrue(result["reverted"])
        self.assertIsNone(self.manager.get_strategy("mcp-test"))

    def test_undo_of_an_overwrite_restores_the_previous(self):
        self.data("strategy_save", dict(MINIMAL))
        second = dict(MINIMAL)
        second["profiles"] = [{"id": "p2", "args": "--dpi-desync=split2"}]
        self.data("strategy_save", second)

        self.assertTrue(self.undo()["reverted"])
        restored = self.manager.get_strategy("mcp-test")
        self.assertEqual(restored["profiles"][0]["id"], "p1")

    def test_undo_of_a_delete_restores(self):
        self.data("strategy_save", dict(MINIMAL))
        self.data("strategy_delete", {"id": "mcp-test"})
        self.assertTrue(self.undo()["reverted"])
        self.assertIsNotNone(self.manager.get_strategy("mcp-test"))

    def test_undo_walks_back_one_step_at_a_time(self):
        self.data("strategy_save", dict(MINIMAL))
        self.data("strategy_save", dict(MINIMAL, name="Вторая"))
        self.undo()
        self.assertEqual(self.manager.get_strategy("mcp-test")["name"],
                         "Тестовая")
        self.undo()
        self.assertIsNone(self.manager.get_strategy("mcp-test"))


class TestAcceptanceCycle(Sandbox):
    """Приёмка S7: сохранить → применить → перезапустить → откатить всё.

    Проверяется набором разрешений ИЗ ЗАДАНИЯ — `control` +
    `strategies_write`, без `config_write`. Именно здесь видно, что
    `mcp_undo_last` не прибит к записи настроек: иначе модель, которой
    разрешили менять стратегии, не смогла бы вернуть ни одну правку.
    """

    BOTH = {"control": True, "strategies_write": True}

    def setUp(self):
        super().setUp()
        from core import nfqws_control

        self.engine = _Engine()
        self.firewall = _Firewall()
        self.runtime = _Runtime()
        for name, value in (("_managers",
                             lambda: (self.engine, self.firewall,
                                      self.runtime)),
                            ("busy", dict),
                            ("active_strategy_args", lambda: ["--x"])):
            saved = getattr(nfqws_control, name)
            self.addCleanup(setattr, nfqws_control, name, saved)
            setattr(nfqws_control, name, value)

    def both(self, name, args=None):
        return registry.call(name, args or {},
                             self.BOTH)["structuredContent"]

    def test_full_cycle(self):
        saved = self.both("strategy_save", dict(MINIMAL))
        self.assertTrue(saved["ok"])

        applied = self.both("strategy_apply", {"id": "mcp-test"})
        self.assertTrue(applied["ok"])
        self.assertEqual(self.runtime.get("strategy", "current_id"),
                         "mcp-test")

        restarted = self.both("nfqws_restart")
        self.assertTrue(restarted["ok"])

        # Откат идёт по одному шагу, от нового к старому: сначала
        # применение, потом сохранение.
        first = self.both("mcp_undo_last")
        self.assertTrue(first["reverted"])
        self.assertIsNone(self.runtime.get("strategy", "current_id"))

        second = self.both("mcp_undo_last")
        self.assertTrue(second["reverted"])
        self.assertIsNone(self.manager.get_strategy("mcp-test"))

        # Больше откатывать нечего — и это ответ, а не ошибка.
        self.assertFalse(self.both("mcp_undo_last")["reverted"])

    def test_undo_is_available_without_config_write(self):
        self.both("strategy_save", dict(MINIMAL))
        answer = registry.call("mcp_undo_last", {},
                               {"strategies_write": True})
        self.assertFalse(answer["isError"])


class _Engine:
    def __init__(self):
        self.running = False

    def is_running(self):
        return self.running

    def start(self, args=None):
        self.running = True
        return True

    def restart(self, args=None):
        self.running = True
        return True

    def stop(self):
        self.running = False
        return True

    def get_status(self):
        return {"running": self.running, "pid": 1, "binary": "nfqws2",
                "last_args": [], "exit_code": None}


class _Firewall:
    def apply_rules(self, *a, **kw):
        return True

    def remove_rules(self):
        return True

    def get_status(self):
        return {"type": "iptables", "applied": True, "rules_count": 1}


class _Runtime:
    """Конфиг, который видит только nfqws_control (движок и автозапуск)."""

    def __init__(self):
        self.values = {("firewall", "apply_on_start"): False,
                       ("autostart", "enabled"): False}

    def get(self, *parts, **kw):
        return self.values.get(tuple(parts), kw.get("default"))

    def set(self, *args):
        self.values[tuple(args[:-1])] = args[-1]

    def save(self):
        return True


if __name__ == "__main__":
    unittest.main()
