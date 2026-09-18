# tests/test_mcp_lists_write.py
"""
Правка списков, blob'ов и lua через MCP: режимы, лимиты и откат.

Что стережём.

**`replace` затирает список целиком, и об этом сказано трижды** — в
описании инструмента, в `hint` ответа и прежним содержимым в `before`.
Самая дорогая ошибка модели здесь звучит как «добавь домен в other»:
прочитав задачу буквально, она пришлёт список из одного элемента.

**Пустой hostlist — это выключенный фильтр.** Профиль с `--hostlist`
перестаёт применяться к чему бы то ни было, а снаружи это выглядит как
«ничего не изменилось». Ответ обязан сказать это словами.

**Имена файлов — по белому списку.** Никакой подстановки пути:
`../../etc/passwd` отклоняется до менеджера, а не превращается в файл
со странным именем.

**Каждая правка кладёт снимок** — иначе `mcp_undo_last` для списков не
работает, а мутирующий инструмент без отката нарушает §5.4 контракта.

Всё пишется во ВРЕМЕННЫЕ каталоги.
"""

import os
import shutil
import tempfile
import unittest

from core.mcp import audit
from core.mcp import registry


WRITE = {"strategies_write": True}


class Sandbox(unittest.TestCase):
    """Временные каталоги списков, ipset'ов, blob'ов, lua и настроек."""

    def setUp(self):
        import core.config_manager as cm

        registry.load_tools()

        self.dir = tempfile.mkdtemp(prefix="mcp-lists-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        for sub in ("lists", "ipset", "blobs", "lua"):
            os.makedirs(os.path.join(self.dir, sub), exist_ok=True)

        saved = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        cfg = cm._config_manager
        # base_path важен не меньше остальных: BlobManager строит свой
        # каталог от него и создаёт его прямо в __init__. Без подмены
        # тест заводит /opt/zapret2/blobs на машине разработчика.
        cfg.set("zapret", "base_path", self.dir)
        cfg.set("zapret", "lists_path", os.path.join(self.dir, "lists"))
        cfg.set("zapret", "ipset_path", os.path.join(self.dir, "ipset"))
        cfg.set("zapret", "lua_path", os.path.join(self.dir, "lua"))
        cfg.set("zapret", "bin_path", os.path.join(self.dir, "fake"))
        cfg.save()

        before = os.environ.get("ZAPRET_GUI_CONFIG_DIR")
        self.addCleanup(_restore_env, before)
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = self.dir

        # SIGHUP: живого движка здесь нет, и ходить в /proc на каждый
        # вызов незачем. Подменяем поиск PID, а не сам сигнал.
        import core.nfqws_reload as reload_mod

        saved_find = reload_mod.find_nfqws_pids
        self.addCleanup(setattr, reload_mod, "find_nfqws_pids", saved_find)
        reload_mod.find_nfqws_pids = lambda: []

    def call(self, name, args=None, perms=None):
        return registry.call(name, args or {},
                             WRITE if perms is None else perms)

    def data(self, name, args=None, perms=None):
        return self.call(name, args, perms)["structuredContent"]

    def undo(self):
        return registry.call("mcp_undo_last", {},
                             WRITE)["structuredContent"]


def _restore_env(value):
    if value is None:
        os.environ.pop("ZAPRET_GUI_CONFIG_DIR", None)
    else:
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = value


class TestPermission(unittest.TestCase):

    TOOLS = ("hostlist_edit", "ipset_edit", "blob_add", "lua_script_save")

    def setUp(self):
        registry.load_tools()

    def test_not_listed_without_permission(self):
        names = {spec.name for spec in registry.available_tools({})}
        for tool in self.TOOLS:
            with self.subTest(tool=tool):
                self.assertNotIn(tool, names)

    def test_calling_by_name_is_refused(self):
        for tool in self.TOOLS:
            with self.subTest(tool=tool):
                answer = registry.call(
                    tool, {"name": "other", "domains": [], "entries": [],
                           "hex": "00", "content": ""}, {})
                self.assertTrue(answer["isError"])
                self.assertEqual(
                    answer["structuredContent"]["permission"],
                    "strategies_write")


class TestHostlist(Sandbox):

    def seed(self, *domains):
        from core.hostlist_manager import get_hostlist_manager
        get_hostlist_manager().save_hostlist("other", list(domains))

    def read(self):
        from core.hostlist_manager import get_hostlist_manager
        return get_hostlist_manager().get_hostlist("other")

    def test_add_keeps_the_rest(self):
        self.seed("a.com", "b.com")
        payload = self.data("hostlist_edit",
                            {"name": "other", "mode": "add",
                             "domains": ["c.com"]})
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["added"], 1)
        self.assertEqual(payload["count"], 3)
        self.assertEqual(self.read(), ["a.com", "b.com", "c.com"])

    def test_add_is_the_default_mode(self):
        self.seed("a.com")
        self.data("hostlist_edit",
                  {"name": "other", "domains": ["b.com"]})
        self.assertEqual(self.read(), ["a.com", "b.com"])

    def test_replace_wipes_and_says_so(self):
        self.seed("a.com", "b.com")
        payload = self.data("hostlist_edit",
                            {"name": "other", "mode": "replace",
                             "domains": ["c.com"]})
        self.assertTrue(payload["replaced"])
        self.assertIn("ЦЕЛИКОМ", payload["hint"])
        # Прежнее содержимое отдаётся целиком — собрать обратно можно
        # без второго вызова.
        self.assertEqual(payload["before"], ["a.com", "b.com"])
        self.assertEqual(self.read(), ["c.com"])

    def test_remove(self):
        self.seed("a.com", "b.com")
        payload = self.data("hostlist_edit",
                            {"name": "other", "mode": "remove",
                             "domains": ["a.com"]})
        self.assertEqual(payload["removed"], 1)
        self.assertEqual(self.read(), ["b.com"])

    def test_emptying_the_list_is_a_warning(self):
        # Пустой hostlist — это выключенный фильтр, а не «ничего не
        # изменилось».
        self.seed("a.com")
        payload = self.data("hostlist_edit",
                            {"name": "other", "mode": "replace",
                             "domains": []})
        self.assertEqual(payload["count"], 0)
        self.assertIn("ПУСТ", payload["warning"])
        self.assertIn("не применится", payload["warning"])

    def test_url_is_normalised_and_junk_reported(self):
        payload = self.data("hostlist_edit",
                            {"name": "other", "mode": "replace",
                             "domains": ["https://www.example.com/path",
                                         "не домен вовсе"]})
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["rejected_count"], 1)
        self.assertIn("не принято", payload["hint"])

    def test_unknown_list_shows_what_exists(self):
        payload = self.data("hostlist_edit",
                            {"name": "nope", "domains": ["a.com"]})
        self.assertFalse(payload["ok"])
        self.assertIn("other", payload["available"])

    def test_bad_names_are_refused(self):
        for bad in ("../../etc/passwd", "a/b", "..", "with space"):
            with self.subTest(name=bad):
                payload = self.data("hostlist_edit",
                                    {"name": bad, "domains": ["a.com"]})
                self.assertFalse(payload["ok"])
                self.assertIn("имя", payload["error"])

    def test_size_limit(self):
        import core.mcp.tools.lists as tools

        saved = tools.MAX_LIST_ENTRIES
        self.addCleanup(setattr, tools, "MAX_LIST_ENTRIES", saved)
        tools.MAX_LIST_ENTRIES = 3
        self.seed("a.com")
        payload = self.data(
            "hostlist_edit",
            {"name": "other", "mode": "replace",
             "domains": ["a%d.com" % i for i in range(5)]})
        self.assertFalse(payload["ok"])
        self.assertIn("предел", payload["error"])
        # Отказ не должен трогать файл — ни частично, ни «на всякий».
        self.assertEqual(self.read(), ["a.com"])

    def test_reload_is_reported_honestly(self):
        import core.nfqws_reload as reload_mod

        self.seed("a.com")
        payload = self.data("hostlist_edit",
                            {"name": "other", "domains": ["b.com"]})
        self.assertFalse(payload["reloaded"])
        self.assertIn("не запущен", payload["hint"])

        reload_mod.find_nfqws_pids = lambda: [777]
        payload = self.data("hostlist_edit",
                            {"name": "other", "domains": ["c.com"]})
        self.assertTrue(payload["reloaded"])

    def test_undo_restores_the_whole_list(self):
        self.seed("a.com", "b.com")
        payload = self.data("hostlist_edit",
                            {"name": "other", "mode": "replace",
                             "domains": ["c.com"]})
        self.assertEqual(payload["undo"]["kind"], audit.KIND_HOSTLIST)
        self.assertTrue(self.undo()["reverted"])
        self.assertEqual(self.read(), ["a.com", "b.com"])


class TestIPSet(Sandbox):

    def read(self):
        from core.ipset_manager import get_ipset_manager
        return get_ipset_manager().get_ipset("my-ipset")

    def test_add_and_reject_junk(self):
        payload = self.data("ipset_edit",
                            {"name": "my-ipset", "mode": "add",
                             "entries": ["1.2.3.4", "10.0.0.0/8",
                                         "не адрес"]})
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["added"], 2)
        self.assertEqual(payload["rejected_count"], 1)
        self.assertEqual(sorted(self.read()), ["1.2.3.4", "10.0.0.0/8"])

    def test_replace_and_undo(self):
        self.data("ipset_edit", {"name": "my-ipset", "mode": "add",
                                 "entries": ["1.2.3.4"]})
        payload = self.data("ipset_edit",
                            {"name": "my-ipset", "mode": "replace",
                             "entries": ["8.8.8.8"]})
        self.assertEqual(payload["before"], ["1.2.3.4"])
        self.assertEqual(self.read(), ["8.8.8.8"])
        self.assertTrue(self.undo()["reverted"])
        self.assertEqual(self.read(), ["1.2.3.4"])

    def test_bad_name(self):
        payload = self.data("ipset_edit",
                            {"name": "../x", "entries": ["1.2.3.4"]})
        self.assertFalse(payload["ok"])


class TestBlob(Sandbox):

    def setUp(self):
        super().setUp()
        import core.blob_manager as bm

        # BlobManager берёт каталог из zapret.base_path при создании —
        # он уже подменён песочницей, поэтому свой экземпляр пишет в
        # tmp, а не в /opt/zapret2/blobs.
        manager = bm.BlobManager()
        self.assertTrue(manager.blobs_dir.startswith(self.dir),
                        "blob-менеджер смотрит мимо песочницы: %s"
                        % manager.blobs_dir)
        saved = bm.get_blob_manager
        self.addCleanup(setattr, bm, "get_blob_manager", saved)
        bm.get_blob_manager = lambda: manager
        self.blobs = manager

    def test_writes_and_undo_deletes(self):
        payload = self.data("blob_add",
                            {"name": "mcp-test", "hex": "16 03 01 00 05"})
        if not payload["ok"]:
            self.skipTest("blob-менеджер недоступен: %s" % payload["error"])
        self.assertTrue(payload["created"])
        self.assertEqual(payload["undo"]["kind"], audit.KIND_BLOB)
        self.assertTrue(self.undo()["reverted"])
        self.assertIsNone(self.blobs.get_blob("mcp-test"))

    def test_builtin_name_is_refused(self):
        name = next((n for n in ("fake_default_tls", "tls_google")
                     if self.blobs.is_builtin(n)), "")
        if not name:
            self.skipTest("встроенных blob'ов на этой машине нет")
        payload = self.data("blob_add", {"name": name, "hex": "00"})
        self.assertFalse(payload["ok"])

    def test_bad_name(self):
        payload = self.data("blob_add", {"name": "../x", "hex": "00"})
        self.assertFalse(payload["ok"])
        self.assertIn("имя", payload["error"])

    def test_junk_hex_is_refused(self):
        payload = self.data("blob_add",
                            {"name": "mcp-test", "hex": "не hex вовсе"})
        self.assertFalse(payload["ok"])
        self.assertIn("hex", payload["hint"])


class TestLua(Sandbox):

    def read(self, name="mcp_test"):
        """Текст скрипта или None, если файла нет.

        `get_script` отдаёт "" в обоих случаях — по нему «скрипта нет» и
        «скрипт пуст» не различить, а тесту отката нужно именно это.
        """
        from core.lua_manager import get_lua_manager
        manager = get_lua_manager()
        if name not in manager.list_names():
            return None
        return manager.get_script(name)

    def test_saves_a_valid_script(self):
        payload = self.data("lua_script_save",
                            {"name": "mcp_test",
                             "content": "local x = 1\nreturn x\n"})
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["created"])
        self.assertTrue(payload["validation"]["ok"])
        self.assertIn("nfqws_restart", payload["hint"])
        self.assertIn("local x = 1", self.read())

    def test_broken_syntax_is_refused(self):
        # Битый скрипт не даёт ошибки при СТАРТЕ: обработка обрывается на
        # первом пакете, и стратегия «тихо не работает».
        payload = self.data("lua_script_save",
                            {"name": "mcp_test",
                             "content": "function broken(\n"})
        self.assertFalse(payload["ok"])
        self.assertIn("синтаксис", payload["error"])
        self.assertIn("force=true", payload["hint"])
        self.assertIsNone(self.read())

    def test_force_saves_anyway(self):
        payload = self.data("lua_script_save",
                            {"name": "mcp_test",
                             "content": "function broken(\n",
                             "force": True})
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["forced"])
        self.assertIsNotNone(self.read())

    def test_bad_names_are_refused(self):
        for bad in ("../../etc/passwd", "a/b", "..", "with space"):
            with self.subTest(name=bad):
                payload = self.data("lua_script_save",
                                    {"name": bad, "content": "return 1\n"})
                self.assertFalse(payload["ok"])

    def test_size_limit(self):
        import core.mcp.tools.lists as tools

        saved = tools.MAX_LUA_BYTES
        self.addCleanup(setattr, tools, "MAX_LUA_BYTES", saved)
        tools.MAX_LUA_BYTES = 10
        payload = self.data("lua_script_save",
                            {"name": "mcp_test",
                             "content": "-- " + "x" * 100 + "\n"})
        self.assertFalse(payload["ok"])
        self.assertIn("великоват", payload["error"])

    def test_undo_restores_and_deletes(self):
        self.data("lua_script_save",
                  {"name": "mcp_test", "content": "return 1\n"})
        self.data("lua_script_save",
                  {"name": "mcp_test", "content": "return 2\n"})
        self.assertTrue(self.undo()["reverted"])
        self.assertIn("return 1", self.read())
        self.assertTrue(self.undo()["reverted"])
        self.assertIsNone(self.read())


if __name__ == "__main__":
    unittest.main()
