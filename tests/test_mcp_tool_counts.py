# tests/test_mcp_tool_counts.py
"""
Сколько инструментов публикуется при каждом наборе разрешений.

Зачем таблица цифр. Число инструментов — это контракт с UI (страница
MCP его показывает) и с пользователем, который по нему судит, что
именно он открыл. Инструмент, случайно уехавший в read-only набор
(забыли `scope`, опечатались в имени разрешения), никак иначе не
виден: `tools/list` просто становится на строку длиннее.

**Каждая следующая сессия обновляет `BY_SCOPE`**, добавляя свои
инструменты. Это не формальность: если цифра меняется не там, где
ожидалось, — что-то published не под тем разрешением.
"""

import os
import sys
import unittest

from core.mcp import permissions as perms
from core.mcp import registry


# scope → сколько инструментов его открывает. Отсутствие ключа — ноль.
#
# S2: четыре read-only инструмента-эталона (system_status, nfqws_status,
# config_get, logs_tail). Остальные scope наполняют S5–S13.
# S3: + docs_get, config_describe — справочники, тоже чтение.
# S4: + 13 read-only по nfqws2 — стратегии (5), списки и ассеты (6),
# firewall (1), трафик (1). Все они читают и ничего не меняют, поэтому
# уезжают в тот же набор «без единого разрешения»; write-операции по
# тем же доменам заводит S7.
# S5: + 4 по туннелям и диагностике — tunnels_status, diagnostics_run,
# dpi_report, updates_check. `diagnostics_run` и `updates_check` живут в
# read-наборе НАМЕРЕННО: они публикуются всегда, а разрешение `probes`
# спрашивают за конкретное действие (сетевые пробы, поход в апстрим).
# Спрятать их целиком значило бы спрятать и пассивную часть — ровно то,
# что чинит половину жалоб и не выпускает ни одного пакета.
# S6: + 2 на чтение (config_writable_paths, audit_list) и первые два
# мутирующих — config_set и mcp_undo_last под `config_write`. Запись
# настроек и откат ходят парой: инструмент, который меняет, но не
# умеет вернуть, нарушает инвариант §5.4 контракта.
BY_SCOPE = {
    "read": 25,
    "control": 0,
    "strategies_write": 0,
    "config_write": 2,
    "probes": 0,
    "experiments": 0,
    "tunnels_write": 0,
    "dangerous": 0,
    "shell_readonly": 0,
    "shell_full": 0,
    "self_edit": 0,
    "self_edit_core": 0,
}

ALL_ON = {name: True for name in perms.PERMISSIONS}


class TestToolCounts(unittest.TestCase):

    def setUp(self):
        registry.load_tools()

    def test_table_covers_every_permission(self):
        # Новое разрешение без строки в таблице означает набор
        # инструментов, за которым никто не следит.
        self.assertEqual(set(BY_SCOPE) - {"read"}, set(perms.PERMISSIONS))

    def test_read_only_set(self):
        self.assertEqual(len(registry.available_tools({})), BY_SCOPE["read"])

    def test_every_scope_adds_exactly_its_tools(self):
        base = len(registry.available_tools({}))
        for name in perms.PERMISSIONS:
            granted = {name: True}
            # Зависимости включаем вместе с разрешением, иначе меряем не
            # набор инструментов, а работу REQUIRES (её проверяет
            # test_mcp_permissions).
            for dependency in perms.REQUIRES.get(name, ()):
                granted[dependency] = True
            expected = base + sum(BY_SCOPE[key] for key in granted)
            with self.subTest(permission=name):
                self.assertEqual(len(registry.available_tools(granted)),
                                 expected)

    def test_everything_on(self):
        self.assertEqual(len(registry.available_tools(ALL_ON)),
                         sum(BY_SCOPE.values()))

    def test_total_equals_everything_on(self):
        # Инструмент, не попадающий ни в один набор разрешений, не
        # вызовется никогда — это опечатка в scope, а не фича.
        self.assertEqual(len(registry.all_tools()),
                         len(registry.available_tools(ALL_ON)))

    def test_scope_counts_matches_the_table(self):
        counts = registry.scope_counts(ALL_ON)
        for scope, expected in BY_SCOPE.items():
            with self.subTest(scope=scope):
                self.assertEqual(counts.get(scope, 0), expected)

    READ_TOOLS = [
        # S2 — эталоны
        "config_get", "logs_tail", "nfqws_status", "system_status",
        # S3 — справочники
        "config_describe", "docs_get",
        # S4 — стратегии
        "catalog_search", "nfqws_command_preview", "strategy_get",
        "strategy_list", "strategy_state_list",
        # S4 — списки и ассеты
        "blobs_list", "hostlist_get", "hostlists_list", "ipsets_list",
        "lists_list", "lua_functions_list",
        # S4 — перехват и трафик
        "firewall_status", "traffic_recent",
        # S5 — туннели, диагностика, обновления
        "diagnostics_run", "dpi_report", "tunnels_status", "updates_check",
        # S6 — что можно менять и что уже менялось
        "audit_list", "config_writable_paths",
    ]

    def test_read_tools_are_named_in_the_table(self):
        names = sorted(spec.name for spec in registry.available_tools({}))
        self.assertEqual(names, sorted(self.READ_TOOLS))

    def test_the_named_table_matches_the_count(self):
        # Две записи об одном и том же расходятся молча: список имён
        # правят, число — забывают (или наоборот).
        self.assertEqual(len(self.READ_TOOLS), BY_SCOPE["read"])


class TestAutoload(unittest.TestCase):
    """Новый модуль в core/mcp/tools/ подхватывается сам.

    Это приёмка S2: следующие сессии кладут файл и объявляют `@tool` —
    и ничего больше. Если однажды реестр потребует правки списка,
    кто-нибудь её забудет, и инструмент молча не появится.
    """

    MODULE = "zz_autoload_probe"

    def setUp(self):
        self.path = os.path.join(os.path.dirname(registry.__file__),
                                 "tools", "%s.py" % self.MODULE)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)
        registry._REGISTRY.pop("zz_probe_tool", None)
        sys.modules.pop("core.mcp.tools.%s" % self.MODULE, None)
        registry.load_tools(force=True)

    def test_new_module_appears_without_touching_the_registry(self):
        before = {spec.name for spec in registry.all_tools()}
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(
                "from core.mcp.registry import tool\n\n\n"
                "@tool(name='zz_probe_tool', scope='read', mutating=False,\n"
                "      title='Probe', description='probe / проба',\n"
                "      schema={'type': 'object', 'properties': {}})\n"
                "def zz_probe_tool(args):\n"
                "    return {'ok': True}\n")
        registry.load_tools(force=True)
        after = {spec.name for spec in registry.all_tools()}
        self.assertEqual(after - before, {"zz_probe_tool"})
        self.assertFalse(
            registry.call("zz_probe_tool", {}, {})["isError"])


if __name__ == "__main__":
    unittest.main()
