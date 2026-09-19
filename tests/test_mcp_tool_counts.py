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
# мутирующих — config_set и mcp_undo_last. Запись настроек и откат ходят
# парой: инструмент, который меняет, но не умеет вернуть, нарушает
# инвариант §5.4 контракта.
# S7: + 7 под `control` (движок: start/stop/restart/reload_lists,
# strategy_apply; правила перехвата: firewall_apply/firewall_remove) и
# + 6 под `strategies_write` (strategy_save/strategy_delete,
# hostlist_edit, ipset_edit, blob_add, lua_script_save). Тогда же
# `mcp_undo_last` уехал из `config_write` в псевдо-scope `any_write`:
# снимки бывают шести видов, и модель с `strategies_write` без
# `config_write` иначе получила бы право менять стратегии без права их
# вернуть.
# S8: + 8 под `probes` (пробы: probe_targets/probe_compare; сканер:
# scan_start/scan_stop; диагностика: blockcheck_start,
# blockcheck2_start/blockcheck2_stop, healthcheck_run) и + 7 на чтение
# (scan_status, scan_results, blockcheck_status, blockcheck2_status,
# blockcheck2_output, healthcheck_status, connectivity_matrix). Опрос
# задачи и её результаты — чтение: они не выпускают ни одного пакета, а
# без них асинхронный контракт («*_start отдаёт job_id, дальше
# опрашивай») не работает вовсе. `scan_apply` уехал в `control`: он
# поднимает движок и сверх того требует `strategies_write`, потому что
# сохраняет найденное как USER-стратегию.
# S10: + 7 под `experiments` — движок экспериментов целиком
# (strategy_experiment_start/_status/_result/_commit/_rollback/_stop/
# _history). Опрос и отчёт НЕ вынесены в чтение, как у сканера: у
# сканера статус описывает прогон, запущенный кем угодно, а здесь и
# статус, и отчёт — результат изменений, которые внесла сама модель, и
# открывать их без права эти изменения делать незачем. Само разрешение
# не действует без `control` и `probes` (см. test_mcp_permissions).
# S11: + 2 под `strategies_write` — strategy_compose и strategy_validate.
# Оба НЕ мутирующие: собрать стратегию и прогнать её через
# `nfqws2 --intercept=0` — это чтение, ничего на устройстве не меняется.
# Разрешение здесь не про «мы что-то пишем», а про то, что собранное
# предназначено для записи: модель, которой не дали править стратегии,
# собирать их вслепую тоже незачем.
# S12: + 11 под `shell_readonly` (команды: shell_exec, shell_exec_async,
# shell_job_status/_output/_stop, shell_confirm; файлы: file_read,
# file_list; система: package_list, service_list, service_control),
# + 3 под `shell_full` (file_write, package_install, package_remove) и
# + 1 под `dangerous` (system_reboot). `shell_exec` и `service_control`
# объявлены под `shell_readonly`, а `shell_full` спрашивают ПО МЕСТУ:
# один инструмент, два действия (safe-список против произвольной
# команды, status против start/stop) — как `scan_apply` спрашивает
# `strategies_write`. Сам `shell_full` включает `shell_readonly`
# (`permissions.IMPLIES`): кому отдали root, тому `df -h` уже отдали.
BY_SCOPE = {
    "read": 32,
    "control": 8,
    "strategies_write": 8,
    "config_write": 1,
    "probes": 8,
    "experiments": 7,
    "tunnels_write": 0,
    "dangerous": 1,
    "shell_readonly": 11,
    "shell_full": 3,
    "self_edit": 0,
    "self_edit_core": 0,
    # Псевдо-scope: открывается ЛЮБЫМ разрешением на запись, поэтому в
    # арифметике «каждое разрешение добавляет ровно свои» он считается
    # отдельно (см. test_every_scope_adds_exactly_its_tools).
    perms.ANY_WRITE_SCOPE: 1,
}

ALL_ON = {name: True for name in perms.PERMISSIONS}


class TestToolCounts(unittest.TestCase):

    def setUp(self):
        registry.load_tools()

    def test_table_covers_every_permission(self):
        # Новое разрешение без строки в таблице означает набор
        # инструментов, за которым никто не следит.
        self.assertEqual(set(BY_SCOPE) - {"read", perms.ANY_WRITE_SCOPE},
                         set(perms.PERMISSIONS))

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
            # А вложенные разрешения (`shell_full` → `shell_readonly`)
            # включаются сами: их инструменты тоже становятся видны.
            counted = dict(granted)
            for opened in perms.IMPLIES.get(name, ()):
                counted[opened] = True
            expected = base + sum(BY_SCOPE[key] for key in counted)
            if any(key in perms.WRITE_PERMISSIONS for key in granted):
                # Откат публикуется при любом разрешении на запись.
                expected += BY_SCOPE[perms.ANY_WRITE_SCOPE]
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
        # S8 — опрос задач и их результаты (пакетов не выпускают)
        "blockcheck2_output", "blockcheck2_status", "blockcheck_status",
        "connectivity_matrix", "healthcheck_status", "scan_results",
        "scan_status",
    ]

    # S7 — мутирующие наборы. Список имён рядом с числом: две записи об
    # одном и том же расходятся молча.
    CONTROL_TOOLS = [
        "firewall_apply", "firewall_remove", "nfqws_reload_lists",
        "nfqws_restart", "nfqws_start", "nfqws_stop", "scan_apply",
        "strategy_apply",
    ]
    STRATEGIES_WRITE_TOOLS = [
        "blob_add", "hostlist_edit", "ipset_edit", "lua_script_save",
        "strategy_delete", "strategy_save",
        # S11 — сборка и проверка; записи не делают, но открываются тем
        # же разрешением.
        "strategy_compose", "strategy_validate",
    ]
    # S10 — движок экспериментов: и мутирующие, и опрос под одним
    # разрешением.
    EXPERIMENTS_TOOLS = [
        "strategy_experiment_commit", "strategy_experiment_history",
        "strategy_experiment_result", "strategy_experiment_rollback",
        "strategy_experiment_start", "strategy_experiment_status",
        "strategy_experiment_stop",
    ]
    # S12 — shell и система. `shell_exec`/`service_control` объявлены
    # под `shell_readonly`, потому что под ним они и работают (safe-
    # список, status); `shell_full` они спрашивают по месту.
    SHELL_READONLY_TOOLS = [
        "file_list", "file_read", "package_list", "service_control",
        "service_list", "shell_confirm", "shell_exec", "shell_exec_async",
        "shell_job_output", "shell_job_status", "shell_job_stop",
    ]
    SHELL_FULL_TOOLS = ["file_write", "package_install", "package_remove"]
    DANGEROUS_TOOLS = ["system_reboot"]

    # S8 — всё, что выпускает трафик с роутера.
    PROBES_TOOLS = [
        "blockcheck2_start", "blockcheck2_stop", "blockcheck_start",
        "healthcheck_run", "probe_compare", "probe_targets",
        "scan_start", "scan_stop",
    ]

    def test_read_tools_are_named_in_the_table(self):
        names = sorted(spec.name for spec in registry.available_tools({}))
        self.assertEqual(names, sorted(self.READ_TOOLS))

    def test_the_named_table_matches_the_count(self):
        # Две записи об одном и том же расходятся молча: список имён
        # правят, число — забывают (или наоборот).
        self.assertEqual(len(self.READ_TOOLS), BY_SCOPE["read"])
        self.assertEqual(len(self.CONTROL_TOOLS), BY_SCOPE["control"])
        self.assertEqual(len(self.STRATEGIES_WRITE_TOOLS),
                         BY_SCOPE["strategies_write"])
        self.assertEqual(len(self.PROBES_TOOLS), BY_SCOPE["probes"])
        self.assertEqual(len(self.EXPERIMENTS_TOOLS),
                         BY_SCOPE["experiments"])
        self.assertEqual(len(self.SHELL_READONLY_TOOLS),
                         BY_SCOPE["shell_readonly"])
        self.assertEqual(len(self.SHELL_FULL_TOOLS), BY_SCOPE["shell_full"])
        self.assertEqual(len(self.DANGEROUS_TOOLS), BY_SCOPE["dangerous"])

    def test_write_tools_are_named_in_the_table(self):
        for scope, expected in (("control", self.CONTROL_TOOLS),
                                ("strategies_write",
                                 self.STRATEGIES_WRITE_TOOLS),
                                ("probes", self.PROBES_TOOLS),
                                ("experiments",
                                 self.EXPERIMENTS_TOOLS),
                                ("shell_readonly",
                                 self.SHELL_READONLY_TOOLS),
                                ("shell_full", self.SHELL_FULL_TOOLS),
                                ("dangerous", self.DANGEROUS_TOOLS)):
            names = sorted(spec.name for spec in registry.all_tools()
                           if spec.scope == scope)
            with self.subTest(scope=scope):
                self.assertEqual(names, sorted(expected))

    # Инструменты под разрешением на запись, которые НИЧЕГО не меняют
    # (S11). Разрешение у них не про «мы пишем», а про то, что собранное
    # предназначено для записи: модель, которой не дали править
    # стратегии, собирать их вслепую тоже незачем. Список поимённый —
    # чтобы следующий мутирующий инструмент не проехал сюда молча.
    READ_ONLY_UNDER_WRITE = {"strategy_compose", "strategy_validate"}

    # Обратный случай (S12): инструмент объявлен мутирующим под
    # `shell_readonly`, хотя под этим разрешением он только читает.
    # Так честнее: тот же вызов с `shell_full` меняет устройство, и
    # уехать клиенту с пометкой readOnlyHint он не должен.
    MUTATING_UNDER_READONLY_SHELL = {"shell_exec", "shell_exec_async",
                                     "shell_job_stop", "shell_confirm",
                                     "service_control"}

    def test_mutating_tools_declare_it(self):
        # Инструмент, меняющий устройство под видом чтения, уехал бы
        # клиенту с пометкой readOnlyHint — и модель применила бы его
        # «чтобы посмотреть».
        for spec in registry.all_tools():
            if spec.name in self.READ_ONLY_UNDER_WRITE:
                continue
            if spec.scope in ("control", "strategies_write",
                              perms.ANY_WRITE_SCOPE):
                with self.subTest(tool=spec.name):
                    self.assertTrue(spec.mutating)

    def test_shell_write_tools_declare_mutating(self):
        # Инструмент, который под `shell_full` меняет устройство, обязан
        # быть объявлен мутирующим — независимо от того, что под
        # `shell_readonly` он только читает.
        by_name = {spec.name: spec for spec in registry.all_tools()}
        for name in (self.SHELL_FULL_TOOLS + self.DANGEROUS_TOOLS
                     + sorted(self.MUTATING_UNDER_READONLY_SHELL)):
            with self.subTest(tool=name):
                self.assertIn(name, by_name)
                self.assertTrue(by_name[name].mutating)

    def test_shell_read_tools_are_not_mutating(self):
        for name in ("file_read", "file_list", "package_list",
                     "service_list", "shell_job_status",
                     "shell_job_output"):
            with self.subTest(tool=name):
                spec = registry.get_tool(name)
                self.assertIsNotNone(spec)
                self.assertFalse(spec.mutating)

    def test_the_read_only_exceptions_really_are_read_only(self):
        # Обратная сторона списка исключений: запись, попавшая в него по
        # ошибке, иначе осталась бы без единой проверки.
        by_name = {spec.name: spec for spec in registry.all_tools()}
        for name in self.READ_ONLY_UNDER_WRITE:
            with self.subTest(tool=name):
                self.assertIn(name, by_name)
                self.assertFalse(by_name[name].mutating)


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
