# tests/test_mcp_permissions.py
"""
Модель разрешений MCP (core/mcp/permissions.py + реестр).

Проверяется то, из-за чего разрешения перестают быть защитой:
переключатель, который не влияет на `tools/list`; инструмент, который
зовётся по имени в обход списка; зависимость `experiments` →
`control`+`probes`, выключенная молча (пользователь видит включённый
флаг и не понимает, почему ничего не работает).

Отдельно — граница записи настроек: она проходит по обратимости, а не
по чувствительности, и именно поэтому её легко «улучшить» в сторону
дыры.
"""

import unittest

from core.mcp import permissions as perms
from core.mcp import registry, server


def call(method, params=None, ctx=None):
    message = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        message["params"] = params
    return server.dispatch(message, ctx or {})


class _WithTempTool(unittest.TestCase):
    """База: временный инструмент с заданным scope."""

    NAME = "test_temp_tool"
    SCOPE = "control"

    def setUp(self):
        registry.load_tools()

        @registry.tool(name=self.NAME, scope=self.SCOPE, mutating=True,
                       title="Temp", description="temp tool / временный",
                       schema={"type": "object", "properties": {}})
        def _handler(args):
            return {"ok": True, "called": True}

    def tearDown(self):
        registry._REGISTRY.pop(self.NAME, None)


class TestToolsListFollowsPermissions(_WithTempTool):

    def names(self, perms_map):
        result = call("tools/list", ctx={"permissions": perms_map})
        return {t["name"] for t in result["result"]["tools"]}

    def test_switch_off_hides_the_tool(self):
        self.assertNotIn(self.NAME, self.names({}))

    def test_switch_on_shows_it_without_restart(self):
        # Разрешения читаются на каждый запрос: перезапуск GUI после
        # переключения галочки — это не «так задумано», это баг.
        self.assertIn(self.NAME, self.names({"control": True}))

    def test_read_tools_are_always_listed(self):
        for name in ("system_status", "config_get", "logs_tail"):
            self.assertIn(name, self.names({}))


class TestForbiddenCallByName(_WithTempTool):

    def test_call_by_name_is_refused_with_a_hint(self):
        # Инструмента нет в списке — но клиент знает его имя из
        # документации. Проверка обязана быть на вызове, а не на выдаче.
        result = call("tools/call", {"name": self.NAME},
                      ctx={"permissions": {}})["result"]
        self.assertTrue(result["isError"])
        payload = result["structuredContent"]
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["permission"], "control")
        self.assertIn("control", payload["hint"])
        self.assertNotIn("called", payload)

    def test_call_allowed_when_permission_granted(self):
        result = call("tools/call", {"name": self.NAME},
                      ctx={"permissions": {"control": True}})["result"]
        self.assertFalse(result["isError"])
        self.assertTrue(result["structuredContent"]["called"])


class TestDependencies(unittest.TestCase):

    def test_experiments_needs_control_and_probes(self):
        granted = {"experiments": True}
        self.assertFalse(perms.effective(granted)["experiments"])
        self.assertEqual(perms.unmet("experiments", granted),
                         ["control", "probes"])

    def test_experiments_works_with_both(self):
        granted = {"experiments": True, "control": True, "probes": True}
        self.assertTrue(perms.effective(granted)["experiments"])

    def test_half_of_the_dependencies_is_not_enough(self):
        granted = {"experiments": True, "control": True}
        self.assertFalse(perms.effective(granted)["experiments"])
        self.assertEqual(perms.unmet("experiments", granted), ["probes"])

    def test_reason_is_returned_not_silently_ignored(self):
        # Самый непонятный случай: флаг стоит, а инструмента нет. Текст
        # обязан назвать недостающее — иначе пользователь чинит не то.
        granted = {"experiments": True, "control": True}
        denial = perms.denial("experiments", granted)
        self.assertIn("probes", denial["error"])
        self.assertIn("probes", denial["hint"])
        self.assertEqual(denial["missing"], ["probes"])
        self.assertEqual(denial["requires"], ["control", "probes"])

    def test_self_edit_core_needs_self_edit(self):
        self.assertFalse(perms.effective({"self_edit_core": True})
                         ["self_edit_core"])
        self.assertTrue(perms.effective({"self_edit_core": True,
                                         "self_edit": True})
                        ["self_edit_core"])

    def test_missing_key_means_false(self):
        # Новая настройка не становится доступной на запись сама по себе.
        self.assertEqual(set(perms.normalize({})), set(perms.PERMISSIONS))
        self.assertFalse(any(perms.normalize({}).values()))

    def test_read_is_always_allowed(self):
        self.assertTrue(perms.allowed(None, {}))
        self.assertTrue(perms.allowed("read", {}))

    def test_describe_shows_granted_and_effective(self):
        table = {row["key"]: row
                 for row in perms.describe({"experiments": True})}
        self.assertTrue(table["experiments"]["granted"])
        self.assertFalse(table["experiments"]["effective"])
        self.assertEqual(table["experiments"]["missing"],
                         ["control", "probes"])


class TestWritableBoundary(unittest.TestCase):

    def test_whitelisted_leaf_is_writable(self):
        self.assertTrue(perms.is_writable("nfqws.ports_tcp"))
        self.assertTrue(perms.is_writable("filter.mode"))
        self.assertTrue(perms.is_writable("logging.level"))

    def test_section_as_a_whole_is_not(self):
        # Запись пачкой обошла бы проверку запрещённых листьев внутри.
        self.assertFalse(perms.is_writable("nfqws"))
        self.assertFalse(perms.is_writable(""))

    def test_interception_knobs_are_denied(self):
        for path in ("nfqws.queue_num", "nfqws.user", "nfqws.desync_mark",
                     "nfqws.desync_mark_postnat", "firewall.type"):
            self.assertFalse(perms.is_writable(path), path)

    def test_gui_and_mcp_are_denied(self):
        # gui.* — можно потерять способ отменить изменение;
        # mcp.* — модель не расширяет собственные права.
        for path in ("gui.port", "gui.host", "gui.auth_password",
                     "mcp.permissions.shell_full", "mcp.token",
                     "mcp.enabled"):
            self.assertFalse(perms.is_writable(path), path)

    def test_locations_are_denied_but_content_is_not(self):
        # Неверный путь не ломает громко — он тихо выключает часть
        # логики. Содержимое списков модель правит через strategies_write.
        self.assertFalse(perms.is_writable("zapret.lists_path"))
        self.assertFalse(perms.is_writable("logging.file_path"))
        self.assertFalse(perms.is_writable("logging.persist_path"))
        self.assertTrue(perms.is_writable("logging.file_enabled"))

    def test_reason_is_human_readable(self):
        self.assertIn("расположение",
                      perms.why_not_writable("logging.file_path"))
        self.assertIn("nfqws.queue_num",
                      perms.why_not_writable("nfqws.queue_num"))
        self.assertEqual(perms.why_not_writable("nfqws.ports_tcp"), "")

    def test_writable_paths_carry_type_and_value(self):
        by_path = {item["path"]: item for item in perms.writable_paths()}
        self.assertIn("filter.mode", by_path)
        self.assertEqual(by_path["filter.mode"]["type"], "string")
        self.assertIn("none", by_path["filter.mode"]["enum"])
        self.assertEqual(by_path["nfqws.ports_tcp"]["type"], "string")
        self.assertNotIn("nfqws.queue_num", by_path)

    def test_every_writable_path_passes_is_writable(self):
        for item in perms.writable_paths():
            self.assertTrue(perms.is_writable(item["path"]), item["path"])


class TestProbesBoundary(unittest.TestCase):
    """S8: выпустить трафик — отдельное разрешение, и оно режет ДЕЙСТВИЕ.

    Граница проходит не по инструменту, а по тому, что он делает:
    `healthcheck_status` и `scan_status` только читают состояние и
    доступны всегда, `healthcheck_run` и `scan_start` выпускают пробы —
    и без `probes` их нет ни в списке, ни по имени.
    """

    PROBING = ("probe_targets", "probe_compare", "scan_start", "scan_stop",
               "blockcheck_start", "blockcheck2_start", "blockcheck2_stop",
               "healthcheck_run")
    READING = ("scan_status", "scan_results", "blockcheck_status",
               "blockcheck2_status", "blockcheck2_output",
               "healthcheck_status", "connectivity_matrix",
               # S5 — тот же приём: публикуется всегда, пробы по
               # разрешению. Поведение не должно измениться.
               "diagnostics_run", "dpi_report", "updates_check")

    def setUp(self):
        registry.load_tools()

    def names(self, perms_map):
        result = call("tools/list", ctx={"permissions": perms_map})
        return {t["name"] for t in result["result"]["tools"]}

    def test_probing_tools_are_hidden_without_the_permission(self):
        listed = self.names({})
        for name in self.PROBING:
            with self.subTest(tool=name):
                self.assertNotIn(name, listed)

    def test_reading_tools_are_listed_anyway(self):
        listed = self.names({})
        for name in self.READING:
            with self.subTest(tool=name):
                self.assertIn(name, listed)

    def test_probing_tools_appear_with_the_permission(self):
        listed = self.names({"probes": True})
        for name in self.PROBING:
            with self.subTest(tool=name):
                self.assertIn(name, listed)

    def test_call_by_name_is_refused_and_names_the_switch(self):
        # Отказ, не называющий переключатель, заставляет модель гадать —
        # и она гадает, пробуя соседние инструменты.
        for name in self.PROBING:
            result = call("tools/call", {"name": name, "arguments": {}},
                          ctx={"permissions": {}})["result"]
            with self.subTest(tool=name):
                self.assertTrue(result["isError"])
                payload = result["structuredContent"]
                self.assertEqual(payload["permission"], "probes")
                self.assertIn("probes", payload["hint"])

    def test_healthcheck_reads_but_does_not_run(self):
        # Ровно тот случай, ради которого инструмент не прячется
        # целиком: расписание и история видны, прогон — нет.
        listed = self.names({})
        self.assertIn("healthcheck_status", listed)
        self.assertNotIn("healthcheck_run", listed)


if __name__ == "__main__":
    unittest.main()
