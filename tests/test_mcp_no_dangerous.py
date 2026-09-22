# tests/test_mcp_no_dangerous.py
"""
Чего в MCP нет и не должно появиться.

Инвариант §5.7 контракта: **инструмента ``teardown`` не существует**.
Снос runtime-артефактов (правила, интерфейсы, установленные бинарники,
каталоги zapret2) — операция, которую делают осознанно, с консолью под
рукой, а не «чтобы начать с чистого листа» посреди диалога с моделью.
Такой инструмент однажды кто-нибудь добавит «для симметрии» — этот
файл существует затем, чтобы такой PR упал.

Здесь же — перезагрузка, единственная по-настоящему разрушительная
операция, которая всё-таки есть:

* она живёт под отдельным разрешением ``dangerous`` (не «заодно» с
  shell);
* она **не выполняется одним вызовом**: первый возвращает токен,
  исполняет ``shell_confirm``;
* разрешение проверяется на ОБОИХ шагах — токен сам по себе прав не
  даёт;
* и она идёт через ``core/system_control.py`` (на Keenetic — ``ndmc``),
  отложенно и в отвязанном процессе, чтобы ответ успел уйти.

Настоящий ``reboot`` тест, разумеется, не зовёт: ``system_control``
подменяется.
"""

import unittest
from unittest import mock

from core.mcp import permissions as perms_mod
from core.mcp import registry
from tests._shell_sandbox import Sandbox


DANGEROUS = {"dangerous": True}
FULL = {"shell_full": True}
ALL_ON = {name: True for name in perms_mod.PERMISSIONS}


class TestNoTeardown(unittest.TestCase):
    """Разрушительных «сделай как было с завода» инструментов нет."""

    FORBIDDEN = ("teardown", "factory_reset", "uninstall", "wipe",
                 "purge", "reset_all", "nfqws_teardown",
                 "system_factory_reset", "self_destruct")

    def setUp(self):
        registry.load_tools()

    def test_no_teardown_tool_exists(self):
        names = {spec.name for spec in registry.all_tools()}
        for forbidden in self.FORBIDDEN:
            with self.subTest(tool=forbidden):
                self.assertNotIn(forbidden, names)

    def test_nothing_new_hides_under_dangerous(self):
        # Под `dangerous` живут ровно две вещи, и обе названы поимённо:
        # перезагрузка (S12) и переприменение ВСЕЙ маршрутизации (S17,
        # `unified_reapply_all`) — он не правит одну запись, а сносит
        # «левые» ip rule и раскладывает картину маршрутов заново, то
        # есть на секунды меняет всё сразу, включая путь, которым ходит
        # сам админ. Появился третий — он обязан быть описан и в скиле,
        # и здесь.
        names = sorted(spec.name for spec in registry.all_tools()
                       if spec.scope == "dangerous")
        self.assertEqual(names, ["system_reboot", "unified_reapply_all"])


class TestReboot(unittest.TestCase):
    """Перезагрузка: только под `dangerous` и только в два шага."""

    def setUp(self):
        import core.system_control as system_control

        self.box = Sandbox(self, DANGEROUS)
        # Подменяем ФУНКЦИИ модуля, а не сам модуль в sys.modules:
        # `from core import system_control` берёт уже импортированный
        # атрибут пакета, и подмена в sys.modules мимо него проезжает —
        # в одиночку тест проходил, в общем прогоне звал настоящий
        # reboot.
        self.control = system_control
        caps = mock.Mock(return_value={
            "ok": True, "reboot": True, "restart_gui": True,
            "reboot_command": 'ndmc -c "system reboot"',
            "restart_command": "",
        })
        reboot = mock.Mock(return_value={
            "ok": True, "command": 'ndmc -c "system reboot"',
            "delay_sec": 2, "message": "Устройство перезагружается."})
        for name, replacement in (("capabilities", caps),
                                  ("reboot_device", reboot)):
            patcher = mock.patch.object(system_control, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_not_available_without_dangerous(self):
        for granted in ({}, FULL, {"control": True, "shell_full": True}):
            with self.subTest(perms=sorted(granted)):
                names = {s.name for s in registry.available_tools(granted)}
                self.assertNotIn("system_reboot", names)

    def test_call_by_name_without_permission_is_refused(self):
        self.box.permissions(shell_full=True)
        call = self.box.call("system_reboot", {}, FULL)
        self.assertTrue(call["isError"])
        self.assertEqual(call["structuredContent"]["permission"],
                         "dangerous")
        self.control.reboot_device.assert_not_called()

    def test_first_call_only_returns_a_token(self):
        result = self.box.data("system_reboot", {"reason": "тест"},
                               DANGEROUS)
        self.assertFalse(result["ok"])
        self.assertTrue(result["need_confirm"])
        self.assertTrue(result["confirm_token"].startswith("cf-"))
        self.assertIn("1–2 минуты", result["consequences"])
        self.control.reboot_device.assert_not_called()

    def test_confirmation_reboots_through_system_control(self):
        first = self.box.data("system_reboot", {"reason": "тест"},
                              DANGEROUS)
        self.box.permissions(dangerous=True, shell_readonly=True)
        second = self.box.data("shell_confirm",
                               {"confirm_token": first["confirm_token"]},
                               {"dangerous": True, "shell_readonly": True})
        self.assertTrue(second["ok"])
        self.assertTrue(second["confirmed"])
        self.control.reboot_device.assert_called_once_with()

    def test_token_alone_does_not_grant_dangerous(self):
        # Токен выдан под `dangerous`; снимаем разрешение и пробуем
        # подтвердить — исполниться не должно.
        first = self.box.data("system_reboot", {}, DANGEROUS)
        self.box.permissions(shell_readonly=True)
        second = self.box.data("shell_confirm",
                               {"confirm_token": first["confirm_token"]},
                               {"shell_readonly": True})
        self.assertFalse(second["ok"])
        self.assertEqual(second["permission"], "dangerous")
        self.control.reboot_device.assert_not_called()

    def test_missing_reboot_command_is_an_honest_answer(self):
        self.control.capabilities.return_value = {
            "ok": True, "reboot": False, "reboot_command": ""}
        result = self.box.data("system_reboot", {}, DANGEROUS)
        self.assertFalse(result["ok"])
        self.assertNotIn("confirm_token", result)
        self.assertIn("не найдена", result["error"])


class TestShellCannotEscalate(unittest.TestCase):
    """Shell не должен становиться обходным путём к чужим правам."""

    def setUp(self):
        self.box = Sandbox(self, {"shell_full": True})

    def test_shell_full_does_not_open_dangerous_tools(self):
        names = {s.name for s in registry.available_tools(FULL)}
        self.assertNotIn("system_reboot", names)
        self.assertNotIn("strategy_apply", names)
        self.assertNotIn("config_set", names)

    def test_shell_full_opens_only_shell_readonly_along_with_it(self):
        effective = perms_mod.effective({"shell_full": True})
        opened = [k for k, v in effective.items() if v]
        self.assertEqual(sorted(opened), ["shell_full", "shell_readonly"])

    def test_reboot_through_shell_still_needs_confirmation(self):
        # Обойти двухшаговость, позвав `reboot` командой, тоже нельзя.
        result = self.box.data("shell_exec", {"command": "reboot"}, FULL)
        self.assertFalse(result["ok"])
        self.assertTrue(result["need_confirm"])


if __name__ == "__main__":
    unittest.main()
