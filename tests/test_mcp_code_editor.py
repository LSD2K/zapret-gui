# tests/test_mcp_code_editor.py
"""
Самоправка кода GUI: границы, staging, проверки, снимки (S13).

Главное, что здесь фиксируется, — **правка с ошибкой до диска не
доезжает**. Это свойство механики, а не аккуратности вызывающего:
``code_patch``/``code_write`` пишут в staging, а на место файлы
кладёт только ``code_apply``, и то после проверок.

Второе по важности — границы. Каталог установки GUI, ``..``, симлинк
наружу, абсолютный путь мимо корня, защищённое ядро без
``self_edit_core``: каждый из этих случаев обязан быть отказом, а не
записью «куда-то рядом».
"""

import os
import unittest
from unittest import mock

from core import code_editor as editor
from core import system_control
from tests._code_sandbox import CodeSandbox


ALLOW = {"self_edit": True}
ALLOW_CORE = {"self_edit": True, "self_edit_core": True}


class CodeCase(unittest.TestCase):
    """Общая песочница: конфиг, «проект», разрешения."""

    permissions = ALLOW

    def setUp(self):
        self.box = CodeSandbox(self, permissions=dict(self.permissions))

    def call(self, name, args=None):
        return self.box.data(name, args or {})

    def patch(self, path, old, new):
        return self.call("code_patch",
                         {"path": path, "edits": [{"old": old,
                                                   "new": new}]})

    def apply(self, reason="правка теста", **extra):
        """``code_apply`` с подменёнными сторожем и перезапуском.

        Настоящий сторож — отвязанный процесс, настоящий перезапуск —
        смерть интерпретатора, в котором идёт тест.
        """
        args = {"reason": reason, "restart": False}
        args.update(extra)
        with mock.patch.object(editor, "start_guard",
                               return_value={"ok": True, "pid": 4242}) \
                as guard, \
                mock.patch.object(system_control, "restart_gui",
                                  return_value={"ok": True}):
            result = self.box.data("code_apply", args)
        self.guard_calls = guard.call_args_list
        return result


class TestBoundaries(CodeCase):
    """Править можно только каталог установки GUI."""

    def test_parent_escape_is_refused(self):
        result = self.call("code_read", {"path": "../../etc/passwd"})
        self.assertFalse(result["ok"])
        self.assertIn("вне каталога установки", result["error"])

    def test_absolute_path_outside_root_is_refused(self):
        result = self.call("code_read", {"path": "/etc/passwd"})
        self.assertFalse(result["ok"])
        self.assertIn("вне каталога установки", result["error"])

    def test_symlink_out_of_the_tree_is_refused(self):
        # Симлинк изнутри проекта наружу — готовая дыра: проверять надо
        # резолвнутый путь, а не написанный.
        outside = os.path.join(self.box.dir, "outside.py")
        with open(outside, "w", encoding="utf-8") as f:
            f.write("SECRET = 1\n")
        link = self.box.full("core/escape.py")
        os.symlink(outside, link)
        result = self.call("code_read", {"path": "core/escape.py"})
        self.assertFalse(result["ok"])
        self.assertIn("вне каталога установки", result["error"])

    def test_symlinked_directory_is_resolved_too(self):
        outside = os.path.join(self.box.dir, "elsewhere")
        os.makedirs(outside, exist_ok=True)
        os.symlink(outside, self.box.full("core/away"))
        result = self.call("code_write", {"path": "core/away/new.py",
                                          "content": "X = 1\n"})
        self.assertFalse(result["ok"])
        self.assertFalse(os.path.exists(os.path.join(outside, "new.py")))

    def test_own_settings_file_is_never_editable(self):
        # settings.json лежит вне корня, но если конфиг окажется внутри
        # него, запись туда всё равно запрещена: иначе модель дописала
        # бы себе разрешения.
        self.box.put("settings.json", "{}\n")
        result = self.call("code_write", {"path": "settings.json",
                                          "content": "{}"})
        self.assertFalse(result["ok"])
        self.assertIn("собственный файл GUI", result["error"])

    def test_relative_path_is_the_normal_way(self):
        result = self.call("code_read", {"path": "core/demo.py"})
        self.assertTrue(result["ok"])
        self.assertIn("def compose", result["content"])
        self.assertEqual(result["path"], "core/demo.py")


class TestProtectedCore(CodeCase):
    """Защищённое ядро требует отдельного разрешения."""

    def test_protected_file_needs_self_edit_core(self):
        result = self.patch("core/config_manager.py", "X = 1", "X = 2")
        self.assertFalse(result["ok"])
        self.assertEqual(result["permission"], "self_edit_core")
        self.assertTrue(result["protected"])
        self.assertEqual(editor.staging_summary()["count"], 0)

    def test_guard_itself_is_protected_by_the_code(self):
        # Список из настроек — пол, а не потолок: сторожа и границы
        # нельзя расчехлить, убрав их из settings.json.
        self.assertTrue(editor.is_protected("core/code_guard.py"))
        self.assertTrue(editor.is_protected("core/code_editor.py"))
        self.assertTrue(editor.is_protected("core/mcp/permissions.py"))

    def test_with_the_permission_it_goes_through(self):
        self.box.permissions(self_edit=True, self_edit_core=True)
        result = self.patch("core/config_manager.py", "X = 1", "X = 2")
        self.assertTrue(result["ok"])
        self.assertTrue(result["protected"])

    def test_apply_rechecks_the_permission(self):
        # Разрешение могли выключить между правкой и применением.
        self.box.permissions(self_edit=True, self_edit_core=True)
        self.assertTrue(self.patch("core/config_manager.py",
                                   "X = 1", "X = 2")["ok"])
        self.box.permissions(self_edit=True)
        result = self.apply()
        self.assertFalse(result["ok"])
        self.assertEqual(result["permission"], "self_edit_core")
        self.assertEqual(self.box.text("core/config_manager.py"),
                         "# защищённый файл песочницы\nX = 1\n")


class TestPatching(CodeCase):
    """Точечная правка: точное и единственное совпадение."""

    def test_ambiguous_match_is_refused(self):
        self.box.put("core/dup.py", "A = 1\nB = 1\nC = 1\n")
        result = self.patch("core/dup.py", " = 1", " = 2")
        self.assertFalse(result["ok"])
        self.assertEqual(result["occurrences"], 3)
        self.assertIn("найден 3 раза", result["error"])

    def test_missing_fragment_is_refused(self):
        result = self.patch("core/demo.py", "VALUE = 42", "VALUE = 43")
        self.assertFalse(result["ok"])
        self.assertIn("не найден", result["error"])

    def test_edit_goes_to_staging_not_to_disk(self):
        result = self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        self.assertTrue(result["ok"])
        self.assertTrue(result["staged"])
        self.assertFalse(result["applied"])
        self.assertIn("VALUE = 7", result["diff"])
        self.assertIn("VALUE = 1", self.box.text("core/demo.py"))

    def test_second_patch_sees_the_first(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        result = self.patch("core/demo.py", "VALUE = 7", "VALUE = 8")
        self.assertTrue(result["ok"])
        self.assertIn("VALUE = 8",
                      editor.staged_bytes("core/demo.py").decode())

    def test_no_op_edit_is_refused(self):
        result = self.patch("core/demo.py", "VALUE = 1", "VALUE = 1")
        self.assertFalse(result["ok"])
        self.assertIn("ничего не меняет", result["error"])

    def test_unified_diff_is_applied(self):
        diff = ("--- a/core/demo.py\n+++ b/core/demo.py\n"
                "@@ -1,4 +1,4 @@\n"
                ' """Демо-модуль песочницы."""\n'
                " \n"
                "-VALUE = 1\n"
                "+VALUE = 9\n"
                " \n")
        result = self.call("code_patch", {"path": "core/demo.py",
                                          "diff": diff})
        self.assertTrue(result["ok"], result.get("error"))
        self.assertIn("VALUE = 9",
                      editor.staged_bytes("core/demo.py").decode())

    def test_unified_diff_with_wrong_context_is_refused(self):
        diff = ("@@ -1,3 +1,3 @@\n"
                " СОВСЕМ НЕ ТОТ ТЕКСТ\n"
                "-VALUE = 1\n"
                "+VALUE = 9\n")
        result = self.call("code_patch", {"path": "core/demo.py",
                                          "diff": diff})
        self.assertFalse(result["ok"])
        self.assertIn("контекст не совпал", result["error"])

    def test_edits_and_diff_together_are_refused(self):
        result = self.call("code_patch",
                           {"path": "core/demo.py",
                            "edits": [{"old": "VALUE = 1",
                                       "new": "VALUE = 2"}],
                            "diff": "@@ -1,1 +1,1 @@\n"})
        self.assertFalse(result["ok"])
        self.assertIn("ровно одно", result["error"])

    def test_drop_clears_staging(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        result = self.call("code_patch", {"drop": True})
        self.assertTrue(result["ok"])
        self.assertEqual(editor.staging_summary()["count"], 0)


class TestChecks(CodeCase):
    """Проверки до применения."""

    def test_broken_syntax_never_reaches_the_disk(self):
        self.call("code_write", {"path": "core/demo.py",
                                 "content": "def broken(:\n"})
        check = self.call("code_check", {})
        self.assertFalse(check["ok"])
        self.assertEqual(check["files"][0]["syntax"], "fail")
        applied = self.apply()
        self.assertFalse(applied["ok"])
        self.assertFalse(applied["applied"])
        # Файл на диске остался прежним, правка — в staging.
        self.assertIn("def compose", self.box.text("core/demo.py"))
        self.assertEqual(editor.staging_summary()["count"], 1)

    def test_module_that_raises_on_import_is_caught(self):
        # Синтаксис у такого файла корректный: поймать его может только
        # настоящий импорт в отдельном процессе.
        self.call("code_write", {"path": "core/demo.py",
                                 "content": 'raise RuntimeError("no")\n'})
        check = self.call("code_check", {"lint": False})
        self.assertFalse(check["ok"])
        self.assertEqual(check["files"][0]["import"], "fail")
        self.assertIn("RuntimeError", check["files"][0]["output"])
        self.assertIn("def compose", self.box.text("core/demo.py"))

    def test_good_edit_passes_every_check(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        check = self.call("code_check", {})
        self.assertTrue(check["ok"], check)
        self.assertEqual(check["files"][0]["import"], "ok")
        self.assertTrue(check["lint"]["ok"])

    def test_breaking_a_neighbour_is_caught_by_the_import(self):
        # core/other.py импортирует compose: убрав её, ломаем соседа.
        self.call("code_write", {"path": "core/demo.py",
                                 "content": "VALUE = 1\n"})
        self.patch("core/other.py", "def greet():", "def greet_broken():")
        check = self.call("code_check", {"paths": ["core/other.py"],
                                         "lint": False})
        self.assertFalse(check["ok"])
        self.assertIn("не импортируется", check["files"][0]["error"])

    def test_broken_json_is_caught(self):
        self.call("code_write", {"path": "config/sample.json",
                                 "content": "{not json}"})
        check = self.call("code_check", {"lint": False})
        self.assertFalse(check["ok"])
        self.assertEqual(check["files"][0]["kind"], "json")

    def test_check_without_staging_says_so(self):
        check = self.call("code_check", {})
        self.assertFalse(check["ok"])
        self.assertIn("нет ни одной правки", check["error"])

    def test_tests_are_honest_when_pytest_has_nothing_to_run(self):
        result = self.call("code_test", {})
        self.assertIn("available", result)
        self.assertFalse(result["available"])


class TestApply(CodeCase):
    """Применение: снимок, атомарная запись, сторож."""

    def test_applied_edit_reaches_the_disk(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        result = self.apply(reason="поднять VALUE")
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["applied"])
        self.assertIn("VALUE = 7", self.box.text("core/demo.py"))
        self.assertEqual(editor.staging_summary()["count"], 0)
        self.assertEqual(len(self.guard_calls), 1)

    def test_snapshot_keeps_the_previous_content(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        result = self.apply()
        snapshot_id = result["snapshot_id"]
        saved = editor.snapshot_bytes(snapshot_id, "core/demo.py")
        self.assertIn(b"VALUE = 1", saved)
        manifest = editor.read_manifest(snapshot_id)
        self.assertEqual(manifest["state"], editor.STATE_PENDING)
        self.assertEqual(manifest["files"][0]["path"], "core/demo.py")
        self.assertTrue(manifest["files"][0]["existed"])

    def test_manifest_is_written_before_the_files(self):
        # Выключение питания посреди применения обязано оставлять
        # опись: без неё восстанавливать нечего.
        seen = {}
        original = editor.write_manifest

        def spy(manifest):
            # Именно ПЕРВАЯ запись: манифест дописывается и после
            # применения (сторож, состояние), и она бы затёрла снимок.
            seen.setdefault("at_write", self.box.text("core/demo.py"))
            return original(manifest)

        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        with mock.patch.object(editor, "write_manifest", spy):
            self.apply()
        self.assertIn("VALUE = 1", seen["at_write"])

    def test_new_file_is_created_and_marked(self):
        self.call("code_write", {"path": "core/fresh.py",
                                 "content": "NEW = 1\n"})
        result = self.apply()
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.box.exists("core/fresh.py"))
        manifest = editor.read_manifest(result["snapshot_id"])
        self.assertFalse(manifest["files"][0]["existed"])

    def test_second_unconfirmed_apply_is_refused(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        first = self.apply()
        self.patch("core/demo.py", "VALUE = 7", "VALUE = 8")
        second = self.apply()
        self.assertFalse(second["ok"])
        self.assertEqual(second["snapshot_id"], first["snapshot_id"])
        self.assertIn("не подтверждена", second["error"])

    def test_file_changed_behind_our_back_stops_the_apply(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        self.box.put("core/demo.py", "VALUE = 100\n")
        result = self.apply()
        self.assertFalse(result["ok"])
        self.assertEqual(result["drifted"], ["core/demo.py"])
        self.assertIn("VALUE = 100", self.box.text("core/demo.py"))

    def test_commit_closes_the_snapshot(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        applied = self.apply()
        result = self.call("code_commit", {})
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], editor.STATE_COMMITTED)
        self.assertEqual(
            editor.read_manifest(applied["snapshot_id"])["state"],
            editor.STATE_COMMITTED)
        self.assertFalse(self.call("code_commit", {})["ok"])

    def test_rollback_returns_the_previous_content(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        self.apply()
        with mock.patch.object(system_control, "restart_command",
                               return_value=""):
            result = self.call("code_rollback", {"restart": False})
        self.assertTrue(result["ok"], result)
        self.assertIn("VALUE = 1", self.box.text("core/demo.py"))
        self.assertEqual(result["restored"], ["core/demo.py"])

    def test_rollback_removes_a_created_file(self):
        self.call("code_write", {"path": "core/fresh.py",
                                 "content": "NEW = 1\n"})
        self.apply()
        with mock.patch.object(system_control, "restart_command",
                               return_value=""):
            self.call("code_rollback", {"restart": False})
        self.assertFalse(self.box.exists("core/fresh.py"))

    def test_undo_last_rolls_back_code(self):
        # mcp_undo_last для правок кода равен code_rollback.
        from core.mcp import audit
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        self.apply()
        with mock.patch.object(system_control, "restart_command",
                               return_value=""):
            result = audit.undo_last(audit.KIND_CODE)
        self.assertTrue(result["ok"], result)
        self.assertIn("VALUE = 1", self.box.text("core/demo.py"))

    def test_mode_of_an_executable_file_survives(self):
        # Атомарная запись создаёт НОВЫЙ файл: без chmod init-скрипт
        # потерял бы +x.
        path = self.box.put("tools/run.sh", "#!/bin/sh\necho old\n")
        os.chmod(path, 0o755)
        self.call("code_write", {"path": "tools/run.sh",
                                 "content": "#!/bin/sh\necho new\n"})
        self.apply()
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o755)


class TestHistoryAndPatchExport(CodeCase):
    """История, диффы и выгрузка локальных правок."""

    def test_history_shows_state_and_files(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        applied = self.apply(reason="поднять VALUE")
        self.call("code_commit", {})
        history = self.call("code_history", {})
        self.assertEqual(history["total"], 1)
        item = history["items"][0]
        self.assertEqual(item["snapshot_id"], applied["snapshot_id"])
        self.assertEqual(item["state"], editor.STATE_COMMITTED)
        self.assertEqual(item["files"], ["core/demo.py"])
        self.assertEqual(item["reason"], "поднять VALUE")

    def test_diff_against_staging(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        result = self.call("code_diff", {})
        self.assertTrue(result["ok"])
        self.assertIn("-VALUE = 1", result["diff"])
        self.assertIn("+VALUE = 7", result["diff"])

    def test_export_patch_carries_local_edits(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        self.apply()
        self.call("code_commit", {})
        result = self.call("code_export_patch", {})
        self.assertTrue(result["ok"])
        self.assertEqual(result["files"], ["core/demo.py"])
        self.assertIn("+VALUE = 7", result["diff"])

    def test_export_patch_is_empty_without_edits(self):
        result = self.call("code_export_patch", {})
        self.assertTrue(result["ok"])
        self.assertEqual(result["files"], [])
        self.assertTrue(result["empty"])

    def test_tree_marks_protected_files(self):
        tree = self.call("code_tree", {"mask": "core/*.py"})
        by_path = {item["path"]: item for item in tree["items"]}
        self.assertTrue(by_path["core/config_manager.py"]["protected"])
        self.assertFalse(by_path["core/demo.py"]["protected"])

    def test_search_returns_context(self):
        result = self.call("code_search", {"pattern": "def compose"})
        self.assertGreaterEqual(result["total"], 1)
        first = result["items"][0]
        self.assertEqual(first["path"], "core/demo.py")
        self.assertIn("def compose", first["text"])
        self.assertTrue(first["before"] or first["after"])

    def test_search_by_regexp(self):
        result = self.call("code_search", {"pattern": r"VALUE\s*=\s*\d",
                                           "regex": True})
        self.assertGreaterEqual(result["total"], 1)

    def test_bad_regexp_is_a_readable_refusal(self):
        result = self.call("code_search", {"pattern": "(", "regex": True})
        self.assertFalse(result["ok"])
        self.assertIn("регэксп", result["error"])


class TestWarnings(CodeCase):
    """О разрыве соединения и о судьбе правок сказано заранее."""

    def test_instructions_warn_about_the_dropped_connection(self):
        # Модель читает врезку до первого вызова: без неё ошибка
        # транспорта после code_apply читается как «правка не прошла».
        from core.mcp import server
        text = server._instructions(["self_edit"], 13)
        self.assertIn("CONNECTION DROPS", text)
        self.assertIn("code_commit", text)
        self.assertNotIn("CONNECTION DROPS",
                         server._instructions(["control"], 8))

    def test_apply_repeats_the_same_warning(self):
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        result = self.apply()
        self.assertIn("code_commit", result["hint"])
        self.assertIn("5–10", result["hint"])

    def test_updates_check_warns_about_local_edits(self):
        # Обновление GUI затирает правки на устройстве без следа.
        self.patch("core/demo.py", "VALUE = 1", "VALUE = 7")
        self.apply()
        self.call("code_commit", {})
        report = self.box.data("updates_check", {}, perms={})
        warning = report["local_code_changes"]
        self.assertEqual(warning["count"], 1)
        self.assertEqual(warning["files"], ["core/demo.py"])
        self.assertIn("затрёт", warning["warning"])

    def test_updates_check_is_silent_without_local_edits(self):
        report = self.box.data("updates_check", {}, perms={})
        self.assertEqual(report["local_code_changes"]["count"], 0)
        self.assertNotIn("warning", report["local_code_changes"])


class TestPermissions(unittest.TestCase):
    """Без ``self_edit`` инструментов не видно вовсе."""

    def setUp(self):
        self.box = CodeSandbox(self, permissions={})

    def test_tools_are_hidden_without_the_permission(self):
        from core.mcp import registry
        names = [spec.name for spec in registry.available_tools({})]
        self.assertNotIn("code_read", names)
        self.assertNotIn("code_apply", names)

    def test_call_without_the_permission_is_denied(self):
        result = self.box.data("code_read", {"path": "core/demo.py"},
                               perms={})
        self.assertFalse(result["ok"])
        self.assertEqual(result["permission"], "self_edit")


if __name__ == "__main__":
    unittest.main()
