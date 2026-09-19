# tests/test_mcp_code_guard.py
"""
Сторож самоправки: кто возвращает код, когда GUI не вернулся (S13).

Сторож — **посторонний процесс**: правка, ломающая импорт, убивает и
GUI, и MCP, и любой откат «изнутри». Поэтому здесь проверяется не
«функция вернула словарь», а три вещи, ради которых он написан:

1. не дождался живого ``/api/status`` — вернул файлы;
2. не дождался ``code_commit`` за TTL — вернул файлы;
3. дождался ``code_commit`` — не тронул ничего.

Гоняется с поддельным health-check'ом и часами, которые двигает сам
``sleep``: поднимать настоящий GUI и ждать реальные секунды тест не
должен.
"""

import json
import os
import re
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from core import code_editor as editor
from core import code_guard as guard_mod
from core import system_control
from tests._code_sandbox import Clock, CodeSandbox, Health


class GuardCase(unittest.TestCase):
    """Песочница с одной применённой (но не подтверждённой) правкой."""

    def setUp(self):
        self.box = CodeSandbox(self, permissions={"self_edit": True})
        self.clock = Clock()

    def apply_edit(self, old="VALUE = 1", new="VALUE = 7"):
        """Применить правку, подменив сторожа и перезапуск."""
        self.box.data("code_patch", {"path": "core/demo.py",
                                     "edits": [{"old": old, "new": new}]})
        with mock.patch.object(editor, "start_guard",
                               return_value={"ok": True, "pid": 1}), \
                mock.patch.object(system_control, "restart_gui",
                                  return_value={"ok": True}):
            result = self.box.data("code_apply", {"reason": "тест",
                                                  "restart": False})
        self.assertTrue(result["ok"], result)
        self.snapshot_id = result["snapshot_id"]
        self.snapshot_dir = editor.snapshot_path(self.snapshot_id)
        return result

    def run_guard(self, health, restart=None, expect_restart=True,
                  timeout=5, commit_ttl=10, sleep=None):
        restarts = []

        def fake_restart():
            restarts.append(True)
            return True

        result = guard_mod.guard(
            self.snapshot_dir, timeout=timeout, commit_ttl=commit_ttl,
            config_dir=self.box.dir, health=health,
            restart=restart or fake_restart,
            sleep=sleep or self.clock.sleep, clock=self.clock.time,
            expect_restart=expect_restart)
        result["restart_calls"] = len(restarts)
        return result


class TestGuardReverts(GuardCase):
    """GUI не вернулся — файлы возвращаются."""

    def test_dead_gui_is_rolled_back(self):
        self.apply_edit()
        self.assertIn("VALUE = 7", self.box.text("core/demo.py"))
        # Жив до перезапуска, ушёл, больше не поднялся.
        result = self.run_guard(Health([True, False]))
        self.assertEqual(result["action"], "reverted")
        self.assertEqual(result["reason"], "health_timeout")
        self.assertIn("VALUE = 1", self.box.text("core/demo.py"))
        self.assertEqual(result["restart_calls"], 1)

    def test_revert_writes_the_reason_into_the_manifest(self):
        self.apply_edit()
        self.run_guard(Health([True, False]))
        manifest = editor.read_manifest(self.snapshot_id)
        self.assertEqual(manifest["state"], editor.STATE_REVERTED)
        self.assertEqual(manifest["revert_reason"], "health_timeout")
        self.assertIn("не ответил", manifest["revert_detail"])

    def test_revert_reason_survives_in_a_persistent_log(self):
        # «Всё само откатилось» без объяснения — худший исход: причина
        # обязана пережить и GUI, и перезагрузку.
        self.apply_edit()
        self.run_guard(Health([True, False]))
        with open(os.path.join(self.box.dir, guard_mod.GUARD_LOG_NAME),
                  encoding="utf-8") as f:
            text = f.read()
        self.assertIn("ОТКАТ", text)
        self.assertIn(self.snapshot_id, text)

    def test_created_file_is_removed_on_revert(self):
        self.box.data("code_write", {"path": "core/fresh.py",
                                     "content": "NEW = 1\n"})
        with mock.patch.object(editor, "start_guard",
                               return_value={"ok": True}), \
                mock.patch.object(system_control, "restart_gui",
                                  return_value={"ok": True}):
            applied = self.box.data("code_apply", {"reason": "новый файл",
                                                   "restart": False})
        self.snapshot_dir = editor.snapshot_path(applied["snapshot_id"])
        self.assertTrue(self.box.exists("core/fresh.py"))
        self.run_guard(Health([True, False]))
        self.assertFalse(self.box.exists("core/fresh.py"))


class TestCommitTtl(GuardCase):
    """Дедмен подтверждения."""

    def test_without_commit_the_edit_is_rolled_back(self):
        self.apply_edit()
        result = self.run_guard(Health([True]), expect_restart=False,
                                commit_ttl=5)
        self.assertEqual(result["action"], "reverted")
        self.assertEqual(result["reason"], "commit_timeout")
        self.assertIn("VALUE = 1", self.box.text("core/demo.py"))

    def test_commit_cancels_the_revert(self):
        self.apply_edit()
        box = self.box
        clock = self.clock

        def sleep(seconds):
            clock.sleep(seconds)
            if clock.slept >= 2:
                box.data("code_commit", {})

        result = self.run_guard(Health([True]), expect_restart=False,
                                commit_ttl=30, sleep=sleep)
        self.assertEqual(result["action"], "committed")
        self.assertIn("VALUE = 7", self.box.text("core/demo.py"))
        self.assertEqual(result["restart_calls"], 0)

    def test_state_becomes_applied_before_the_wait(self):
        self.apply_edit()

        seen = {}
        clock = self.clock
        snapshot_id = self.snapshot_id

        def sleep(seconds):
            seen.setdefault("state",
                            editor.read_manifest(snapshot_id)["state"])
            clock.sleep(seconds)

        self.run_guard(Health([True]), expect_restart=False,
                       commit_ttl=3, sleep=sleep)
        self.assertEqual(seen["state"], editor.STATE_APPLIED)

    def test_rollback_from_outside_stops_the_guard(self):
        self.apply_edit()
        box = self.box
        clock = self.clock

        def sleep(seconds):
            clock.sleep(seconds)
            if clock.slept >= 2:
                with mock.patch.object(system_control, "restart_command",
                                       return_value=""):
                    box.data("code_rollback", {"restart": False})

        result = self.run_guard(Health([True]), expect_restart=False,
                                commit_ttl=30, sleep=sleep)
        self.assertEqual(result["action"], "reverted_elsewhere")


class TestGuardIsCareful(GuardCase):
    """Ложный откат исправного GUI хуже отсутствия отката."""

    def test_unusable_health_check_does_not_revert_by_itself(self):
        # GUI не отвечает уже ДО перезапуска (пароль, порт, bind) —
        # судить по этой проверке нельзя.
        self.apply_edit()
        result = self.run_guard(Health([False]), commit_ttl=5)
        self.assertEqual(result["action"], "reverted")
        # ...но откат — по дедмену подтверждения, а не по «GUI умер».
        self.assertEqual(result["reason"], "commit_timeout")
        manifest = editor.read_manifest(self.snapshot_id)
        self.assertEqual(manifest["revert_reason"], "commit_timeout")

    def test_gui_that_never_went_down_is_not_a_failure(self):
        # Перезапуск не состоялся: код на диске лежит незагруженным.
        # Это не провал — решает дедмен подтверждения.
        self.apply_edit()
        box = self.box
        clock = self.clock

        def sleep(seconds):
            clock.sleep(seconds)
            if clock.slept >= 7:
                box.data("code_commit", {})

        result = self.run_guard(Health([True]), commit_ttl=30,
                                timeout=3, sleep=sleep)
        self.assertEqual(result["action"], "committed")
        manifest = editor.read_manifest(self.snapshot_id)
        self.assertFalse(manifest["restart_observed"])

    def test_closed_snapshot_is_left_alone(self):
        self.apply_edit()
        self.box.data("code_commit", {})
        result = self.run_guard(Health([True, False]))
        self.assertEqual(result["action"], "none")
        self.assertIn("VALUE = 7", self.box.text("core/demo.py"))

    def test_concurrent_commit_is_not_overwritten(self):
        # Манифест правят двое: сторож и GUI. Сторож дописывает СВОИ
        # поля в свежую копию — запись целиком потеряла бы
        # подтверждение, пришедшее секундой раньше.
        self.apply_edit()
        path = editor.manifest_path(self.snapshot_id)
        self.box.data("code_commit", {})
        guard_mod._patch(path, {"restart_observed": True})
        manifest = editor.read_manifest(self.snapshot_id)
        self.assertEqual(manifest["state"], editor.STATE_COMMITTED)
        self.assertTrue(manifest["restart_observed"])

    def test_commit_during_the_wait_is_not_downgraded(self):
        # Подтверждение могло прийти, пока сторож ждал возвращения
        # GUI: вернуть снимок в «ждём» после этого нельзя.
        self.apply_edit()
        box = self.box
        health = Health([True, False, True])

        def wrapped():
            answer = health()
            if health.calls == 2:
                box.data("code_commit", {})
            return answer

        result = self.run_guard(wrapped, commit_ttl=5)
        self.assertEqual(result["action"], "committed")
        self.assertIn("VALUE = 7", self.box.text("core/demo.py"))


class TestRotation(GuardCase):
    """Снимков хранится ровно ``snapshots_keep``."""

    def test_old_snapshots_are_dropped(self):
        for index in range(5):
            self.apply_edit("VALUE = %d" % (index + 1),
                            "VALUE = %d" % (index + 2))
            self.box.data("code_commit", {})
        # snapshots_keep = 3 в песочнице.
        self.assertEqual(len(editor.snapshot_ids()), 3)

    def test_unconfirmed_snapshot_is_never_rotated_away(self):
        # Незакрытый снимок — единственное, чем откатывать: выкинуть
        # его ротацией значит потерять путь назад.
        self.apply_edit("VALUE = 1", "VALUE = 2")
        first = self.snapshot_id
        self.box.data("code_commit", {})
        self.apply_edit("VALUE = 2", "VALUE = 3")
        second = self.snapshot_id
        self.box.data("code_commit", {})
        # Старый снимок снова ждёт решения (так выглядит правка,
        # пережившая перезагрузку посреди применения).
        editor.update_manifest(first, state=editor.STATE_PENDING)

        editor.rotate_snapshots(1)
        self.assertIn(first, editor.snapshot_ids())
        self.assertIn(second, editor.snapshot_ids())

    def test_reused_name_does_not_confuse_the_order(self):
        # Имя уникально только в пределах секунды, а после ротации
        # переиспользуется: порядок обязан считаться по времени из
        # манифеста, иначе самый новый снимок однажды окажется
        # «самым старым» и уедет в ротацию.
        self.apply_edit("VALUE = 1", "VALUE = 2")
        self.box.data("code_commit", {})
        newest = None
        for index in range(2, 7):
            self.apply_edit("VALUE = %d" % index, "VALUE = %d" % (index + 1))
            newest = self.snapshot_id
            self.box.data("code_commit", {})
        self.assertEqual(editor.snapshot_ids()[0], newest)
        self.assertEqual(len(editor.snapshot_ids()), 3)


class TestHealthCheck(unittest.TestCase):
    """«GUI жив» — это ответ ``/api/status``, а не открытый порт."""

    def serve(self, body, status=200):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):                       # noqa: N802
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return {"url": "http://127.0.0.1:%d/api/status"
                       % server.server_address[1], "auth": ""}

    def test_our_answer_is_accepted(self):
        target = self.serve(json.dumps({"ok": True,
                                        "gui_version": "0.0.1"}).encode())
        self.assertTrue(guard_mod.check_health(target, timeout=3))

    def test_open_port_with_a_foreign_body_is_not_enough(self):
        # Порт держит и наполовину поднявшийся процесс, и чужая
        # программа, занявшая его после падения нашей.
        target = self.serve(b"<html>hello</html>")
        self.assertFalse(guard_mod.check_health(target, timeout=3))

    def test_error_status_is_not_alive(self):
        target = self.serve(b'{"ok": true, "gui_version": "x"}', status=503)
        self.assertFalse(guard_mod.check_health(target, timeout=3))

    def test_closed_port_is_not_alive(self):
        self.assertFalse(guard_mod.check_health(
            {"url": "http://127.0.0.1:1/api/status", "auth": ""},
            timeout=1))


class TestHealthTarget(unittest.TestCase):
    """Адрес и авторизация читаются прямо из ``settings.json``."""

    def setUp(self):
        self.box = CodeSandbox(self, permissions={"self_edit": True})

    def test_host_and_port_come_from_the_file(self):
        self.box.cfg.set("gui", "port", 8099)
        self.box.cfg.set("gui", "host", "0.0.0.0")
        # Сторож читает ФАЙЛ, а не объект конфига: config_manager —
        # один из защищённых модулей, и именно он мог быть сломан.
        self.box.cfg.save()
        target = guard_mod.health_target(self.box.dir)
        # 0.0.0.0 — это «слушаю везде», а стучаться надо в себя.
        self.assertEqual(target["url"],
                         "http://127.0.0.1:8099/api/status")
        self.assertEqual(target["auth"], "")

    def test_basic_auth_is_built_when_enabled(self):
        self.box.cfg.set("gui", "auth_enabled", True)
        self.box.cfg.set("gui", "auth_user", "admin")
        self.box.cfg.set("gui", "auth_password", "secret")
        self.box.cfg.save()
        target = guard_mod.health_target(self.box.dir)
        self.assertTrue(target["auth"].startswith("Basic "))

    def test_missing_settings_do_not_crash_the_guard(self):
        target = guard_mod.health_target("/nonexistent-dir")
        self.assertEqual(target["url"],
                         "http://127.0.0.1:8080/api/status")


class TestGuardIndependence(unittest.TestCase):
    """Сторож не может зависеть от того, что он откатывает."""

    def test_guard_imports_nothing_of_ours(self):
        # Модуль, который возвращает сломанный код, не имеет права
        # импортировать сломанный код. Проверяется текстом файла:
        # добавить `from core import ...` слишком легко.
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "core", "code_guard.py")
        with open(path, encoding="utf-8") as f:
            source = f.read()
        bad = re.findall(r"^\s*(?:from|import)\s+(core|api|app)\b",
                         source, re.M)
        self.assertEqual(bad, [])

    def test_states_match_the_editor(self):
        # Константы продублированы намеренно (см. docstring сторожа) —
        # значит, расхождение ловит тест, а не пользователь.
        self.assertEqual(guard_mod.STATE_PENDING, editor.STATE_PENDING)
        self.assertEqual(guard_mod.STATE_APPLIED, editor.STATE_APPLIED)
        self.assertEqual(guard_mod.STATE_COMMITTED, editor.STATE_COMMITTED)
        self.assertEqual(guard_mod.STATE_REVERTED, editor.STATE_REVERTED)
        self.assertEqual(guard_mod.OPEN_STATES, editor.OPEN_STATES)
        self.assertEqual(guard_mod.SNAPSHOTS_DIRNAME,
                         editor.SNAPSHOTS_DIRNAME)
        self.assertEqual(guard_mod.GUARD_LOG_NAME, editor.GUARD_LOG_NAME)


class TestGuardProcess(GuardCase):
    """Сторож как он есть: отдельный процесс, запущенный из CLI."""

    def test_cli_run_reverts_an_unconfirmed_edit(self):
        # Единственный тест, который гоняет НАСТОЯЩИЙ сторож: всё
        # остальное проверяется функцией, а схема держится на том, что
        # `python3 -m core.code_guard` вообще запускается и работает
        # без единого нашего импорта.
        self.apply_edit()
        # Порт заведомо закрыт: health-check недостоверен, значит
        # сторож судит только по дедмену подтверждения.
        self.box.cfg.set("gui", "port", 1)
        self.box.cfg.save()
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        done = subprocess.run(
            [sys.executable, "-B", "-m", "core.code_guard",
             "--snapshot", self.snapshot_id, "--timeout", "1",
             "--commit-ttl", "1", "--config-dir", self.box.dir],
            cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60)
        self.assertEqual(done.stderr.decode("utf-8", "replace"), "")
        self.assertIn("VALUE = 1", self.box.text("core/demo.py"))
        self.assertEqual(
            editor.read_manifest(self.snapshot_id)["revert_reason"],
            "commit_timeout")

    def test_cli_without_the_snapshot_says_so(self):
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        done = subprocess.run(
            [sys.executable, "-B", "-m", "core.code_guard",
             "--snapshot", "snap-20200101-000000",
             "--config-dir", self.box.dir],
            cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60)
        self.assertEqual(done.returncode, 1)


class TestRecoverAfterRestart(GuardCase):
    """Выключение питания посреди применения."""

    def test_expired_snapshot_is_reverted_on_start(self):
        self.apply_edit()
        # Сторож не пережил перезагрузку, TTL давно вышел.
        editor.update_manifest(self.snapshot_id, created_ts=1.0,
                               applied_at=1.0)
        with mock.patch.object(system_control, "restart_command",
                               return_value=""):
            result = editor.recover_after_restart()
        self.assertEqual(result["reverted"], [self.snapshot_id])
        self.assertIn("VALUE = 1", self.box.text("core/demo.py"))

    def test_live_snapshot_gets_a_new_guard(self):
        self.apply_edit()
        with mock.patch.object(editor, "start_guard",
                               return_value={"ok": True}) as started:
            result = editor.recover_after_restart()
        self.assertEqual(result["rearmed"], [self.snapshot_id])
        self.assertEqual(result["reverted"], [])
        self.assertIn("VALUE = 7", self.box.text("core/demo.py"))
        # Ждать перезапуска больше незачем: GUI уже поднят.
        self.assertFalse(started.call_args.kwargs["expect_restart"])

    def test_committed_snapshot_is_left_alone(self):
        self.apply_edit()
        self.box.data("code_commit", {})
        result = editor.recover_after_restart()
        self.assertEqual(result["reverted"], [])
        self.assertEqual(result["rearmed"], [])


if __name__ == "__main__":
    unittest.main()
