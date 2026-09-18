# tests/test_mcp_audit.py
"""
Журнал вызовов MCP, снимки «до» и откат.

Что здесь важно зафиксировать, кроме «работает»:

* **снимок переживает перезапуск GUI.** Он лежит на диске, а не в
  памяти процесса, — и проверяется это честно: журнал читает ДРУГОЙ
  интерпретатор. Роутер перезагружается чаще, чем заканчивается сеанс
  модели, а «верни как было» нужно именно после неудачного
  эксперимента;
* **ротация не уносит снимок, нужный `mcp_undo_last`.** Журнал и
  снимки — разные файлы ровно поэтому;
* **отклонённый вызов — warning.** Попытка сделать то, на что прав не
  давали, должна быть заметна на фоне обычной работы;
* **токен не попадает в журнал никогда** — ни настроенный, ни
  приехавший внутри аргумента.

Всё пишется во временный каталог: тест, трогающий настоящий журнал,
портит устройство, на котором его запустили.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from core.log_buffer import get_log_buffer
from core.mcp import audit
from core.mcp import permissions as perms_mod
from core.mcp import registry


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

WRITE = {"config_write": True}


class Sandbox:
    """Временный каталог: settings.json, журнал и снимки рядом."""

    def __init__(self, case, audit_settings=None):
        import core.config_manager as cm

        self.dir = tempfile.mkdtemp(prefix="mcp-audit-")
        case.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

        saved = cm._config_manager
        case.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        if audit_settings:
            cm._config_manager.set("mcp", "audit", dict(audit_settings))

        before = os.environ.get("ZAPRET_GUI_CONFIG_DIR")
        case.addCleanup(_restore_env, before)
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = self.dir

        # Счётчик ротации — модульный: без сброса тест зависит от того,
        # сколько вызовов сделали соседние.
        case.addCleanup(setattr, audit, "_appends", audit._appends)
        audit._appends = 0

    def rotate_every(self, case, calls: int, keep: int = audit.MIN_KEEP):
        """Проверять длину журнала чаще — иначе тест длинный и хрупкий.

        В бою длина журнала проверяется раз в ``ROTATE_CHECK_EVERY``
        записей (считать строки на каждый вызов — это чтение всего файла
        на роутере). Поэтому журнал законно бывает длиннее ``keep`` —
        ровно до следующей проверки.
        """
        from core.config_manager import get_config_manager

        case.addCleanup(setattr, audit, "ROTATE_CHECK_EVERY",
                        audit.ROTATE_CHECK_EVERY)
        audit.ROTATE_CHECK_EVERY = calls
        audit._appends = 0
        get_config_manager().set("mcp", "audit",
                                 {"enabled": True, "keep": keep})

    @property
    def journal(self) -> str:
        return os.path.join(self.dir, audit.JOURNAL_NAME)

    @property
    def snapshots(self) -> str:
        return os.path.join(self.dir, audit.SNAPSHOT_NAME)

    def lines(self) -> list:
        if not os.path.exists(self.journal):
            return []
        with open(self.journal, encoding="utf-8") as f:
            return [line for line in f.read().splitlines() if line.strip()]

    def records(self) -> list:
        out = []
        for line in self.lines():
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out


def _restore_env(value):
    if value is None:
        os.environ.pop("ZAPRET_GUI_CONFIG_DIR", None)
    else:
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = value


def call(name, args=None, perms=None):
    return registry.call(name, args or {},
                         WRITE if perms is None else perms)


def data(name, args=None, perms=None):
    return call(name, args, perms)["structuredContent"]


class TestJournal(unittest.TestCase):

    def setUp(self):
        self.box = Sandbox(self)

    def test_every_call_is_written(self):
        data("system_status", perms={})
        records = self.box.records()
        self.assertEqual(len(records), 1)
        entry = records[0]
        self.assertEqual(entry["tool"], "system_status")
        self.assertEqual(entry["status"], "ok")
        self.assertFalse(entry["mutating"])
        self.assertIn("ts", entry)
        self.assertIn("elapsed_ms", entry)

    def test_caller_address_is_written(self):
        registry.call("system_status", {}, {},
                      {"subject": "token", "remote_addr": "192.168.1.5"})
        entry = self.box.records()[-1]
        self.assertEqual(entry["remote"], "192.168.1.5")
        self.assertEqual(entry["subject"], "token")

    def test_denied_call_is_a_warning(self):
        buffer = get_log_buffer()
        buffer.clear()
        call("config_set", {"path": "nfqws.debug", "value": True},
             perms={})
        entry = self.box.records()[-1]
        self.assertEqual(entry["status"], "denied")
        self.assertFalse(entry["ok"])
        levels = [e["level"] for e in buffer.get_last(20)
                  if e["source"] == "mcp"]
        self.assertIn("WARNING", levels)

    def test_bad_arguments_are_written_too(self):
        from core.mcp import schema as schema_mod

        with self.assertRaises(schema_mod.SchemaError):
            call("config_set", {"path": "nfqws.debug"})
        entry = self.box.records()[-1]
        self.assertEqual(entry["status"], "invalid")

    def test_unknown_tool_is_written(self):
        with self.assertRaises(registry.UnknownTool):
            call("nope_nope")
        entry = self.box.records()[-1]
        self.assertEqual(entry["tool"], "nope_nope")
        self.assertEqual(entry["status"], "unknown")

    def test_token_never_lands_in_the_journal(self):
        from core.config_manager import get_config_manager

        secret = "c0ffee" * 8
        get_config_manager().set("mcp", "token", secret)
        data("logs_tail", {"search": "token=%s" % secret}, perms={})
        data("system_status", perms={})
        with open(self.box.journal, encoding="utf-8") as f:
            dump = f.read()
        self.assertNotIn(secret, dump)
        self.assertIn("token=***", dump)

    def test_a_broken_line_does_not_break_reading(self):
        data("system_status", perms={})
        with open(self.box.journal, "a", encoding="utf-8") as f:
            f.write('{"tool": "system_status", "sta')   # обрыв питания
        records, stats = audit.read_records()
        self.assertEqual(stats["skipped_lines"], 1)
        self.assertEqual(len(records), 1)

    def test_rotation_keeps_the_last_entries(self):
        self.box.rotate_every(self, 5)
        for _ in range(audit.MIN_KEEP + 12):
            data("system_status", perms={})
        lines = self.box.lines()
        self.assertLessEqual(len(lines), audit.MIN_KEEP + 5)
        self.assertGreaterEqual(len(lines), audit.MIN_KEEP)
        # Подрезаем ХВОСТ, а не начало: журнал нужен, чтобы посмотреть,
        # что делалось только что.
        self.assertEqual(json.loads(lines[-1])["tool"], "system_status")

    def test_journal_is_not_created_outside_its_directory(self):
        # Каталога нет — не пишем и не создаём: на чужой машине это
        # означало бы /opt/etc, заведённый тестом.
        shutil.rmtree(self.box.dir)
        data("system_status", perms={})
        self.assertFalse(os.path.exists(self.box.dir))


class TestSnapshots(unittest.TestCase):

    def setUp(self):
        self.box = Sandbox(self)

    def test_mutating_call_writes_a_snapshot(self):
        before = data("config_get", {"path": "nfqws.ports_tcp"})["value"]
        data("config_set", {"path": "nfqws.ports_tcp", "value": "80"})

        pinned = audit.snapshots()
        self.assertEqual(len(pinned), 1)
        self.assertEqual(pinned[0]["kind"], audit.KIND_CONFIG)
        self.assertEqual(pinned[0]["target"], "nfqws.ports_tcp")
        self.assertEqual(pinned[0]["before"], before)
        self.assertEqual(pinned[0]["after"], "80")

        entry = self.box.records()[-1]
        self.assertEqual(entry["undo"][0]["target"], "nfqws.ports_tcp")

    def test_read_only_call_writes_no_snapshot(self):
        data("config_get", {"path": "nfqws.ports_tcp"}, perms={})
        self.assertEqual(audit.snapshots(), [])

    def test_unchanged_write_leaves_nothing_to_undo(self):
        current = data("config_get", {"path": "nfqws.debug"})["value"]
        data("config_set", {"path": "nfqws.debug", "value": current})
        self.assertEqual(audit.snapshots(), [])

    def test_undo_restores_the_previous_value(self):
        before = data("config_get", {"path": "filter.mode"})["value"]
        data("config_set", {"path": "filter.mode", "value": "hostlist"})

        payload = data("mcp_undo_last")
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["reverted"])
        self.assertEqual(payload["restored"], before)
        self.assertEqual(payload["was"], "hostlist")
        self.assertEqual(
            data("config_get", {"path": "filter.mode"})["value"], before)

    def test_undo_twice_does_not_toggle_the_value_back(self):
        before = data("config_get", {"path": "filter.mode"})["value"]
        data("config_set", {"path": "filter.mode", "value": "hostlist"})
        data("mcp_undo_last")

        payload = data("mcp_undo_last")
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["reverted"])
        self.assertIn("нечего", payload["reason"])
        self.assertEqual(
            data("config_get", {"path": "filter.mode"})["value"], before)

    def test_undo_walks_back_one_change_at_a_time(self):
        data("config_set", {"path": "nfqws.ports_tcp", "value": "80"})
        data("config_set", {"path": "nfqws.ports_tcp", "value": "81"})
        data("mcp_undo_last")
        self.assertEqual(
            data("config_get", {"path": "nfqws.ports_tcp"})["value"], "80")

    def test_undo_without_snapshots_is_an_answer_not_an_error(self):
        answer = call("mcp_undo_last")
        self.assertFalse(answer["isError"])
        self.assertFalse(answer["structuredContent"]["reverted"])

    def test_undo_needs_the_write_permission(self):
        answer = call("mcp_undo_last", perms={})
        self.assertTrue(answer["isError"])
        self.assertEqual(answer["structuredContent"]["permission"],
                         perms_mod.ANY_WRITE_SCOPE)

    def test_undo_comes_with_any_write_permission(self):
        # S7: снимки бывают шести видов, и откат обязан быть доступен
        # тому, кто эти изменения делает. Модель с `strategies_write`
        # без `config_write` иначе могла бы сохранить стратегию и не
        # могла бы её вернуть — §5.4 контракта.
        for name in ("control", "strategies_write", "config_write"):
            with self.subTest(permission=name):
                answer = call("mcp_undo_last", perms={name: True})
                self.assertFalse(answer["isError"])

    def test_undo_of_an_unknown_kind_says_so(self):
        audit.snapshot("zz_unknown", "whatever", 1, 2, tool="test")
        payload = data("mcp_undo_last")
        self.assertFalse(payload["ok"])
        self.assertIn("zz_unknown", payload["error"])
        self.assertIn("config", payload["kinds"])

    def test_rotation_does_not_lose_the_snapshot(self):
        before = data("config_get", {"path": "nfqws.ports_tcp"})["value"]
        self.box.rotate_every(self, 5)
        data("config_set", {"path": "nfqws.ports_tcp", "value": "80"})
        for _ in range(audit.MIN_KEEP + 12):
            data("system_status", perms={})

        # Запись о мутации из журнала вытеснена — снимок обязан остаться:
        # он лежит в другом файле, и ротация его не трогает.
        self.assertLessEqual(len(self.box.lines()), audit.MIN_KEEP + 5)
        self.assertNotIn("config_set",
                         [json.loads(x)["tool"] for x in self.box.lines()])
        payload = data("mcp_undo_last")
        self.assertTrue(payload["reverted"])
        self.assertEqual(payload["restored"], before)

    def test_snapshot_survives_a_restart(self):
        data("config_set", {"path": "nfqws.ports_tcp", "value": "80"})

        # Честная проверка «после перезапуска GUI»: файл читает ДРУГОЙ
        # процесс, ничего не знающий про наши объекты в памяти.
        code = ("import json;"
                "from core.mcp import audit;"
                "print(json.dumps([[e['kind'], e['target'], e['after']]"
                " for e in audit.snapshots()]))")
        env = dict(os.environ, ZAPRET_GUI_CONFIG_DIR=self.box.dir)
        out = subprocess.check_output([sys.executable, "-c", code],
                                      cwd=ROOT, env=env)
        self.assertEqual(json.loads(out.decode("utf-8").strip()),
                         [["config", "nfqws.ports_tcp", "80"]])


class TestAuditList(unittest.TestCase):

    def setUp(self):
        self.box = Sandbox(self)

    def test_newest_first_with_filters(self):
        data("system_status", perms={})
        data("config_set", {"path": "nfqws.ports_tcp", "value": "80"})

        payload = data("audit_list", perms={})
        self.assertEqual(payload["items"][0]["tool"], "config_set")

        payload = data("audit_list", {"mutating_only": True}, perms={})
        self.assertTrue(all(item["mutating"] for item in payload["items"]))

        payload = data("audit_list", {"tool": "system_status"}, perms={})
        self.assertEqual({item["tool"] for item in payload["items"]},
                         {"system_status"})

    def test_undo_availability_flips_after_the_undo(self):
        data("config_set", {"path": "nfqws.ports_tcp", "value": "80"})
        payload = data("audit_list", {"mutating_only": True}, perms={})
        self.assertTrue(payload["items"][0]["undo"][0]["available"])

        data("mcp_undo_last")
        payload = data("audit_list", {"tool": "config_set"}, perms={})
        entry = payload["items"][0]
        self.assertFalse(entry["undo"][0]["available"])
        self.assertIn("откачено", entry["undo"][0]["reason"])

    def test_empty_journal_answers_with_a_reason(self):
        payload = data("audit_list", perms={})
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["count"], 0)
        self.assertIn("ничего не вызывали", payload["reason"])

    def test_filter_without_matches_says_how_many_there_are(self):
        data("system_status", perms={})
        payload = data("audit_list", {"tool": "strategy_list"}, perms={})
        self.assertEqual(payload["count"], 0)
        # Свой вызов инструмент в журнале ещё не видит: запись делается
        # ПОСЛЕ обработчика, иначе её длительность была бы выдумкой.
        self.assertEqual(payload["total_in_journal"], 1)

    def test_arguments_are_stored_redacted(self):
        data("logs_tail", {"search": "password=hunter2"}, perms={})
        payload = data("audit_list", {"tool": "logs_tail"}, perms={})
        self.assertEqual(payload["items"][0]["args"]["search"],
                         "password=***")


class TestDisabled(unittest.TestCase):
    """`mcp.audit.enabled=false` выключает и журнал, и откат."""

    def setUp(self):
        self.box = Sandbox(self, {"enabled": False, "keep": 500})

    def test_nothing_is_written(self):
        data("config_set", {"path": "nfqws.ports_tcp", "value": "80"})
        self.assertFalse(os.path.exists(self.box.journal))
        self.assertFalse(os.path.exists(self.box.snapshots))

    def test_the_write_still_happens_and_says_it_is_not_undoable(self):
        payload = data("config_set", {"path": "nfqws.ports_tcp",
                                      "value": "80"})
        self.assertTrue(payload["ok"])
        self.assertIsNone(payload["undo"])
        self.assertIn("журнал", payload["hint"])

    def test_undo_explains_what_is_missing(self):
        payload = data("mcp_undo_last")
        self.assertFalse(payload["reverted"])
        self.assertIn("mcp.audit.enabled", payload["reason"])


if __name__ == "__main__":
    unittest.main()
