# tests/test_mcp_job_wait.py
"""
`job_wait`: таймер на стороне сервера вместо опроса в цикле.

Асинхронный контракт («*_start отдаёт job_id, дальше опрашивай
*_status») решает проблему клиентского таймаута и создаёт свою: модель
не умеет ждать. Она опрашивает статус по нескольку раз в секунду, и
трёхминутный скан превращается в полторы сотни вызовов, из которых сто
сорок девять говорят «ещё идёт», — контекст, журнал, рейт-лимит.

Что стережём:

* **разрешение спрашивается за ВИД операции.** Инструмент объявлен
  `read`; без этой проверки он стал бы дырой, через которую чтение без
  разрешений видит результаты чужих прогонов;
* **бюджет заведомо меньше `tool_timeout_sec`.** Ожидание, которое само
  отваливается по таймауту, хуже опроса: модель не узнает ни
  результата, ни того, что операция идёт;
* **`done: false` — это не ошибка**, а «позовите ещё раз»;
* **у эксперимента конец — не только `running`**: `awaiting_commit`
  это тоже конец ожидания, и проспать его значит проспать дедмен-свитч,
  по которому всё откатится;
* **второй реализации статуса нет**: job_wait зовёт тот же инструмент,
  которым модель опрашивала бы вручную.
"""

import time
import unittest

from core.mcp import registry
from core.mcp.tools import jobs


class Grant:
    """Включить разрешение на время теста (инструмент спрашивает конфиг)."""

    def __init__(self, case, **names):
        from core.config_manager import get_config_manager

        cfg = get_config_manager()
        saved = cfg.get("mcp", "permissions", default={}) or {}
        case.addCleanup(cfg.set, "mcp", "permissions", dict(saved))
        updated = dict(saved)
        updated.update({k: bool(v) for k, v in names.items()})
        cfg.set("mcp", "permissions", updated)


class Kind:
    """Подменить источник статуса одного вида операции."""

    def __init__(self, case, kind, statuses, permission="probes"):
        saved = jobs.KINDS[kind]
        case.addCleanup(jobs.KINDS.__setitem__, kind, saved)
        self.seen = []
        queue = list(statuses)

        def status(args):
            payload = queue.pop(0) if len(queue) > 1 else queue[0]
            self.seen.append(dict(args))
            return payload

        jobs.KINDS[kind] = (lambda: status, permission, saved[2], saved[3])


class TestPermission(unittest.TestCase):

    def setUp(self):
        registry.load_tools()

    def test_kind_permission_is_checked(self):
        payload = registry.call("job_wait", {"kind": "scan"},
                                {})["structuredContent"]
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["permission"], "probes")
        self.assertIn("probes", payload["hint"])

    def test_every_kind_names_a_real_permission(self):
        from core.mcp import permissions as perms_mod

        for kind, (_, permission, _, _) in jobs.KINDS.items():
            with self.subTest(kind=kind):
                self.assertIn(permission, perms_mod.PERMISSIONS)

    def test_published_without_permissions(self):
        # Сам инструмент виден всегда — иначе о нём не узнает тот, у
        # кого разрешение есть, но кто не читал README.
        names = {spec.name for spec in registry.available_tools({})}
        self.assertIn("job_wait", names)


class TestWaiting(unittest.TestCase):

    def setUp(self):
        registry.load_tools()
        Grant(self, probes=True, experiments=True, control=True)

    def call(self, args):
        return registry.call("job_wait", args, {})["structuredContent"]

    def test_finished_job_returns_at_once(self):
        Kind(self, "scan", [{"ok": True, "running": False,
                             "status": "finished"}])
        started = time.time()
        payload = self.call({"kind": "scan"})
        self.assertTrue(payload["done"])
        self.assertLess(time.time() - started, 1.0)
        self.assertIn("собственным инструментом", payload["hint"])

    def test_waits_until_it_stops_running(self):
        Kind(self, "scan", [{"ok": True, "running": True},
                            {"ok": True, "running": True},
                            {"ok": True, "running": False, "found": 3}])
        payload = self.call({"kind": "scan", "timeout_sec": 10})
        self.assertTrue(payload["done"])
        self.assertEqual(payload["found"], 3)
        self.assertGreaterEqual(payload["polls"], 3)

    def test_budget_ends_the_wait_without_an_error(self):
        Kind(self, "scan", [{"ok": True, "running": True}])
        payload = self.call({"kind": "scan", "timeout_sec": 1})
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["done"])
        self.assertIn("ЕЩЁ ИДЁТ", payload["hint"])

    def test_status_failure_stops_the_wait(self):
        Kind(self, "scan", [{"ok": False, "error": "сканер недоступен"}])
        payload = self.call({"kind": "scan"})
        self.assertFalse(payload["ok"])
        self.assertIn("ожидание прервано", payload["hint"])

    def test_job_id_is_passed_through(self):
        kind = Kind(self, "shell", [{"ok": True, "running": False}],
                    permission="shell_readonly")
        Grant(self, shell_readonly=True)
        self.call({"kind": "shell", "job_id": "job-1"})
        self.assertEqual(kind.seen[0], {"job_id": "job-1"})

    def test_experiment_awaiting_commit_counts_as_done(self):
        # Прогон отработал и ждёт решения. Ждать дальше значит проспать
        # дедмен-свитч, по которому всё откатится.
        from core.strategy_experiment import STATE_RUNNING

        Kind(self, "experiment",
             [{"ok": True, "state": STATE_RUNNING,
               "awaiting_commit": True}],
             permission="experiments")
        payload = self.call({"kind": "experiment"})
        self.assertTrue(payload["done"])


class TestBudget(unittest.TestCase):
    """Потолок ожидания не должен упираться в таймаут инструмента."""

    def patch(self, **limits):
        import core.mcp.auth as auth

        saved = auth.settings
        self.addCleanup(setattr, auth, "settings", saved)
        auth.settings = lambda: {"limits": limits}

    def test_default(self):
        self.patch(wait_sec=45, max_wait_sec=90, tool_timeout_sec=120)
        self.assertEqual(jobs._budget(None), 45)

    def test_request_is_capped_by_max(self):
        self.patch(wait_sec=45, max_wait_sec=90, tool_timeout_sec=300)
        self.assertEqual(jobs._budget(300), 90)

    def test_tool_timeout_lowers_the_ceiling(self):
        # 30 с таймаута инструмента — значит ждать дольше 20 нельзя:
        # ответ ещё надо собрать и отдать.
        self.patch(wait_sec=45, max_wait_sec=90, tool_timeout_sec=30)
        self.assertEqual(jobs._budget(60),
                         30 - jobs.TIMEOUT_MARGIN_SEC)

    def test_garbage_falls_back(self):
        self.patch(wait_sec="долго", max_wait_sec=None,
                   tool_timeout_sec=0)
        self.assertGreater(jobs._budget(None), 0)


if __name__ == "__main__":
    unittest.main()
