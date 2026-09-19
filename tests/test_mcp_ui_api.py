# tests/test_mcp_ui_api.py
"""
Роуты страницы «MCP-сервер» (`api/mcp_ui.py`, S15).

Страница — это руль и тормоз: включить, выдать токен, раздать
разрешения, увидеть журнал и отобрать всё одной кнопкой. Поэтому здесь
проверяется не «роут отвечает 200», а три вещи, в которых цена ошибки —
чужой доступ к роутеру:

1. **Число инструментов меняется синхронно с разрешениями.** Это самая
   наглядная обратная связь во всём интерфейсе, и если она врёт,
   человек раздаёт права вслепую.
2. **«Запретить shell немедленно» действительно запрещает**: гасит оба
   переключателя, снимает живые фоновые задачи и отзывает ожидающие
   подтверждения. Кнопка, которая гасит только флаги, обещает больше,
   чем делает.
3. **MCP-токен не открывает панель разрешений.** Иначе модель могла бы
   расширить себе права своим же токеном.
"""

import json
import unittest

import app as app_module
from core.mcp import auth
from tests._wsgi_client import WSGIClient, build_test_app


GUI_PASSWORD = "s3cret"
TOKEN = "b" * 64


def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


class _UIBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def setUp(self):
        cfg = _cfg()
        cfg.set("mcp", "enabled", False)
        cfg.set("mcp", "token", "")
        cfg.set("mcp", "permissions", {})
        cfg.set("mcp", "transports", {"http": True, "sse": False})
        auth.reset_rate_limit()

    def tearDown(self):
        cfg = _cfg()
        cfg.set("mcp", "enabled", False)
        cfg.set("mcp", "token", "")
        cfg.set("mcp", "permissions", {})

    # ─── помощники ───

    def state(self):
        code, _, body = self.client.request("GET", "/api/mcp/ui/state")
        self.assertEqual(code, 200)
        return body

    def post(self, path, payload=None, expect=200):
        code, _, body = self.client.request("POST", path, body=payload)
        self.assertEqual(code, expect, json.dumps(body, ensure_ascii=False))
        return body

    def perms(self, mapping, expect=200):
        return self.post("/api/mcp/ui/permissions",
                         {"permissions": mapping}, expect)


class TestState(_UIBase):
    """Один роут — один ответ: всё, что рисует страница, сразу."""

    def test_state_has_every_block(self):
        body = self.state()
        self.assertTrue(body["ok"])
        for key in ("info", "access", "audit", "experiment", "code", "shell"):
            self.assertIn(key, body, key)

    def test_info_carries_counts_and_effective_permissions(self):
        info = self.state()["info"]
        self.assertIn("tools_total", info)
        self.assertIn("tools_available", info)
        self.assertIn("tools_by_scope", info)
        self.assertIn("permissions_effective", info)
        self.assertIn("permissions_info", info)
        self.assertGreater(info["tools_total"], info["tools_available"])

    def test_access_says_where_the_endpoint_is_reachable_from(self):
        access = self.state()["access"]
        # gui.host страница не знает, а именно он решает, видна ли точка
        # кому-то, кроме самого роутера.
        self.assertIn("gui_host", access)
        self.assertIn("loopback_only", access)
        # Своего TLS у GUI нет, и предупреждение на странице обязано
        # опираться на факт, а не на догадку.
        self.assertFalse(access["tls_builtin"])

    def test_state_is_reachable_from_lan(self):
        """Страницу открывают из браузера на LAN, а не с петли.

        ``/api/mcp/info`` намеренно loopback-only, и если бы состояние
        брали оттуда, страница была бы пустой у всех, кто админит
        роутер обычным способом.
        """
        code, _, body = self.client.request("GET", "/api/mcp/ui/state",
                                            remote_addr="192.168.1.5")
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])

        code, _, _ = self.client.request("GET", "/api/mcp/info",
                                         remote_addr="192.168.1.5")
        self.assertEqual(code, 403)

    def test_blocks_report_availability(self):
        body = self.state()
        for key in ("experiment", "code", "shell"):
            self.assertIn("available", body[key], key)


class TestEnableAndToken(_UIBase):

    def test_enable_and_disable(self):
        body = self.post("/api/mcp/ui/enabled", {"enabled": True})
        self.assertTrue(body["info"]["enabled"])
        self.assertTrue(auth.settings()["enabled"])

        body = self.post("/api/mcp/ui/enabled", {"enabled": False})
        self.assertFalse(body["info"]["enabled"])

    def test_enabled_without_token_is_not_active(self):
        """Включённый флаг при пустом токене — это «пускать некого»."""
        body = self.post("/api/mcp/ui/enabled", {"enabled": True})
        self.assertTrue(body["info"]["enabled"])
        self.assertFalse(body["info"]["active"])

    def test_rotate_returns_fresh_token_once(self):
        body = self.post("/api/mcp/ui/token", {"action": "rotate"})
        token = body["token"]
        self.assertEqual(len(token), 64)
        self.assertTrue(body["info"]["token_set"])
        # Сам токен в общем состоянии не показывается никогда.
        self.assertNotIn("token", self.state()["info"])

    def test_show_token_needs_an_explicit_request(self):
        rotated = self.post("/api/mcp/ui/token", {"action": "rotate"})
        code, _, body = self.client.request("GET", "/api/mcp/ui/token")
        self.assertEqual(code, 200)
        self.assertEqual(body["token"], rotated["token"])

    def test_show_without_token_is_an_error(self):
        code, _, body = self.client.request("GET", "/api/mcp/ui/token")
        self.assertEqual(code, 400)
        self.assertIn("не задан", body["error"])

    def test_clear_token(self):
        self.post("/api/mcp/ui/token", {"action": "rotate"})
        body = self.post("/api/mcp/ui/token", {"action": "clear"})
        self.assertEqual(body["token"], "")
        self.assertFalse(body["info"]["token_set"])

    def test_unknown_action_is_rejected(self):
        self.post("/api/mcp/ui/token", {"action": "ыыы"}, expect=400)

    def test_sse_toggles_without_restart(self):
        body = self.post("/api/mcp/ui/transports", {"sse": True})
        self.assertTrue(body["info"]["sse"]["enabled"])
        body = self.post("/api/mcp/ui/transports", {"sse": False})
        self.assertFalse(body["info"]["sse"]["enabled"])
        self.post("/api/mcp/ui/transports", {}, expect=400)


class TestPermissions(_UIBase):

    def test_tool_count_follows_the_checkboxes(self):
        """Число инструментов на странице меняется синхронно с галками."""
        before = self.state()["info"]["tools_available"]
        body = self.perms({"control": True})
        after = body["info"]["tools_available"]
        self.assertGreater(after, before)

        body = self.perms({"control": False})
        self.assertEqual(body["info"]["tools_available"], before)

    def test_partial_map_keeps_the_rest(self):
        self.perms({"control": True, "probes": True})
        body = self.perms({"dangerous": True})
        perms = body["info"]["permissions"]
        self.assertTrue(perms["control"])
        self.assertTrue(perms["probes"])
        self.assertTrue(perms["dangerous"])

    def test_experiments_alone_does_not_take_effect(self):
        """`experiments` без control+probes виден, но не действует."""
        body = self.perms({"experiments": True})
        info = body["info"]
        self.assertTrue(info["permissions"]["experiments"])
        self.assertFalse(info["permissions_effective"]["experiments"])
        item = [p for p in info["permissions_info"]
                if p["key"] == "experiments"][0]
        self.assertEqual(sorted(item["missing"]), ["control", "probes"])

        body = self.perms({"control": True, "probes": True})
        self.assertTrue(body["info"]["permissions_effective"]["experiments"])

    def test_shell_full_opens_shell_readonly(self):
        body = self.perms({"shell_full": True})
        effective = body["info"]["permissions_effective"]
        self.assertTrue(effective["shell_readonly"])
        item = [p for p in body["info"]["permissions_info"]
                if p["key"] == "shell_readonly"][0]
        self.assertEqual(item["implied_by"], ["shell_full"])

    def test_unknown_permission_is_rejected(self):
        body = self.perms({"teleport": True}, expect=400)
        self.assertIn("teleport", body["error"])

    def test_empty_body_is_rejected(self):
        self.post("/api/mcp/ui/permissions", {"permissions": {}}, expect=400)

    def test_changed_list_names_only_what_moved(self):
        self.perms({"control": True})
        body = self.perms({"control": True, "probes": True})
        self.assertEqual(body["changed"], ["probes"])


class TestShellPanic(_UIBase):
    """«Запретить shell немедленно» — кнопка, а не жест."""

    def setUp(self):
        super().setUp()
        from core import shell_exec
        shell_exec.reset_jobs()
        shell_exec.reset_confirms()

    def tearDown(self):
        from core import shell_exec
        shell_exec.reset_jobs()
        shell_exec.reset_confirms()
        super().tearDown()

    def test_panic_turns_both_switches_off(self):
        self.perms({"shell_full": True})
        body = self.post("/api/mcp/ui/shell/panic")
        perms = body["info"]["permissions"]
        self.assertFalse(perms["shell_full"])
        self.assertFalse(perms["shell_readonly"])
        self.assertFalse(body["info"]["permissions_effective"]["shell_full"])

    def test_panic_kills_a_running_async_command(self):
        """Снять разрешения мало: запущенная команда живёт сама по себе."""
        from core import shell_exec

        self.perms({"shell_full": True})
        plan, refusal = shell_exec.plan_command(argv=["sleep", "30"],
                                                full=True)
        self.assertIsNone(refusal, refusal)
        started = shell_exec.start_job(plan, timeout_sec=30)
        self.assertTrue(started.get("ok"), started)
        job_id = started["job_id"]
        self.assertTrue(shell_exec.job_status(job_id)["running"])

        body = self.post("/api/mcp/ui/shell/panic")
        self.assertIn(job_id, body["stopped"])
        self.assertFalse(shell_exec.job_status(job_id)["running"])

    def test_panic_revokes_pending_confirmations(self):
        from core import shell_exec

        shell_exec.pending_confirm("reboot", "reboot", "роутер уйдёт в ребут",
                                   scope="dangerous",
                                   payload={"argv": ["true"]})
        self.assertEqual(len(shell_exec.list_confirms()), 1)

        body = self.post("/api/mcp/ui/shell/panic")
        self.assertEqual(body["dropped_confirms"], 1)
        self.assertEqual(shell_exec.list_confirms(), [])

    def test_pending_confirmations_are_visible_on_the_page(self):
        from core import shell_exec

        shell_exec.pending_confirm("rm", "rm -rf /tmp/x", "удалит каталог",
                                   scope="shell_full",
                                   payload={"argv": ["true"]})
        block = self.state()["shell"]
        self.assertTrue(block["available"])
        self.assertEqual(len(block["pending"]), 1)
        item = block["pending"][0]
        self.assertEqual(item["summary"], "rm -rf /tmp/x")
        self.assertIn("expires_in_sec", item)
        # Сам план команды на страницу не уезжает: там только сводка.
        self.assertNotIn("payload", item)

    def test_reject_drops_the_token(self):
        from core import shell_exec

        refusal = shell_exec.pending_confirm(
            "rm", "rm -rf /tmp/x", "удалит каталог", scope="shell_full",
            payload={"argv": ["true"]})
        token = refusal["confirm_token"]

        body = self.post("/api/mcp/ui/shell/confirm",
                         {"token": token, "decision": "reject"})
        self.assertTrue(body["ok"])
        self.assertEqual(shell_exec.list_confirms(), [])

        # Повторное решение по тому же токену уже невозможно.
        self.post("/api/mcp/ui/shell/confirm",
                  {"token": token, "decision": "reject"}, expect=400)

    def test_approve_without_permission_is_refused(self):
        """Токен подтверждения сам по себе прав не даёт."""
        from core import shell_exec

        refusal = shell_exec.pending_confirm(
            "rm", "rm -rf /tmp/x", "удалит каталог", scope="shell_full",
            payload={"argv": ["true"], "mode": "argv", "display": "true"})
        token = refusal["confirm_token"]

        code, _, body = self.client.request(
            "POST", "/api/mcp/ui/shell/confirm",
            body={"token": token, "decision": "approve"})
        self.assertEqual(code, 403)
        self.assertEqual(body["permission"], "shell_full")

    def test_decision_must_be_explicit(self):
        self.post("/api/mcp/ui/shell/confirm",
                  {"token": "cf-x", "decision": "maybe"}, expect=400)
        self.post("/api/mcp/ui/shell/confirm", {"decision": "reject"},
                  expect=400)


class TestAuditBlock(_UIBase):

    def test_journal_and_undo_are_reported(self):
        audit = self.state()["audit"]
        self.assertIn("enabled", audit)
        self.assertIn("records", audit)
        self.assertIn("undoable", audit)
        self.assertIsInstance(audit["records"], list)

    def test_undo_calls_the_same_thing_the_model_calls(self):
        """Кнопка «Отменить последнее» — это ``mcp_undo_last``.

        Настоящий снимок здесь не откатываем: на общем прогоне рядом
        живут снимки других тестов, и «отменить последнее» откатило бы
        чужой firewall. Проверяется проводка: аргумент доезжает, а
        отказ становится 400, а не молчаливым «ок».
        """
        from core.mcp import audit as audit_mod

        seen = {}
        original = audit_mod.undo_last

        def fake(kind=""):
            seen["kind"] = kind
            return {"ok": False, "reverted": False,
                    "reason": "откатывать нечего"}

        audit_mod.undo_last = fake
        try:
            code, _, body = self.client.request("POST", "/api/mcp/ui/undo",
                                                body={"kind": "config"})
        finally:
            audit_mod.undo_last = original

        self.assertEqual(seen["kind"], "config")
        self.assertEqual(code, 400)
        self.assertIn("reason", body)


class TestCodeBlock(_UIBase):

    def test_unknown_snapshot_is_named(self):
        code, _, body = self.client.request(
            "GET", "/api/mcp/ui/code/diff?snapshot_id=snap-19700101-000000")
        self.assertEqual(code, 400)
        self.assertIn("snap-19700101-000000", body["error"])

    def test_diff_requires_a_snapshot_id(self):
        code, _, _ = self.client.request("GET", "/api/mcp/ui/code/diff")
        self.assertEqual(code, 400)


class TestTokenDoesNotOpenThePanel(unittest.TestCase):
    """MCP-токен пускает в протокол, но не в раздачу разрешений.

    Врезка в ``app.py`` пропускает Bearer-токен мимо авторизации GUI —
    у MCP-клиента нет ни Basic-кред, ни Origin. Поддерево
    ``/api/mcp/ui/`` из неё исключено: иначе модель расширяла бы себе
    права своим же токеном.
    """

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(app_module.create_app())

    def setUp(self):
        cfg = _cfg()
        cfg.set("mcp", "enabled", True)
        cfg.set("mcp", "token", TOKEN)
        cfg.set("mcp", "limits", "calls_per_minute", 10000)
        cfg.set("gui", "auth_enabled", True)
        cfg.set("gui", "auth_user", "admin")
        cfg.set("gui", "auth_password", GUI_PASSWORD)
        auth.reset_rate_limit()

    def tearDown(self):
        cfg = _cfg()
        cfg.set("mcp", "enabled", False)
        cfg.set("mcp", "token", "")
        cfg.set("gui", "auth_enabled", False)
        cfg.set("gui", "auth_password", "admin")
        auth.reset_rate_limit()

    def test_token_still_opens_the_protocol_endpoint(self):
        code, _, _ = self.client.request(
            "POST", "/api/mcp",
            body={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(code, 200)

    def test_token_does_not_open_the_permissions_route(self):
        code, headers, _ = self.client.request(
            "POST", "/api/mcp/ui/permissions",
            body={"permissions": {"shell_full": True}},
            headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(code, 401)
        self.assertIn("basic", headers.get("www-authenticate", "").lower())
        self.assertFalse(auth.permissions().get("shell_full"))

    def test_token_does_not_show_the_token(self):
        code, _, _ = self.client.request(
            "GET", "/api/mcp/ui/token",
            headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(code, 401)

    def test_gui_credentials_do_open_the_panel(self):
        import base64

        basic = base64.b64encode(
            ("admin:" + GUI_PASSWORD).encode("utf-8")).decode("ascii")
        code, _, body = self.client.request(
            "GET", "/api/mcp/ui/state",
            headers={"Authorization": "Basic " + basic})
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])


class TestConfigDoesNotLeakTheToken(_UIBase):
    """`/api/config` отдаёт весь settings.json — токену там не место."""

    def test_token_is_masked_in_config(self):
        self.post("/api/mcp/ui/token", {"action": "rotate"})
        code, _, body = self.client.request("GET", "/api/config")
        self.assertEqual(code, 200)
        self.assertEqual(body["config"]["mcp"]["token"], "***")

    def test_mask_is_not_written_back(self):
        """Маска в PUT не должна обнулять секрет."""
        rotated = self.post("/api/mcp/ui/token", {"action": "rotate"})
        code, _, _ = self.client.request(
            "PUT", "/api/config", body={"mcp": {"token": "***"}})
        self.assertEqual(code, 200)
        self.assertEqual(auth.settings()["token"], rotated["token"])


if __name__ == "__main__":
    unittest.main()
