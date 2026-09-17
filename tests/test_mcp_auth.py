# tests/test_mcp_auth.py
"""
Доступ к /api/mcp (core/mcp/auth.py).

Главное, что здесь зафиксировано: **по умолчанию точка закрыта**. MCP
выключен, токен пуст, все одиннадцать разрешений False. Дальше — что
именно отпирает дверь и что её точно не отпирает: чужой Origin,
внешний адрес при bind=local, перебор токена, и — отдельно — что
MCP-токен не открывает никакой другой маршрут API.
"""

import json
import unittest

from core.config_manager import DEFAULT_CONFIG, get_config_manager
from core.mcp import auth
from tests._wsgi_client import WSGIClient, build_test_app


TOKEN = "b" * 64
OTHER = "c" * 64
PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}


class TestDefaults(unittest.TestCase):
    """Дефолты — часть контракта безопасности, а не мелочь."""

    def test_mcp_is_off_out_of_the_box(self):
        mcp = DEFAULT_CONFIG["mcp"]
        self.assertFalse(mcp["enabled"])
        self.assertEqual(mcp["token"], "")
        self.assertFalse(mcp["allow_gui_auth"])
        self.assertEqual(mcp["bind"], "inherit")

    def test_all_eleven_permissions_exist_and_are_false(self):
        perms = DEFAULT_CONFIG["mcp"]["permissions"]
        self.assertEqual(set(perms), {
            "control", "strategies_write", "config_write", "probes",
            "experiments", "tunnels_write", "dangerous",
            "shell_readonly", "shell_full", "self_edit", "self_edit_core",
        })
        self.assertTrue(all(v is False for v in perms.values()))

    def test_token_is_64_hex(self):
        token = auth.generate_token()
        self.assertEqual(len(token), 64)
        int(token, 16)   # состоит только из hex-цифр

    def test_tokens_are_not_repeated(self):
        self.assertNotEqual(auth.generate_token(), auth.generate_token())

    def test_settings_fall_back_to_defaults(self):
        # Конфиг мог не загрузиться (ранний старт, тесты) — лимиты
        # всё равно обязаны быть числами, а не None.
        self.assertIsInstance(
            auth.settings()["limits"]["calls_per_minute"], int)


class _AuthBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def setUp(self):
        cfg = get_config_manager()
        cfg.set("mcp", "enabled", True)
        cfg.set("mcp", "token", TOKEN)
        cfg.set("mcp", "bind", "inherit")
        cfg.set("mcp", "allow_gui_auth", False)
        cfg.set("mcp", "limits", "calls_per_minute", 10000)
        cfg.set("gui", "cors_origins", [])
        cfg.set("gui", "auth_enabled", False)
        auth.reset_rate_limit()

    def tearDown(self):
        cfg = get_config_manager()
        cfg.set("mcp", "enabled", False)
        cfg.set("mcp", "token", "")
        cfg.set("mcp", "allow_gui_auth", False)
        cfg.set("mcp", "bind", "inherit")
        cfg.set("gui", "auth_enabled", False)
        auth.reset_rate_limit()

    def rpc(self, headers=None, **kw):
        return self.client.request("POST", "/api/mcp", body=PING,
                                   headers=headers or {}, **kw)

    def bearer(self, token=TOKEN, **extra):
        head = {"Authorization": "Bearer " + token}
        head.update(extra)
        return head


class TestToken(_AuthBase):

    def test_valid_token_passes(self):
        code, _, body = self.rpc(self.bearer())
        self.assertEqual(code, 200)
        self.assertEqual(body["result"], {})

    def test_no_token_is_401(self):
        code, headers, body = self.rpc()
        self.assertEqual(code, 401)
        self.assertIn("Bearer", headers.get("www-authenticate", ""))
        self.assertFalse(body["ok"])

    def test_wrong_token_is_401(self):
        code, _, _ = self.rpc(self.bearer(OTHER))
        self.assertEqual(code, 401)

    def test_prefix_of_the_token_is_not_enough(self):
        code, _, _ = self.rpc(self.bearer(TOKEN[:32]))
        self.assertEqual(code, 401)

    def test_disabled_mcp_rejects_valid_token(self):
        get_config_manager().set("mcp", "enabled", False)
        code, _, body = self.rpc(self.bearer())
        self.assertEqual(code, 401)
        self.assertEqual(body["reason"], "disabled")

    def test_empty_token_means_disabled(self):
        # Пустой токен — это выключенный MCP, как бы ни стоял enabled.
        get_config_manager().set("mcp", "token", "")
        code, _, body = self.rpc(self.bearer())
        self.assertEqual(code, 401)
        self.assertEqual(body["reason"], "no-token")
        self.assertFalse(auth.is_enabled())

    def test_basic_auth_alone_is_rejected_by_default(self):
        # allow_gui_auth=False: Basic-кредов мало, нужен токен.
        code, _, _ = self.rpc({"Authorization": "Basic YWRtaW46YWRtaW4="})
        self.assertEqual(code, 401)

    def test_gui_auth_when_allowed(self):
        cfg = get_config_manager()
        cfg.set("mcp", "allow_gui_auth", True)
        cfg.set("gui", "auth_enabled", True)
        cfg.set("gui", "auth_user", "admin")
        cfg.set("gui", "auth_password", "s3cret")
        import base64
        good = base64.b64encode(b"admin:s3cret").decode()
        bad = base64.b64encode(b"admin:nope").decode()
        self.assertEqual(self.rpc({"Authorization": "Basic " + good})[0], 200)
        self.assertEqual(self.rpc({"Authorization": "Basic " + bad})[0], 401)

    def test_token_never_appears_in_the_answer(self):
        for headers in (self.bearer(), self.bearer(OTHER), {}):
            _, _, body = self.rpc(headers)
            self.assertNotIn(TOKEN, json.dumps(body, ensure_ascii=False))


class TestTokenScope(_AuthBase):
    """Токен действует только на /api/mcp*."""

    def test_token_does_not_open_other_api_routes(self):
        # Ни один другой маршрут не спрашивает MCP-токен и не выдаёт по
        # нему ничего особенного: он там просто лишний заголовок.
        code, _, _ = self.client.request("GET", "/api/status",
                                         headers=self.bearer())
        self.assertEqual(code, 200)          # /api/status и так открыт
        self.assertFalse(auth.token_is_valid("Bearer " + OTHER))

    def test_token_is_valid_only_for_the_configured_one(self):
        self.assertTrue(auth.token_is_valid("Bearer " + TOKEN))
        self.assertTrue(auth.token_is_valid("bearer " + TOKEN))
        self.assertFalse(auth.token_is_valid("Bearer " + OTHER))
        self.assertFalse(auth.token_is_valid(""))
        self.assertFalse(auth.token_is_valid("Basic " + TOKEN))

    def test_token_is_invalid_while_mcp_is_off(self):
        get_config_manager().set("mcp", "enabled", False)
        self.assertFalse(auth.token_is_valid("Bearer " + TOKEN))


class TestOrigin(_AuthBase):
    """Защита от DNS-rebinding: браузер на чужом сайте не должен
    добираться до роутера, даже угадав адрес."""

    def test_foreign_origin_is_403(self):
        code, _, body = self.rpc(self.bearer(Origin="http://evil.example"))
        self.assertEqual(code, 403)
        self.assertEqual(body["reason"], "origin")

    def test_localhost_origin_is_allowed(self):
        for origin in ("http://localhost:3000", "http://127.0.0.1:8080",
                       "https://[::1]:8443"):
            code, _, _ = self.rpc(self.bearer(Origin=origin))
            self.assertEqual(code, 200, origin)

    def test_same_origin_is_allowed(self):
        # Host в тест-клиенте — "localhost".
        code, _, _ = self.rpc(self.bearer(Origin="http://localhost"))
        self.assertEqual(code, 200)

    def test_allowlisted_origin_is_allowed(self):
        get_config_manager().set("gui", "cors_origins",
                                 ["https://panel.example"])
        code, _, _ = self.rpc(self.bearer(Origin="https://panel.example"))
        self.assertEqual(code, 200)

    def test_no_origin_header_is_fine(self):
        # Запрос не из браузера — Origin не шлётся вовсе.
        self.assertEqual(self.rpc(self.bearer())[0], 200)

    def test_origin_is_checked_before_the_token(self):
        # Иначе чужой сайт узнаёт по коду ответа, верен ли токен.
        code, _, _ = self.rpc({"Origin": "http://evil.example"})
        self.assertEqual(code, 403)


class TestBind(_AuthBase):

    def test_bind_local_blocks_external_address(self):
        get_config_manager().set("mcp", "bind", "local")
        code, _, body = self.rpc(self.bearer(), remote_addr="192.168.1.50")
        self.assertEqual(code, 403)
        self.assertEqual(body["reason"], "bind")

    def test_bind_local_allows_loopback(self):
        get_config_manager().set("mcp", "bind", "local")
        self.assertEqual(self.rpc(self.bearer(),
                                  remote_addr="127.0.0.1")[0], 200)
        self.assertEqual(self.rpc(self.bearer(), remote_addr="::1")[0], 200)

    def test_bind_inherit_allows_lan(self):
        self.assertEqual(self.rpc(self.bearer(),
                                  remote_addr="192.168.1.50")[0], 200)

    def test_bind_is_checked_before_the_token(self):
        get_config_manager().set("mcp", "bind", "local")
        code, _, _ = self.rpc(self.bearer(OTHER), remote_addr="10.0.0.5")
        self.assertEqual(code, 403)


class TestRateLimit(_AuthBase):

    def test_limit_is_enforced_and_names_the_setting(self):
        get_config_manager().set("mcp", "limits", "calls_per_minute", 3)
        auth.reset_rate_limit()
        for _ in range(3):
            self.assertEqual(self.rpc(self.bearer())[0], 200)
        code, headers, body = self.rpc(self.bearer())
        self.assertEqual(code, 429)
        self.assertTrue(int(headers["retry-after"]) >= 1)
        self.assertIn("calls_per_minute", body["error"])

    def test_failed_auth_does_not_burn_the_quota(self):
        # Иначе перебор токена снаружи выбивает квоту у легального
        # клиента: отказ в обслуживании без единого угаданного токена.
        get_config_manager().set("mcp", "limits", "calls_per_minute", 3)
        auth.reset_rate_limit()
        for _ in range(20):
            self.rpc(self.bearer(OTHER))
        self.assertEqual(self.rpc(self.bearer())[0], 200)

    def test_zero_disables_the_limit(self):
        get_config_manager().set("mcp", "limits", "calls_per_minute", 0)
        auth.reset_rate_limit()
        for _ in range(30):
            self.assertEqual(self.rpc(self.bearer())[0], 200)


class TestDenyLogging(_AuthBase):
    """Отказы сворачиваются: перебор токена не должен забить лог-буфер,
    вытеснив из него всё остальное."""

    def test_repeated_denials_log_once(self):
        from core.log_buffer import get_log_buffer
        auth.reset_rate_limit()
        before = len(get_log_buffer().get_last(500))
        for _ in range(50):
            self.rpc(self.bearer(OTHER))
        after = len(get_log_buffer().get_last(500))
        self.assertLessEqual(after - before, 2)

    def test_token_is_never_written_to_the_log(self):
        from core.log_buffer import get_log_buffer
        self.rpc(self.bearer(OTHER))
        self.rpc(self.bearer())
        dump = json.dumps(get_log_buffer().get_last(200), ensure_ascii=False)
        self.assertNotIn(TOKEN, dump)
        self.assertNotIn(OTHER, dump)


class TestFullAppSecurityGate(unittest.TestCase):
    """Приложение целиком: MCP-клиент проходит гейт GUI.

    У MCP-клиента нет ни Basic-кред, ни браузерного Origin — только
    Bearer-токен. Общий `before_request`-гейт в app.py про токен ничего
    не знает и при `gui.auth_enabled=true` отдавал бы 401 ещё до
    `core/mcp/auth.check`. Врезка в гейте пускает такой запрос дальше —
    но только на /api/mcp* и только с верным токеном.
    """

    @classmethod
    def setUpClass(cls):
        import app as app_module
        cls.client = WSGIClient(app_module.create_app())

    def setUp(self):
        cfg = get_config_manager()
        cfg.set("mcp", "enabled", True)
        cfg.set("mcp", "token", TOKEN)
        cfg.set("mcp", "bind", "inherit")
        cfg.set("gui", "auth_enabled", True)
        cfg.set("gui", "auth_user", "admin")
        cfg.set("gui", "auth_password", "s3cret")
        auth.reset_rate_limit()

    def tearDown(self):
        cfg = get_config_manager()
        cfg.set("mcp", "enabled", False)
        cfg.set("mcp", "token", "")
        cfg.set("gui", "auth_enabled", False)
        cfg.set("gui", "auth_password", "")
        auth.reset_rate_limit()

    def rpc(self, headers):
        return self.client.request("POST", "/api/mcp", body=PING,
                                   headers=headers)

    def test_bearer_passes_the_gui_gate(self):
        code, _, body = self.rpc({"Authorization": "Bearer " + TOKEN})
        self.assertEqual(code, 200)
        self.assertEqual(body["result"], {})

    def test_wrong_bearer_still_fails(self):
        self.assertEqual(self.rpc({"Authorization": "Bearer " + OTHER})[0],
                         401)

    def test_bearer_does_not_open_other_routes(self):
        # Тот же токен на обычном маршруте GUI — по-прежнему 401 от
        # Basic-гейта: врезка касается только /api/mcp*.
        code, _, _ = self.client.request(
            "GET", "/api/status",
            headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(code, 401)


class TestTokenStorage(unittest.TestCase):

    def test_settings_file_is_not_world_readable(self):
        # Токен лежит в общем settings.json — файл не должен читаться
        # кем попало.
        import os
        import stat
        import tempfile
        from core.config_manager import ConfigManager

        with tempfile.TemporaryDirectory() as tmp:
            cfg = ConfigManager(config_dir=tmp)
            cfg.load()
            cfg.set("mcp", "token", TOKEN)
            self.assertTrue(cfg.save())
            mode = stat.S_IMODE(os.stat(cfg.path).st_mode)
            self.assertEqual(mode & (stat.S_IRGRP | stat.S_IROTH), 0,
                             "settings.json доступен на чтение чужим: %o"
                             % mode)


if __name__ == "__main__":
    unittest.main()
