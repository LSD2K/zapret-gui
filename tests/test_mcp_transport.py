# tests/test_mcp_transport.py
"""
HTTP-слой MCP (api/mcp.py).

Транспорт без SSE: единственный рабочий метод — POST. GET и DELETE
обязаны отвечать 405 с `Allow: POST` и **понятным текстом**: клиент,
получивший голый 405, пишет в лог «сервер не поддерживает MCP», хотя
поддерживает.
"""

import json
import unittest

from core.mcp import auth, server
from tests._wsgi_client import WSGIClient, build_test_app


TOKEN = "a" * 64


class _McpHTTPBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def setUp(self):
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        cfg.set("mcp", "enabled", True)
        cfg.set("mcp", "token", TOKEN)
        cfg.set("mcp", "bind", "inherit")
        cfg.set("mcp", "allow_gui_auth", False)
        cfg.set("mcp", "limits", "calls_per_minute", 10000)
        auth.reset_rate_limit()

    def tearDown(self):
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        cfg.set("mcp", "enabled", False)
        cfg.set("mcp", "token", "")
        auth.reset_rate_limit()

    def rpc(self, payload, headers=None, **kw):
        head = {"Authorization": "Bearer " + TOKEN}
        head.update(headers or {})
        return self.client.request("POST", "/api/mcp", body=payload,
                                   headers=head, **kw)


class TestMethods(_McpHTTPBase):

    def test_post_initialize(self):
        code, headers, body = self.rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": server.PROTOCOL_VERSION}})
        self.assertEqual(code, 200)
        self.assertEqual(body["result"]["serverInfo"]["name"], "zapret-gui")
        self.assertIn("application/json", headers["content-type"])

    def test_get_is_405_with_allow_and_explanation(self):
        code, headers, body = self.client.request("GET", "/api/mcp")
        self.assertEqual(code, 405)
        self.assertEqual(headers["allow"], "POST")
        self.assertIn("POST", body["error"])
        self.assertIn("не ошибка", body["error"])

    def test_delete_is_405_with_allow(self):
        code, headers, body = self.client.request("DELETE", "/api/mcp")
        self.assertEqual(code, 405)
        self.assertEqual(headers["allow"], "POST")
        self.assertIn("сесси", body["error"])


class TestProtocolHeader(_McpHTTPBase):

    def test_unknown_version_is_400_and_lists_supported(self):
        code, _, body = self.rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"MCP-Protocol-Version": "1999-01-01"})
        self.assertEqual(code, 400)
        self.assertIn(server.PROTOCOL_VERSION, body["supported"])

    def test_known_version_passes(self):
        code, _, _ = self.rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"MCP-Protocol-Version": "2025-03-26"})
        self.assertEqual(code, 200)

    def test_absent_header_is_not_an_error(self):
        # Первый initialize идёт без заголовка — это штатно.
        code, _, _ = self.rpc({"jsonrpc": "2.0", "id": 1,
                               "method": "initialize", "params": {}})
        self.assertEqual(code, 200)


class TestBodyHandling(_McpHTTPBase):

    def test_broken_json_is_parse_error_with_http_200(self):
        # Ошибка JSON-RPC едет телом с кодом 200: клиент разбирает её
        # как ответ, а не как сбой транспорта.
        code, _, body = self.client.request(
            "POST", "/api/mcp", body="{не json",
            content_type="application/json",
            headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(code, 200)
        self.assertEqual(body["error"]["code"], server.PARSE_ERROR)

    def test_wrong_content_type_is_415(self):
        code, _, body = self.client.request(
            "POST", "/api/mcp", body="{}", content_type="text/plain",
            headers={"Authorization": "Bearer " + TOKEN})
        self.assertEqual(code, 415)
        self.assertIn("application/json", body["error"])

    def test_notification_only_body_is_202(self):
        code, _, _ = self.rpc({"jsonrpc": "2.0",
                               "method": "notifications/initialized"})
        self.assertEqual(code, 202)

    def test_batch_over_http(self):
        code, _, body = self.rpc([
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ])
        self.assertEqual(code, 200)
        self.assertEqual(len(body["_data"]), 2)

    def test_cyrillic_body_is_not_truncated(self):
        # Bottle считает Content-Length по байтам: str с кириллицей
        # разъезжается с длиной и доезжает обрезанным.
        code, _, body = self.rpc({"jsonrpc": "2.0", "id": 1,
                                  "method": "tools/call",
                                  "params": {"name": "нет_такого"}})
        self.assertEqual(code, 200)
        self.assertIn("не найден", body["error"]["message"])


class TestBrokenHeaders(_McpHTTPBase):
    """Мусор в заголовках — это 4xx, а не 500.

    bottle декодирует заголовок как latin-1 → utf-8 и бросает на
    байтах, которые в UTF-8 не складываются. Точка, куда каждый
    желающий шлёт Authorization, обязана пережить один неверный байт.
    """

    def test_broken_authorization_is_401_not_500(self):
        code, _, _ = self.client.request(
            "POST", "/api/mcp", body={"jsonrpc": "2.0", "id": 1,
                                      "method": "ping"},
            headers={"Authorization": "Bearer \udcff\udcfe"})
        self.assertEqual(code, 401)

    def test_broken_session_id_is_not_500(self):
        code, _, _ = self.rpc({"jsonrpc": "2.0", "id": 1, "method": "ping"},
                              headers={"Mcp-Session-Id": "\udcff"})
        self.assertEqual(code, 200)


class TestSession(_McpHTTPBase):

    def test_session_id_is_issued(self):
        _, headers, _ = self.rpc({"jsonrpc": "2.0", "id": 1,
                                  "method": "initialize", "params": {}})
        self.assertTrue(headers.get("mcp-session-id"))

    def test_client_session_id_is_echoed_back(self):
        _, headers, _ = self.rpc({"jsonrpc": "2.0", "id": 1,
                                  "method": "ping"},
                                 headers={"Mcp-Session-Id": "abc123"})
        self.assertEqual(headers.get("mcp-session-id"), "abc123")

    def test_unknown_session_id_still_works(self):
        # Сервер без состояния: чужая сессия — не повод отказывать,
        # иначе после ребута роутера клиент получает «сессия не найдена».
        code, _, _ = self.rpc({"jsonrpc": "2.0", "id": 1, "method": "ping"},
                              headers={"Mcp-Session-Id": "неизвестная"})
        self.assertEqual(code, 200)


class TestInfo(_McpHTTPBase):

    def test_info_is_open_locally_without_token(self):
        code, _, body = self.client.request("GET", "/api/mcp/info",
                                            remote_addr="127.0.0.1")
        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["protocol_version"], server.PROTOCOL_VERSION)
        self.assertGreaterEqual(body["tools_total"], 2)
        self.assertIn("control", body["permissions"])

    def test_info_never_returns_the_token(self):
        _, _, body = self.client.request("GET", "/api/mcp/info")
        self.assertTrue(body["token_set"])
        self.assertNotIn(TOKEN, json.dumps(body, ensure_ascii=False))
        self.assertNotIn("token", [k for k in body if k != "token_set"])

    def test_info_is_403_from_outside(self):
        code, _, body = self.client.request("GET", "/api/mcp/info",
                                            remote_addr="192.168.1.50")
        self.assertEqual(code, 403)
        self.assertFalse(body["ok"])

    def test_info_allows_ipv4_mapped_loopback(self):
        code, _, _ = self.client.request("GET", "/api/mcp/info",
                                         remote_addr="::ffff:127.0.0.1")
        self.assertEqual(code, 200)


class TestExistingRoutesIntact(_McpHTTPBase):
    """MCP не должен ничего сдвинуть в уже работающем API."""

    def test_status_still_works(self):
        self.assertEqual(self.client.get_json("/api/status")["_status"], 200)

    def test_ping_still_works(self):
        self.assertEqual(self.client.get_json("/api/ping")["_status"], 200)


if __name__ == "__main__":
    unittest.main()
