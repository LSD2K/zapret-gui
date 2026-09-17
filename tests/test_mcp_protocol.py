# tests/test_mcp_protocol.py
"""
JSON-RPC-слой MCP (core/mcp/server.py).

Проверяется то, на что клиент опирается при подключении и на чём
ломается молча: negotiation версии, capabilities, форма ответа
tools/call, батч, уведомления и — главное — что **ошибка инструмента не
является ошибкой JSON-RPC**. Клиент, получивший -32603 вместо
isError, показывает модели «сервер сломался» и та перестаёт пробовать.
"""

import json
import unittest

from core.mcp import server


def call(method, params=None, request_id=1, ctx=None):
    message = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return server.dispatch(message, ctx or {})


class TestInitialize(unittest.TestCase):

    def test_server_info_and_capabilities(self):
        r = call("initialize", {"protocolVersion": server.PROTOCOL_VERSION,
                                "clientInfo": {"name": "t", "version": "1"}})
        result = r["result"]
        self.assertEqual(result["serverInfo"]["name"], "zapret-gui")
        self.assertTrue(result["serverInfo"]["version"])
        caps = result["capabilities"]
        self.assertTrue(caps["tools"]["listChanged"])
        self.assertTrue(caps["resources"]["listChanged"])
        self.assertFalse(caps["prompts"]["listChanged"])
        self.assertIn("logging", caps)

    def test_known_client_version_is_echoed(self):
        r = call("initialize", {"protocolVersion": "2025-03-26"})
        self.assertEqual(r["result"]["protocolVersion"], "2025-03-26")

    def test_unknown_client_version_falls_back_to_ours(self):
        r = call("initialize", {"protocolVersion": "1999-01-01"})
        self.assertEqual(r["result"]["protocolVersion"],
                         server.PROTOCOL_VERSION)

    def test_permissions_reported_to_model(self):
        # Модель должна знать, что ей можно, ДО первой попытки: иначе
        # она пробует вслепую и собирает отказы.
        perms = {"control": True, "probes": False}
        r = call("initialize", {}, ctx={"permissions": perms})
        meta = r["result"]["_meta"]["zapret-gui"]
        self.assertEqual(meta["permissions"], perms)
        self.assertIn("control", r["result"]["instructions"])

    def test_readonly_instructions_when_nothing_granted(self):
        r = call("initialize", {}, ctx={"permissions": {"control": False}})
        self.assertIn("Read-only", r["result"]["instructions"])


class TestToolsList(unittest.TestCase):

    def test_two_builtin_tools(self):
        r = call("tools/list", ctx={"permissions": {}})
        names = {t["name"] for t in r["result"]["tools"]}
        self.assertIn("system_status", names)
        self.assertIn("nfqws_status", names)

    def test_tool_shape(self):
        r = call("tools/list", ctx={"permissions": {}})
        tool = r["result"]["tools"][0]
        self.assertIn("description", tool)
        self.assertEqual(tool["inputSchema"]["type"], "object")
        # Описание читает модель: английский + русский, и не простыня.
        self.assertLessEqual(len(tool["description"]), 300)
        self.assertTrue(tool["annotations"]["readOnlyHint"])

    def test_scope_filters_list(self):
        spec = server.register_tool(
            "test_scoped_tool", lambda args: {"ok": True},
            description="test", scope="control", mutating=True)
        try:
            closed = call("tools/list", ctx={"permissions": {}})
            self.assertNotIn("test_scoped_tool",
                             {t["name"] for t in closed["result"]["tools"]})
            opened = call("tools/list",
                          ctx={"permissions": {"control": True}})
            self.assertIn("test_scoped_tool",
                          {t["name"] for t in opened["result"]["tools"]})
            self.assertFalse(spec.to_wire()["annotations"]["readOnlyHint"])
        finally:
            server._REGISTRY.pop("test_scoped_tool", None)

    def test_bad_cursor_is_invalid_params(self):
        r = call("tools/list", {"cursor": "потом"})
        self.assertEqual(r["error"]["code"], server.INVALID_PARAMS)


class TestToolsCall(unittest.TestCase):

    def test_result_shape(self):
        r = call("tools/call", {"name": "nfqws_status", "arguments": {}})
        result = r["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["content"][0]["type"], "text")
        # content[0].text — тот же JSON строкой: клиенты, не умеющие
        # structuredContent, иначе видят пустой ответ.
        self.assertEqual(json.loads(result["content"][0]["text"]),
                         result["structuredContent"])
        self.assertIn("running", result["structuredContent"])

    def test_arguments_optional(self):
        r = call("tools/call", {"name": "system_status"})
        self.assertFalse(r["result"]["isError"])

    def test_tool_failure_is_not_a_jsonrpc_error(self):
        def boom(args):
            raise RuntimeError("движок не отвечает")

        server.register_tool("test_boom", boom, description="test")
        try:
            r = call("tools/call", {"name": "test_boom", "arguments": {}})
            self.assertNotIn("error", r)
            self.assertTrue(r["result"]["isError"])
            self.assertIn("движок не отвечает",
                          r["result"]["structuredContent"]["error"])
        finally:
            server._REGISTRY.pop("test_boom", None)

    def test_missing_permission_is_tool_error_with_hint(self):
        server.register_tool("test_needs_perm", lambda args: {"ok": True},
                             description="test", scope="control",
                             mutating=True)
        try:
            r = call("tools/call", {"name": "test_needs_perm"},
                     ctx={"permissions": {"control": False}})
            self.assertTrue(r["result"]["isError"])
            payload = r["result"]["structuredContent"]
            self.assertEqual(payload["permission"], "control")
            self.assertIn("control", payload["hint"])
        finally:
            server._REGISTRY.pop("test_needs_perm", None)

    def test_unknown_tool_is_invalid_params(self):
        r = call("tools/call", {"name": "нет_такого"})
        self.assertEqual(r["error"]["code"], server.INVALID_PARAMS)

    def test_bad_argument_is_invalid_params_naming_the_field(self):
        server.register_tool(
            "test_args", lambda args: {"ok": True, "got": args},
            description="test",
            schema={"type": "object",
                    "properties": {"limit": {"type": "integer"}},
                    "required": ["limit"]})
        try:
            r = call("tools/call",
                     {"name": "test_args", "arguments": {"limit": "сто"}})
            self.assertEqual(r["error"]["code"], server.INVALID_PARAMS)
            self.assertEqual(r["error"]["data"]["field"], "arguments.limit")
            self.assertIn("integer", r["error"]["message"])
        finally:
            server._REGISTRY.pop("test_args", None)

    def test_defaults_reach_the_handler(self):
        seen = {}
        server.register_tool(
            "test_defaults", lambda args: seen.update(args) or {"ok": True},
            description="test",
            schema={"type": "object",
                    "properties": {"limit": {"type": "integer",
                                             "default": 20}}})
        try:
            call("tools/call", {"name": "test_defaults", "arguments": {}})
            self.assertEqual(seen["limit"], 20)
        finally:
            server._REGISTRY.pop("test_defaults", None)


class TestResponseLimit(unittest.TestCase):

    def test_oversized_result_is_explained_not_chopped(self):
        # Обрубок JSON клиент не разберёт и не поймёт, что случилось.
        payload = {"ok": True, "rows": ["x" * 1024 for _ in range(64)]}
        result = server.tool_result(payload)
        parsed = json.loads(result["content"][0]["text"])
        self.assertTrue(parsed["truncated"])
        self.assertIn("response_kb", parsed["hint"])
        self.assertEqual(parsed, result["structuredContent"])


class TestProtocolErrors(unittest.TestCase):

    def test_parse_error(self):
        r = server.parse_error("Expecting value")
        self.assertEqual(r["error"]["code"], server.PARSE_ERROR)
        self.assertIsNone(r["id"])

    def test_invalid_request_not_an_object(self):
        r = server.dispatch("привет")
        self.assertEqual(r["error"]["code"], server.INVALID_REQUEST)

    def test_invalid_request_wrong_jsonrpc(self):
        r = server.dispatch({"jsonrpc": "1.0", "id": 1, "method": "ping"})
        self.assertEqual(r["error"]["code"], server.INVALID_REQUEST)

    def test_invalid_request_no_method(self):
        r = server.dispatch({"jsonrpc": "2.0", "id": 1})
        self.assertEqual(r["error"]["code"], server.INVALID_REQUEST)

    def test_method_not_found(self):
        r = call("tools/полёт")
        self.assertEqual(r["error"]["code"], server.METHOD_NOT_FOUND)

    def test_invalid_params_type(self):
        r = server.dispatch({"jsonrpc": "2.0", "id": 1, "method": "ping",
                             "params": "строка"})
        self.assertEqual(r["error"]["code"], server.INVALID_PARAMS)

    def test_id_is_preserved_including_string_and_zero(self):
        self.assertEqual(call("ping", request_id="abc")["id"], "abc")
        self.assertEqual(call("ping", request_id=0)["id"], 0)


class TestNotificationsAndBatch(unittest.TestCase):

    def test_notification_gets_no_answer(self):
        self.assertIsNone(
            server.dispatch({"jsonrpc": "2.0",
                             "method": "notifications/initialized"}))

    def test_unknown_notification_is_silently_ignored(self):
        self.assertIsNone(
            server.dispatch({"jsonrpc": "2.0",
                             "method": "notifications/чего-то"}))

    def test_batch_answers_only_requests(self):
        r = server.dispatch([
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ], {"permissions": {}})
        self.assertEqual([x["id"] for x in r], [1, 2])

    def test_batch_of_notifications_only(self):
        r = server.dispatch([
            {"jsonrpc": "2.0", "method": "notifications/initialized"}])
        self.assertIsNone(r)

    def test_empty_batch_is_invalid_request(self):
        r = server.dispatch([])
        self.assertEqual(r["error"]["code"], server.INVALID_REQUEST)


class TestQuietMethods(unittest.TestCase):
    """resources/* и prompts/* обязаны отвечать, а не падать в -32601.

    Клиенты опрашивают их сразу после initialize; «метод не найден»
    попадает им в лог как ошибка подключения, и пользователь идёт
    чинить то, что не сломано. С S3 они отвечают не пустотой, а
    настоящими списками (содержимое стережёт test_mcp_resources.py).
    """

    def test_resources_list_answers_with_resources(self):
        r = call("resources/list")
        self.assertTrue(r["result"]["resources"])

    def test_resource_templates_list(self):
        r = call("resources/templates/list")
        self.assertTrue(r["result"]["resourceTemplates"])

    def test_prompts_list_answers_with_prompts(self):
        r = call("prompts/list")
        self.assertTrue(r["result"]["prompts"])

    def test_resources_read_says_not_found(self):
        r = call("resources/read", {"uri": "zapret://docs/strategies"})
        self.assertEqual(r["error"]["code"], server.RESOURCE_NOT_FOUND)

    def test_ping(self):
        self.assertEqual(call("ping")["result"], {})

    def test_logging_set_level(self):
        self.assertEqual(call("logging/setLevel",
                              {"level": "info"})["result"], {})

    def test_logging_set_level_rejects_garbage(self):
        r = call("logging/setLevel", {"level": "громко"})
        self.assertEqual(r["error"]["code"], server.INVALID_PARAMS)


if __name__ == "__main__":
    unittest.main()
