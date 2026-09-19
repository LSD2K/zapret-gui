# tests/test_mcp_stdio.py
"""
stdio-мост MCP (`core/mcp/stdio.py`).

Мост — это `ssh router zapret-gui mcp --stdio`: канал дал ssh, протокол
едет построчно через stdin/stdout. Проверяем то, из-за чего клиент
молча перестаёт работать и об этом никак не узнать:

* одна строка — один JSON-RPC объект, и в stdout **больше ничего**;
* мусор в stdin даёт `-32700`, а мост живёт дальше;
* уведомление ответа не порождает;
* EOF завершает мост нулём;
* чужой `print()` не попадает в протокол;
* режим прокси возвращает ответ чужой точки и не падает на её отказах.
"""

import io
import json
import unittest
from unittest import mock

from core.mcp import stdio


def run(lines, **kw):
    """Прогнать мост на готовых строках. Вернуть (код, stdout, stderr)."""
    text = "".join(line + "\n" for line in lines)
    out, err = io.StringIO(), io.StringIO()
    code = stdio.serve(io.StringIO(text), out, err, **kw)
    return code, out.getvalue(), err.getvalue()


def answers(stdout):
    """Разобрать stdout построчно — заодно проверка «одна строка = объект»."""
    return [json.loads(line) for line in stdout.splitlines() if line]


class TestLocalBridge(unittest.TestCase):

    def test_request_gets_one_line_answer(self):
        code, out, _ = run(['{"jsonrpc":"2.0","id":1,"method":"ping"}'])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertEqual(answers(out)[0], {"jsonrpc": "2.0", "id": 1,
                                           "result": {}})

    def test_initialize_answers_with_server_info(self):
        _, out, _ = run(['{"jsonrpc":"2.0","id":7,"method":"initialize",'
                         '"params":{}}'])
        result = answers(out)[0]["result"]
        self.assertEqual(result["serverInfo"]["name"], "zapret-gui")

    def test_several_requests_keep_order_and_ids(self):
        _, out, _ = run([
            '{"jsonrpc":"2.0","id":1,"method":"ping"}',
            '{"jsonrpc":"2.0","id":2,"method":"ping"}',
            '{"jsonrpc":"2.0","id":"третий","method":"ping"}',
        ])
        self.assertEqual([a["id"] for a in answers(out)], [1, 2, "третий"])

    def test_batch_is_one_line_with_array(self):
        _, out, _ = run(['[{"jsonrpc":"2.0","id":1,"method":"ping"},'
                         '{"jsonrpc":"2.0","id":2,"method":"ping"}]'])
        self.assertEqual(len(out.splitlines()), 1)
        batch = answers(out)[0]
        self.assertEqual([item["id"] for item in batch], [1, 2])

    def test_notification_produces_nothing(self):
        # Уведомление ответа не порождает — ни успешного, ни ошибочного.
        _, out, _ = run(['{"jsonrpc":"2.0","method":'
                         '"notifications/initialized"}'])
        self.assertEqual(out, "")

    def test_batch_of_notifications_produces_nothing(self):
        _, out, _ = run(['[{"jsonrpc":"2.0","method":"notifications/'
                         'initialized"},{"jsonrpc":"2.0","method":'
                         '"notifications/cancelled"}]'])
        self.assertEqual(out, "")

    def test_blank_lines_are_skipped(self):
        _, out, _ = run(["", "   ",
                         '{"jsonrpc":"2.0","id":1,"method":"ping"}', ""])
        self.assertEqual(len(answers(out)), 1)

    def test_eof_ends_the_bridge_with_zero(self):
        code, out, _ = run([])
        self.assertEqual(code, 0)
        self.assertEqual(out, "")


class TestGarbageInStdin(unittest.TestCase):
    """Кривая строка не должна убивать сессию целиком."""

    def test_garbage_is_parse_error(self):
        _, out, _ = run(["мусор"])
        answer = answers(out)[0]
        self.assertEqual(answer["error"]["code"], stdio.PARSE_ERROR)
        self.assertIsNone(answer["id"])

    def test_bridge_survives_garbage_and_answers_next(self):
        _, out, err = run(["{не json",
                           '{"jsonrpc":"2.0","id":5,"method":"ping"}'])
        got = answers(out)
        self.assertEqual(got[0]["error"]["code"], stdio.PARSE_ERROR)
        self.assertEqual(got[1]["id"], 5)
        # Объяснение — в stderr, а не в протоколе.
        self.assertIn("нечитаемая строка", err)

    def test_json_null_is_parse_error(self):
        _, out, _ = run(["null"])
        self.assertEqual(answers(out)[0]["error"]["code"],
                         stdio.PARSE_ERROR)

    def test_broken_method_is_a_protocol_error_not_a_crash(self):
        _, out, _ = run(['{"jsonrpc":"2.0","id":1,"method":"нет/такого"}'])
        self.assertEqual(answers(out)[0]["error"]["code"],
                         -32601)

    def test_handler_exception_answers_instead_of_dying(self):
        def boom(payload):
            raise RuntimeError("диспетчер упал")

        with mock.patch.object(stdio, "_local", lambda err: boom):
            _, out, err = run(['{"jsonrpc":"2.0","id":9,"method":"ping"}',
                               '{"jsonrpc":"2.0","id":10,"method":"ping"}'])
        got = answers(out)
        self.assertEqual(got[0]["id"], 9)
        self.assertEqual(got[0]["error"]["code"], stdio.INTERNAL_ERROR)
        # Вторая строка тоже обслужена: одна ошибка не заканчивает сессию.
        self.assertEqual(got[1]["id"], 10)
        self.assertIn("ошибка обработки", err)


class TestStdoutIsSacred(unittest.TestCase):
    """В stdout не должно попасть ничего, кроме JSON-RPC."""

    def test_nothing_but_json_lines(self):
        _, out, _ = run(['{"jsonrpc":"2.0","id":1,"method":"initialize",'
                         '"params":{}}',
                         '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'])
        for line in out.splitlines():
            self.assertTrue(line.strip())
            json.loads(line)          # упадёт, если в stdout попал текст

    def test_service_messages_go_to_stderr(self):
        _, out, err = run(["не json"])
        self.assertNotIn("zapret-gui mcp:", out)
        self.assertIn("zapret-gui mcp:", err)

    def test_answer_holds_no_newlines(self):
        # Перевод строки внутри ответа разорвал бы объект надвое.
        _, out, _ = run(['{"jsonrpc":"2.0","id":1,"method":"initialize",'
                         '"params":{}}'])
        self.assertEqual(len(out.splitlines()), 1)
        self.assertIn("\\n", out)     # переводы строк экранированы

    def test_non_utf8_stdout_falls_back_to_ascii(self):
        """Локаль без UTF-8 не должна ронять мост."""

        class AsciiOut(io.StringIO):
            def write(self, text):
                text.encode("ascii")   # как настоящий stdout в POSIX-локали
                return super().write(text)

        out, err = AsciiOut(), io.StringIO()
        stdio.serve(io.StringIO('{"jsonrpc":"2.0","id":1,'
                                '"method":"нет/такого"}\n'), out, err)
        answer = json.loads(out.getvalue().strip())
        self.assertEqual(answer["error"]["code"], -32601)


class TestProxyMode(unittest.TestCase):
    """`--url`: мост пересылает строки в HTTP-точку другого экземпляра."""

    def _urlopen(self, status=200, body=b'{"jsonrpc":"2.0","id":1,'
                                         b'"result":{}}'):
        response = mock.MagicMock()
        response.read.return_value = body
        response.status = status
        response.__enter__ = lambda s: s
        response.__exit__ = lambda s, *a: False
        return mock.MagicMock(return_value=response)

    def test_answer_comes_from_the_remote(self):
        opener = self._urlopen()
        with mock.patch("urllib.request.urlopen", opener):
            _, out, _ = run(['{"jsonrpc":"2.0","id":1,"method":"ping"}'],
                            url="http://192.168.1.1:8080", token="t" * 8)
        self.assertEqual(answers(out)[0], {"jsonrpc": "2.0", "id": 1,
                                           "result": {}})
        request = opener.call_args[0][0]
        self.assertEqual(request.full_url, "http://192.168.1.1:8080/api/mcp")
        self.assertEqual(request.headers["Authorization"], "Bearer " + "t" * 8)

    def test_url_with_endpoint_is_not_doubled(self):
        opener = self._urlopen()
        with mock.patch("urllib.request.urlopen", opener):
            run(['{"jsonrpc":"2.0","id":1,"method":"ping"}'],
                url="http://router/api/mcp/")
        self.assertEqual(opener.call_args[0][0].full_url,
                         "http://router/api/mcp")

    def test_202_means_nothing_to_answer(self):
        opener = self._urlopen(status=202, body=b"")
        with mock.patch("urllib.request.urlopen", opener):
            _, out, _ = run(['{"jsonrpc":"2.0","method":'
                             '"notifications/initialized"}'],
                            url="http://router")
        self.assertEqual(out, "")

    def test_unreachable_remote_answers_instead_of_hanging(self):
        # Без ответа клиент висит до собственного таймаута — а причина
        # видна только здесь.
        with mock.patch("urllib.request.urlopen",
                        side_effect=OSError("connection refused")):
            _, out, _ = run(['{"jsonrpc":"2.0","id":3,"method":"ping"}'],
                            url="http://router")
        answer = answers(out)[0]
        self.assertEqual(answer["id"], 3)
        self.assertEqual(answer["error"]["code"], stdio.INTERNAL_ERROR)
        self.assertIn("недоступен", answer["error"]["message"])

    def test_http_error_with_jsonrpc_body_is_passed_through(self):
        import urllib.error
        body = b'{"jsonrpc":"2.0","id":4,"error":{"code":-32600,' \
               b'"message":"bad"}}'
        error = urllib.error.HTTPError("http://router/api/mcp", 400, "Bad",
                                       {}, io.BytesIO(body))
        with mock.patch("urllib.request.urlopen", side_effect=error):
            _, out, _ = run(['{"jsonrpc":"2.0","id":4,"method":"ping"}'],
                            url="http://router")
        self.assertEqual(answers(out)[0]["error"]["code"], -32600)

    def test_http_error_without_body_becomes_readable_error(self):
        import urllib.error
        error = urllib.error.HTTPError("http://router/api/mcp", 401,
                                       "Unauthorized", {},
                                       io.BytesIO(b"nope"))
        with mock.patch("urllib.request.urlopen", side_effect=error):
            _, out, _ = run(['{"jsonrpc":"2.0","id":4,"method":"ping"}'],
                            url="http://router")
        message = answers(out)[0]["error"]["message"]
        self.assertIn("401", message)


class TestEndpoint(unittest.TestCase):

    def test_root_gets_api_mcp(self):
        self.assertEqual(stdio._endpoint("http://router:8080"),
                         "http://router:8080/api/mcp")

    def test_trailing_slash_is_trimmed(self):
        self.assertEqual(stdio._endpoint("http://router:8080/"),
                         "http://router:8080/api/mcp")

    def test_empty_stays_empty(self):
        self.assertEqual(stdio._endpoint(""), "")


if __name__ == "__main__":
    unittest.main()
