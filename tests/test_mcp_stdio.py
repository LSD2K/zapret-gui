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
* режим прокси возвращает ответ чужой точки и не падает на её отказах;
* **уведомления** (подписка на ресурсы, смена инструментов) приходят,
  пока мост ждёт строки в stdin, — и не рвут строку ответа пополам.
"""

import io
import json
import threading
import time
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

        with mock.patch.object(stdio, "_local",
                               lambda err, session=None: boom):
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


class _SlowStdin:
    """stdin, который отдаёт строки по одной и ждёт, когда скажут.

    Мост читает stdin в один поток; уведомление обязано прийти, пока
    он ЖДЁТ следующей строки, — поэтому тесту нужен вход, который
    умеет ждать, а не готовый текст.
    """

    def __init__(self):
        self._lines = []
        self._cond = threading.Condition()
        self._closed = False

    def feed(self, obj):
        with self._cond:
            self._lines.append(json.dumps(obj) + "\n")
            self._cond.notify_all()

    def close(self):
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def __iter__(self):
        while True:
            with self._cond:
                while not self._lines and not self._closed:
                    self._cond.wait(0.05)
                if self._lines:
                    line = self._lines.pop(0)
                else:
                    return
            yield line


class _LockedOut(io.StringIO):
    """stdout, который замечает запись из двух потоков одновременно."""

    def __init__(self):
        super().__init__()
        self.overlaps = 0
        self._busy = False

    def write(self, text):
        if self._busy:
            self.overlaps += 1
        self._busy = True
        try:
            # Пауза расширяет окно гонки: без замка вокруг записи две
            # строки перемешались бы здесь гарантированно.
            time.sleep(0.001)
            return super().write(text)
        finally:
            self._busy = False


class TestNotificationsOverStdio(unittest.TestCase):
    """Поток-писатель: подписка и смена инструментов по stdio."""

    URI = "zapret://docs/overview"

    def setUp(self):
        from core.mcp import resources
        from core.mcp import session as mcp_session

        self.digest = "v1"
        self._patch(resources, "digest", lambda uri: self.digest)
        self._patch(resources, "poll_sec", lambda uri: 0.05)
        self._patch(mcp_session, "KEEPALIVE_SEC", 0.05)
        self.perms = {"control": False}
        self._patch(mcp_session, "permissions_snapshot",
                    lambda: dict(self.perms))

        self.stdin = _SlowStdin()
        self.out = _LockedOut()
        self.err = io.StringIO()
        self.code = None
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        self.addCleanup(self._finish)

    def _patch(self, obj, name, value):
        patcher = mock.patch.object(obj, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _serve(self):
        self.code = stdio.serve(self.stdin, self.out, self.err)

    def _finish(self):
        self.stdin.close()
        self.thread.join(5)

    def lines(self):
        return answers(self.out.getvalue())

    def wait_for(self, predicate, limit=5.0):
        deadline = time.time() + limit
        while time.time() < deadline:
            found = [m for m in self.lines() if predicate(m)]
            if found:
                return found[0]
            time.sleep(0.02)
        self.fail("не дождались сообщения; stdout: %r, stderr: %r"
                  % (self.out.getvalue(), self.err.getvalue()))

    def request(self, request_id, method, params=None):
        self.stdin.feed({"jsonrpc": "2.0", "id": request_id,
                         "method": method, "params": params or {}})
        return self.wait_for(lambda m: m.get("id") == request_id)

    def subscribe(self):
        answer = self.request(1, "resources/subscribe", {"uri": self.URI})
        self.assertNotIn("error", answer)
        # Подписка по спеке ничего не отвечает сверх факта, а сервер
        # квантует период до секунды — ждём её честно.
        return answer

    def test_capability_is_promised(self):
        answer = self.request(7, "initialize")
        self.assertTrue(
            answer["result"]["capabilities"]["resources"]["subscribe"])
        self.assertIn("zapret://state/jobs",
                      answer["result"]["instructions"])

    def test_subscribe_is_accepted(self):
        meta = self.subscribe()["result"]["_meta"]["zapret-gui"]
        self.assertTrue(meta["added"])
        self.assertEqual(meta["uri"], self.URI)

    def test_change_reaches_the_client_while_stdin_is_silent(self):
        self.subscribe()
        self.digest = "v2"
        notice = self.wait_for(
            lambda m: m.get("method") == "notifications/resources/updated")
        self.assertEqual(notice["params"]["uri"], self.URI)

    def test_nothing_changed_means_no_notification(self):
        self.subscribe()
        time.sleep(1.5)
        self.assertFalse([m for m in self.lines() if "method" in m])

    def test_unsubscribe_stops_it(self):
        self.subscribe()
        answer = self.request(2, "resources/unsubscribe", {"uri": self.URI})
        self.assertTrue(answer["result"]["_meta"]["zapret-gui"]["removed"])
        self.digest = "v2"
        time.sleep(1.5)
        self.assertFalse([m for m in self.lines()
                          if m.get("method") ==
                          "notifications/resources/updated"])

    def test_permission_change_announces_new_tools(self):
        self.request(3, "ping")
        self.perms = {"control": True}
        self.wait_for(
            lambda m: m.get("method") == "notifications/tools/list_changed")

    def test_writes_never_interleave(self):
        # Ответы пишет поток stdin, уведомления — поток-писатель; всё,
        # что ушло в stdout, обязано разбираться построчно.
        self.subscribe()
        for number in range(30):
            self.digest = "v%d" % number
            self.stdin.feed({"jsonrpc": "2.0", "id": 100 + number,
                             "method": "ping"})
        self.wait_for(lambda m: m.get("id") == 129)
        self.assertEqual(self.out.overlaps, 0)
        self.lines()                    # каждая строка — JSON

    def test_eof_stops_the_writer(self):
        self.request(4, "ping")
        self.stdin.close()
        self.thread.join(5)
        self.assertEqual(self.code, 0)
        self.assertFalse([t for t in threading.enumerate()
                          if t.name == "mcp-stdio-notifier"])


class TestProxyHasNoWriter(unittest.TestCase):

    def test_proxy_mode_does_not_start_the_writer(self):
        # Чужая точка stateless: уведомление доставить некуда, и
        # подписку она отклонит сама — писатель здесь был бы обманом.
        with mock.patch.object(stdio, "_Notifier") as notifier:
            run([], url="http://127.0.0.1:1")
        notifier.assert_not_called()


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
