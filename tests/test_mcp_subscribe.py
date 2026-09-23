# tests/test_mcp_subscribe.py
"""
Подписка на ресурсы (S18): ``resources/subscribe`` вместо опроса.

Что здесь важно проверить и почему.

* **Подписка обещается только там, где её можно исполнить.** У
  stateless-HTTP канала «сервер → клиент» нет по построению, поэтому
  ``capabilities.resources.subscribe`` там ``false``, а сам вызов —
  честный отказ с адресом потока. Тихое «принято» обернулось бы
  клиентом, который ждёт уведомлений и не дождётся ни одного.
* **Уведомление приходит от ИЗМЕНЕНИЯ, а не от круга.** Поток
  крутится каждые пару секунд; если бы ``notifications/resources/
  updated`` уходило на каждом круге, подписка стоила бы дороже опроса.
* **Подписки не копятся.** Сессия держит не больше
  ``MAX_SUBSCRIPTIONS``, и закрытый поток уносит их с собой: на роутере
  со 128 МБ брошенная подписка — это утечка, как и брошенная сессия.
"""

import json
import unittest

from core.mcp import resources
from core.mcp import server
from core.mcp import session as mcp_session
from tests.test_mcp_transport import TOKEN, _McpHTTPBase, _SSEBase


class TestSubscribeWithoutChannel(_McpHTTPBase):
    """POST /api/mcp: подписаться нельзя, и сказано почему."""

    def test_capability_is_not_promised(self):
        _, _, body = self.rpc({"jsonrpc": "2.0", "id": 1,
                               "method": "initialize", "params": {}})
        caps = body["result"]["capabilities"]["resources"]
        self.assertFalse(caps["subscribe"])
        self.assertTrue(caps["listChanged"])

    def test_subscribe_refuses_and_names_the_stream(self):
        _, _, body = self.rpc({"jsonrpc": "2.0", "id": 2,
                               "method": "resources/subscribe",
                               "params": {"uri": "zapret://state/jobs"}})
        error = body["error"]
        self.assertEqual(error["code"], server.INVALID_REQUEST)
        self.assertIn("/api/mcp/sse", error["message"])
        self.assertEqual(error["data"]["endpoint"], "/api/mcp/sse")

    def test_unsubscribe_is_not_an_error(self):
        # Отписка без канала — не повод ломать клиенту сессию: он мог
        # подписаться на другом транспорте и просто прибирается.
        _, _, body = self.rpc({"jsonrpc": "2.0", "id": 3,
                               "method": "resources/unsubscribe",
                               "params": {"uri": "zapret://state/jobs"}})
        self.assertNotIn("error", body)
        self.assertFalse(body["result"]["_meta"]["zapret-gui"]["removed"])


class TestJobsResource(unittest.TestCase):
    """``zapret://state/jobs`` — сводка, ради которой подписка и нужна."""

    def test_resource_is_listed_and_readable(self):
        self.assertIn("zapret://state/jobs", resources.uris())
        payload = json.loads(
            resources.render("zapret://state/jobs")["text"])
        self.assertEqual(payload["running"], [])
        self.assertEqual(payload["running_count"], 0)
        # Виды операций те же, что у job_wait: второй реализации
        # прогресса быть не должно.
        from core.mcp.tools import jobs as jobs_tool
        self.assertEqual(sorted(payload["idle"]), sorted(jobs_tool.KINDS))

    def test_it_is_cheap_enough_to_poll(self):
        # Две секунды — это про цену рендера, а не про желание: сводка
        # читает поля в памяти процесса и ничего не запускает.
        self.assertEqual(resources.poll_sec("zapret://state/jobs"),
                         resources.POLL_FAST_SEC)
        self.assertGreaterEqual(resources.poll_sec("zapret://catalogs"),
                                resources.POLL_DEFAULT_SEC)

    def test_digest_changes_only_with_content(self):
        first = resources.digest("zapret://docs/overview")
        self.assertEqual(first, resources.digest("zapret://docs/overview"))
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        cfg.set("mcp", "permissions", "control", True)
        try:
            self.assertNotEqual(first,
                                resources.digest("zapret://docs/overview"))
        finally:
            cfg.set("mcp", "permissions", "control", False)

    def test_unknown_uri_is_not_subscribable(self):
        self.assertFalse(resources.exists("zapret://нет/такого"))
        self.assertTrue(resources.exists("zapret://state/jobs"))


class TestSubscribeOverStream(_SSEBase):
    """SSE: подписались — получили уведомление об изменении."""

    def setUp(self):
        super().setUp()
        # Период опроса задаёт сам ресурс; в тесте он должен быть
        # короче, чем терпение unittest, поэтому подменяем его целиком.
        self._poll_sec = resources.poll_sec
        resources.poll_sec = lambda uri: 0.05
        mcp_session.KEEPALIVE_SEC = 0.05

    def tearDown(self):
        resources.poll_sec = self._poll_sec
        super().tearDown()

    def subscribe(self, session_id, uri, request_id=1):
        code, _, _ = self.send(session_id,
                               {"jsonrpc": "2.0", "id": request_id,
                                "method": "resources/subscribe",
                                "params": {"uri": uri}})
        self.assertEqual(code, 202)
        return self.await_message(request_id)

    def await_message(self, request_id, limit=20):
        """Дождаться ответа с нужным id, пропуская keep-alive."""
        for _ in range(limit):
            name, data = self.stream.event()
            if name != "message":
                continue
            payload = json.loads(data)
            if payload.get("id") == request_id:
                return payload
        raise AssertionError("ответ %s не пришёл" % request_id)

    def await_notification(self, method, limit=40):
        for _ in range(limit):
            name, data = self.stream.event()
            if name != "message":
                continue
            payload = json.loads(data)
            if payload.get("method") == method:
                return payload
        raise AssertionError("уведомление %s не пришло" % method)

    def open_subscribed(self, uri="zapret://docs/overview"):
        self.stream = self.open_stream()
        session_id = self.session_of(self.stream)
        answer = self.subscribe(session_id, uri)
        return session_id, answer

    def test_capability_is_promised_on_the_stream(self):
        self.stream = self.open_stream()
        session_id = self.session_of(self.stream)
        self.send(session_id, {"jsonrpc": "2.0", "id": 7,
                               "method": "initialize", "params": {}})
        answer = self.await_message(7)
        caps = answer["result"]["capabilities"]["resources"]
        self.assertTrue(caps["subscribe"])
        self.assertIn("zapret://state/jobs",
                      answer["result"]["instructions"])

    def test_subscribe_answers_and_remembers(self):
        session_id, answer = self.open_subscribed()
        meta = answer["result"]["_meta"]["zapret-gui"]
        self.assertTrue(meta["added"])
        self.assertEqual(meta["uri"], "zapret://docs/overview")
        self.assertEqual(mcp_session.get(session_id).subscriptions(),
                         ["zapret://docs/overview"])

    def test_change_reaches_the_client(self):
        from core.config_manager import get_config_manager

        self.open_subscribed()
        cfg = get_config_manager()
        cfg.set("mcp", "permissions", "control", True)
        try:
            notice = self.await_notification(
                "notifications/resources/updated")
        finally:
            cfg.set("mcp", "permissions", "control", False)
        self.assertEqual(notice["params"]["uri"], "zapret://docs/overview")

    def test_nothing_changed_means_no_notification(self):
        # Уведомление на каждом круге сделало бы подписку дороже опроса.
        self.open_subscribed()
        for _ in range(6):
            name, text = self.stream.event()
            self.assertEqual(name, "")
            self.assertIn("keep-alive", text)

    def test_unsubscribe_stops_it(self):
        from core.config_manager import get_config_manager

        session_id, _ = self.open_subscribed()
        code, _, _ = self.send(session_id,
                               {"jsonrpc": "2.0", "id": 5,
                                "method": "resources/unsubscribe",
                                "params": {"uri": "zapret://docs/overview"}})
        self.assertEqual(code, 202)
        self.assertTrue(
            self.await_message(5)["result"]["_meta"]["zapret-gui"]["removed"])
        self.assertEqual(mcp_session.get(session_id).subscriptions(), [])

        cfg = get_config_manager()
        cfg.set("mcp", "permissions", "control", True)
        try:
            for _ in range(4):
                name, data = self.stream.event()
                if name != "message":
                    continue
                self.assertNotEqual(
                    json.loads(data).get("method"),
                    "notifications/resources/updated")
        finally:
            cfg.set("mcp", "permissions", "control", False)

    def test_unknown_resource_is_refused(self):
        self.stream = self.open_stream()
        session_id = self.session_of(self.stream)
        self.send(session_id, {"jsonrpc": "2.0", "id": 9,
                               "method": "resources/subscribe",
                               "params": {"uri": "zapret://нет/такого"}})
        answer = self.await_message(9)
        self.assertEqual(answer["error"]["code"], server.RESOURCE_NOT_FOUND)

    def test_limit_is_enforced(self):
        self.stream = self.open_stream()
        session_id = self.session_of(self.stream)
        session = mcp_session.get(session_id)
        for number in range(mcp_session.MAX_SUBSCRIPTIONS):
            session.subscribe("zapret://fake/%d" % number, "", 60)
        self.send(session_id, {"jsonrpc": "2.0", "id": 11,
                               "method": "resources/subscribe",
                               "params": {"uri": "zapret://state/jobs"}})
        answer = self.await_message(11)
        self.assertEqual(answer["error"]["data"]["max_subscriptions"],
                         mcp_session.MAX_SUBSCRIPTIONS)

    def test_closed_stream_forgets_subscriptions(self):
        session_id, _ = self.open_subscribed()
        self.stream.close()
        self.assertIsNone(mcp_session.get(session_id))


if __name__ == "__main__":
    unittest.main()
