# tests/test_api_agent.py
"""
Роуты страницы «Агент» (`api/agent.py`).

Три вещи, в которых цена ошибки не «страница выглядит криво»:

1. **Ключ API не уезжает наружу.** Как и токен MCP, он отдаётся только
   фактом «задан / не задан». И пустое поле при сохранении означает «не
   менять»: иначе правка соседней настройки стирала бы ключ, введённый
   минуту назад.
2. **Состояние приезжает одним ответом.** Страница опрашивает его раз в
   полторы секунды, пока идёт прогон; собирать его из пяти вызовов на
   роутере со 128 МБ значит заставить страницу мигать.
3. **Выключенный агент выключен.** ``available: false`` — это то, по
   чему страница прячет кнопку запуска, и оно обязано следовать флагу,
   а не желанию.
"""

import json
import unittest

from tests._wsgi_client import WSGIClient, build_test_app


def _cfg():
    from core.config_manager import get_config_manager
    return get_config_manager()


class _AgentAPIBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def setUp(self):
        from core import agent_runner

        self.saved = dict(_cfg().get("agent", default={}) or {})
        self.addCleanup(_cfg().set, "agent", self.saved)
        agent_runner.get_agent_runner().reset()

    def state(self):
        code, _, body = self.client.request("GET", "/api/agent/state")
        self.assertEqual(code, 200)
        return body

    def post(self, path, payload=None, expect=200):
        code, _, body = self.client.request("POST", path, body=payload)
        self.assertEqual(code, expect, json.dumps(body, ensure_ascii=False))
        return body


class TestState(_AgentAPIBase):

    def test_everything_the_page_needs_in_one_answer(self):
        body = self.state()
        self.assertTrue(body["ok"])
        for key in ("settings", "available", "presets", "tools",
                    "permissions", "permissions_effective", "run",
                    "history"):
            self.assertIn(key, body, key)

    def test_api_key_never_leaves(self):
        _cfg().set("agent", dict(self.saved, api_key="очень-секретно"))
        body = self.state()
        self.assertNotIn("api_key", body["settings"])
        self.assertTrue(body["settings"]["api_key_set"])
        self.assertNotIn("очень-секретно",
                         json.dumps(body, ensure_ascii=False))

    def test_disabled_agent_is_not_available(self):
        _cfg().set("agent", dict(self.saved, enabled=False))
        self.assertFalse(self.state()["available"])
        _cfg().set("agent", dict(self.saved, enabled=True,
                                 base_url="http://127.0.0.1:1234/v1"))
        self.assertTrue(self.state()["available"])

    def test_tools_and_permissions_are_shown_together(self):
        # Агент живёт под разрешениями MCP, и человек должен видеть это
        # на странице, а не узнавать из документации.
        body = self.state()
        self.assertGreater(body["tools"]["count"], 0)
        self.assertIn("mode", body["tools"])
        self.assertIn("control", body["permissions"])


class TestSettings(_AgentAPIBase):

    def test_empty_key_means_keep(self):
        _cfg().set("agent", dict(self.saved, api_key="старый"))
        self.post("/api/agent/settings", {"model": "qwen"})
        self.assertEqual(_cfg().get("agent", "api_key"), "старый")
        self.assertEqual(_cfg().get("agent", "model"), "qwen")

    def test_key_can_be_set_and_cleared_explicitly(self):
        self.post("/api/agent/settings", {"api_key": "новый"})
        self.assertEqual(_cfg().get("agent", "api_key"), "новый")
        self.post("/api/agent/settings", {"clear_api_key": True})
        self.assertEqual(_cfg().get("agent", "api_key"), "")

    def test_base_url_is_normalized_on_save(self):
        # Человек вставляет адрес из документации LM Studio целиком.
        self.post("/api/agent/settings",
                  {"base_url": "127.0.0.1:1234/v1/chat/completions"})
        self.assertEqual(_cfg().get("agent", "base_url"),
                         "http://127.0.0.1:1234/v1")

    def test_numbers_must_be_numbers(self):
        self.post("/api/agent/settings", {"max_steps": "много"}, expect=400)

    def test_tools_mode_is_one_of_two(self):
        self.post("/api/agent/settings", {"tools": "выдумка"})
        self.assertEqual(_cfg().get("agent", "tools"), "scenarios")


class TestStart(_AgentAPIBase):

    def test_disabled_agent_refuses_to_start(self):
        _cfg().set("agent", dict(self.saved, enabled=False))
        body = self.post("/api/agent/start", {"goal": "сделай хорошо"},
                         expect=400)
        self.assertFalse(body["ok"])
        self.assertIn("agent.enabled", body["error"])

    def test_empty_goal_is_refused(self):
        _cfg().set("agent", dict(self.saved, enabled=True))
        self.post("/api/agent/start", {}, expect=400)

    def test_preset_without_its_argument_is_explained(self):
        _cfg().set("agent", dict(self.saved, enabled=True))
        body = self.post("/api/agent/start",
                         {"preset": "strategy_for_domain"}, expect=400)
        self.assertIn("домен", body["error"].lower())

    def test_unknown_preset(self):
        _cfg().set("agent", dict(self.saved, enabled=True))
        self.post("/api/agent/start", {"preset": "сделай_хорошо"},
                  expect=400)

    def test_stop_without_a_run_is_not_an_error(self):
        body = self.post("/api/agent/stop", {})
        self.assertTrue(body["ok"])
        self.assertFalse(body["stopped"])


class TestTest(_AgentAPIBase):
    """«Проверить связь» — единственный роут, который ходит наружу."""

    def test_unreachable_server_is_an_answer_not_a_500(self):
        # Порт, на котором заведомо никого нет: ответ обязан объяснить,
        # что запустить, а не показать трассировку.
        body = self.post("/api/agent/test",
                         {"base_url": "http://127.0.0.1:9/v1"})
        self.assertFalse(body["ok"])
        self.assertTrue(body["error"])


if __name__ == "__main__":
    unittest.main()
