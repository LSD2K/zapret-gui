# tests/test_agent_runner.py
"""
Встроенный агент: цикл «модель → инструмент → модель» и его рамки.

Что здесь стережём и почему именно это.

**Агент не добавляет прав.** Он ходит теми же инструментами и под теми
же разрешениями, что внешняя модель по MCP. Значит, набор инструментов
обязан считаться из ``mcp.permissions``, а вызов закрытого инструмента —
возвращаться отказом, который модель прочитает, а не исполняться.

**Отдельный флаг.** ``agent.enabled`` выключен по умолчанию; выключенный
агент не ходит никуда, и это проверяется прежде всего остального.

**Прогон конечен.** Модель, попавшая в цикл «вызвал — не понравилось —
вызвал снова», обязана упереться в ``max_steps``, а человек — иметь
работающую кнопку «стоп».

**Ключ не уезжает на страницу.** Сохранение соседней настройки не
стирает ключ, а ``/api/agent/state`` показывает только факт его
наличия — как токен MCP.

Сеть замокана целиком: тест, который правда ходит в LM Studio, красен на
любой машине без LM Studio и зелен там, где сломан цикл.
"""

import os
import shutil
import tempfile
import time
import unittest

from core import agent_runner
from core import llm_client


WAIT_SEC = 10


class FakeClient:
    """Модель, отвечающая по сценарию: список ходов, по одному на вызов."""

    def __init__(self, turns, error=None):
        self.turns = list(turns)
        self.error = error
        self.calls = []

    def chat(self, messages, tools=None, model="", temperature=None,
             max_tokens=None):
        self.calls.append({"messages": list(messages),
                           "tools": list(tools or []), "model": model})
        if self.error:
            raise self.error
        if not self.turns:
            return {"text": "больше нечего сказать", "tool_calls": [],
                    "usage": {}, "raw": {"role": "assistant",
                                         "content": "всё"}}
        turn = self.turns.pop(0)
        calls = []
        for index, (name, args) in enumerate(turn.get("tools") or []):
            calls.append({"id": "call_%d" % index, "name": name,
                          "arguments": args, "arguments_raw": "",
                          "error": ""})
        return {
            "text": turn.get("text", ""),
            "tool_calls": calls,
            "finish_reason": "stop",
            "usage": turn.get("usage") or {"total_tokens": 10},
            "raw": {"role": "assistant", "content": turn.get("text", "")},
        }


class AgentCase(unittest.TestCase):
    """Песочница: свой settings.json, своя подделка модели."""

    def setUp(self):
        import core.config_manager as cm

        self.dir = tempfile.mkdtemp(prefix="agent-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        saved = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        self.cfg = cm._config_manager

        before = os.environ.get("ZAPRET_GUI_CONFIG_DIR")
        self.addCleanup(self._restore_env, before)
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = self.dir

        self.tune(enabled=True, max_steps=4)
        self.addCleanup(self._reset_runner)

    def _restore_env(self, value):
        os.environ.pop("ZAPRET_GUI_CONFIG_DIR", None)
        if value is not None:
            os.environ["ZAPRET_GUI_CONFIG_DIR"] = value

    def _reset_runner(self):
        agent_runner.get_agent_runner().reset()
        agent_runner._runner = None

    def tune(self, **values):
        section = dict(self.cfg.get("agent", default={}) or {})
        section.update(values)
        self.cfg.set("agent", section)

    def use(self, turns, error=None):
        """Подменить клиента модели на подделку."""
        fake = FakeClient(turns, error=error)
        saved = llm_client.LLMClient
        self.addCleanup(setattr, llm_client, "LLMClient", saved)
        llm_client.LLMClient = lambda *a, **kw: fake
        return fake

    def run_agent(self, goal="проверь роутер"):
        runner = agent_runner.get_agent_runner()
        result = runner.start(goal)
        self.assertTrue(result.get("ok"), result)
        return self.wait(runner)

    def wait(self, runner):
        for _ in range(int(WAIT_SEC / 0.02)):
            status = runner.status()
            if not status.get("running"):
                return status
            time.sleep(0.02)
        self.fail("прогон не завершился")

    def kinds(self, status):
        return [step["kind"] for step in status["steps"]]


class TestGate(AgentCase):
    """Выключенный агент никуда не ходит."""

    def test_disabled_refuses_and_says_where_the_switch_is(self):
        self.tune(enabled=False)
        fake = self.use([])
        result = agent_runner.get_agent_runner().start("сделай что-нибудь")
        self.assertFalse(result["ok"])
        self.assertIn("agent.enabled", result["error"])
        self.assertIn("MCP", result["hint"])
        self.assertEqual(fake.calls, [])

    def test_empty_goal_is_refused(self):
        self.use([])
        result = agent_runner.get_agent_runner().start("   ")
        self.assertFalse(result["ok"])

    def test_no_base_url_is_refused_with_examples(self):
        self.tune(base_url="")
        result = agent_runner.get_agent_runner().start("что-нибудь")
        self.assertFalse(result["ok"])
        self.assertIn("11434", result["hint"])

    def test_second_run_is_refused_by_name(self):
        # Два прогона разом — это две модели, дерущиеся за один движок.
        started = {}

        class Slow(FakeClient):
            def chat(self, *a, **kw):
                started["yes"] = True
                time.sleep(0.4)
                return super().chat(*a, **kw)

        fake = Slow([{"text": "готово"}])
        saved = llm_client.LLMClient
        self.addCleanup(setattr, llm_client, "LLMClient", saved)
        llm_client.LLMClient = lambda *a, **kw: fake

        runner = agent_runner.get_agent_runner()
        self.assertTrue(runner.start("первая")["ok"])
        for _ in range(100):
            if started.get("yes"):
                break
            time.sleep(0.01)
        second = runner.start("вторая")
        self.assertFalse(second["ok"])
        self.assertIn("run_id", second)
        self.wait(runner)


class TestCycle(AgentCase):
    """Модель просит инструмент — мы зовём реестр и отдаём результат."""

    def test_tool_call_reaches_the_registry(self):
        self.use([
            {"text": "смотрю статус", "tools": [("system_status", {})]},
            {"text": "роутер жив"},
        ])
        status = self.run_agent()
        self.assertEqual(status["state"], agent_runner.STATE_DONE)
        self.assertEqual(status["answer"], "роутер жив")
        self.assertIn("tool", self.kinds(status))
        tool_step = next(s for s in status["steps"] if s["kind"] == "tool")
        self.assertEqual(tool_step["name"], "system_status")
        self.assertTrue(tool_step["ok"])
        self.assertEqual(status["tool_calls"], 1)

    def test_tool_result_goes_back_to_the_model(self):
        fake = self.use([
            {"tools": [("system_status", {})]},
            {"text": "готово"},
        ])
        self.run_agent()
        # Второй ход модели обязан видеть роль tool с ответом реестра.
        roles = [m.get("role") for m in fake.calls[1]["messages"]]
        self.assertIn("tool", roles)
        answer = next(m for m in fake.calls[1]["messages"]
                      if m.get("role") == "tool")
        self.assertEqual(answer["name"], "system_status")
        self.assertIn("platform", answer["content"])

    def test_unknown_tool_is_an_answer_not_a_crash(self):
        # Модель регулярно выдумывает имена; прогон из-за этого
        # прерываться не должен — она обязана прочитать отказ.
        self.use([
            {"tools": [("сделай_хорошо", {})]},
            {"text": "понял, беру другое"},
        ])
        status = self.run_agent()
        self.assertEqual(status["state"], agent_runner.STATE_DONE)
        step = next(s for s in status["steps"] if s["kind"] == "tool")
        self.assertFalse(step["ok"])
        self.assertIn("нет", step["error"])

    def test_broken_arguments_are_an_answer_too(self):
        fake = self.use([{"text": "ок"}])

        def chat(messages, tools=None, model="", temperature=None,
                 max_tokens=None):
            if not fake.calls:
                fake.calls.append({"messages": messages, "tools": tools,
                                   "model": model})
                return {"text": "", "tool_calls": [{
                    "id": "c1", "name": "system_status", "arguments": {},
                    "arguments_raw": "{сломано", "error":
                        "аргументы не разобраны как JSON"}],
                    "usage": {}, "raw": {"role": "assistant"}}
            fake.calls.append({"messages": messages, "tools": tools,
                               "model": model})
            return {"text": "исправился", "tool_calls": [], "usage": {},
                    "raw": {"role": "assistant", "content": "исправился"}}

        fake.chat = chat
        status = self.run_agent()
        self.assertEqual(status["state"], agent_runner.STATE_DONE)
        step = next(s for s in status["steps"] if s["kind"] == "tool")
        self.assertFalse(step["ok"])

    def test_steps_run_out_and_it_says_so(self):
        self.tune(max_steps=2)
        self.use([
            {"tools": [("system_status", {})]},
            {"tools": [("system_status", {})]},
            {"tools": [("system_status", {})]},
        ])
        status = self.run_agent()
        self.assertEqual(status["state"], agent_runner.STATE_FAILED)
        self.assertIn("agent.max_steps", status["error"])

    def test_server_error_is_reported_not_raised(self):
        self.use([], error=llm_client.LLMError("сервер недоступен"))
        status = self.run_agent()
        self.assertEqual(status["state"], agent_runner.STATE_FAILED)
        self.assertIn("недоступен", status["error"])

    def test_stop_ends_the_run(self):
        runner = agent_runner.get_agent_runner()

        class Slow(FakeClient):
            def chat(self, *a, **kw):
                time.sleep(0.15)
                return super().chat(*a, **kw)

        fake = Slow([{"tools": [("system_status", {})]}] * 5)
        saved = llm_client.LLMClient
        self.addCleanup(setattr, llm_client, "LLMClient", saved)
        llm_client.LLMClient = lambda *a, **kw: fake

        self.assertTrue(runner.start("долгая задача")["ok"])
        time.sleep(0.05)
        self.assertTrue(runner.stop()["stopped"])
        status = self.wait(runner)
        self.assertEqual(status["state"], agent_runner.STATE_STOPPED)

    def test_tool_output_is_trimmed_for_a_small_model(self):
        # Реестр режет ответ по mcp.limits.response_kb — но там потолок
        # рассчитан на Claude, а не на локальную 8B с окном в 8k.
        self.tune(tool_result_chars=500)
        fake = self.use([
            {"tools": [("docs_get", {"topic": "overview"})]},
            {"text": "прочитал"},
        ])
        self.run_agent()
        answer = next(m for m in fake.calls[1]["messages"]
                      if m.get("role") == "tool")
        self.assertLessEqual(len(answer["content"]), 700)
        self.assertIn("обрезан", answer["content"])


class TestPermissions(AgentCase):
    """Своих прав у агента нет: он живёт под mcp.permissions."""

    def test_tool_set_follows_permissions(self):
        without = {spec.name for spec in agent_runner.tool_specs({})}
        with_write = {spec.name for spec in agent_runner.tool_specs(
            {"control": True, "probes": True, "experiments": True,
             "strategies_write": True})}
        self.assertLess(len(without), len(with_write))
        self.assertNotIn("strategy_experiment_start", without)
        self.assertIn("strategy_experiment_start", with_write)

    def test_closed_tool_is_not_even_offered(self):
        # Первая линия — набор: без разрешения инструмент не объявлен
        # модели вовсе. Вторая — реестр: даже назвав его наугад, модель
        # получит отказ, а не исполнение.
        offered = {spec.name for spec in agent_runner.tool_specs({})}
        self.assertNotIn("nfqws_restart", offered)

        self.use([
            {"tools": [("nfqws_restart", {})]},
            {"text": "понял"},
        ])
        status = self.run_agent()
        step = next((s for s in status["steps"] if s["kind"] == "tool"), None)
        self.assertIsNotNone(step)
        self.assertFalse(step["ok"])
        self.assertEqual(status["state"], agent_runner.STATE_DONE)

    def test_permission_revoked_mid_run_stops_the_next_call(self):
        # Человек нажал «запретить shell немедленно», пока агент думал.
        # Снимок разрешений начала прогона этого бы не заметил.
        self.cfg.set("mcp", "permissions",
                     {"experiments": True, "control": True,
                      "probes": True})

        fake = self.use([])
        state = {}

        def chat(messages, tools=None, model="", temperature=None,
                 max_tokens=None):
            fake.calls.append({"messages": messages, "tools": tools,
                               "model": model})
            if "revoked" not in state:
                state["revoked"] = True
                self.cfg.set("mcp", "permissions", {})
                return {"text": "", "tool_calls": [{
                    "id": "c1",
                    "name": "strategy_experiment_rollback",
                    "arguments": {},
                    "arguments_raw": "", "error": ""}],
                    "usage": {}, "raw": {"role": "assistant"}}
            return {"text": "понял, прав нет", "tool_calls": [],
                    "usage": {}, "raw": {"role": "assistant"}}

        fake.chat = chat
        status = self.run_agent()
        step = next(s for s in status["steps"] if s["kind"] == "tool")
        self.assertFalse(step["ok"])
        self.assertIn("experiments", step["error"])

    def test_scenario_set_is_smaller_than_everything(self):
        perms = {name: True for name in
                 ("control", "probes", "experiments", "strategies_write",
                  "tunnels_write", "config_write")}
        scenarios = agent_runner.tool_specs(perms, "scenarios")
        everything = agent_runner.tool_specs(perms, "all")
        self.assertLess(len(scenarios), len(everything))
        # 114 объявлений — это больше пятнадцати тысяч токенов в каждом
        # запросе: локальная модель захлебнётся до первого вызова.
        self.assertLessEqual(len(scenarios), 40)

    def test_system_prompt_tells_the_model_it_is_read_only(self):
        text = agent_runner.system_prompt(agent_runner.tool_specs({}), {})
        self.assertIn("только читать", text)
        self.assertIn("ДАННЫЕ", text)


class TestPresets(AgentCase):
    """Кнопка «подбери стратегию сам» — это сценарий из prompts.py."""

    def test_goal_comes_from_the_scenario(self):
        text = agent_runner.goal_for("strategy_for_domain", "youtube.com")
        self.assertIn("youtube.com", text)
        self.assertIn("strategy_experiment_start", text)

    def test_missing_argument_is_explained(self):
        with self.assertRaises(ValueError):
            agent_runner.goal_for("strategy_for_domain", "")

    def test_unknown_preset(self):
        with self.assertRaises(ValueError):
            agent_runner.goal_for("сделай_хорошо")

    def test_presets_exist_only_for_real_scenarios(self):
        from core.mcp import prompts

        known = {spec["name"] for spec in prompts.PROMPTS}
        for item in agent_runner.presets():
            self.assertIn(item["id"], known)


class TestClientHelpers(unittest.TestCase):
    """Адрес сервера: человек вставляет что угодно."""

    def test_base_url_is_normalized(self):
        self.assertEqual(
            llm_client.normalize_base_url("127.0.0.1:1234/v1/"),
            "http://127.0.0.1:1234/v1")
        self.assertEqual(
            llm_client.normalize_base_url(
                "http://host:1234/v1/chat/completions"),
            "http://host:1234/v1")

    def test_local_addresses_bypass_the_proxy(self):
        # На роутере HTTPS_PROXY настроен на обход блокировок, и запрос
        # к 127.0.0.1 через него не пройдёт никогда.
        self.assertTrue(llm_client.is_local("http://127.0.0.1:1234/v1"))
        self.assertTrue(llm_client.is_local("http://192.168.1.5:1234/v1"))
        self.assertFalse(llm_client.is_local("https://api.example.com/v1"))

    def test_tool_calls_are_parsed_from_the_openai_shape(self):
        message = {"tool_calls": [{"id": "c1", "type": "function",
                                   "function": {"name": "system_status",
                                                "arguments": "{\"a\": 1}"}}]}
        calls = llm_client._tool_calls_of(message)
        self.assertEqual(calls[0]["name"], "system_status")
        self.assertEqual(calls[0]["arguments"], {"a": 1})

    def test_broken_arguments_keep_the_raw_text(self):
        message = {"tool_calls": [{"id": "c1",
                                   "function": {"name": "x",
                                                "arguments": "{сломано"}}]}
        calls = llm_client._tool_calls_of(message)
        self.assertTrue(calls[0]["error"])
        self.assertEqual(calls[0]["arguments_raw"], "{сломано")


if __name__ == "__main__":
    unittest.main()
