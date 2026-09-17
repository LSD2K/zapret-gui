# tests/test_mcp_prompts.py
"""
Промты: ``prompts/list`` и ``prompts/get``.

Главный инвариант — **промт не врёт модели**. Сценарии описывают весь
путь целиком, включая инструменты, которых на сервере ещё нет (они
появятся в S4–S10). Поэтому каждое упомянутое имя обязано либо
существовать в реестре, либо быть помечено как недоступное прямо в
тексте: иначе модель тратит вызов, получает ошибку и не понимает, она
ошиблась или сервер сломан.

Здесь же — то, что обещано контрактом §5.6: промт называет границу
доверия к данным (домены, журнал, вывод проб приходят из внешнего мира).
"""

import unittest

from core.mcp import prompts
from core.mcp import registry
from core.mcp import server


def rpc(method, params=None):
    return server.dispatch({"jsonrpc": "2.0", "id": 1, "method": method,
                            "params": params or {}})


def text_of(name, arguments=None):
    result = rpc("prompts/get", {"name": name,
                                 "arguments": arguments or {}})["result"]
    return result["messages"][0]["content"]["text"]


class TestPromptList(unittest.TestCase):

    def test_list_is_not_empty(self):
        items = rpc("prompts/list")["result"]["prompts"]
        self.assertTrue(items)
        for item in items:
            with self.subTest(prompt=item["name"]):
                self.assertTrue(item["title"])
                self.assertTrue(item["description"])

    def test_names_are_unique(self):
        names = [item["name"] for item in prompts.list_prompts()]
        self.assertEqual(len(names), len(set(names)))

    def test_declared_arguments_are_described(self):
        for item in prompts.list_prompts():
            for argument in item.get("arguments", []):
                with self.subTest(prompt=item["name"],
                                  argument=argument["name"]):
                    self.assertTrue(argument["description"])


class TestPromptGet(unittest.TestCase):

    def test_scenario_is_rendered(self):
        text = text_of("strategy_for_domain", {"domain": "youtube.com"})
        self.assertIn("youtube.com", text)
        self.assertIn("nfqws_status", text)

    def test_optional_argument_has_a_default(self):
        text = text_of("strategy_for_domain", {"domain": "example.com"})
        self.assertIn("tcp", text)
        self.assertNotIn("{protocol}", text)

    def test_no_placeholder_survives_rendering(self):
        # Незаменённый {domain} в тексте — это сценарий, отправленный
        # модели с дыркой вместо цели.
        for item in prompts.list_prompts():
            arguments = {a["name"]: "example.com"
                         for a in item.get("arguments", [])}
            text = text_of(item["name"], arguments)
            for argument in item.get("arguments", []):
                with self.subTest(prompt=item["name"],
                                  argument=argument["name"]):
                    self.assertNotIn("{%s}" % argument["name"], text)

    def test_missing_required_argument_is_invalid_params(self):
        error = rpc("prompts/get", {"name": "strategy_for_domain"})["error"]
        self.assertEqual(error["code"], server.INVALID_PARAMS)
        self.assertIn("domain", error["message"])

    def test_unknown_prompt_lists_known(self):
        error = rpc("prompts/get", {"name": "nope"})["error"]
        self.assertEqual(error["code"], server.INVALID_PARAMS)
        self.assertIn("router_health", error["message"])


class TestPromptsDoNotLie(unittest.TestCase):
    """Каждый упомянутый инструмент существует либо помечен как будущий."""

    def setUp(self):
        registry.load_tools()

    def test_existing_tools_are_not_marked_as_missing(self):
        for item in prompts.list_prompts():
            arguments = {a["name"]: "example.com"
                         for a in item.get("arguments", [])}
            text = text_of(item["name"], arguments)
            # Смотрим только строки шагов: итоговая сводка «недоступные
            # сейчас шаги» перечисляет те же имена без пометки — это её
            # работа, а не обещание, что инструмент есть.
            for line in text.splitlines():
                if not line[:1].isdigit() or ". `" not in line:
                    continue
                for name in prompts.tool_names():
                    if "`%s`" % name not in line:
                        continue
                    exists = registry.get_tool(name) is not None
                    with self.subTest(prompt=item["name"], tool=name):
                        self.assertEqual(exists,
                                         "инструмента пока нет" not in line)

    def test_future_tools_are_marked_in_the_text(self):
        # Смысл пометки: модель не должна пробовать вызвать то, чего
        # нет, и тем более считать отказ своей ошибкой.
        missing = [name for name in prompts.tool_names()
                   if registry.get_tool(name) is None]
        if not missing:
            self.skipTest("все инструменты сценариев уже реализованы")
        text = text_of("strategy_for_domain", {"domain": "example.com"})
        self.assertIn("Недоступные сейчас шаги", text)

    def test_tool_names_look_like_tool_names(self):
        # Опечатка в имени внутри сценария превращается в «инструмента
        # пока нет» и живёт незамеченной до самой S10.
        for name in prompts.tool_names():
            with self.subTest(tool=name):
                self.assertRegex(name, r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")

    def test_scenarios_mention_the_untrusted_data_boundary(self):
        for item in prompts.list_prompts():
            arguments = {a["name"]: "example.com"
                         for a in item.get("arguments", [])}
            with self.subTest(prompt=item["name"]):
                text = text_of(item["name"], arguments)
                self.assertIn("не инструкции", text)

    def test_strategy_scenario_starts_with_the_reference(self):
        # Смысл всей S3: сначала справочник этого устройства, потом
        # предложения. Сценарий, начинающийся с правки, воспроизводит
        # ровно ту ошибку, против которой он написан.
        text = text_of("strategy_for_domain", {"domain": "example.com"})
        first_step = [line for line in text.splitlines()
                      if line.startswith("1. ")][0]
        self.assertIn("docs_get", first_step)


if __name__ == "__main__":
    unittest.main()
