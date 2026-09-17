# tests/test_mcp_resources.py
"""
Ресурсы ``zapret://…``: список, чтение, шаблоны, пагинация.

Что здесь сторожится:

* ``resources/list``, ``resources/read`` и ``resources/templates/list``
  отвечают **по-настоящему**. Пустой список из S1 был временной
  заглушкой; клиент опрашивает эти методы сразу после ``initialize``,
  и пустота выглядит как «сервер ничего не умеет».
* Неизвестный URI даёт понятную ошибку со списком доступных, а не
  ``-32601`` и не молчаливый пустой ответ.
* ``zapret://nfqws2/cli`` на машине **без бинарника** (в CI его нет
  никогда) честно отвечает «недоступно» и называет причину — а не
  падает и не выдумывает справку.
* Большой справочник читается страницами: ответ инструмента обязан
  укладываться в ``mcp.limits.response_kb`` при любом запросе.
"""

import unittest

from core.mcp import registry
from core.mcp import resources
from core.mcp import server


def rpc(method, params=None):
    """Один запрос JSON-RPC к диспетчеру."""
    return server.dispatch({"jsonrpc": "2.0", "id": 1, "method": method,
                            "params": params or {}})


def call(name, args=None):
    return registry.call(name, args or {}, {})["structuredContent"]


class TestResourceList(unittest.TestCase):

    def test_list_is_not_empty(self):
        items = rpc("resources/list")["result"]["resources"]
        self.assertTrue(items)
        for item in items:
            with self.subTest(uri=item.get("uri")):
                self.assertTrue(item["uri"].startswith("zapret://"))
                self.assertTrue(item["name"])
                self.assertTrue(item["description"])
                self.assertTrue(item["mimeType"])

    def test_uris_are_unique(self):
        uris = [item["uri"] for item in resources.list_resources()]
        self.assertEqual(len(uris), len(set(uris)))

    def test_templates_declare_placeholders(self):
        items = rpc("resources/templates/list")["result"]["resourceTemplates"]
        self.assertTrue(items)
        for item in items:
            with self.subTest(template=item.get("uriTemplate")):
                self.assertIn("{", item["uriTemplate"])
                self.assertTrue(item["description"])

    def test_every_listed_resource_renders(self):
        # Ресурс, который виден в списке, но не читается, — худший
        # вариант: клиент показывает его пользователю, а нажатие даёт
        # ошибку.
        for uri in resources.uris():
            with self.subTest(uri=uri):
                item = resources.render(uri)
                self.assertTrue(item["text"].strip(), "пустой ресурс")
                self.assertTrue(item["mime_type"])


class TestResourceRead(unittest.TestCase):

    def test_read_returns_contents(self):
        result = rpc("resources/read",
                     {"uri": "zapret://docs/overview"})["result"]
        content = result["contents"][0]
        self.assertEqual(content["uri"], "zapret://docs/overview")
        self.assertIn("zapret-gui", content["text"])

    def test_unknown_uri_names_available_ones(self):
        error = rpc("resources/read", {"uri": "zapret://nope"})["error"]
        self.assertEqual(error["code"], server.RESOURCE_NOT_FOUND)
        self.assertIn("zapret://docs/overview", error["message"])
        self.assertIn("available", error["data"])

    def test_missing_uri_is_invalid_params(self):
        error = rpc("resources/read", {})["error"]
        self.assertEqual(error["code"], server.INVALID_PARAMS)

    def test_foreign_scheme_is_rejected(self):
        error = rpc("resources/read", {"uri": "file:///etc/passwd"})["error"]
        self.assertEqual(error["code"], server.RESOURCE_NOT_FOUND)


class TestOverview(unittest.TestCase):

    def test_says_what_is_allowed_now(self):
        text = resources.render("zapret://docs/overview")["text"]
        # Обзор читает модель до первого вызова: он обязан сказать, что
        # прав на запись нет, иначе она будет пробовать вслепую.
        self.assertIn("только чтение", text.lower())
        self.assertIn("docs_get", text)

    def test_warns_against_inventing_flags(self):
        text = resources.render("zapret://docs/overview")["text"]
        self.assertIn("придум", text.lower())


class TestNfqwsCli(unittest.TestCase):
    """Живая справка: на машине без бинарника — честный отказ."""

    def test_no_binary_is_answered_not_crashed(self):
        item = resources.render("zapret://nfqws2/cli")
        self.assertIn("available", item)
        if item["available"]:
            # Бинарник есть — тогда это его собственный вывод.
            self.assertTrue(item["binary"])
            self.assertTrue(item["text"].strip())
        else:
            self.assertTrue(item["error"], "причина обязана быть названа")
            self.assertIn("nfqws2", item["text"])

    def test_help_is_not_hardcoded(self):
        # Содержимое обязано приходить из менеджера, а не из строки в
        # коде: на устройстве с другой версией zapret2 справка другая.
        from core.nfqws_manager import get_nfqws_manager

        info = get_nfqws_manager().get_help()
        item = resources.render("zapret://nfqws2/cli")
        self.assertEqual(bool(info.get("available")),
                         bool(item.get("available")))


class TestLuaMap(unittest.TestCase):

    def test_map_comes_from_scripts(self):
        from core.lua_manager import get_lua_manager

        functions = get_lua_manager().desync_functions()
        item = resources.render("zapret://nfqws2/lua")
        if not functions:
            self.assertFalse(item["available"])
            return
        self.assertEqual(item["count"], len(functions))
        # Базовые приёмы обязаны находиться — иначе разбор сломан.
        for name in ("fake", "multisplit", "multidisorder"):
            with self.subTest(function=name):
                self.assertIn("## %s" % name, item["text"])

    def test_blob_requirement_is_visible(self):
        from core.lua_manager import get_lua_manager

        functions = {f["name"]: f
                     for f in get_lua_manager().desync_functions()}
        if "fake" not in functions:
            self.skipTest("нет lua-скриптов")
        self.assertTrue(functions["fake"]["needs_blob"])
        self.assertEqual(functions["fake"]["nfqws1"], "--dpi-desync=fake")


class TestCatalogs(unittest.TestCase):

    def test_index_lists_catalogs(self):
        item = resources.render("zapret://catalogs")
        self.assertTrue(item["available"])
        for key in item["catalogs"]:
            with self.subTest(catalog=key):
                self.assertIn("zapret://catalogs/%s" % key, item["text"])

    def test_catalog_entries_carry_args(self):
        index = resources.render("zapret://catalogs")
        keys = sorted(index["catalogs"])
        if not keys:
            self.skipTest("каталогов нет")
        item = resources.render("zapret://catalogs/%s" % keys[0])
        self.assertTrue(item["available"])
        self.assertGreater(item["count"], 0)
        self.assertIn("--", item["text"])

    def test_unknown_catalog_is_an_error_not_silence(self):
        item = resources.render("zapret://catalogs/basic/nope")
        self.assertFalse(item["found"])
        self.assertTrue(item["error"])
        self.assertTrue(item["known"])

    def test_malformed_catalog_uri_is_unknown_resource(self):
        with self.assertRaises(resources.UnknownResource):
            resources.render("zapret://catalogs/basic")


class TestSkillSections(unittest.TestCase):

    def test_sections_are_listed(self):
        if not resources.skill_available():
            self.skipTest("справочник не установлен")
        sections = resources.skill_sections()
        self.assertTrue(sections)
        numbers = [s["section"] for s in sections]
        self.assertIn("12", numbers)          # сборка argv
        self.assertIn("3", numbers)           # CLI

    def test_one_section_is_smaller_than_whole(self):
        if not resources.skill_available():
            self.skipTest("справочник не установлен")
        whole = resources.render("zapret://skills/nfqws2")["text"]
        part = resources.render("zapret://skills/nfqws2?section=12")["text"]
        self.assertLess(len(part), len(whole))
        self.assertIn("## 12.", part)

    def test_unknown_section_lists_known(self):
        if not resources.skill_available():
            self.skipTest("справочник не установлен")
        item = resources.render("zapret://skills/nfqws2?section=99")
        self.assertFalse(item["found"])
        self.assertIn("12", item["text"])

    def test_missing_skill_names_the_url(self):
        # Пакет может ставиться без каталога .claude/ — это нормально,
        # но модель обязана узнать, где справочник лежит.
        original = resources.SKILL_PATH
        resources.SKILL_PATH = original + ".missing"
        try:
            item = resources.render("zapret://skills/nfqws2")
            self.assertFalse(item["available"])
            self.assertIn(resources.SKILL_URL, item["text"])
            self.assertIn("docs_get", item["text"])
        finally:
            resources.SKILL_PATH = original


class TestPagination(unittest.TestCase):
    """Большой текст читается страницами и влезает в лимит ответа."""

    def test_pages_cover_the_whole_text(self):
        uri = "zapret://nfqws2/lua"
        whole = resources.render(uri)["text"]
        collected = ""
        offset = 0
        for _ in range(200):
            page = call("docs_get", {"uri": uri, "offset": offset})
            collected += page["text"]
            if not page["truncated"]:
                break
            offset = page["next_offset"]
        else:
            self.fail("пагинация не сходится за 200 страниц")
        self.assertEqual(collected, whole)

    def test_first_page_carries_the_table_of_contents(self):
        if not resources.skill_available():
            self.skipTest("справочник не установлен")
        first = call("docs_get", {"topic": "nfqws2"})
        self.assertIn("sections", first)
        # На следующих страницах оглавления быть не должно: оно
        # съедало бы место под сам текст.
        second = call("docs_get", {"topic": "nfqws2",
                                   "offset": first["next_offset"]})
        self.assertNotIn("sections", second)

    def test_any_answer_fits_the_response_limit(self):
        from core.mcp import auth

        limit = int(auth.settings().get("limits", {})
                    .get("response_kb", 32)) * 1024
        requests = [{"topic": name} for name in sorted(set(resources.TOPICS))]
        requests.append({"topic": "nfqws2", "limit": 200000})
        requests.append({"uri": "zapret://catalogs/basic/tcp"})
        for args in requests:
            with self.subTest(args=args):
                result = registry.call("docs_get", args, {})
                size = len(result["content"][0]["text"].encode("utf-8"))
                self.assertLessEqual(size, limit)
                # Ответ обязан остаться страницей текста, а не
                # заглушкой «слишком много» из registry._truncated().
                self.assertNotIn("limit_bytes", result["structuredContent"])

    def test_offset_past_the_end_is_empty_not_an_error(self):
        page = call("docs_get", {"topic": "overview", "offset": 10 ** 6})
        self.assertTrue(page["ok"])
        self.assertEqual(page["text"], "")
        self.assertFalse(page["truncated"])


class TestCompletion(unittest.TestCase):

    def test_completes_catalog_levels(self):
        result = rpc("completion/complete", {
            "ref": {"type": "ref/resource",
                    "uri": "zapret://catalogs/{level}/{protocol}"},
            "argument": {"name": "level", "value": "b"},
        })["result"]["completion"]
        for value in result["values"]:
            self.assertTrue(value.startswith("b"))

    def test_unknown_argument_gives_empty_list(self):
        result = rpc("completion/complete", {
            "ref": {"type": "ref/resource", "uri": "zapret://catalogs"},
            "argument": {"name": "nope", "value": ""},
        })["result"]["completion"]
        self.assertEqual(result["values"], [])


if __name__ == "__main__":
    unittest.main()
