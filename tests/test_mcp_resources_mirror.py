# tests/test_mcp_resources_mirror.py
"""
Зеркало «ресурс = инструмент».

Зачем оно вообще. Многие MCP-клиенты (LM Studio, OpenAI-совместимые
мосты) показывают ресурсы **пользователю, а не модели**: их выбирают
руками, и в контекст модели они сами не попадают. Справка, доступная
только ресурсом, — это справка, которую модель никогда не прочитает, а
непрочитанная справка означает придуманные флаги и «тихий 0%».

Поэтому здесь фиксируется: **каждый** ресурс ``zapret://…`` читается
инструментом ``docs_get`` и даёт дословно тот же текст. Расхождение
означает, что кто-то завёл второй источник текста, — и рано или поздно
они разъедутся.

Вторая половина — про честное «не знаю»: запрос описания
недокументированной настройки обязан сказать, что описания нет, и
показать документированные рядом. Молчаливый пустой ответ модель
достраивает догадкой по имени поля, а догадка про
``nfqws.tcp_pkt_out`` стоит сломанного перехвата.
"""

import unittest

from core.mcp import config_docs
from core.mcp import registry
from core.mcp import resources


def call(name, args=None):
    return registry.call(name, args or {}, {})["structuredContent"]


def read_all(uri):
    """Собрать текст ресурса целиком через docs_get, по страницам."""
    collected = ""
    offset = 0
    for _ in range(500):
        page = call("docs_get", {"uri": uri, "offset": offset})
        collected += page["text"]
        if not page["truncated"]:
            return collected
        offset = page["next_offset"]
    raise AssertionError("пагинация %s не сходится" % uri)


class TestMirror(unittest.TestCase):

    def test_every_resource_is_readable_as_a_tool(self):
        for uri in resources.uris():
            if uri in resources.VOLATILE:
                continue          # см. test_live_resource_mirrors_by_shape
            with self.subTest(uri=uri):
                self.assertEqual(read_all(uri), resources.render(uri)["text"])

    def test_live_resource_mirrors_by_shape(self):
        # Состояние роутера меняется между двумя чтениями (свободная
        # память, аптайм), поэтому дословно оно совпасть не может.
        # Зеркало здесь — одинаковый набор полей: инструмент и ресурс
        # обязаны отдавать одно и то же, а не два разных снимка.
        import json

        for uri in resources.VOLATILE:
            with self.subTest(uri=uri):
                from_tool = json.loads(read_all(uri))
                from_resource = json.loads(resources.render(uri)["text"])
                self.assertEqual(sorted(from_tool), sorted(from_resource))
                for key in from_tool:
                    if isinstance(from_tool[key], dict):
                        self.assertEqual(sorted(from_tool[key]),
                                         sorted(from_resource[key]))

    def test_every_topic_points_at_a_real_resource(self):
        for topic, uri in resources.TOPICS.items():
            with self.subTest(topic=topic):
                page = call("docs_get", {"topic": topic})
                self.assertTrue(page["ok"])
                self.assertEqual(page["uri"], uri)

    def test_topics_cover_every_resource(self):
        # Ресурс без короткого имени доступен только тому, кто помнит
        # схему URI, — то есть фактически никому.
        covered = set(resources.TOPICS.values())
        for uri in resources.uris():
            with self.subTest(uri=uri):
                self.assertIn(uri, covered)

    def test_topic_enum_matches_the_topics(self):
        # Схема инструмента — то, что видит модель. Разошлась со
        # словарём — и половина тем недоступна.
        spec = registry.get_tool("docs_get")
        enum = spec.schema["properties"]["topic"]["enum"]
        self.assertEqual(sorted(enum), sorted(set(resources.TOPICS)))

    def test_section_reads_the_same_as_the_resource(self):
        if not resources.skill_available():
            self.skipTest("справочник не установлен")
        uri = "zapret://skills/nfqws2?section=12"
        page = call("docs_get", {"topic": "nfqws2", "section": "12"})
        self.assertEqual(page["text"], resources.render(uri)["text"])

    def test_catalog_mirrors_too(self):
        keys = sorted(resources.render("zapret://catalogs")["catalogs"])
        if not keys:
            self.skipTest("каталогов нет")
        uri = "zapret://catalogs/%s" % keys[0]
        self.assertEqual(read_all(uri), resources.render(uri)["text"])


class TestConfigDescribeMirror(unittest.TestCase):

    def test_resource_lists_every_documented_key(self):
        text = resources.render("zapret://config/describe")["text"]
        for path in config_docs.paths():
            with self.subTest(path=path):
                self.assertIn("`%s`" % path, text)

    def test_tool_lists_the_same_keys(self):
        listed = {item["path"] for item in call("config_describe")["items"]}
        self.assertEqual(listed, set(config_docs.paths()))

    def test_description_matches_the_resource(self):
        for path in config_docs.paths()[:10]:
            with self.subTest(path=path):
                item = call("config_describe", {"path": path})["item"]
                self.assertEqual(item, resources.describe_path(path))


class TestHonestNoAnswer(unittest.TestCase):

    def test_undocumented_key_says_so(self):
        # Ключ в конфиге есть, описания нет: ответ обязан это назвать.
        payload = call("config_describe", {"path": "usque.default_sni"})
        self.assertFalse(payload["documented"])
        self.assertTrue(payload["error"])
        self.assertIn("нет", payload["error"])

    def test_undocumented_key_shows_documented_neighbours(self):
        payload = call("config_describe", {"path": "nfqws.nope"})
        self.assertFalse(payload["found"])
        self.assertTrue(payload["documented_nearby"])
        for path in payload["documented_nearby"]:
            self.assertTrue(path.startswith("nfqws."))

    def test_unknown_path_is_distinguished_from_undocumented(self):
        # «Такой настройки нет» и «описания нет» — разные ответы:
        # во втором случае значение всё равно можно прочитать.
        payload = call("config_describe", {"path": "nope.nope"})
        self.assertFalse(payload["item"]["exists"])
        self.assertIn("ни в конфиге", payload["error"])

    def test_search_without_hits_is_an_error_with_a_way_out(self):
        payload = call("config_describe", {"query": "квантовый туннель"})
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["hint"])


class TestDocumentedCoverage(unittest.TestCase):
    """Что обязано быть описано — описано."""

    def test_every_writable_path_has_a_description(self):
        # Запись в настройку, смысл которой модель не может прочитать,
        # — это запись наугад. S6 будет ссылаться на этот же словарь в
        # отказах config_set.
        from core.mcp import permissions as perms

        documented = set(config_docs.paths())
        for item in perms.writable_paths():
            with self.subTest(path=item["path"]):
                self.assertIn(item["path"], documented)

    def test_no_description_for_a_nonexistent_setting(self):
        # Описание пути, которого нет в конфиге, — это описание, которое
        # никто никогда не увидит (и признак опечатки).
        from core.config_manager import DEFAULT_CONFIG

        for path in config_docs.paths():
            with self.subTest(path=path):
                node = DEFAULT_CONFIG
                for key in path.split("."):
                    self.assertIsInstance(node, dict)
                    self.assertIn(key, node)
                    node = node[key]

    def test_descriptions_are_not_empty(self):
        for path in config_docs.paths():
            with self.subTest(path=path):
                self.assertTrue(config_docs.get(path)["text"].strip())

    def test_zero_meaning_is_explained_where_it_is_not_obvious(self):
        # Ровно те поля, ради которых словарь и заведён: «0» в них
        # означает не «выключено», а «без ограничения».
        for path in ("nfqws.tcp_pkt_out", "nfqws.udp_pkt_out"):
            with self.subTest(path=path):
                self.assertIn("ограничения нет",
                              config_docs.get(path)["empty"])


class TestNoSecretsInResources(unittest.TestCase):
    """Ресурсы — второй канал наружу, мимо tool_result()."""

    def test_password_is_not_rendered(self):
        from core.config_manager import get_config_manager

        cfg = get_config_manager()
        secret = "s3cr3t-mcp-mirror"
        original = cfg.get("gui", "auth_password")
        cfg.set("gui", "auth_password", secret)
        try:
            for uri in resources.uris():
                with self.subTest(uri=uri):
                    self.assertNotIn(secret, resources.render(uri)["text"])
            payload = call("config_describe", {"path": "gui.auth_password"})
            self.assertNotIn(secret, str(payload))
        finally:
            cfg.set("gui", "auth_password", original)


if __name__ == "__main__":
    unittest.main()
