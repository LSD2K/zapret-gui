# tests/test_mcp_compose.py
"""
`strategy_compose`: декларативное описание → argv, который реально уедет.

Главное, что здесь фиксируется, — **сборка не дублируется**. Профили
собираются в строку аргументов (`strategy_builder.compose_profile_args`),
а дальше идут через тот же `build_nfqws_args`, что и стратегия,
сохранённая из веб-интерфейса: автообёртка голого приёма, дозаявка
блобов по ссылкам, резолв `lists/` и `@bin/` в пути устройства. Поэтому
есть тест на дословное совпадение argv из `strategy_compose` и argv из
эквивалентной «рукописной» стратегии: разойдись они — модель отлаживала
бы одно, а роутер запускал другое.

Второе: неизвестная lua-функция обязана **остановить** ответ, а не
уехать в поле, которое можно не заметить. `nfqws2 --intercept=0` её не
ловит (вызов происходит по-пакетно), значит отбить её может только
линтер — и отбивает так, что вызов становится `isError`.

Ничего не пишется: оба инструмента только читают, поэтому временный
каталог здесь нужен не для сохранности файлов, а чтобы тест не зависел
от настроек машины, на которой его запустили.
"""

import os
import shutil
import tempfile
import unittest

from core.mcp import registry


WRITE = {"strategies_write": True}


class Sandbox(unittest.TestCase):
    """Свой конфиг и свой менеджер стратегий на время теста."""

    def setUp(self):
        import core.config_manager as cm
        import core.strategy_builder as sb

        registry.load_tools()

        self.dir = tempfile.mkdtemp(prefix="mcp-compose-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

        saved_cfg = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved_cfg)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()

        manager = sb.StrategyManager(base_dir=os.path.join(self.dir,
                                                           "strategies"))
        manager._loaded = True
        self.manager = manager
        saved_factory = sb.get_strategy_manager
        self.addCleanup(setattr, sb, "get_strategy_manager", saved_factory)
        sb.get_strategy_manager = lambda: manager

    def call(self, name, args=None, perms=None):
        return registry.call(name, args or {},
                             WRITE if perms is None else perms)

    def data(self, name, args=None, perms=None):
        return self.call(name, args, perms)["structuredContent"]


class TestPermission(unittest.TestCase):

    def setUp(self):
        registry.load_tools()

    def test_not_listed_without_permission(self):
        names = {spec.name for spec in registry.available_tools({})}
        self.assertNotIn("strategy_compose", names)
        self.assertNotIn("strategy_validate", names)

    def test_listed_with_strategies_write(self):
        names = {spec.name for spec in registry.available_tools(WRITE)}
        self.assertIn("strategy_compose", names)
        self.assertIn("strategy_validate", names)

    def test_neither_tool_is_declared_mutating(self):
        # Оба только читают: собрать и проверить — не значит записать.
        for name in ("strategy_compose", "strategy_validate"):
            with self.subTest(tool=name):
                spec = next(s for s in registry.available_tools(WRITE)
                            if s.name == name)
                self.assertFalse(spec.mutating)


class TestCompose(Sandbox):
    """Описание → аргументы."""

    TLS = {
        "filter": {"proto": "tcp", "ports": "443", "l7": "tls",
                   "hostlist": "youtube"},
        "payload": "tls_client_hello",
        "out_range": "-d10",
        "desync": [
            {"fn": "fake", "params": {"blob": "fake_default_tls",
                                      "tcp_md5": True, "repeats": 11}},
            {"fn": "multidisorder", "params": {"pos": "1,midsld"}},
        ],
    }

    def test_profile_is_built_in_the_order_of_the_reference(self):
        # Фильтр профиля → внутрипрофильные фильтры → инстансы (§15).
        # Порядок значим: --payload действует на СЛЕДУЮЩИЕ --lua-desync.
        got = self.data("strategy_compose", {"profiles": [self.TLS]})
        self.assertTrue(got["ok"], got)
        self.assertEqual(
            got["profiles"][0]["args"],
            "--filter-tcp=443 --filter-l7=tls "
            "--hostlist=lists/youtube.txt "
            "--out-range=-d10 --payload=tls_client_hello "
            "--lua-desync=fake:blob=fake_default_tls:tcp_md5:repeats=11 "
            "--lua-desync=multidisorder:pos=1,midsld")

    def test_argv_matches_a_handwritten_strategy(self):
        # Пункт приёмки S11: сборка через strategy_compose и сборка через
        # UI дают ОДИНАКОВЫЙ argv для одного набора профилей.
        got = self.data("strategy_compose", {"profiles": [self.TLS]})
        handwritten = self.manager.build_nfqws_args({
            "profiles": [{"id": "p1", "enabled": True,
                          "args": got["profiles"][0]["args"]}],
        })
        self.assertEqual(got["strategy_args"], handwritten)

    def test_profiles_go_into_strategy_save_as_they_are(self):
        got = self.data("strategy_compose", {"profiles": [self.TLS]})
        saved = self.data("strategy_save", {
            "id": "composed", "name": "Собранная",
            "profiles": [{"id": p["id"], "args": p["args"]}
                         for p in got["profiles"]],
        })
        self.assertTrue(saved["ok"], saved)
        self.assertEqual(
            self.manager.build_nfqws_args(
                self.manager.get_strategy("composed")),
            got["strategy_args"])

    def test_command_is_the_real_one(self):
        got = self.data("strategy_compose", {"profiles": [self.TLS]})
        # Превью собирается тем же compose_command, что и живой запуск:
        # base-args движка в нём обязаны быть.
        self.assertIn("--qnum=", got["command"])
        self.assertIn("--lua-desync=fake:", got["command"])

    def test_several_profiles_are_separated_by_new(self):
        udp = {"filter": {"proto": "udp", "ports": "443", "l7": "quic"},
               "payload": "quic_initial",
               "desync": [{"fn": "fake",
                           "params": {"blob": "fake_default_quic"}}]}
        got = self.data("strategy_compose", {"profiles": [self.TLS, udp]})
        self.assertTrue(got["ok"], got)
        self.assertIn("--new", got["strategy_args"])
        self.assertEqual(len(got["profiles"]), 2)

    def test_true_is_a_flag_and_false_omits_the_argument(self):
        spec = {"filter": {"proto": "tcp", "ports": "443"},
                "payload": "tls_client_hello",
                "desync": [{"fn": "fake", "params": {"tcp_md5": True,
                                                     "badsum": False,
                                                     "repeats": 3}}]}
        got = self.data("strategy_compose", {"profiles": [spec]})
        args = got["profiles"][0]["args"]
        self.assertIn("--lua-desync=fake:tcp_md5:repeats=3", args)
        self.assertNotIn("badsum", args)

    def test_hostlist_name_is_resolved_to_the_device_path(self):
        got = self.data("strategy_compose", {"profiles": [self.TLS]})
        self.assertTrue(any(a.startswith("--hostlist=/")
                            for a in got["strategy_args"]), got)

    def test_a_path_traversal_in_a_list_name_is_refused(self):
        spec = dict(self.TLS,
                    filter={"proto": "tcp", "ports": "443",
                            "hostlist": "../../etc/passwd"})
        answer = self.call("strategy_compose", {"profiles": [spec]})
        self.assertTrue(answer["isError"])
        self.assertIn("filter.hostlist",
                      answer["structuredContent"]["error"])

    def test_explicit_blob_is_declared_before_the_first_new(self):
        spec = {"filter": {"proto": "tcp", "ports": "443"},
                "payload": "tls_client_hello",
                "blobs": ["tls_google"],
                "desync": [{"fn": "multidisorder",
                            "params": {"seqovl_pattern": "tls_google",
                                       "seqovl": "680"}}]}
        got = self.data("strategy_compose", {"profiles": [spec, spec]})
        self.assertTrue(got["ok"], got)
        argv = got["strategy_args"]
        decl = next(i for i, a in enumerate(argv) if a.startswith("--blob="))
        self.assertLess(decl, argv.index("--new"))

    def test_an_invented_blob_name_is_refused_outright(self):
        spec = {"filter": {"proto": "tcp", "ports": "443"},
                "payload": "tls_client_hello",
                "blobs": ["tls_that_does_not_exist"],
                "desync": [{"fn": "fake", "params": {}}]}
        answer = self.call("strategy_compose", {"profiles": [spec]})
        self.assertTrue(answer["isError"])
        # Отказ обязан назвать, где смотреть существующие имена:
        # «blob не известен» без адреса заставляет их выдумывать дальше.
        self.assertIn("blobs_list", answer["structuredContent"]["error"])


class TestComposeLint(Sandbox):
    """Замечания линтера доезжают до ответа — и ошибка его роняет."""

    def test_unknown_function_makes_the_call_an_error(self):
        answer = self.call("strategy_compose", {"profiles": [{
            "filter": {"proto": "tcp", "ports": "443"},
            "payload": "tls_client_hello",
            "desync": [{"fn": "fake_tls_v2", "params": {}}],
        }]})
        self.assertTrue(answer["isError"])
        got = answer["structuredContent"]
        self.assertFalse(got["valid"])
        self.assertTrue(got["lint"]["blocking"])
        self.assertIn("unknown_lua_function", got["lint"]["codes"])

    def test_a_broken_strategy_still_shows_its_argv(self):
        # Пустой отказ означал бы второй вызов только ради того, чтобы
        # увидеть, что же собралось.
        got = self.data("strategy_compose", {"profiles": [{
            "filter": {"proto": "tcp", "ports": "443"},
            "payload": "tls_client_hello",
            "desync": [{"fn": "fake_tls_v2", "params": {}}],
        }]})
        self.assertTrue(got["strategy_args"])
        self.assertTrue(got["command"])
        self.assertTrue(got["profiles"])

    def test_a_warning_alone_does_not_fail_the_call(self):
        # Голый приём — предупреждение: так собран весь каталог.
        answer = self.call("strategy_compose", {"profiles": [{
            "desync": [{"fn": "fake", "params": {
                "blob": "fake_default_tls"}}],
        }]})
        self.assertFalse(answer["isError"])
        got = answer["structuredContent"]
        self.assertTrue(got["valid"])
        self.assertEqual(got["lint"]["errors"], 0)
        self.assertIn("bare_trick_no_filter", got["lint"]["codes"])
        self.assertIn("lint.findings", got["hint"])

    def test_a_clean_strategy_says_it_was_not_checked_by_the_engine(self):
        got = self.data("strategy_compose", {"profiles": [{
            "filter": {"proto": "tcp", "ports": "443", "l7": "tls"},
            "payload": "tls_client_hello",
            "desync": [{"fn": "fake", "params": {
                "blob": "fake_default_tls"}}],
        }]})
        self.assertEqual(got["lint"]["findings"], [])
        self.assertIn("strategy_validate", got["hint"])

    def test_the_lint_says_what_it_managed_to_check(self):
        # «Правило пропущено, потому что карты функций нет» и «правило
        # проверено и молчит» — разные ответы.
        got = self.data("strategy_compose", {"profiles": [{
            "filter": {"proto": "tcp", "ports": "443"},
            "payload": "tls_client_hello",
            "desync": [{"fn": "fake", "params": {}}],
        }]})
        self.assertIn("lua_functions", got["lint"]["checked"])
        self.assertIn("blobs", got["lint"]["checked"])


class TestComposeInputErrors(Sandbox):
    """Вход, который собрать нельзя, объясняется словами."""

    def test_ports_without_proto(self):
        answer = self.call("strategy_compose", {"profiles": [{
            "filter": {"ports": "443"},
            "desync": [{"fn": "fake", "params": {}}],
        }]})
        self.assertTrue(answer["isError"])
        self.assertIn("filter.proto", answer["structuredContent"]["error"])

    def test_a_profile_without_desync_is_refused_by_the_schema(self):
        from core.mcp.schema import SchemaError

        with self.assertRaises(SchemaError):
            registry.call("strategy_compose",
                          {"profiles": [{"filter": {"proto": "tcp"}}]},
                          WRITE)

    def test_an_empty_function_name_is_refused(self):
        answer = self.call("strategy_compose", {"profiles": [{
            "desync": [{"fn": "  "}],
        }]})
        self.assertTrue(answer["isError"])
        self.assertIn("lua_functions_list",
                      answer["structuredContent"]["hint"])


if __name__ == "__main__":
    unittest.main()
