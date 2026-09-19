# tests/test_mcp_validate.py
"""
`strategy_validate`: прогон `nfqws2 --intercept=0`, ничего не сохраняя.

Почему это отдельный инструмент, а не «часть сохранения»: модель обязана
иметь возможность проверить стратегию, не записывая её. Отсюда три
входа — `strategy_id` (проверить сохранённую), `profiles` (то же
описание, что у `strategy_compose`) и `args` (готовая строка).

Сам движок здесь замокан. Бинарника nfqws2 на машине разработчика нет, а
на роутере прогон занимает секунды — тест про КОНТРАКТ инструмента:
успех, ошибка разбора опций, ошибка внутри lua, честное «проверить
нечем». Что именно делает `dry_run`, проверяет `test_nfqws_manager`.

Отдельно фиксируется, что подсказки привязаны к выводу: правило
«blob» из `HINT_RULES` — короткая подстрока, и на УСПЕШНОМ выводе оно
дало бы совет чинить то, что работает. Поэтому подсказки считаются
только по неудачной проверке.
"""

import os
import shutil
import tempfile
import unittest

from core.mcp import registry


WRITE = {"strategies_write": True}

# Что печатает nfqws2, когда опция не разобралась.
PARSE_ERROR = ("nfqws2: unknown option --lua-desyn\n"
               "Try 'nfqws2 -?' for more information.")
# А что — когда упал lua-init (ровно тот случай, ради которого взят
# --intercept=0, а не --dry-run).
LUA_ERROR = ("lua: /opt/zapret2/lua/zapret-antidpi.lua:12: "
             "bad argument #2 to 'tls_mod' (string expected, got nil)")


class Sandbox(unittest.TestCase):
    """Свой конфиг, свой менеджер стратегий и замоканный dry_run."""

    def setUp(self):
        import core.config_manager as cm
        import core.nfqws_manager as nm
        import core.strategy_builder as sb

        registry.load_tools()

        self.dir = tempfile.mkdtemp(prefix="mcp-validate-")
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

        # Подменяем ТОЛЬКО dry_run, оставляя настоящий compose_command:
        # команда в ответе обязана оставаться настоящей.
        engine = nm.get_nfqws_manager()
        saved_dry = engine.dry_run
        self.addCleanup(setattr, engine, "dry_run", saved_dry)
        self.engine = engine
        self.calls = []
        self.answer(ok=True)

    def answer(self, ok=True, returncode=0, output="", available=True,
               error=""):
        """Задать, что ответит замоканный `dry_run` на следующий вызов."""
        def fake(argv, timeout=8.0):
            self.calls.append(list(argv))
            return {"ok": ok, "available": available,
                    "returncode": returncode, "output": output,
                    "error": error, "command": " ".join(argv)}
        self.engine.dry_run = fake

    def call(self, args=None, perms=None):
        return registry.call("strategy_validate", args or {},
                             WRITE if perms is None else perms)

    def data(self, args=None, perms=None):
        return self.call(args, perms)["structuredContent"]


GOOD_PROFILE = {
    "filter": {"proto": "tcp", "ports": "443", "l7": "tls"},
    "payload": "tls_client_hello",
    "desync": [{"fn": "fake", "params": {"blob": "fake_default_tls"}}],
}


class TestSources(Sandbox):
    """Три входа и отказ на их отсутствии."""

    def test_profiles(self):
        got = self.data({"profiles": [GOOD_PROFILE]})
        self.assertTrue(got["ok"], got)
        self.assertEqual(got["source"], "profiles")
        self.assertTrue(got["validation"]["ok"])

    def test_raw_args(self):
        got = self.data({"args": "--filter-tcp=443 --payload=tls_client_hello"
                                 " --lua-desync=fake:blob=fake_default_tls"})
        self.assertTrue(got["ok"], got)
        self.assertEqual(got["source"], "args")

    def test_saved_strategy_by_id(self):
        self.manager.save_user_strategy({
            "id": "saved", "name": "Сохранённая",
            "profiles": [{"id": "p1", "enabled": True,
                          "args": "--filter-tcp=443 "
                                  "--payload=tls_client_hello "
                                  "--lua-desync=fake:blob=fake_default_tls"}],
        })
        got = self.data({"strategy_id": "saved"})
        self.assertTrue(got["ok"], got)
        self.assertEqual(got["source"], "strategy_id")
        self.assertEqual(got["strategy_id"], "saved")

    def test_nothing_to_check(self):
        answer = self.call({})
        self.assertTrue(answer["isError"])
        self.assertIn("strategy_compose",
                      answer["structuredContent"]["hint"])

    def test_two_sources_at_once_are_refused(self):
        # «Проверил одно, ответил про другое» — худший вид ответа.
        answer = self.call({"strategy_id": "saved", "args": "--lua-desync=x"})
        self.assertTrue(answer["isError"])
        self.assertIn("несколько источников",
                      answer["structuredContent"]["error"])

    def test_unknown_strategy_id(self):
        answer = self.call({"strategy_id": "no-such"})
        self.assertTrue(answer["isError"])
        self.assertIn("strategy_list", answer["structuredContent"]["hint"])


class TestVerdict(Sandbox):
    """Что движок ответил — и что из этого следует."""

    def test_success(self):
        got = self.data({"profiles": [GOOD_PROFILE]})
        self.assertTrue(got["valid"])
        self.assertEqual(got["validation"]["checker"], "nfqws2 --intercept=0")
        self.assertEqual(got["hints"], [])
        self.assertIn("lua-init исполнился", got["hint"])

    def test_the_engine_gets_intercept_zero_argv(self):
        # Валидация не открывает NFQUEUE и не трогает трафик — проверяем,
        # что в движок ушли именно аргументы стратегии.
        self.data({"profiles": [GOOD_PROFILE]})
        self.assertEqual(len(self.calls), 1)
        self.assertIn("--filter-tcp=443", self.calls[0])

    def test_option_parse_error_fails_the_call(self):
        self.answer(ok=False, returncode=1, output=PARSE_ERROR)
        answer = self.call({"profiles": [GOOD_PROFILE]})
        self.assertTrue(answer["isError"])
        got = answer["structuredContent"]
        self.assertFalse(got["valid"])
        self.assertIn("unknown option", got["validation"]["output"])
        self.assertIn("код 1", got["error"])

    def test_lua_error_is_caught_and_explained(self):
        # Ровно то, ради чего взят --intercept=0: ошибка ВНУТРИ lua.
        self.answer(ok=False, returncode=1, output=LUA_ERROR)
        got = self.data({"profiles": [GOOD_PROFILE]})
        self.assertFalse(got["valid"])
        ids = [h["id"] for h in got["hints"]]
        self.assertIn("lua_bad_argument", ids)
        self.assertIn("--lua-init",
                      next(h["hint"] for h in got["hints"]
                           if h["id"] == "lua_bad_argument"))

    def test_hints_are_tied_to_a_failed_run_only(self):
        # Правило `blob_missing` ловится одной короткой подстрокой: на
        # успешном выводе оно послало бы чинить исправное.
        self.answer(ok=True, returncode=0, output="blob tls_google loaded")
        got = self.data({"profiles": [GOOD_PROFILE]})
        self.assertTrue(got["valid"])
        self.assertEqual(got["hints"], [])

    def test_failed_validation_reports_dry_run_failed(self):
        self.answer(ok=False, returncode=1, output=PARSE_ERROR)
        got = self.data({"profiles": [GOOD_PROFILE]})
        self.assertIn("dry_run_failed", [h["id"] for h in got["hints"]])

    def test_missing_binary_is_not_a_failure(self):
        # На машине без zapret2 «не проверяли» ≠ «проверили и не прошло».
        self.answer(ok=False, available=False, returncode=None,
                    error="Бинарник nfqws2 недоступен: /opt/zapret2/nfqws2")
        answer = self.call({"profiles": [GOOD_PROFILE]})
        self.assertFalse(answer["isError"])
        got = answer["structuredContent"]
        self.assertTrue(got["valid"])
        self.assertFalse(got["validation"]["available"])
        self.assertIn("reason", got["validation"])
        self.assertIn("бинарника nfqws2", got["hint"])
        self.assertEqual(got["hints"], [])

    def test_long_output_is_cut(self):
        from core.mcp.tools import compose

        self.answer(ok=False, returncode=1, output="x" * 5000)
        got = self.data({"profiles": [GOOD_PROFILE]})
        self.assertEqual(len(got["validation"]["output"]),
                         compose.MAX_OUTPUT)
        self.assertTrue(got["validation"]["output_truncated"])


class TestLintAlongsideTheEngine(Sandbox):
    """Линтер работает и тогда, когда движок доволен."""

    def test_unknown_function_fails_even_with_a_green_dry_run(self):
        # Главная причина, по которой линтер вообще есть: вызов
        # несуществующей функции происходит по-пакетно, и --intercept=0
        # его пропускает.
        got = self.data({"args": "--filter-tcp=443 "
                                 "--payload=tls_client_hello "
                                 "--lua-desync=fake_tls_v2"})
        self.assertTrue(got["validation"]["ok"])
        self.assertFalse(got["valid"])
        self.assertIn("unknown_lua_function", got["lint"]["codes"])
        self.assertIn("только на живом пакете", got["hint"])

    def test_a_catalog_style_bare_trick_only_warns(self):
        got = self.data({"args": "--lua-desync=fake:blob=fake_default_tls"})
        self.assertTrue(got["valid"])
        self.assertEqual(got["lint"]["errors"], 0)
        self.assertIn("bare_trick_no_filter", got["lint"]["codes"])


if __name__ == "__main__":
    unittest.main()
