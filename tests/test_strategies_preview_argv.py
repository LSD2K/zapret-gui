# tests/test_strategies_preview_argv.py
"""
POST /api/strategies/preview: поле argv (debian-gw,
docs/gw/spec-t4-updates.md).

argv это полная команда nfqws2 списком токенов без пути к бинарю, тот же
compose_command, что у живого запуска. gw-panel гоняет им dry-run нового
бинаря и не должна разбирать строку command с кавычками inline-Lua.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import core.config_manager as cm_mod
import core.strategy_builder as sb_mod
from core.config_manager import ConfigManager
from core.nfqws_manager import get_nfqws_manager
from tests._wsgi_client import WSGIClient, build_test_app

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VIDNOE = os.path.join(REPO, "config", "strategies", "user",
                      "keenetic_vidnoe.json")

INLINE_LUA = '--lua-desync=luaexec:code="local a = 1"'

STRATEGY = {
    "id": "t4_preview",
    "name": "t4",
    "profiles": [
        {"id": "tls", "enabled": True,
         "args": "--filter-tcp=443 --hostlist=lists/keenetic.txt "
                 "--payload=tls_client_hello " + INLINE_LUA +
                 " --lua-desync=fake:blob=tls_google:tls_mod=rnd,dupsid"},
        {"id": "off", "enabled": False,
         "args": "--filter-udp=1 --lua-desync=fake"},
        {"id": "quic", "enabled": True,
         "args": "--filter-udp=443 --filter-l7=quic "
                 "--payload=quic_initial "
                 "--lua-desync=fake:blob=quic_google:repeats=11"},
    ],
}


class _Base(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.lists = os.path.join(self.tmp, "lists")
        self.lua = os.path.join(self.tmp, "lua")
        os.makedirs(self.lists)
        os.makedirs(self.lua)
        for name in ("netrogat.txt", "keenetic.txt"):
            with open(os.path.join(self.lists, name), "w") as f:
                f.write("example.org\n")

        cm = ConfigManager(config_dir=self.tmp)
        cm.load()
        cm.set("zapret", "lists_path", self.lists)
        cm.set("zapret", "lua_path", self.lua)
        cm.set("zapret", "ipset_path", self.lists)
        cm.set("zapret", "nfqws_binary", "/opt/zapret2/nfq2/nfqws2")
        cm.save()
        p = mock.patch.object(cm_mod, "_config_manager", cm)
        p.start()
        self.addCleanup(p.stop)

        # Менеджер стратегий на временном каталоге с живой стратегией gw.
        sdir = os.path.join(self.tmp, "strategies")
        os.makedirs(os.path.join(sdir, "user"))
        shutil.copy(VIDNOE, os.path.join(sdir, "user"))
        self.sm = sb_mod.StrategyManager(base_dir=sdir)
        p = mock.patch.object(sb_mod, "get_strategy_manager",
                              lambda: self.sm)
        p.start()
        self.addCleanup(p.stop)

    def preview(self, body):
        code, _, data = self.client.request(
            "POST", "/api/strategies/preview", body=body)
        self.assertEqual(code, 200, data)
        return data


class TestPreviewArgv(_Base):

    def test_argv_is_full_command_without_binary(self):
        r = self.preview({"strategy_data": STRATEGY})
        argv = r["argv"]
        self.assertIsInstance(argv, list)
        self.assertTrue(argv)
        self.assertTrue(all(isinstance(a, str) for a in argv))
        self.assertNotIn("/opt/zapret2/nfq2/nfqws2", argv)
        expected = get_nfqws_manager().compose_command(
            self.sm.build_nfqws_args(STRATEGY))
        self.assertEqual(argv, expected[1:])
        self.assertEqual(expected[0], "/opt/zapret2/nfq2/nfqws2")

    def test_base_args_and_profile_args_are_there(self):
        argv = self.preview({"strategy_data": STRATEGY})["argv"]
        # base-args движка идут первыми, как в живом запуске.
        self.assertTrue(any(a.startswith("--qnum=") for a in argv))
        self.assertTrue(any(a.startswith("--user=") for a in argv))
        # args стратегии целиком в хвосте argv.
        r = self.preview({"strategy_data": STRATEGY})
        self.assertEqual(argv[-len(r["args"]):], r["args"])

    def test_command_is_the_same_argv_joined(self):
        r = self.preview({"strategy_data": STRATEGY})
        self.assertEqual(
            r["command"],
            " \\\n  ".join(["/opt/zapret2/nfq2/nfqws2"] + r["argv"]))

    def test_inline_lua_with_quotes_is_one_token(self):
        argv = self.preview({"strategy_data": STRATEGY})["argv"]
        self.assertIn(INLINE_LUA, argv)
        self.assertNotIn('code="local', argv)

    def test_lists_are_substituted_per_profile(self):
        argv = self.preview({"strategy_data": STRATEGY})["argv"]
        netrogat = "--hostlist-exclude=%s" % os.path.join(
            self.lists, "netrogat.txt")
        # Выключенный профиль не попадает: два профиля, один --new.
        self.assertEqual(argv.count("--new"), 1)
        # Исключения движка подмешаны в каждый профиль.
        self.assertEqual(argv.count(netrogat), 2)
        # lists/ разрешён в абсолютный путь.
        self.assertIn("--hostlist=%s" % os.path.join(self.lists,
                                                     "keenetic.txt"), argv)
        self.assertNotIn("--hostlist=lists/keenetic.txt", argv)

    def test_strategy_id_of_live_gw_strategy(self):
        with open(VIDNOE, encoding="utf-8") as f:
            vidnoe = json.load(f)
        enabled = [p for p in vidnoe["profiles"] if p.get("enabled", True)]
        r = self.preview({"strategy_id": "keenetic_vidnoe"})
        self.assertEqual(r["profiles_count"], len(enabled))
        self.assertEqual(r["argv"].count("--new"), len(enabled) - 1)
        self.assertEqual(
            r["command"],
            " \\\n  ".join(["/opt/zapret2/nfq2/nfqws2"] + r["argv"]))

    def test_old_fields_unchanged(self):
        r = self.preview({"strategy_data": STRATEGY})
        self.assertEqual(r["args"], self.sm.build_nfqws_args(STRATEGY))
        self.assertEqual(r["command"],
                         self.sm.build_preview_command(STRATEGY))
        self.assertEqual(r["profiles_count"], 2)

    def test_errors_have_no_argv(self):
        code, _, data = self.client.request(
            "POST", "/api/strategies/preview", body={"strategy_id": "nope"})
        self.assertEqual(code, 404)
        self.assertNotIn("argv", data)


class TestBuildPreviewArgv(_Base):

    def test_first_element_is_binary(self):
        full = self.sm.build_preview_argv(STRATEGY)
        self.assertEqual(full[0], "/opt/zapret2/nfq2/nfqws2")
        self.assertEqual(" \\\n  ".join(full),
                         self.sm.build_preview_command(STRATEGY))


if __name__ == "__main__":
    unittest.main()
