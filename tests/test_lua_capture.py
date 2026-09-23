# tests/test_lua_capture.py
"""
Lua-дамп движка: ``--writable`` + ``zapret-pcap.lua``.

Что стережём:

* **``--writable`` выдаётся сам**, как только в стратегии есть
  ``pcap``, — и только тогда. Без него ``pcap`` с относительным именем
  пишет в текущий каталог nfqws2, куда под ``--user nobody`` писать
  нельзя, и обработка пакета обрывается ошибкой lua. Свой каталог
  стратегии не положен: nfqws2 делает его ``chown`` от root, и сборщик
  заменяет его нашим;
* **``pcap`` встаёт перед первым приёмом профиля** и больше ничего в
  argv не меняет: ``--payload``/``--out-range`` действуют на следующие
  инстансы, и поставь мы его раньше со своими диапазонами — мерили бы
  уже не стратегию модели;
* **дамп читается тем же разбором, что tcpdump** (формат, который
  пишет ``zapret-pcap.lua``: big-endian, наносекунды, raw IP), и
  файлы после разбора удаляются;
* **внутри эксперимента** ``pcap`` уходит в движок, но НЕ в отчёт и не
  в commit — это прибор, а не часть стратегии; пустой дамп при
  поднятом движке превращается в подсказку «чините фильтр, а не
  приём».
"""

import os
import shutil
import struct
import tempfile
import unittest

from core import lua_capture, pcap_reader

from tests.test_mcp_experiment import ExperimentCase, get_experiment_runner
from tests.test_pcap_reader import ipv4, tcp, tls_client_hello


def lua_pcap(frames) -> bytes:
    """Файл ровно в том виде, в каком его пишет zapret-pcap.lua."""
    out = (b"\xA1\xB2\x3C\x4D\x00\x02\x00\x04" + b"\x00" * 8
           + b"\x00\x00\xFF\xFF\x00\x00\x00\x65")
    for index, raw in enumerate(frames):
        out += struct.pack(">IIII", 1700000000 + index, 5, len(raw),
                           len(raw))
        out += raw
    return out


class TestWritable(unittest.TestCase):

    PCAP = ["--filter-tcp=443", "--lua-desync=pcap:file=x.pcap"]

    def test_only_when_pcap_is_used(self):
        self.assertEqual(lua_capture.writable_args(
            ["--filter-tcp=443", "--lua-desync=fake:blob=x"]), [])
        self.assertEqual(lua_capture.writable_args(self.PCAP, "/tmp/w"),
                         ["--writable=/tmp/w"])

    def test_similar_names_are_not_pcap(self):
        self.assertFalse(lua_capture.uses_pcap(
            ["--lua-desync=pcap_write:file=x"]))

    def test_explicit_dir_is_not_doubled(self):
        # Страховка для argv в обход сборщика: второй --writable не
        # добавляем (сам сборщик чужой вырезает раньше — тест ниже).
        for own in ("--writable=/data/dump", "--writable",
                    "--writeable=/old"):
            with self.subTest(flag=own):
                self.assertEqual(
                    lua_capture.writable_args(self.PCAP + [own]), [])

    def test_compose_replaces_the_strategy_dir_with_ours(self):
        # nfqws2 делает chown каталога --writable от root — и
        # существующего тоже: чужой каталог в стратегии — это «отдай
        # /etc пользователю nobody».
        argv = self._compose(self.PCAP + ["--writable=/etc"])
        self.assertEqual([a for a in argv if a.startswith("--writ")],
                         ["--writable=%s" % lua_capture.writable_dir()])

    def test_symlink_in_place_of_the_dir_is_replaced(self):
        base = tempfile.mkdtemp(prefix="lua-w-")
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        victim = os.path.join(base, "victim")
        os.makedirs(victim)
        link = os.path.join(base, "writable")
        os.symlink(victim, link)
        lua_capture.prepare_dir(link)
        self.assertFalse(os.path.islink(link))
        self.assertTrue(os.path.isdir(link))

    def _compose(self, strategy):
        from core.nfqws_manager import NFQWSManager

        lua_dir = tempfile.mkdtemp(prefix="lua-")
        self.addCleanup(shutil.rmtree, lua_dir, ignore_errors=True)

        class Cfg:
            def get(self, section, key=None, default=None):
                if (section, key) == ("zapret", "lua_path"):
                    return lua_dir
                if (section, key) == ("interfaces", "wan"):
                    return "eth0"
                return default

        mgr = NFQWSManager.__new__(NFQWSManager)
        return mgr.compose_command(strategy, binary="/bin/nfqws2", cfg=Cfg())

    def test_compose_command_puts_it_before_lua_init(self):
        from core.nfqws_manager import NFQWSManager

        lua_dir = tempfile.mkdtemp(prefix="lua-")
        self.addCleanup(shutil.rmtree, lua_dir, ignore_errors=True)
        for name in ("zapret-lib.lua", "zapret-antidpi.lua",
                     "zapret-pcap.lua"):
            open(os.path.join(lua_dir, name), "w").close()

        class Cfg:
            def get(self, section, key=None, default=None):
                if (section, key) == ("zapret", "lua_path"):
                    return lua_dir
                if (section, key) == ("interfaces", "wan"):
                    return "eth0"
                return default

        mgr = NFQWSManager.__new__(NFQWSManager)
        argv = mgr.compose_command(self.PCAP, binary="/bin/nfqws2",
                                   cfg=Cfg())
        writable = [a for a in argv if a.startswith("--writable=")]
        self.assertEqual(writable,
                         ["--writable=%s" % lua_capture.writable_dir()])
        first_init = next(i for i, a in enumerate(argv)
                          if a.startswith("--lua-init="))
        self.assertLess(argv.index(writable[0]), first_init)
        self.assertIn("--lua-init=@%s"
                      % os.path.join(lua_dir, "zapret-pcap.lua"), argv)

        plain = mgr.compose_command(["--filter-tcp=443",
                                     "--lua-desync=fake:blob=x"],
                                    binary="/bin/nfqws2", cfg=Cfg())
        self.assertFalse([a for a in plain if a.startswith("--writable")])


class TestInject(unittest.TestCase):

    def test_pcap_goes_right_before_the_first_trick(self):
        argv = ["--filter-tcp=443", "--payload=tls_client_hello",
                "--lua-desync=fake:blob=x", "--lua-desync=multisplit",
                "--new", "--filter-udp=443", "--lua-desync=fake:blob=q"]
        out, files = lua_capture.inject(argv, "A")
        self.assertEqual(out, [
            "--filter-tcp=443", "--payload=tls_client_hello",
            "--lua-desync=pcap:file=A-p1.pcap",
            "--lua-desync=fake:blob=x", "--lua-desync=multisplit",
            "--new", "--filter-udp=443",
            "--lua-desync=pcap:file=A-p2.pcap",
            "--lua-desync=fake:blob=q"])
        self.assertEqual(files, [{"profile": 1, "file": "A-p1.pcap"},
                                 {"profile": 2, "file": "A-p2.pcap"}])

    def test_nothing_else_changes(self):
        argv = ["--filter-tcp=80", "--out-range=-d5",
                "--lua-desync=fake:blob=x", "--new", "--filter-udp=53"]
        out, files = lua_capture.inject(argv, "B")
        self.assertEqual([a for a in out if "pcap" not in a], argv)
        # Профиль без приёмов пропускает пакеты мимо lua — писать нечего.
        self.assertEqual([f["profile"] for f in files], [1])

    def test_own_pcap_is_not_doubled(self):
        argv = ["--filter-tcp=443", "--lua-desync=pcap:file=mine.pcap",
                "--lua-desync=fake"]
        out, files = lua_capture.inject(argv, "A")
        self.assertEqual(out, argv)
        self.assertEqual(files, [])

    def test_label_cannot_break_the_argument(self):
        out, files = lua_capture.inject(["--lua-desync=fake"],
                                        "a:b c/../d")
        self.assertEqual(files[0]["file"], "a_b_c_d-p1.pcap")
        self.assertNotIn(" ", out[0])


class TestCollect(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="lua-pcap-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def test_engine_format_is_read_and_removed(self):
        path = os.path.join(self.dir, "A-p1.pcap")
        with open(path, "wb") as f:
            f.write(lua_pcap([
                ipv4(tcp(b"", flags=0x02)),
                ipv4(tcp(tls_client_hello(b"blocked.example"))),
            ]))
        # Файл того самого формата: big-endian, наносекунды, raw IP.
        with open(path, "rb") as f:
            self.assertEqual(pcap_reader.read_bytes(f.read())["linktype"],
                             pcap_reader.LINKTYPE_RAW)

        got = lua_capture.collect([{"profile": 1, "file": "A-p1.pcap"}],
                                  self.dir)
        self.assertTrue(got["measured"])
        self.assertEqual(got["packets"], 2)
        self.assertEqual(got["sni"], ["blocked.example"])
        self.assertEqual(got["profiles"], [{"profile": 1, "packets": 2,
                                            "total": 2}])
        self.assertFalse(os.path.exists(path))

    def test_missing_file_means_no_packets(self):
        # pcap не вызывался ни разу: ни один пакет не дошёл до профиля.
        got = lua_capture.collect([{"profile": 1, "file": "none.pcap"}],
                                  self.dir)
        self.assertTrue(got["measured"])
        self.assertEqual(got["packets"], 0)
        self.assertEqual(got["profiles"], [{"profile": 1, "packets": 0}])

    def test_garbage_is_reported_not_raised(self):
        path = os.path.join(self.dir, "bad.pcap")
        with open(path, "wb") as f:
            f.write(b"not a pcap")
        got = lua_capture.collect([{"profile": 1, "file": "bad.pcap"}],
                                  self.dir)
        self.assertFalse(got["measured"])
        self.assertIn("error", got)
        self.assertFalse(os.path.exists(path))


class TestInsideTheExperiment(ExperimentCase):
    """``lua_capture=true``: прибор в движке, но не в стратегии."""

    TRICK = "--lua-desync=fake:blob=x"

    def setUp(self):
        super().setUp()
        self.lua_dir = os.path.join(self.dir, "lua")
        os.makedirs(self.lua_dir)
        open(os.path.join(self.lua_dir, "zapret-pcap.lua"), "w").close()
        self.cfg.set("zapret", "lua_path", self.lua_dir)

        self.dump_dir = os.path.join(self.dir, "writable")
        os.makedirs(self.dump_dir)
        self._patch(lua_capture, "writable_dir", lambda: self.dump_dir)

        # «Движок»: хороший вариант получает пакеты, плохой — ни одного
        # (фильтр не пропускает трафик до стратегии).
        restart = self.nfqws.restart

        def engine(args=None):
            ok = restart(args)
            if self.GOOD in (args or []):
                for arg in args:
                    if arg.startswith("--lua-desync=pcap:file="):
                        name = arg.split("=", 2)[2]
                        with open(os.path.join(self.dump_dir, name),
                                  "wb") as f:
                            f.write(lua_pcap([ipv4(tcp(
                                tls_client_hello(b"a.example")))]))
            return ok

        self.nfqws.restart = engine

    def run_it(self, **kwargs):
        kwargs.setdefault("variants", [
            {"label": "A", "args": ["--filter-tcp=443", self.GOOD,
                                    self.TRICK]},
            {"label": "B", "args": ["--filter-tcp=443", "--bad",
                                    self.TRICK]},
        ])
        result = self.start(**kwargs)
        self.wait_idle()
        report = get_experiment_runner().get_result()
        return result, {v["label"]: v for v in report["variants"]}

    def test_off_by_default(self):
        _, variants = self.run_it()
        for item in variants.values():
            self.assertNotIn("lua_capture", item)
        for call, args in self.nfqws.calls:
            self.assertFalse(any("pcap" in a for a in args))

    def test_engine_gets_pcap_report_does_not(self):
        result, variants = self.run_it(lua_capture=True)
        self.assertTrue(result["lua_capture"]["available"])
        restarts = [args for call, args in self.nfqws.calls
                    if call == "restart"]
        self.assertTrue(restarts)
        for args in restarts:
            self.assertIn("--lua-desync=pcap:file=%s-p1.pcap"
                          % ("A" if self.GOOD in args else "B"), args)
        for label, item in variants.items():
            with self.subTest(variant=label):
                self.assertFalse(any("pcap" in a for a in item["args"]))

    def test_dump_lands_in_the_report_and_files_go_away(self):
        _, variants = self.run_it(lua_capture=True)
        good = variants["A"]["lua_capture"]
        self.assertTrue(good["measured"])
        self.assertEqual(good["packets"], 1)
        self.assertEqual(good["sni"], ["a.example"])
        self.assertEqual(os.listdir(self.dump_dir), [])

    def test_empty_dump_points_at_the_filter(self):
        _, variants = self.run_it(lua_capture=True)
        bad = variants["B"]
        self.assertEqual(bad["lua_capture"]["packets"], 0)
        self.assertIn("lua_capture_empty",
                      [h["id"] for h in bad["hints"]])
        self.assertNotIn("lua_capture_empty",
                         [h["id"] for h in variants["A"]["hints"]])

    def test_no_script_does_not_break_the_run(self):
        os.remove(os.path.join(self.lua_dir, "zapret-pcap.lua"))
        result, variants = self.run_it(lua_capture=True)
        self.assertFalse(result["lua_capture"]["available"])
        self.assertIn("zapret-pcap.lua", result["lua_capture"]["reason"])
        self.assertEqual(len(variants), 2)
        for call, args in self.nfqws.calls:
            self.assertFalse(any("pcap" in a for a in args))

    def test_variant_without_tricks_says_why(self):
        _, variants = self.run_it(lua_capture=True, variants=[
            {"label": "A", "args": ["--filter-tcp=443", self.GOOD]}])
        dump = variants["A"]["lua_capture"]
        self.assertFalse(dump["measured"])
        self.assertIn("--lua-desync", dump["reason"])


if __name__ == "__main__":
    unittest.main()
