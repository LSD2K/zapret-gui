# tests/test_traffic_capture.py
"""
Рамки снифера: argv, фильтр, потолки — и то, что модель их не обойдёт.

Настоящий tcpdump здесь не запускается (в CI его нет, а на машине
разработчика он потребовал бы root). Проверяется то, что от него не
зависит и что как раз и отличает инструмент от «выдайте `shell_full` и
пусть модель сама»:

* **в командной строке нет ни одной строки от модели.** Фильтр
  собирается из разобранных полей, интерфейс сверяется с
  `/sys/class/net`, произвольное BPF-выражение не принимается вовсе —
  это же и способ дописать `-z` с посторонней командой;
* **потолки не поднимаются** ни аргументом вызова, ни настройкой выше
  жёстких рамок модуля;
* **«tcpdump не установлен» — это ответ, а не ошибка**: инструмент
  говорит, чем его поставить.

Весь путь целиком (запуск → файл → разбор → уборка) проверяется с
**подставным** tcpdump: он кладёт заранее собранный pcap туда, куда
просят ключом `-w`. Так проверяется наше, а не чужое: дошли ли
аргументы, разобрался ли дамп в поля и не остался ли файл на диске (на
роутере с `/tmp` в оперативной памяти это не мелочь).
"""

import os
import shutil
import tempfile
import time
import unittest

from core import traffic_capture as capture
from core.mcp import registry


PROBES = {"probes": True}


class TestFilter(unittest.TestCase):
    """Фильтр собирается ЗДЕСЬ, из полей, и уезжает списком."""

    def test_empty_filter(self):
        self.assertEqual(capture._filter("", None, ""), [])

    def test_host_port_proto(self):
        self.assertEqual(
            capture._filter("1.2.3.4", 443, "tcp"),
            ["tcp", "and", "host", "1.2.3.4", "and", "port", "443"])

    def test_subnet_uses_net(self):
        self.assertEqual(capture._filter("10.0.0.0/8", None, ""),
                         ["net", "10.0.0.0/8"])

    def test_ipv6_host(self):
        self.assertEqual(capture._filter("2001:db8::1", None, ""),
                         ["host", "2001:db8::1"])

    def test_domain_is_refused(self):
        # Домен пришлось бы резолвить самому tcpdump — то есть пустить
        # в командную строку имя, которое пришло от модели.
        with self.assertRaises(capture.CaptureError) as ctx:
            capture._filter("example.com", None, "")
        self.assertIn("probe_targets", str(ctx.exception))

    def test_injection_attempts_are_refused(self):
        for bad in ("1.2.3.4 or 1", "-z ls", "1.2.3.4; reboot",
                    "$(id)", "1.2.3.4 and port 22"):
            with self.subTest(host=bad):
                with self.assertRaises(capture.CaptureError):
                    capture._filter(bad, None, "")

    def test_bad_proto_and_port(self):
        with self.assertRaises(capture.CaptureError):
            capture._filter("", None, "sctp")
        with self.assertRaises(capture.CaptureError):
            capture._filter("", 70000, "")
        with self.assertRaises(capture.CaptureError):
            capture._filter("", "not a number", "")


class TestIface(unittest.TestCase):

    def test_unknown_iface_lists_the_real_ones(self):
        with self.assertRaises(capture.CaptureError) as ctx:
            capture._iface("nosuchiface0")
        self.assertIn("есть:", str(ctx.exception))

    def test_bad_name_is_refused(self):
        for bad in ("../../etc", "eth0;id", "a" * 20):
            with self.subTest(iface=bad):
                with self.assertRaises(capture.CaptureError):
                    capture._iface(bad)

    def test_real_iface_passes(self):
        known = capture.interfaces()
        if not known:
            self.skipTest("на машине не видно ни одного интерфейса")
        self.assertEqual(capture._iface(known[0]), known[0])


class TestLimits(unittest.TestCase):
    """Настройка может потолок опустить, но не поднять."""

    def patch(self, **values):
        import core.mcp.auth as auth

        saved = auth.settings
        self.addCleanup(setattr, auth, "settings", saved)
        auth.settings = lambda: {"capture": values}

    def test_defaults(self):
        self.patch()
        caps = capture.limits()
        self.assertEqual(caps["max_packets"], 200)
        self.assertEqual(caps["max_seconds"], 30)

    def test_settings_cannot_raise_the_hard_ceiling(self):
        self.patch(max_packets=999999, max_seconds=99999, snaplen=999999)
        caps = capture.limits()
        self.assertEqual(caps["max_packets"], capture.HARD_MAX_PACKETS)
        self.assertEqual(caps["max_seconds"], capture.HARD_MAX_SECONDS)
        self.assertEqual(caps["snaplen"], capture.HARD_MAX_SNAPLEN)

    def test_settings_can_lower_it(self):
        self.patch(max_packets=10, max_seconds=5)
        caps = capture.limits()
        self.assertEqual(caps["max_packets"], 10)
        self.assertEqual(caps["max_seconds"], 5)

    def test_garbage_falls_back_to_defaults(self):
        self.patch(max_packets="много", max_seconds=-1, snaplen=0)
        caps = capture.limits()
        self.assertEqual(caps["max_packets"], 200)
        self.assertEqual(caps["max_seconds"], 30)
        self.assertEqual(caps["snaplen"], 256)


class TestTools(unittest.TestCase):

    def setUp(self):
        registry.load_tools()
        capture.reset()
        self.addCleanup(capture.reset)

    def data(self, name, args=None, perms=None):
        return registry.call(name, args or {},
                             PROBES if perms is None else perms
                             )["structuredContent"]

    def test_capture_needs_the_probes_permission(self):
        for name in ("traffic_capture_start", "traffic_capture_status",
                     "traffic_capture_result", "traffic_capture_stop"):
            with self.subTest(tool=name):
                answer = registry.call(name, {}, {})
                self.assertTrue(answer["isError"])
                self.assertEqual(
                    answer["structuredContent"]["permission"], "probes")

    def test_missing_tcpdump_is_an_answer(self):
        saved = capture.binary
        self.addCleanup(setattr, capture, "binary", saved)
        capture.binary = lambda: ""
        payload = self.data("traffic_capture_start", {"host": "1.2.3.4"})
        # `ok: true` + `available: false`: «этого на устройстве нет» —
        # не ошибка вызова, и в ответе сказано, чем это ставится.
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["available"])
        self.assertIn("package_install", payload["hint"])

    def test_nothing_captured_yet(self):
        payload = self.data("traffic_capture_result", {})
        self.assertTrue(payload["ok"])
        self.assertIn("traffic_capture_start", payload["hint"])

    def test_unknown_run_id_lists_what_there_is(self):
        payload = self.data("traffic_capture_status", {"run_id": "nope"})
        self.assertFalse(payload["ok"])
        self.assertIn("known_run_ids", payload)

    def test_bad_arguments_show_the_interfaces_and_limits(self):
        saved = capture.binary
        self.addCleanup(setattr, capture, "binary", saved)
        capture.binary = lambda: "/bin/true"
        payload = self.data("traffic_capture_start",
                            {"host": "example.com"})
        self.assertFalse(payload["ok"])
        self.assertIn("interfaces", payload)
        self.assertIn("limits", payload)


class TestRunEndToEnd(unittest.TestCase):
    """Весь путь: запуск → файл → разбор → уборка, с подставным tcpdump.

    Настоящий tcpdump не нужен: проверяется НАШЕ — что аргументы дошли,
    что pcap разобран в поля и что файл после разбора не остался на
    диске (на роутере с /tmp в RAM это не мелочь).
    """

    def setUp(self):
        import stat

        capture.reset()
        self.addCleanup(capture.reset)
        self.dir = tempfile.mkdtemp(prefix="capture-e2e-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

        # Подставной «tcpdump»: кладёт готовый pcap туда, куда просят
        # ключом -w, и выходит. Сам дамп собирается тем же кодом, что в
        # tests/test_pcap_reader.py.
        from tests.test_pcap_reader import ethernet, ipv4, pcap, tcp,             tls_client_hello

        dump = pcap([ethernet(ipv4(tcp(tls_client_hello(b"example.org")))),
                     ethernet(ipv4(tcp(b""), ttl=3))])
        self.dump_path = os.path.join(self.dir, "sample.pcap")
        with open(self.dump_path, "wb") as f:
            f.write(dump)

        self.argv_log = os.path.join(self.dir, "argv.txt")
        self.fake = os.path.join(self.dir, "tcpdump")
        with open(self.fake, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\n"
                    "echo \"$@\" > %s\n"
                    "while [ $# -gt 0 ]; do\n"
                    "  if [ \"$1\" = '-w' ]; then cp %s \"$2\"; fi\n"
                    "  shift\n"
                    "done\n"
                    "exit 0\n" % (self.argv_log, self.dump_path))
        os.chmod(self.fake, os.stat(self.fake).st_mode | stat.S_IEXEC)

        saved = capture.binary
        self.addCleanup(setattr, capture, "binary", saved)
        capture.binary = lambda: self.fake

    def wait(self, run, limit=10.0):
        deadline = time.time() + limit
        while run.running and time.time() < deadline:
            time.sleep(0.05)
        return run

    def test_full_run(self):
        iface = capture.interfaces()[0]
        state = capture.start(iface=iface, host="1.2.3.4", port=443,
                              proto="tcp", packets=10, seconds=5)
        run = self.wait(capture.get(state["run_id"]))

        self.assertFalse(run.running)
        self.assertEqual(run.error, "")

        packets = capture.packets(run)
        self.assertEqual(len(packets), 2)
        self.assertEqual(packets[0]["sni"], "example.org")

        summary = capture.summary(run)
        self.assertEqual(summary["sni"], ["example.org"])
        # Разные TTL в одном потоке — признак того, что fake-пакеты
        # десинка действительно уходят.
        self.assertEqual(sorted(summary["ttl"]), ["3", "64"])

        with open(self.argv_log, encoding="utf-8") as f:
            argv = f.read()
        self.assertIn("-i %s" % iface, argv)
        self.assertIn("tcp and host 1.2.3.4 and port 443", argv)
        self.assertIn("-c 10", argv)

    def test_file_is_removed_after_parsing(self):
        state = capture.start(iface=capture.interfaces()[0])
        self.wait(capture.get(state["run_id"]))
        leftovers = [n for n in os.listdir(tempfile.gettempdir())
                     if n.startswith("zapret-capture-")]
        self.assertEqual(leftovers, [])

    def test_second_run_is_refused_while_the_first_one_lives(self):
        run = capture._Run("capture-busy", {}, ["x"])
        capture._runs.append(run)
        self.addCleanup(capture.reset)
        with self.assertRaises(capture.CaptureError) as ctx:
            capture.start(iface=capture.interfaces()[0])
        self.assertIn("уже идёт", str(ctx.exception))

    def test_result_tool_reads_the_run(self):
        registry.load_tools()
        state = capture.start(iface=capture.interfaces()[0])
        self.wait(capture.get(state["run_id"]))
        payload = registry.call("traffic_capture_result", {},
                                PROBES)["structuredContent"]
        self.assertEqual(payload["count"], 2)
        self.assertIn("SNI", payload["hint"])


class TestSummary(unittest.TestCase):
    """Сводка — то, ради чего снифер и читают."""

    def make(self, packets):
        run = capture._Run("capture-test", {}, ["tcpdump"])
        run.report = {"packets": packets, "total": len(packets)}
        run.running = False
        return run

    def test_counts_ttl_names_and_flags(self):
        run = self.make([
            {"ttl": 64, "flags": ["SYN"], "l7": "tls", "sni": "a.com"},
            {"ttl": 3, "flags": ["PSH", "ACK"], "l7": "tls", "sni": "a.com"},
            {"ttl": 64, "flags": ["RST"], "proto": "tcp"},
        ])
        summary = capture.summary(run)
        self.assertEqual(summary["packets"], 3)
        self.assertEqual(summary["sni"], ["a.com"])
        self.assertEqual(summary["ttl"], {"64": 2, "3": 1})
        self.assertEqual(summary["flags"]["RST"], 1)

    def test_hint_names_the_three_things_that_matter(self):
        from core.mcp.tools import traffic

        run = self.make([
            {"ttl": 64, "flags": ["PSH"], "l7": "tls", "sni": "a.com"},
            {"ttl": 3, "flags": ["RST"], "l7": "tls"},
        ])
        hint = traffic._capture_hint(run, capture.summary(run))
        self.assertIn("SNI", hint)
        self.assertIn("TTL", hint)
        self.assertIn("RST", hint)

    def test_empty_capture_says_what_to_check(self):
        from core.mcp.tools import traffic

        run = self.make([])
        hint = traffic._capture_hint(run, capture.summary(run))
        self.assertIn("интерфейс", hint)


if __name__ == "__main__":
    unittest.main()
