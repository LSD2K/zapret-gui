# tests/test_dnsmasq_ujail.py
"""
OpenWrt: dnsmasq в ujail и наш managed-файл (issue #332).

procd запускает dnsmasq в джейле и прокидывает внутрь только явный
список путей (`procd_add_jail_mount`). /etc/dnsmasq.conf там есть,
/etc/dnsmasq.d — нет. Значит `conf-file=/etc/dnsmasq.d/zapret-gui-awg-
routing.conf` указывает для dnsmasq в никуда: он не стартует и уносит
с собой DHCP и DNS роутера. Путь надо добавлять в UCI-список
`dhcp.<section>.addnmount` — и так же убирать за собой.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest import mock

from core.routing import dnsmasq_integration as di


class FakeUci:
    """Минимальная модель `uci` для dhcp: одна секция + список addnmount."""

    def __init__(self, sections=("cfg01411c",), fail_on=""):
        self.sections = list(sections)
        self.lists = {s: [] for s in self.sections}
        self.staged = None
        self.commits = 0
        self.fail_on = fail_on

    def __call__(self, args, timeout=5):
        if not args or os.path.basename(args[0]) != "uci":
            raise AssertionError("неожиданный вызов: %r" % (args,))
        cmd = args[1]
        if cmd == self.fail_on:
            return 1, "", "uci: boom"
        if cmd == "show":
            out = "".join("dhcp.%s=dnsmasq\n" % s for s in self.sections)
            out += "dhcp.lan=dhcp\ndhcp.@dnsmasq[0].domainneeded='1'\n"
            return 0, out, ""
        if cmd == "get":
            sec = args[2].split(".")[1]
            vals = self._view().get(sec, [])
            return (0, " ".join(vals) + "\n", "") if vals else (1, "", "not found")
        if cmd in ("add_list", "del_list"):
            spec = args[2]
            path = spec.partition("=")[2]
            sec = spec.split(".")[1]
            view = self._view()
            if cmd == "add_list":
                view[sec] = view.get(sec, []) + [path]
            else:
                view[sec] = [v for v in view.get(sec, []) if v != path]
            self.staged = view
            return 0, "", ""
        if cmd == "commit":
            if self.staged is not None:
                self.lists = self.staged
                self.staged = None
            self.commits += 1
            return 0, "", ""
        if cmd == "revert":
            self.staged = None
            return 0, "", ""
        raise AssertionError("неизвестная команда uci: %r" % (args,))

    def _view(self):
        if self.staged is None:
            return {k: list(v) for k, v in self.lists.items()}
        return self.staged


class UjailCase(unittest.TestCase):

    def setUp(self):
        self.dn = di.DnsmasqIntegration()
        self.tmp = tempfile.mkdtemp()
        self.main_conf = os.path.join(self.tmp, "dnsmasq.conf")
        self.managed = os.path.join(self.tmp, di.MANAGED_FILENAME)
        with open(self.main_conf, "w") as f:
            f.write("port=53\n")
        self.uci = FakeUci()

    def _patched(self, jailed=True, uci=None):
        """Контекст, где dnsmasq «живёт» в ujail на OpenWrt."""
        return [
            mock.patch.object(self.dn, "find_main_config",
                              return_value=self.main_conf),
            mock.patch.object(self.dn, "managed_file_path",
                              return_value=self.managed),
            mock.patch.object(self.dn, "uses_procd_jail",
                              return_value=jailed),
            mock.patch.object(di, "_which", lambda name: "/sbin/uci"
                              if name == "uci" else ""),
            mock.patch.object(di, "_run", uci or self.uci),
        ]

    def _run_in(self, fn, **kw):
        patches = self._patched(**kw)
        for p in patches:
            p.start()
        try:
            return fn()
        finally:
            for p in reversed(patches):
                p.stop()


class TestEnsureJailMount(UjailCase):

    def test_path_is_added_and_committed(self):
        res = self._run_in(lambda: self.dn.ensure_jail_mount(self.managed))
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["changed"])
        self.assertEqual(self.uci.lists["cfg01411c"], [self.managed])
        self.assertEqual(self.uci.commits, 1)

    def test_is_idempotent(self):
        self.uci.lists["cfg01411c"] = [self.managed]
        res = self._run_in(lambda: self.dn.ensure_jail_mount(self.managed))
        self.assertTrue(res["ok"], res)
        self.assertFalse(res["changed"])
        self.assertEqual(self.uci.commits, 0)

    def test_noop_when_not_jailed(self):
        res = self._run_in(lambda: self.dn.ensure_jail_mount(self.managed),
                           jailed=False)
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["skipped"])
        self.assertEqual(self.uci.commits, 0)

    def test_foreign_mounts_are_kept(self):
        self.uci.lists["cfg01411c"] = ["/etc/other.conf"]
        self._run_in(lambda: self.dn.ensure_jail_mount(self.managed))
        self.assertEqual(self.uci.lists["cfg01411c"],
                         ["/etc/other.conf", self.managed])


class TestRemoveJailMount(UjailCase):

    def test_only_our_path_is_removed(self):
        self.uci.lists["cfg01411c"] = ["/etc/other.conf", self.managed]
        res = self._run_in(lambda: self.dn.remove_jail_mount(self.managed))
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["changed"])
        self.assertEqual(self.uci.lists["cfg01411c"], ["/etc/other.conf"])

    def test_idempotent_when_absent(self):
        res = self._run_in(lambda: self.dn.remove_jail_mount(self.managed))
        self.assertTrue(res["ok"], res)
        self.assertFalse(res["changed"])
        self.assertEqual(self.uci.commits, 0)


class TestIncludeOrdering(UjailCase):
    """include в dnsmasq.conf нельзя добавлять раньше ujail-mount'а."""

    def test_include_is_added_after_successful_mount(self):
        res = self._run_in(self.dn.ensure_include)
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["added"])
        with open(self.main_conf) as f:
            self.assertIn("conf-file=%s" % self.managed, f.read())
        self.assertEqual(self.uci.lists["cfg01411c"], [self.managed])

    def test_include_is_NOT_added_when_mount_fails(self):
        broken = FakeUci(fail_on="add_list")
        res = self._run_in(self.dn.ensure_include, uci=broken)
        self.assertFalse(res["ok"], res)
        with open(self.main_conf) as f:
            text = f.read()
        # Главное: dnsmasq.conf не получил ссылку на файл, который
        # dnsmasq из джейла прочитать не сможет.
        self.assertNotIn("conf-file=", text)
        self.assertNotIn(di.INCLUDE_MARKER, text)

    def test_remove_include_also_drops_the_mount(self):
        self._run_in(self.dn.ensure_include)
        res = self._run_in(self.dn.remove_include)
        self.assertTrue(res["ok"], res)
        self.assertTrue(res["removed_jail_mount"])
        self.assertEqual(self.uci.lists["cfg01411c"], [])
        self.assertFalse(os.path.exists(self.managed))
        with open(self.main_conf) as f:
            self.assertNotIn("conf-file=", f.read())


class TestUsesProcdJail(unittest.TestCase):

    def test_detects_openwrt_init_script(self):
        dn = di.DnsmasqIntegration()
        init = "#!/bin/sh /etc/rc.common\nprocd_add_jail dnsmasq ubus log\n"
        with mock.patch.object(di.os.path, "isfile",
                               lambda p: p in ("/etc/init.d/dnsmasq",
                                               "/etc/config/dhcp")), \
             mock.patch.object(di, "_which", lambda n: "/sbin/uci"), \
             mock.patch.object(di, "_read_file", lambda p: init):
            self.assertTrue(dn.uses_procd_jail())

    def test_false_without_uci(self):
        dn = di.DnsmasqIntegration()
        with mock.patch.object(di.os.path, "isfile", lambda p: True), \
             mock.patch.object(di, "_which", lambda n: ""):
            self.assertFalse(dn.uses_procd_jail())


class TestManagedFileChangeDetection(unittest.TestCase):
    """restart dnsmasq нужен только когда конфиг реально изменился."""

    def _write(self, dn, managed, domains):
        with mock.patch.object(dn, "find_main_config", return_value=""), \
             mock.patch.object(dn, "managed_file_path", return_value=managed):
            return dn.write_managed_file([{
                "rule_id": "r1", "set_kind": "ipset",
                "set_name": "awgr_r1", "domains": domains,
            }])

    def test_first_write_is_a_change(self):
        dn = di.DnsmasqIntegration()
        managed = os.path.join(tempfile.mkdtemp(), "managed.conf")
        self.assertTrue(self._write(dn, managed, ["a.com"])["changed"])

    def test_same_content_is_not_a_change(self):
        dn = di.DnsmasqIntegration()
        managed = os.path.join(tempfile.mkdtemp(), "managed.conf")
        self._write(dn, managed, ["a.com"])
        # Таймстамп «Generated at» меняется всегда — он не в счёт.
        self.assertFalse(self._write(dn, managed, ["a.com"])["changed"])

    def test_new_domain_is_a_change(self):
        dn = di.DnsmasqIntegration()
        managed = os.path.join(tempfile.mkdtemp(), "managed.conf")
        self._write(dn, managed, ["a.com"])
        self.assertTrue(self._write(dn, managed, ["a.com", "b.com"])["changed"])


class TestRestart(unittest.TestCase):
    """restart() — единственный способ применить конфиг (SIGHUP не годится)."""

    def test_uses_init_script_when_running(self):
        dn = di.DnsmasqIntegration()
        calls = []

        def fake_run(args, timeout=5):
            calls.append(args)
            return 0, "", ""

        with mock.patch.object(dn, "get_pid", return_value=1234), \
             mock.patch.object(dn, "_has_dnsmasq_service", return_value=False), \
             mock.patch.object(dn, "_find_init_script",
                               return_value="/etc/init.d/dnsmasq"), \
             mock.patch.object(di, "_run", fake_run), \
             mock.patch.object(di.time, "sleep", lambda _s: None):
            res = dn.restart()

        self.assertTrue(res["ok"], res)
        self.assertEqual(res["how"], "/etc/init.d/dnsmasq")
        self.assertIn(["/etc/init.d/dnsmasq", "restart"], calls)

    def test_does_not_start_a_stopped_dnsmasq(self):
        """Снятие последнего правила не должно поднимать чужой сервис."""
        dn = di.DnsmasqIntegration()
        init = mock.Mock(return_value="/etc/init.d/dnsmasq")
        with mock.patch.object(dn, "get_pid", return_value=0), \
             mock.patch.object(dn, "_find_init_script", init), \
             mock.patch.object(di, "_run", lambda a, timeout=5: (1, "", "no")):
            res = dn.restart()
        self.assertFalse(res["ok"], res)
        init.assert_not_called()

    def test_falls_back_to_sighup_without_any_service(self):
        dn = di.DnsmasqIntegration()
        sent = []
        with mock.patch.object(dn, "get_pid", return_value=4321), \
             mock.patch.object(dn, "_has_dnsmasq_service", return_value=False), \
             mock.patch.object(dn, "_find_init_script", return_value=""), \
             mock.patch.object(di.os, "kill",
                               lambda pid, sig: sent.append((pid, sig))):
            res = dn.restart()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["how"], "SIGHUP")
        self.assertTrue(res["degraded"])
        self.assertEqual(sent, [(4321, di.signal.SIGHUP)])


if __name__ == "__main__":
    unittest.main()
