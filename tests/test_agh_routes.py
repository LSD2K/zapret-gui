# tests/test_agh_routes.py
"""
Маршруты через AdGuard Home (core/agh_routes.py, api/agh_routes.py).

AdGuard Home и sing-box подменяются фейками: HTTP — через единственную
обёртку `_http_request`, sing-box — через `get_singbox_manager`.
Настройки живут во временном settings.json.
"""

import copy
import json
import os
import shutil
import tempfile
import unittest
import urllib.error
from unittest import mock

from core import agh_routes
from core import config_manager as cm_mod
from core.config_manager import ConfigManager
from tests._wsgi_client import WSGIClient, build_test_app


TARGET = "127.0.0.1:1053"


# ─────────────────────── фейки ───────────────────────────────────────

class FakeAGH:
    """Минимальный AdGuard Home: dns_info, clients, запись вызовов."""

    def __init__(self, upstreams=None, clients=None):
        self.info = {
            "upstream_dns": list(upstreams or
                                 ["https://dns.cloudflare.com/dns-query"]),
            "upstream_dns_file": "",
            "bootstrap_dns": ["1.1.1.1"],
            "protection_enabled": True,
            "ratelimit": 20,
            "blocking_mode": "default",
            "upstream_mode": "load_balance",
            "cache_size": 4194304,
            "default_local_ptr_upstreams": ["192.168.1.1"],
        }
        self.clients = copy.deepcopy(clients or [])
        self.posts = []
        self.fail = None          # AghError, которую бросать на любой вызов
        self.auth = []

    def __call__(self, method, url, *, body=None, user="", password="",
                 timeout=10):
        self.auth.append((user, password))
        if self.fail:
            raise self.fail
        path = url.split("://", 1)[1].split("/", 1)[1]
        path = "/" + path
        if method == "GET" and path == "/control/status":
            return 200, {"version": "v0.107.52", "running": True,
                         "protection_enabled": True, "dns_port": 53}
        if method == "GET" and path == "/control/dns_info":
            return 200, copy.deepcopy(self.info)
        if method == "GET" and path == "/control/clients":
            return 200, {"clients": copy.deepcopy(self.clients) or None,
                         "auto_clients": [], "supported_tags": []}
        if method == "POST":
            self.posts.append((path, copy.deepcopy(body)))
            if path == "/control/dns_config":
                for k, v in body.items():
                    self.info[k] = copy.deepcopy(v)
                return 200, {}
            if path == "/control/clients/add":
                self.clients.append(copy.deepcopy(body))
                return 200, {}
            if path == "/control/clients/update":
                for i, c in enumerate(self.clients):
                    if c["name"] == body["name"]:
                        self.clients[i] = copy.deepcopy(body["data"])
                return 200, {}
        raise AssertionError("неожиданный вызов %s %s" % (method, path))

    def client(self, name):
        return next(c for c in self.clients if c["name"] == name)


def b2_config(extra_rules=None):
    """Конфиг в духе B2 (external front DNS)."""
    return {
        "log": {"level": "info"},
        "inbounds": [
            {"type": "direct", "tag": "dns-in", "listen": "127.0.0.1",
             "listen_port": 1053, "network": "udp"},
            {"type": "tun", "tag": "tun-in",
             "interface_name": "singbox-tun",
             "address": ["172.19.0.1/30"]},
        ],
        "outbounds": [
            {"type": "mieru", "tag": "mieruNeth", "server": "192.0.2.10"},
            {"type": "mieru", "tag": "Finland", "server": "192.0.2.20"},
            {"type": "selector", "tag": "proxy-out",
             "outbounds": ["mieruNeth", "Finland"]},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
            ] + list(extra_rules or []) + [
                {"inbound": ["tun-in"], "outbound": "proxy-out"},
            ],
            "final": "direct",
        },
    }


class FakeSingbox:
    """Фейк SingboxManager: конфиги в памяти."""

    def __init__(self, configs=None, running=()):
        self.configs = {k: json.dumps(v, indent=2)
                        for k, v in (configs or {}).items()}
        self.running = set(running)
        self.saves = []
        self.restarts = []
        self.check_ok = True
        self.restart_fail = False

    def get_config(self, name):
        if name not in self.configs:
            return {"ok": False, "error": "Конфиг не найден"}
        text = self.configs[name]
        return {"ok": True, "name": name, "text": text,
                "parsed": json.loads(text), "errors": []}

    def parsed(self, name):
        return json.loads(self.configs[name])

    def save_config(self, name, *, text="", parsed=None):
        if parsed is not None and not text:
            text = json.dumps(parsed)
        json.loads(text)
        self.configs[name] = text
        self.saves.append(name)
        return {"ok": True, "name": name}

    def check_text(self, text):
        return {"ok": self.check_ok, "error": "" if self.check_ok
                else "unknown field", "returncode": 0}

    def is_running(self, name):
        return name in self.running

    def restart(self, name):
        self.restarts.append(name)
        if self.restart_fail:
            self.restart_fail = False      # откат поднимается
            return {"ok": False, "error": "bind: address in use"}
        return {"ok": True}


class _Base(unittest.TestCase):
    """Временный settings.json, фейки AdGuard и sing-box."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.lists_dir = os.path.join(self.tmp, "lists")
        os.makedirs(self.lists_dir)
        cm = ConfigManager(config_dir=self.tmp)
        cm.load()
        cm.set("zapret", "lists_path", self.lists_dir)
        cm.save()
        self.cm = cm
        p = mock.patch.object(cm_mod, "_config_manager", cm)
        p.start()
        self.addCleanup(p.stop)

        self.agh = FakeAGH()
        p = mock.patch.object(agh_routes, "_http_request", self.agh)
        p.start()
        self.addCleanup(p.stop)

        self.sb = FakeSingbox({"gw": b2_config()}, running=("gw",))
        p = mock.patch("core.singbox_manager.get_singbox_manager",
                       return_value=self.sb)
        p.start()
        self.addCleanup(p.stop)

        self.geosite = {"openai": ["openai.com", "chatgpt.com",
                                   "oaistatic.com"]}

        def fake_expand(items, force_refresh=False):
            out = {"domains": [], "cidrs": [], "aliases_resolved": [],
                   "aliases_failed": []}
            for it in items:
                kind, name = it.split(":", 1)
                if name in self.geosite:
                    out["domains"] += self.geosite[name]
                else:
                    out["aliases_failed"].append({"kind": kind,
                                                  "name": name})
            return out
        p = mock.patch("core.routing.alias_resolver.expand_domains",
                       side_effect=fake_expand)
        p.start()
        self.addCleanup(p.stop)

    def settings(self, **kw):
        base = {"enabled": True, "agh_url": "http://127.0.0.1:3000",
                "agh_user": "admin", "agh_password": "pw",
                "dns_target": TARGET, "singbox_config": "gw",
                "clients": [],
                "rules": [
                    {"id": "ai", "name": "AI", "enabled": True,
                     "outbound": "mieruNeth",
                     "lists": ["geosite:openai"],
                     "domains": ["claude.ai", "anthropic.com"]},
                    {"id": "fi", "name": "Finland", "enabled": True,
                     "outbound": "Finland", "lists": [],
                     "domains": ["example.org"]},
                ]}
        base.update(kw)
        agh_routes.update_settings(base)

    def write_hostlist(self, name, lines):
        with open(os.path.join(self.lists_dir, name + ".txt"), "w") as f:
            f.write("\n".join(lines) + "\n")

    def our_rules(self, name="gw"):
        return [r for r in self.sb.parsed(name)["route"]["rules"]
                if "domain_suffix" in r]


# ─────────────────────── чистые функции ──────────────────────────────

class TestRenderLines(unittest.TestCase):

    def test_format_and_chunks(self):
        doms = ["d%03d.com" % i for i in range(85)]
        lines = agh_routes.render_agh_lines(list(reversed(doms)), TARGET)
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0].startswith("[/d000.com/d001.com/"))
        self.assertTrue(all(x.endswith("/]" + TARGET) for x in lines))
        counts = [len(agh_routes.line_domains(x)) for x in lines]
        self.assertEqual(counts, [40, 40, 5])

    def test_dedup_and_empty(self):
        self.assertEqual(agh_routes.render_agh_lines([], TARGET), [])
        self.assertEqual(
            agh_routes.render_agh_lines(["b.org", "a.com", "b.org"],
                                        TARGET),
            ["[/a.com/b.org/]127.0.0.1:1053"])

    def test_managed_detection(self):
        t = [TARGET]
        self.assertTrue(agh_routes.is_managed_line(
            "[/a.com/]127.0.0.1:1053", t))
        self.assertFalse(agh_routes.is_managed_line(
            "[/a.com/]127.0.0.1:1054", t))
        self.assertFalse(agh_routes.is_managed_line(
            "https://dns.cloudflare.com/dns-query", t))

    def test_replace_keeps_foreign_lines_in_place(self):
        t = [TARGET]
        lines = ["https://1.1.1.1/dns-query",
                 "[/old.com/]127.0.0.1:1053",
                 "[/corp.lan/]10.0.0.1",
                 "[/old2.com/]127.0.0.1:1053"]
        out = agh_routes.replace_managed(lines, ["[/new.com/]127.0.0.1:1053"],
                                         t)
        self.assertEqual(out, ["https://1.1.1.1/dns-query",
                               "[/new.com/]127.0.0.1:1053",
                               "[/corp.lan/]10.0.0.1"])
        # Наших не было — новые в конец.
        out = agh_routes.replace_managed(["x"], ["[/n/]" + TARGET], t)
        self.assertEqual(out, ["x", "[/n/]" + TARGET])


class TestNormalize(unittest.TestCase):

    def test_normalize(self):
        got = agh_routes.normalize_domains([
            "*.Example.COM", "https://www.site.org/path", "1.2.3.4",
            "localhost", "^foo.net", "bar.io # коммент", ".lead.dev",
            "президент.рф", "bad domain", "-x.com", "", "example.com",
        ])
        self.assertEqual(got, ["example.com", "site.org", "foo.net",
                               "bar.io", "lead.dev", "xn--d1abbgf6aiiy.xn--p1ai",
                               "bad"])


class TestMergeSingboxRules(unittest.TestCase):

    R1 = {"domain_suffix": ["a.com"], "outbound": "mieruNeth"}
    R2 = {"domain_suffix": ["b.org"], "outbound": "Finland"}

    def test_after_hijack_before_tun(self):
        user = {"domain_suffix": ["user.net"], "outbound": "direct"}
        cfg = b2_config([user])
        agh_routes.merge_singbox_rules(cfg, [], [self.R1, self.R2])
        rules = cfg["route"]["rules"]
        self.assertEqual(rules[1]["action"], "hijack-dns")
        self.assertEqual(rules[2:4], [self.R1, self.R2])
        self.assertEqual(rules[4], user)
        self.assertEqual(rules[5]["inbound"], ["tun-in"])

    def test_old_rules_removed_exactly(self):
        cfg = b2_config([self.R1, self.R2])
        near = {"domain_suffix": ["a.com"], "outbound": "Finland"}
        cfg["route"]["rules"].insert(2, near)
        agh_routes.merge_singbox_rules(cfg, [self.R1, self.R2], [])
        rules = cfg["route"]["rules"]
        self.assertNotIn(self.R1, rules)
        self.assertNotIn(self.R2, rules)
        self.assertIn(near, rules)       # похожее, но чужое — остаётся

    def test_after_sniff_or_front(self):
        cfg = {"route": {"rules": [{"action": "sniff"},
                                   {"inbound": "tun-in",
                                    "outbound": "proxy-out"}]}}
        agh_routes.merge_singbox_rules(cfg, [], [self.R1])
        self.assertEqual(cfg["route"]["rules"][1], self.R1)
        cfg = {"route": {"rules": [{"ip_is_private": True,
                                    "outbound": "direct"}]}}
        agh_routes.merge_singbox_rules(cfg, [], [self.R1])
        self.assertEqual(cfg["route"]["rules"][0], self.R1)
        cfg = {}
        agh_routes.merge_singbox_rules(cfg, [], [])
        self.assertEqual(cfg, {})

    def test_never_after_tun_in(self):
        cfg = {"route": {"rules": [{"inbound": ["tun-in"],
                                    "outbound": "proxy-out"},
                                   {"action": "sniff"},
                                   {"action": "hijack-dns",
                                    "protocol": "dns"}]}}
        agh_routes.merge_singbox_rules(cfg, [], [self.R1])
        self.assertEqual(cfg["route"]["rules"][0], self.R1)


# ─────────────────────── сбор доменов ────────────────────────────────

class TestCollect(_Base):

    def test_sources(self):
        self.write_hostlist("claude", ["# комментарий", "claude.ai",
                                       "*.anthropic.com", "CLAUDE.AI"])
        from core import named_lists
        lst = named_lists.create("ai-extra",
                                 entries="perplexity.ai 10.0.0.0/8")["list"]
        rule = {"name": "AI", "lists": ["hl:claude", "geosite:openai",
                                        lst["id"], "ipl:ipset-base"],
                "domains": ["www.poe.com", "openai.com"]}
        got = agh_routes.collect(rule)
        self.assertEqual(got, sorted(["claude.ai", "anthropic.com",
                                      "openai.com", "chatgpt.com",
                                      "oaistatic.com", "perplexity.ai",
                                      "poe.com"]))
        _doms, warns = agh_routes._collect_detail(rule)
        self.assertTrue(any("ipl:ipset-base" in w for w in warns))

    def test_missing_sources_warn(self):
        rule = {"name": "X", "lists": ["geosite:nope", "list-missing",
                                       "hl:absent"], "domains": []}
        doms, warns = agh_routes._collect_detail(rule)
        self.assertEqual(doms, [])
        self.assertEqual(len(warns), 3)


# ─────────────────────── план и применение: глобально ───────────────

class TestApplyGlobal(_Base):

    def test_plan_does_not_write(self):
        self.settings()
        p = agh_routes.plan()
        self.assertEqual(p["errors"], [])
        self.assertTrue(p["changed"])
        self.assertEqual(p["agh"]["mode"], "global")
        self.assertEqual(p["domains_total"], 6)
        self.assertEqual(len(p["agh"]["add"]), 1)
        self.assertEqual(p["agh"]["domains_add"],
                         sorted(["anthropic.com", "chatgpt.com", "claude.ai",
                                 "example.org", "oaistatic.com",
                                 "openai.com"]))
        self.assertEqual(len(p["singbox"]["rules_desired"]), 2)
        self.assertEqual(self.agh.posts, [])
        self.assertEqual(self.sb.saves, [])
        # Basic-авторизация из настроек.
        self.assertIn(("admin", "pw"), self.agh.auth)

    def test_apply_writes_both_sides(self):
        self.settings()
        r = agh_routes.apply()
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["changed"])

        rules = self.sb.parsed("gw")["route"]["rules"]
        self.assertEqual(rules[1]["action"], "hijack-dns")
        self.assertEqual(rules[2], {"domain_suffix": [
            "anthropic.com", "chatgpt.com", "claude.ai", "oaistatic.com",
            "openai.com"], "outbound": "mieruNeth"})
        self.assertEqual(rules[3], {"domain_suffix": ["example.org"],
                                    "outbound": "Finland"})
        self.assertEqual(rules[4]["inbound"], ["tun-in"])
        self.assertEqual(self.sb.restarts, ["gw"])

        path, body = self.agh.posts[-1]
        self.assertEqual(path, "/control/dns_config")
        # Полное тело из dns_info, без read-only поля.
        self.assertEqual(body["bootstrap_dns"], ["1.1.1.1"])
        self.assertEqual(body["ratelimit"], 20)
        self.assertNotIn("default_local_ptr_upstreams", body)
        self.assertEqual(body["upstream_dns"], [
            "https://dns.cloudflare.com/dns-query",
            "[/anthropic.com/chatgpt.com/claude.ai/example.org/"
            "oaistatic.com/openai.com/]127.0.0.1:1053"])

        applied = agh_routes.get_settings()["_applied"]
        self.assertEqual(applied["singbox"]["config"], "gw")
        self.assertEqual(len(applied["singbox"]["rules"]), 2)

    def test_idempotent(self):
        self.settings()
        self.assertTrue(agh_routes.apply()["ok"])
        posts, saves = len(self.agh.posts), len(self.sb.saves)
        r = agh_routes.apply()
        self.assertTrue(r["ok"])
        self.assertFalse(r["changed"])
        self.assertEqual(len(self.agh.posts), posts)
        self.assertEqual(len(self.sb.saves), saves)
        self.assertEqual(self.sb.restarts, ["gw"])

    def test_only_managed_lines_replaced(self):
        self.agh.info["upstream_dns"] = [
            "https://dns.cloudflare.com/dns-query",
            "[/stale.com/]127.0.0.1:1053",
            "[/corp.lan/]10.0.0.1",
            "# комментарий",
        ]
        self.settings()
        self.assertTrue(agh_routes.apply()["ok"])
        up = self.agh.info["upstream_dns"]
        self.assertEqual(up[0], "https://dns.cloudflare.com/dns-query")
        self.assertIn("claude.ai", up[1])
        self.assertEqual(up[2:], ["[/corp.lan/]10.0.0.1", "# комментарий"])
        self.assertFalse(any("stale.com" in x for x in up))

    def test_rule_change_replaces_old_singbox_rules(self):
        self.settings()
        agh_routes.apply()
        rules = agh_routes.get_settings()["rules"]
        rules[1]["domains"] = ["example.net"]
        agh_routes.update_settings({"rules": rules})
        self.assertTrue(agh_routes.apply()["ok"])
        ours = self.our_rules()
        self.assertEqual(len(ours), 2)
        self.assertEqual(ours[1], {"domain_suffix": ["example.net"],
                                   "outbound": "Finland"})
        up = self.agh.info["upstream_dns"]
        self.assertFalse(any("example.org" in x for x in up))

    def test_first_rule_wins(self):
        self.settings(rules=[
            {"name": "A", "outbound": "mieruNeth",
             "domains": ["dup.com", "a.com"]},
            {"name": "B", "outbound": "Finland",
             "domains": ["dup.com", "b.com"]},
        ])
        p = agh_routes.plan()
        rd = p["singbox"]["rules_desired"]
        self.assertEqual(rd[0]["domain_suffix"], ["a.com", "dup.com"])
        self.assertEqual(rd[1]["domain_suffix"], ["b.com"])
        self.assertTrue(any("берётся первое" in w for w in p["warnings"]))

    def test_disabled_removes_everything(self):
        self.settings()
        agh_routes.apply()
        agh_routes.update_settings({"enabled": False})
        p = agh_routes.plan()
        self.assertTrue(p["changed"])
        self.assertTrue(agh_routes.apply()["ok"])
        self.assertEqual(self.our_rules(), [])
        self.assertEqual(self.agh.info["upstream_dns"],
                         ["https://dns.cloudflare.com/dns-query"])
        # После снятия — снова без изменений.
        self.assertFalse(agh_routes.apply()["changed"])

    def test_target_change_drops_old_lines(self):
        self.settings()
        agh_routes.apply()
        agh_routes.update_settings({"dns_target": "127.0.0.1:1153"})
        self.assertTrue(agh_routes.apply()["ok"])
        up = self.agh.info["upstream_dns"]
        self.assertFalse(any(x.endswith("]127.0.0.1:1053") for x in up))
        self.assertTrue(any(x.endswith("]127.0.0.1:1153") for x in up))

    def test_config_switch_cleans_previous(self):
        self.sb.configs["other"] = json.dumps(b2_config())
        self.settings()
        agh_routes.apply()
        agh_routes.update_settings({"singbox_config": "other"})
        self.assertTrue(agh_routes.apply()["ok"])
        self.assertEqual(self.our_rules("gw"), [])
        self.assertEqual(len(self.our_rules("other")), 2)


class TestApplyErrors(_Base):

    def test_agh_unreachable_blocks_apply(self):
        self.settings()
        self.agh.fail = agh_routes.AghError("нет связи с AdGuard Home")
        r = agh_routes.apply()
        self.assertFalse(r["ok"])
        self.assertTrue(any("нет связи" in e for e in r["errors"]))
        self.assertEqual(self.sb.saves, [])

    def test_unknown_outbound(self):
        self.settings(rules=[{"name": "X", "outbound": "nope",
                              "domains": ["x.com"]}])
        p = agh_routes.plan()
        self.assertTrue(any("nope" in e for e in p["errors"]))
        self.assertFalse(agh_routes.apply()["ok"])
        self.assertEqual(self.agh.posts, [])

    def test_no_config(self):
        self.settings(singbox_config="")
        self.assertIn("не выбран конфиг sing-box", agh_routes.plan()["errors"])

    def test_check_failure_leaves_agh_untouched(self):
        self.settings()
        self.sb.check_ok = False
        r = agh_routes.apply()
        self.assertFalse(r["ok"])
        self.assertEqual(self.sb.saves, [])
        self.assertEqual(self.agh.posts, [])

    def test_restart_failure_rolls_back(self):
        before = self.sb.configs["gw"]
        self.settings()
        self.sb.restart_fail = True
        r = agh_routes.apply()
        self.assertFalse(r["ok"])
        self.assertTrue(r["singbox"].get("rolled_back"))
        self.assertEqual(self.sb.configs["gw"], before)
        self.assertEqual(self.agh.posts, [])


# ─────────────────────── режим клиентов ──────────────────────────────

class TestClientsMode(_Base):

    def setUp(self):
        super().setUp()
        self.agh.clients = [
            {"name": "phone", "ids": ["10.10.10.6"],
             "use_global_settings": True, "filtering_enabled": True,
             "tags": ["device_phone"], "upstreams": []},
            {"name": "tv", "ids": ["10.10.10.7"],
             "use_global_settings": False, "filtering_enabled": True,
             "upstreams": ["tls://dns.example"]},
        ]

    def test_create_and_update(self):
        self.agh.info["upstream_dns"].append("[/stale.com/]127.0.0.1:1053")
        self.settings(clients=["10.10.10.5", "10.10.10.6", "10.10.10.7"])
        r = agh_routes.apply()
        self.assertTrue(r["ok"], r)
        lines = r["plan"]["agh"]["lines"]
        self.assertEqual(len(lines), 1)

        new = self.agh.client("zg-10.10.10.5")
        self.assertEqual(new["ids"], ["10.10.10.5"])
        self.assertEqual(new["upstreams"],
                         ["https://dns.cloudflare.com/dns-query"] + lines)
        # Флаг про фильтрацию: новый клиент остаётся на глобальных фильтрах.
        self.assertTrue(new["use_global_settings"])

        phone = self.agh.client("phone")
        self.assertEqual(phone["upstreams"],
                         ["https://dns.cloudflare.com/dns-query"] + lines)
        self.assertEqual(phone["tags"], ["device_phone"])   # не потерялось
        self.assertTrue(phone["filtering_enabled"])

        tv = self.agh.client("tv")
        self.assertEqual(tv["upstreams"], ["tls://dns.example"] + lines)
        self.assertFalse(tv["use_global_settings"])

        # Глобальные upstream'ы — без наших строк.
        self.assertEqual(self.agh.info["upstream_dns"],
                         ["https://dns.cloudflare.com/dns-query"])
        # Клиентам — до смены глобального списка.
        paths = [p for p, _ in self.agh.posts]
        self.assertLess(paths.index("/control/clients/add"),
                        paths.index("/control/dns_config"))

        self.assertFalse(agh_routes.apply()["changed"])

    def test_remove_when_clients_empty(self):
        self.settings(clients=["10.10.10.5", "10.10.10.6", "10.10.10.7"])
        agh_routes.apply()
        agh_routes.update_settings({"clients": []})
        p = agh_routes.plan()
        acts = {c["name"]: c["action"] for c in p["agh"]["clients"]}
        self.assertEqual(acts, {"zg-10.10.10.5": "remove",
                                "phone": "remove", "tv": "remove"})
        self.assertTrue(agh_routes.apply()["ok"])
        self.assertEqual(self.agh.client("zg-10.10.10.5")["upstreams"], [])
        self.assertEqual(self.agh.client("phone")["upstreams"], [])
        self.assertEqual(self.agh.client("tv")["upstreams"],
                         ["tls://dns.example"])
        # Режим снова глобальный: строки ушли в upstream_dns.
        self.assertTrue(any("claude.ai" in x
                            for x in self.agh.info["upstream_dns"]))
        paths = [p for p, _ in self.agh.posts[-4:]]
        self.assertEqual(paths[0], "/control/dns_config")

    def test_client_on_global_copy_is_global(self):
        # Записи о прошлом применении нет, а upstream'ы клиента равны
        # глобальным — это клиент «на глобальных»: снятие вернёт его к [].
        self.agh.client("phone")["upstreams"] = list(
            self.agh.info["upstream_dns"])
        self.settings(clients=["10.10.10.6"])
        agh_routes.apply()
        rec = agh_routes.get_settings()["_applied"]["agh"]["clients"]
        self.assertEqual(rec[0]["base"], "global")
        agh_routes.update_settings({"clients": []})
        agh_routes.apply()
        self.assertEqual(self.agh.client("phone")["upstreams"], [])

    def test_client_dropped_from_list(self):
        self.settings(clients=["10.10.10.6", "10.10.10.7"])
        agh_routes.apply()
        agh_routes.update_settings({"clients": ["10.10.10.6"]})
        self.assertTrue(agh_routes.apply()["ok"])
        self.assertEqual(self.agh.client("tv")["upstreams"],
                         ["tls://dns.example"])
        self.assertTrue(len(self.agh.client("phone")["upstreams"]) > 1)


# ─────────────────────── HTTP-обёртка ────────────────────────────────

class TestHttpWrapper(unittest.TestCase):

    def test_auth_header_and_errors(self):
        seen = {}

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def getcode(self):
                return 200

            def read(self):
                return b'{"version": "v0.107.52"}'

        class Opener:
            def open(self, req, timeout=None):
                seen["auth"] = req.get_header("Authorization")
                seen["timeout"] = timeout
                return Resp()

        with mock.patch("urllib.request.build_opener",
                        return_value=Opener()):
            code, data = agh_routes._http_request(
                "GET", "http://127.0.0.1:3000/control/status",
                user="admin", password="pw")
        self.assertEqual(data["version"], "v0.107.52")
        self.assertEqual(seen["auth"], "Basic YWRtaW46cHc=")
        self.assertEqual(seen["timeout"], agh_routes.HTTP_TIMEOUT)

        class Down:
            def open(self, req, timeout=None):
                raise urllib.error.URLError("connection refused")

        with mock.patch("urllib.request.build_opener", return_value=Down()):
            with self.assertRaises(agh_routes.AghError):
                agh_routes._http_request("GET", "http://127.0.0.1:1/x")


# ─────────────────────── API ─────────────────────────────────────────

class TestAPI(_Base):

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def test_password_masked_and_kept(self):
        r = self.client.put_json("/api/agh-routes", {
            "agh_user": "admin", "agh_password": "s3cret"})
        self.assertEqual(r["_status"], 200)
        self.assertEqual(r["settings"]["agh_password"], "***")
        g = self.client.get_json("/api/agh-routes")
        self.assertEqual(g["settings"]["agh_password"], "***")
        self.assertTrue(g["settings"]["has_password"])
        self.assertNotIn("_applied", g["settings"])
        # Пустой пароль и маска не меняют сохранённый.
        self.client.put_json("/api/agh-routes", {"agh_password": ""})
        self.client.put_json("/api/agh-routes", {"agh_password": "***"})
        self.assertEqual(agh_routes.get_settings()["agh_password"], "s3cret")

    def test_config_api_masks_password(self):
        agh_routes.update_settings({"agh_password": "s3cret"})
        r = self.client.get_json("/api/config")
        self.assertEqual(r["config"]["agh_routes"]["agh_password"], "***")
        self.client.put_json("/api/config",
                             {"agh_routes": {"agh_password": "***"}})
        self.assertEqual(agh_routes.get_settings()["agh_password"], "s3cret")
        st, body = self.client.post("/api/config/export", {})
        self.assertNotIn("s3cret", body.decode("utf-8"))

    def test_put_validation(self):
        r = self.client.put_json("/api/agh-routes",
                                 {"clients": ["10.10.10.5", "10.10.10.x"]})
        self.assertEqual(r["_status"], 400)
        self.assertIn("10.10.10.x", r["error"])
        r = self.client.put_json("/api/agh-routes", {"agh_url": "ftp://x"})
        self.assertEqual(r["_status"], 400)
        r = self.client.put_json("/api/agh-routes",
                                 {"clients": "10.10.10.5/32\n10.10.11.0/24"})
        self.assertEqual(r["settings"]["clients"],
                         ["10.10.10.5", "10.10.11.0/24"])

    def test_plan_apply_test_sources(self):
        self.settings()
        r = self.client.get_json("/api/agh-routes/plan")
        self.assertTrue(r["ok"])
        self.assertEqual(r["plan"]["errors"], [])
        for op in r["plan"]["agh"]["clients"]:
            self.assertNotIn("body", op)
        r = self.client.post_json("/api/agh-routes/apply", {})
        self.assertTrue(r["ok"], r)
        self.assertTrue(r["changed"])
        r = self.client.post_json("/api/agh-routes/test", {})
        self.assertTrue(r["ok"])
        self.assertEqual(r["version"], "v0.107.52")
        r = self.client.get_json("/api/agh-routes/sources?config=gw")
        tags = [o["tag"] for o in r["outbounds"]]
        self.assertIn("mieruNeth", tags)
        self.assertIn("proxy-out", tags)
        self.assertTrue(any(g["id"] == "geosite:openai"
                            for g in r["geosite"]))
        self.assertTrue(any(h["id"] == "hl:other" for h in r["hostlists"]))


if __name__ == "__main__":
    unittest.main()
