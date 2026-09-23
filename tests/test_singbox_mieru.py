# tests/test_singbox_mieru.py
"""
Unit-тесты outbound'а `mieru` (только sing-box-extended): билдер
make_mieru_outbound, разбор ссылок mierus:// / mieru:// и экспорт обратно,
то, что тип известен валидатору и прочим спискам типов, TCP-отсев тестера,
дедуп пула и tag'и при импорте подписки.

Логины/пароли/адреса выдуманные (203.0.113.0/24 это TEST-NET-3).
"""

import json
import unittest
from unittest import mock

from core import proxy_tester as pt
from core import server_pool
from core import singbox_manager
from core import subscription_importer
from core.singbox_config import (
    KNOWN_OUTBOUND_TYPES, make_mieru_outbound, pick_proxy_outbound,
    validate,
)
from core.singbox_subscription import (
    mieru_to_outbound, outbound_to_uri, outbounds_to_links, uri_to_outbound,
)
from core.subscription_importer import extract_items
from core.mcp import redact

USER, PASS, HOST = "tstUser1", "tstPass9", "203.0.113.10"


class TestMakeMieruOutbound(unittest.TestCase):

    def test_exact_schema(self):
        # Лишние поля sing-box-extended отвергает, схема ровно такая.
        ob = make_mieru_outbound("mieruTest", HOST, ["9000-9010"],
                                 USER, PASS, transport="TCP",
                                 multiplexing="MULTIPLEXING_LOW")
        self.assertEqual(ob, {
            "type": "mieru", "tag": "mieruTest",
            "server": HOST, "server_ports": ["9000-9010"],
            "transport": "TCP", "username": USER, "password": PASS,
            "multiplexing": "MULTIPLEXING_LOW",
        })

    def test_optional_fields_absent_by_default(self):
        ob = make_mieru_outbound("m", HOST, [9000], USER, PASS)
        self.assertEqual(ob["transport"], "TCP")
        self.assertNotIn("multiplexing", ob)
        self.assertNotIn("mtu", ob)

    def test_ports_normalized_to_strings(self):
        ob = make_mieru_outbound(
            "m", HOST, [9000, "9010-9020", " 9030 , 9040-9041 ",
                        "9050 - 9055", "9000"], USER, PASS)
        # Числа → строки, запятые разворачиваются, пробелы в диапазоне
        # убираются, дубль 9000 выкинут, порядок сохранён.
        self.assertEqual(ob["server_ports"],
                         ["9000", "9010-9020", "9030", "9040-9041",
                          "9050-9055"])

    def test_single_port_scalar(self):
        self.assertEqual(
            make_mieru_outbound("m", HOST, 9000, USER, PASS)["server_ports"],
            ["9000"])
        self.assertEqual(
            make_mieru_outbound("m", HOST, "9000-9001", USER,
                                PASS)["server_ports"],
            ["9000-9001"])

    def test_transport_and_multiplexing_case_insensitive(self):
        ob = make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                 transport="udp",
                                 multiplexing="multiplexing_high")
        self.assertEqual(ob["transport"], "UDP")
        self.assertEqual(ob["multiplexing"], "MULTIPLEXING_HIGH")

    def test_mtu_passed_when_set(self):
        ob = make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                 transport="UDP", mtu="1400")
        self.assertEqual(ob["mtu"], 1400)
        ob = make_mieru_outbound("m", HOST, ["9000"], USER, PASS, mtu=1280)
        self.assertEqual(ob["mtu"], 1280)

    def test_single_port_range_collapsed(self):
        ob = make_mieru_outbound("m", HOST, ["9000-9000", "9000"],
                                 USER, PASS)
        self.assertEqual(ob["server_ports"], ["9000"])

    def test_multiplexing_default_accepted_not_written(self):
        # MULTIPLEXING_DEFAULT валиден в enum mieru, но в outbound не пишем.
        ob = make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                 multiplexing="MULTIPLEXING_DEFAULT")
        self.assertNotIn("multiplexing", ob)

    def test_handshake_mode_and_traffic_pattern(self):
        ob = make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                 handshake_mode="handshake_no_wait",
                                 traffic_pattern="GgQIARAK")
        self.assertEqual(ob["handshake_mode"], "HANDSHAKE_NO_WAIT")
        self.assertEqual(ob["traffic_pattern"], "GgQIARAK")
        ob = make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                 handshake_mode="HANDSHAKE_DEFAULT")
        self.assertNotIn("handshake_mode", ob)
        self.assertNotIn("traffic_pattern", ob)
        with self.assertRaises(ValueError):
            make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                handshake_mode="HANDSHAKE_FAST")

    def test_bad_ports_rejected(self):
        for bad in ([], [""], ["abc"], ["0"], ["70000"], ["9010-9000"],
                    ["9000-"], ["-9000"], None, 9000.0, {"9000": 1},
                    [9000.5], [{"port": 9000}], True, [True]):
            with self.subTest(ports=bad):
                # Именно ValueError (не TypeError): вызывающие ловят его.
                with self.assertRaises(ValueError):
                    make_mieru_outbound("m", HOST, bad, USER, PASS)

    def test_bad_transport_rejected(self):
        with self.assertRaises(ValueError):
            make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                transport="QUIC")

    def test_bad_multiplexing_rejected(self):
        with self.assertRaises(ValueError):
            make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                multiplexing="MULTIPLEXING_MAX")

    def test_bad_mtu_rejected(self):
        for bad in ("big", "0", 0, -1, "-1400", 1400.5, "1400.0", True):
            with self.subTest(mtu=bad):
                with self.assertRaises(ValueError):
                    make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                        mtu=bad)

    def test_credentials_required(self):
        with self.assertRaises(ValueError):
            make_mieru_outbound("m", HOST, ["9000"], "", PASS)
        with self.assertRaises(ValueError):
            make_mieru_outbound("m", HOST, ["9000"], USER, "")


class TestMieruKnownType(unittest.TestCase):

    def _cfg(self):
        return {"outbounds": [
            {"type": "direct", "tag": "direct"},
            make_mieru_outbound("mieru-out", HOST, ["9000"], USER, PASS),
        ]}

    def test_in_known_outbound_types(self):
        self.assertIn("mieru", KNOWN_OUTBOUND_TYPES)

    def test_validate_does_not_warn(self):
        errs = validate(self._cfg())
        self.assertFalse([e for e in errs if "неизвестный тип" in e], errs)

    def test_pick_proxy_outbound(self):
        self.assertEqual(pick_proxy_outbound(self._cfg()), "mieru-out")


class TestMieruUri(unittest.TestCase):

    def test_full_link_with_profile(self):
        uri = ("mierus://%s:%s@%s?multiplexing=MULTIPLEXING_LOW"
               "&port=9000-9010&profile=mieruTest&protocol=TCP"
               % (USER, PASS, HOST))
        r = mieru_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["tag"], "mieruTest")
        self.assertEqual(r["outbound"], {
            "type": "mieru", "tag": "mieruTest",
            "server": HOST, "server_ports": ["9000-9010"],
            "transport": "TCP", "username": USER, "password": PASS,
            "multiplexing": "MULTIPLEXING_LOW",
        })

    def test_link_without_profile_and_protocol(self):
        r = uri_to_outbound("mierus://%s:%s@%s?port=9010-9020"
                            % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        ob = r["outbound"]
        self.assertEqual(ob["tag"], "mieru-%s" % HOST.replace(".", "-"))
        self.assertEqual(ob["transport"], "TCP")          # дефолт
        self.assertEqual(ob["server_ports"], ["9010-9020"])
        self.assertNotIn("multiplexing", ob)

    def test_profile_sanitized_into_tag(self):
        r = uri_to_outbound("mierus://%s:%s@%s?port=9000&profile=My%%20Box"
                            % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["tag"], "My-Box")

    def test_udp_and_mtu(self):
        r = uri_to_outbound("mierus://%s:%s@%s?mtu=1400&port=9000"
                            "&protocol=UDP" % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["transport"], "UDP")
        self.assertEqual(r["outbound"]["mtu"], 1400)

    def test_repeated_and_comma_ports(self):
        r = uri_to_outbound("mierus://%s:%s@%s?port=9000&port=9010-9020"
                            "&port=9030,9040-9050&protocol=TCP"
                            % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["server_ports"],
                         ["9000", "9010-9020", "9030", "9040-9050"])

    def test_paired_protocols_keep_first_transport_ports(self):
        # В ссылке mieru i-й protocol относится к i-му port. transport у
        # outbound'а один, поэтому оставляем порты первого протокола.
        r = uri_to_outbound("mierus://%s:%s@%s?port=9000&port=9001-9002"
                            "&port=9003&protocol=TCP&protocol=UDP"
                            "&protocol=TCP" % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["transport"], "TCP")
        self.assertEqual(r["outbound"]["server_ports"], ["9000", "9003"])

    def test_mieru_scheme_is_synonym(self):
        a = uri_to_outbound("mieru://%s:%s@%s?port=9000&profile=x"
                            % (USER, PASS, HOST))
        b = uri_to_outbound("mierus://%s:%s@%s?port=9000&profile=x"
                            % (USER, PASS, HOST))
        self.assertTrue(a["ok"], msg=a.get("error"))
        self.assertEqual(a["outbound"], b["outbound"])

    def test_hostname_and_encoded_password(self):
        r = uri_to_outbound("mierus://%s:p%%40ss%%3Aword@mieru.example"
                            "?port=9000" % USER)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["server"], "mieru.example")
        self.assertEqual(r["outbound"]["password"], "p@ss:word")

    def test_bad_links(self):
        base = "mierus://%s:%s@%s" % (USER, PASS, HOST)
        cases = {
            "нет пароля":      "mierus://%s@%s?port=9000" % (USER, HOST),
            "нет логина":      "mierus://%s?port=9000" % HOST,
            "нет хоста":       "mierus://%s:%s@?port=9000" % (USER, PASS),
            "нет порта":       base + "?profile=x",
            "плохой порт":     base + "?port=99999",
            "плохой протокол": base + "?port=9000&protocol=QUIC",
            "плохой mux":      base + "?port=9000&multiplexing=MAX",
            "плохой mtu":      base + "?port=9000&mtu=big",
        }
        for name, uri in cases.items():
            with self.subTest(case=name):
                r = uri_to_outbound(uri)
                self.assertFalse(r["ok"], msg=r)
                self.assertTrue(r.get("error"))

    def test_error_style_for_importer(self):
        # «не <scheme>-URI» это сигнал импортеру «не наш URI»; ошибки разбора
        # нашей же схемы так начинаться не должны, иначе импорт их молча
        # проглотит вместо показа причины.
        self.assertEqual(mieru_to_outbound("vless://u@h:1")["error"],
                         "не mieru-URI")
        r = uri_to_outbound("mierus://%s:%s@%s" % (USER, PASS, HOST))
        self.assertFalse(r["ok"])
        self.assertFalse(r["error"].startswith("не "), r["error"])

    def test_mieru_base64_config_explicit_error(self):
        # `mieru export config` даёт mieru://<base64 protobuf>, без «@».
        r = uri_to_outbound("mieru://CiQKBmJhb3ppEhJtYW5saWFucGVuZmVuGgQIARAK")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"],
                         "mieru:// с base64-конфигом не поддерживается, "
                         "нужна ссылка mierus://")

    def test_empty_or_useless_profile_falls_back_to_host(self):
        fallback = "mieru-%s" % HOST.replace(".", "-")
        for prof in ("", "!!!", "out", "%20"):
            with self.subTest(profile=prof):
                r = uri_to_outbound("mierus://%s:%s@%s?port=9000&profile=%s"
                                    % (USER, PASS, HOST, prof))
                self.assertTrue(r["ok"], msg=r.get("error"))
                self.assertEqual(r["tag"], fallback)
                self.assertEqual(r["outbound"]["tag"], fallback)

    def test_port_in_address_without_query_port(self):
        r = uri_to_outbound("mierus://%s:%s@%s:9000" % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["server_ports"], ["9000"])

    def test_query_port_wins_over_address_port(self):
        r = uri_to_outbound("mierus://%s:%s@%s:9000?port=9100-9110"
                            % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["server_ports"], ["9100-9110"])

    def test_handshake_mode_and_traffic_pattern_from_link(self):
        # Имена параметров как у `mieru export config simple`. '+' в base64
        # может прийти неэкранированным (parse_qsl сделал бы из него пробел).
        for tp_in in ("ab%2Bcd%2Fef%3D", "ab+cd/ef="):
            with self.subTest(traffic_pattern=tp_in):
                r = uri_to_outbound(
                    "mierus://%s:%s@%s?handshake-mode=HANDSHAKE_NO_WAIT"
                    "&port=9000&traffic-pattern=%s"
                    % (USER, PASS, HOST, tp_in))
                self.assertTrue(r["ok"], msg=r.get("error"))
                ob = r["outbound"]
                self.assertEqual(ob["handshake_mode"], "HANDSHAKE_NO_WAIT")
                self.assertEqual(ob["traffic_pattern"], "ab+cd/ef=")

    def test_default_enums_from_link_not_written(self):
        r = uri_to_outbound("mierus://%s:%s@%s?port=9000"
                            "&multiplexing=MULTIPLEXING_DEFAULT"
                            "&handshake-mode=HANDSHAKE_DEFAULT"
                            % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertNotIn("multiplexing", r["outbound"])
        self.assertNotIn("handshake_mode", r["outbound"])


class TestMieruExport(unittest.TestCase):

    def test_round_trip_full(self):
        ob = make_mieru_outbound(
            "mieruTest", HOST, ["9000-9010", "9020"], USER, "p@ss:w/rd",
            transport="UDP", multiplexing="MULTIPLEXING_LOW", mtu=1400,
            handshake_mode="HANDSHAKE_NO_WAIT", traffic_pattern="ab+cd/ef=")
        uri = outbound_to_uri(ob)
        self.assertTrue(uri.startswith("mierus://%s:" % USER), uri)
        r = uri_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"], ob)

    def test_round_trip_minimal_and_ipv6(self):
        ob = make_mieru_outbound("v6box", "2001:db8::10", 9000, USER, PASS)
        uri = outbound_to_uri(ob)
        self.assertIn("@[2001:db8::10]?", uri)
        self.assertEqual(uri_to_outbound(uri)["outbound"], ob)

    def test_links_include_mieru(self):
        ob = make_mieru_outbound("m", HOST, ["9000"], USER, PASS)
        self.assertEqual(len(outbounds_to_links([ob])), 1)
        self.assertEqual(outbound_to_uri(dict(ob, server_ports=[])), "")


class TestMieruProxyTester(unittest.TestCase):
    """У mieru нет server_port, только server_ports: без учёта этого
    TCP-отсев пропускал outbound, и тест помечал его мёртвым."""

    def _ob(self, **kw):
        return make_mieru_outbound("m", HOST, ["9000-9010", "9100"],
                                   USER, PASS, **kw)

    def test_tcp_probe_uses_lower_port_of_first_element(self):
        with mock.patch.object(pt, "_tcp_connect_ok",
                               return_value=(True, 12, "")) as m:
            res = pt.tcp_prefilter([self._ob()])
        m.assert_called_once()
        self.assertEqual(m.call_args[0][:2], (HOST, "9000"))
        self.assertEqual(res["m"], (True, 12, ""))

    def test_udp_transport_skips_tcp_probe(self):
        with mock.patch.object(pt, "_tcp_connect_ok") as m:
            res = pt.tcp_prefilter([self._ob(transport="UDP")])
        m.assert_not_called()
        self.assertEqual(res["m"], (True, None, ""))

    def test_result_row_alive_with_server_ports(self):
        with mock.patch.object(pt, "_tcp_connect_ok",
                               return_value=(True, 12, "")):
            res = pt.run_outbound_tests([self._ob()], binary="")
        row = res["results"][0]
        self.assertTrue(row["alive"], row)
        self.assertEqual(row["port"], ["9000-9010", "9100"])

    def test_udp_not_dead_without_engine(self):
        res = pt.run_outbound_tests([self._ob(transport="UDP")], binary="")
        self.assertTrue(res["results"][0]["alive"])


class TestMieruPoolDedup(unittest.TestCase):

    def test_ports_and_transport_are_part_of_identity(self):
        a = make_mieru_outbound("a", HOST, ["9000"], USER, PASS)
        b = make_mieru_outbound("b", HOST, ["9100"], USER, PASS)
        c = make_mieru_outbound("c", HOST, ["9000"], USER, PASS,
                                transport="UDP")
        dup = make_mieru_outbound("d", HOST, ["9000"], USER, PASS)
        out = server_pool.dedup_outbounds([a, b, c, dup])
        self.assertEqual([o["tag"] for o in out], ["a", "b", "c"])


class _FakeSingboxManager:
    """get_config/save_config в памяти вместо файлов конфигов."""

    def __init__(self):
        self.text = None

    def get_config(self, name):
        if self.text is None:
            return {"ok": False, "error": "Конфиг не найден"}
        return {"ok": True, "parsed": json.loads(self.text)}

    def save_config(self, name, *, text=""):
        self.text = text
        return {"ok": True}


class TestMieruImporterTags(unittest.TestCase):
    """Одинаковый profile у разных серверов не должен затирать сервер
    сервером при импорте подписки (там outbound с тем же tag заменяется)."""

    def _import(self, mgr, host):
        uri = ("mierus://%s:%s@%s?port=9000&profile=default"
               % (USER, PASS, host))
        with mock.patch.object(singbox_manager, "get_singbox_manager",
                               return_value=mgr):
            return subscription_importer._try_import_singbox_uri(uri)

    def _mieru(self, mgr):
        return [o for o in json.loads(mgr.text)["outbounds"]
                if o.get("type") == "mieru"]

    def test_same_profile_other_host_gets_host_suffix(self):
        mgr = _FakeSingboxManager()
        self._import(mgr, "203.0.113.10")
        r = self._import(mgr, "203.0.113.20")
        self.assertTrue(r["item"]["ok"], r)
        self.assertEqual(r["item"]["tag"], "default-203-0-113-20")
        tags = sorted(o["tag"] for o in self._mieru(mgr))
        self.assertEqual(tags, ["default", "default-203-0-113-20"])

    def test_same_host_reimport_replaces(self):
        mgr = _FakeSingboxManager()
        self._import(mgr, "203.0.113.10")
        self._import(mgr, "203.0.113.10")
        self.assertEqual([o["tag"] for o in self._mieru(mgr)], ["default"])


class TestMieruInLists(unittest.TestCase):

    def test_extract_items_finds_mieru_links(self):
        text = ("vless://u@h.example:443#a\n"
                "mierus://%s:%s@%s?port=9000&profile=one\n"
                "mieru://%s:%s@%s?port=9001" % (USER, PASS, HOST,
                                                USER, PASS, HOST))
        schemes = [it["scheme"] for it in extract_items(text)
                   if it["type"] == "uri"]
        self.assertEqual(schemes, ["vless", "mierus", "mieru"])

    def test_redact_masks_mieru_credentials(self):
        out = redact.redact_text(
            "mierus://%s:%s@%s?port=9000" % (USER, PASS, HOST), force=True)
        self.assertNotIn(PASS, out)
        self.assertIn(HOST, out)


if __name__ == "__main__":
    unittest.main()
