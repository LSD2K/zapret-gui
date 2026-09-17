# tests/test_mcp_tools_tunnels.py
"""
`tunnels_status` — шесть движков одним ответом.

Что здесь зафиксировано:

* **форма записи движка одна на всех** — ``engine``/``installed``/
  ``running``/``instances``/``version``/``reason``/``error``. На неё
  будут опираться S7 (запуск туннелей) и S15 (страница MCP), и разнобой
  здесь означает, что каждый потребитель помнит, у кого `active`, а у
  кого `running`;
* **не установлен ≠ ошибка.** Машина без единого движка — штатный
  случай, и ответ на ней обязан быть осмысленным, а не пустым;
* **упавший движок не роняет сводку.** Опрос каждого — под своим
  ``try``, и сломанный отвечает полем ``error``, а не исключением;
* **фильтр `engine`** отдаёт ровно один движок, а неизвестное имя —
  отказ со списком известных;
* **секреты не уезжают.** Ключи пиров AmneziaWG, UUID в имени конфига,
  токен в строке лога — всё это проходит через ответ инструмента, и
  проверяется именно сериализованный результат, а не dict до маскировки.

Менеджеры подменяются целиком: настоящих движков на машине с тестами
нет, а ответ должен проверяться на полных данных, а не на пустых.
"""

import json
import unittest

from core import tunnels_overview as overview
from core.mcp import registry


# Узнаваемые секреты: если хоть один долетит до модели — тест красный.
PEER_KEY = "PEERPUBKEYaaaabbbbccccddddeeeeffff0011223344="
PRESHARED = "PRESHAREDkeyzzzz9999888877776666555544443333="
LOG_TOKEN = "logtokendeadbeef0123"


def call(name, args=None):
    """Вызов инструмента с правами только на чтение."""
    return registry.call(name, args or {}, {})


def payload(name, args=None):
    return call(name, args)["structuredContent"]


class Fake:
    """Объект-заглушка: атрибуты задаются словарём."""

    def __init__(self, **methods):
        for key, value in methods.items():
            setattr(self, key, value)


class EnginePatch:
    """Подмена фабрик движка на время теста.

    Фабрики импортируются ВНУТРИ обработчика, поэтому патчится атрибут
    модуля — перехватить импорт на уровне tools/ невозможно.
    """

    def __init__(self, case, *targets):
        self.saved = []
        for module_name, attr, value in targets:
            module = __import__(module_name, fromlist=["x"])
            self.saved.append((module, attr, getattr(module, attr)))
            setattr(module, attr, value)
        case.addCleanup(self.restore)

    def restore(self):
        for module, attr, value in self.saved:
            setattr(module, attr, value)


def singbox(running=True, log=""):
    """Фабрики sing-box: детектор + менеджер с одним конфигом."""
    manager = Fake(
        list_configs=lambda: [{"name": "vps", "path": "/opt/etc/sb/vps.json",
                               "size": 900, "mtime": 1,
                               "running": running, "tun_iface": "sbtun0"}],
        status=lambda name: {"name": name, "active": running,
                             "pid": 4242 if running else None,
                             "log_path": "/opt/var/log/sb-%s.log" % name},
        read_log=lambda name, lines=200: {"ok": True, "log": log},
    )
    detector = Fake(detect_binary=lambda: {
        "installed": True, "path": "/opt/sbin/sing-box", "version": "1.12.4"})
    return (("core.singbox_detector", "get_singbox_detector",
             lambda: detector),
            ("core.singbox_manager", "get_singbox_manager", lambda: manager))


def awg(running=True):
    """Фабрики AmneziaWG: установщик + менеджер с одним интерфейсом."""
    manager = Fake(
        list_configs=lambda: [{"name": "warp", "iface": "awg0",
                               "path": "/opt/etc/awg/warp.conf",
                               "size": 400, "mtime": 1, "active": running}],
        status=lambda iface: {
            "name": iface, "active": running, "pid": 777,
            "interface": {"private_key": "***", "public_key": "OURPUB=",
                          "listen_port": 51820},
            "peers": [{"public_key": PEER_KEY, "preshared_key": PRESHARED,
                       "endpoint": "162.159.192.1:2408",
                       "allowed_ips": "0.0.0.0/0",
                       "latest_handshake": 1700000000,
                       "rx_bytes": 1024, "tx_bytes": 2048}]},
    )
    installer = Fake(get_installed_version=lambda: {
        "installed": True, "external": False, "go_version": "0.2.12",
        "tools_version": "1.0.20241018", "amneziawg_go": "/opt/bin/amneziawg-go",
        "awg": "/opt/bin/awg"})
    return (("core.awg_installer", "get_awg_installer", lambda: installer),
            ("core.awg_manager", "get_awg_manager", lambda: manager))


class TestEngineRecordShape(unittest.TestCase):
    """Общая форма записи — контракт для S7/S15."""

    FIELDS = ("engine", "title", "installed", "running", "version",
              "binary", "instances", "instances_count", "running_count",
              "reason", "error")

    def test_every_engine_has_the_same_fields(self):
        items = payload("tunnels_status")["items"]
        self.assertEqual(len(items), len(overview.ENGINES))
        for record in items:
            with self.subTest(engine=record.get("engine")):
                for field in self.FIELDS:
                    self.assertIn(field, record)
                self.assertEqual(record["instances_count"],
                                 len(record["instances"]))

    def test_common_list_shape(self):
        data = payload("tunnels_status")
        for field in ("items", "total", "count", "offset", "limit",
                      "truncated"):
            self.assertIn(field, data)
        self.assertEqual(data["count"], len(data["items"]))

    def test_instances_share_one_shape(self):
        EnginePatch(self, *singbox(), *awg())
        for record in payload("tunnels_status")["items"]:
            for instance in record["instances"]:
                with self.subTest(engine=record["engine"],
                                  instance=instance.get("name")):
                    for field in ("name", "running", "pid", "iface",
                                  "config", "traffic", "traffic_source",
                                  "last_error"):
                        self.assertIn(field, instance)


class TestNothingInstalled(unittest.TestCase):
    """Машина без единого движка — это ответ, а не ошибка."""

    def test_answer_is_ok_and_explains_itself(self):
        data = payload("tunnels_status")
        self.assertTrue(data["ok"])
        for record in data["items"]:
            with self.subTest(engine=record["engine"]):
                if not record["installed"]:
                    # «Почему пусто» обязано быть сказано словами:
                    # installed=false без причины читается как сбой.
                    self.assertTrue(record["reason"])
                    self.assertFalse(record["running"])

    def test_hint_points_at_nfqws_status(self):
        # Движок обхода в эту сводку не входит, и модель не должна
        # искать его здесь.
        self.assertIn("nfqws_status", payload("tunnels_status")["hint"])


class TestSingbox(unittest.TestCase):

    def test_running_config_is_reported(self):
        EnginePatch(self, *singbox(running=True))
        record = self._record()
        self.assertTrue(record["installed"])
        self.assertTrue(record["running"])
        self.assertEqual(record["version"], "1.12.4")
        self.assertEqual(record["instances_count"], 1)
        instance = record["instances"][0]
        self.assertEqual(instance["name"], "vps")
        self.assertEqual(instance["iface"], "sbtun0")
        self.assertEqual(instance["pid"], 4242)

    def test_stopped_config_is_not_an_error(self):
        EnginePatch(self, *singbox(running=False))
        record = self._record()
        self.assertTrue(record["installed"])
        self.assertFalse(record["running"])
        self.assertIn("не запущен", record["reason"])
        self.assertIsNone(record["instances"][0]["pid"])

    def test_last_error_comes_from_the_log(self):
        EnginePatch(self, *singbox(
            log="start ok\nFATAL: dial tcp: connection refused\nretry"))
        self.assertIn("connection refused",
                      self._record()["instances"][0]["last_error"])

    def test_logs_false_skips_the_log(self):
        EnginePatch(self, *singbox(log="FATAL: connection refused"))
        record = payload("tunnels_status",
                         {"engine": "singbox", "logs": False})["items"][0]
        self.assertEqual(record["instances"][0]["last_error"], "")

    def test_traffic_is_none_without_a_counter(self):
        # Интерфейса sbtun0 на машине с тестами нет — «неизвестно»
        # полезнее нуля, который читается как «трафика не было».
        EnginePatch(self, *singbox())
        instance = self._record()["instances"][0]
        self.assertIsNone(instance["traffic"])
        self.assertEqual(instance["traffic_source"], "")

    def test_traffic_carries_its_source(self):
        EnginePatch(self, *singbox(),
                    ("core.tunnels_overview", "iface_counters",
                     lambda iface: {"rx_bytes": 10, "tx_bytes": 20}))
        instance = self._record()["instances"][0]
        self.assertEqual(instance["traffic"],
                         {"rx_bytes": 10, "tx_bytes": 20})
        self.assertEqual(instance["traffic_source"], "/sys/class/net")

    def _record(self):
        return payload("tunnels_status", {"engine": "singbox"})["items"][0]


class TestAwg(unittest.TestCase):

    def test_peers_and_handshake(self):
        EnginePatch(self, *awg())
        instance = self._record()["instances"][0]
        self.assertEqual(instance["peers"], 1)
        self.assertEqual(instance["last_handshake"], 1700000000)

    def test_traffic_is_summed_over_peers_not_the_interface(self):
        # У userspace-туннеля счётчики интерфейса считают и служебный
        # трафик; `awg show` отдаёт ровно прошедшее через пиров.
        EnginePatch(self, *awg())
        instance = self._record()["instances"][0]
        self.assertEqual(instance["traffic"],
                         {"rx_bytes": 1024, "tx_bytes": 2048})
        self.assertEqual(instance["traffic_source"], "awg show")

    def test_native_keenetic_interface_reports_ndms_as_source(self):
        manager = Fake(
            list_configs=lambda: [{"name": "wg0", "iface": "Wireguard0",
                                   "path": "/x.conf", "active": True}],
            status=lambda iface: {"name": iface, "active": True,
                                  "native": True, "source": "ndms",
                                  "rx_bytes": 5, "tx_bytes": 7,
                                  "peers": []})
        installer = Fake(get_installed_version=lambda: {
            "installed": True, "go_version": "0.2.12",
            "amneziawg_go": "/opt/bin/amneziawg-go"})
        EnginePatch(self,
                    ("core.awg_installer", "get_awg_installer",
                     lambda: installer),
                    ("core.awg_manager", "get_awg_manager", lambda: manager))
        instance = self._record()["instances"][0]
        self.assertEqual(instance["traffic_source"], "ndms")
        self.assertTrue(instance["native"])

    def _record(self):
        return payload("tunnels_status", {"engine": "awg"})["items"][0]


class TestFilters(unittest.TestCase):

    def test_engine_filter_narrows_to_one(self):
        data = payload("tunnels_status", {"engine": "mihomo"})
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["engine"], "mihomo")

    def test_unknown_engine_is_an_error_with_the_known_list(self):
        # Схема сама не пропустит чужое имя — проверяем ядро, где та же
        # проверка стоит для UI и CLI.
        report = overview.overview(engine="wireguard")
        self.assertFalse(report["ok"])
        self.assertIn("known", report)
        self.assertIn("singbox", report["known"])

    def test_running_only_filters_out_the_idle(self):
        EnginePatch(self, *singbox(running=False))
        data = payload("tunnels_status", {"running_only": True})
        self.assertEqual(data["items"], [])
        self.assertIn("reason", data)

    def test_running_only_keeps_the_live_one(self):
        EnginePatch(self, *singbox(running=True))
        data = payload("tunnels_status", {"running_only": True})
        self.assertEqual([e["engine"] for e in data["items"]], ["singbox"])


class TestBrokenEngineDoesNotSinkTheAnswer(unittest.TestCase):
    """Фабрика менеджера падает раньше его метода — и это норма."""

    def _boom(self):
        raise RuntimeError("нет каталога конфигов")

    def test_one_broken_engine_is_reported_in_its_own_record(self):
        EnginePatch(self, ("core.usque_manager", "get_usque_manager",
                           lambda: self._boom()))
        data = payload("tunnels_status")
        self.assertTrue(data["ok"])
        self.assertEqual(len(data["items"]), len(overview.ENGINES))
        broken = [e for e in data["items"] if e["engine"] == "usque"][0]
        self.assertIn("нет каталога конфигов", broken["error"])
        self.assertTrue(broken["reason"])
        self.assertIn("usque", data["hint"])

    def test_the_other_engines_still_answer(self):
        EnginePatch(self, ("core.usque_manager", "get_usque_manager",
                           lambda: self._boom()),
                    *singbox())
        records = {e["engine"]: e for e in payload("tunnels_status")["items"]}
        self.assertTrue(records["singbox"]["installed"])
        self.assertEqual(records["singbox"]["error"], "")


class TestSecretsNeverLeave(unittest.TestCase):
    """Ключи, токены и ссылки не уезжают модели.

    Проверяется сериализованный результат `tools/call` целиком — и
    `content`, и `structuredContent`: маскировка живёт в одной точке
    (`registry.tool_result`), и смотреть надо именно на её выход.
    """

    def haystack(self, args=None):
        result = call("tunnels_status", args)
        return "\n".join([
            json.dumps(result["structuredContent"], ensure_ascii=False,
                       default=str),
            result["content"][0]["text"],
        ])

    def test_awg_peer_keys_are_masked(self):
        EnginePatch(self, *awg())
        text = self.haystack({"engine": "awg"})
        self.assertNotIn(PEER_KEY, text)
        self.assertNotIn(PRESHARED, text)

    def test_token_inside_a_log_line_is_masked(self):
        EnginePatch(self, *singbox(
            log="ERROR subscription failed token=%s" % LOG_TOKEN))
        text = self.haystack({"engine": "singbox"})
        # Строка видна — иначе непонятно, что сломалось; секрет нет.
        self.assertIn("subscription failed", text)
        self.assertNotIn(LOG_TOKEN, text)

    def test_telegram_proxy_link_is_never_built(self):
        # `get_connect_info()` собирает tg://proxy с секретом. Сводка
        # его не зовёт — и не должна начать звать «для полноты».
        def boom(*a, **kw):
            raise AssertionError("tunnels_status не должен звать "
                                 "get_connect_info")

        manager = Fake(
            detect=lambda: {"installed": True, "path": "/opt/etc/init.d/S99",
                            "config_dir": "/opt/etc/tgwsproxy",
                            "package": "tg-ws-proxy", "version": "1.2.3"},
            get_status=lambda: {"installed": True, "running": True,
                                "host": "0.0.0.0", "port": 1443},
            get_connect_info=boom)
        EnginePatch(self, ("core.tgproxy_manager", "get_tgwsproxy_manager",
                           lambda: manager))
        text = self.haystack({"engine": "tgproxy"})
        self.assertIn("tgwsproxy", text)
        self.assertNotIn("tg://proxy", text)


class TestAnswerFitsTheLimit(unittest.TestCase):
    """Сводка по шести движкам укладывается в лимит ответа.

    Приёмка S5: один вызов должен давать картину целиком. Ответ сверх
    `mcp.limits.response_kb` реестр заменяет ЦЕЛИКОМ на «слишком
    много» — то есть вместо картины модель получает сообщение об
    ошибке и тратит ещё один вызов.
    """

    def test_many_configs_shrink_the_window_instead_of_blowing_it(self):
        many = [{"name": "cfg-%03d" % i, "path": "/opt/etc/sb/cfg-%03d.json" % i,
                 "running": True, "tun_iface": "sbtun%d" % i,
                 "size": 1, "mtime": 1} for i in range(200)]
        manager = Fake(
            list_configs=lambda: many,
            status=lambda name: {"name": name, "active": True, "pid": 1,
                                 "log_path": "/x"},
            read_log=lambda name, lines=200: {"ok": True, "log": ""})
        detector = Fake(detect_binary=lambda: {
            "installed": True, "path": "/opt/sbin/sing-box",
            "version": "1.12.4"})
        EnginePatch(self,
                    ("core.singbox_detector", "get_singbox_detector",
                     lambda: detector),
                    ("core.singbox_manager", "get_singbox_manager",
                     lambda: manager))

        data = call("tunnels_status")["structuredContent"]
        # Реестр подменяет слишком большой ответ — если это случилось,
        # `items` не будет вовсе.
        self.assertIn("items", data)
        # Подрезаются КОНФИГИ ОДНОГО движка, а не остальные движки:
        # потерять пять движков из шести ради полного списка конфигов
        # шестого — это не та сводка, за которой звали.
        self.assertEqual(len(data["items"]), len(overview.ENGINES))
        record = data["items"][0]
        self.assertTrue(record["instances_truncated"])
        self.assertEqual(record["instances_count"], 200)
        self.assertEqual(len(record["instances"]), 10)
        self.assertIn("instances=", data["hint"])
        size = len(json.dumps(data, ensure_ascii=False).encode("utf-8"))
        self.assertLess(size, 32 * 1024)

    def test_instances_argument_lifts_the_cap(self):
        many = [{"name": "cfg-%02d" % i, "path": "/x/%02d.json" % i,
                 "running": False, "tun_iface": ""} for i in range(30)]
        manager = Fake(
            list_configs=lambda: many,
            status=lambda name: {"name": name, "active": False, "pid": None},
            read_log=lambda name, lines=200: {"ok": True, "log": ""})
        detector = Fake(detect_binary=lambda: {
            "installed": True, "path": "/opt/sbin/sing-box", "version": "1"})
        EnginePatch(self,
                    ("core.singbox_detector", "get_singbox_detector",
                     lambda: detector),
                    ("core.singbox_manager", "get_singbox_manager",
                     lambda: manager))
        record = payload("tunnels_status",
                         {"engine": "singbox", "instances": 30})["items"][0]
        self.assertEqual(len(record["instances"]), 30)
        self.assertNotIn("instances_truncated", record)

    def test_engine_filter_is_the_way_back_to_the_details(self):
        # Ужатое окно не тупик: сводка ужимается по движкам, а за
        # подробностями модель идёт тем же инструментом с фильтром.
        data = payload("tunnels_status", {"engine": "opera"})
        self.assertEqual(data["total"], 1)


class TestOverviewIsUsableOutsideMcp(unittest.TestCase):
    """Логика живёт в core — значит, доступна и UI, и CLI."""

    def test_core_returns_the_same_records(self):
        EnginePatch(self, *singbox())
        report = overview.overview(engine="singbox")
        self.assertTrue(report["ok"])
        self.assertEqual(report["engines"][0]["engine"], "singbox")
        self.assertEqual(report["installed"], 1)

    def test_known_engines_are_named_for_the_ui(self):
        names = [e["engine"] for e in overview.known_engines()]
        self.assertEqual(names, list(overview.ENGINES))
        for entry in overview.known_engines():
            self.assertTrue(entry["title"])

    def test_last_error_picks_the_last_complaint_not_the_first(self):
        # Движок, упавший на старте, пишет причину один раз и дальше
        # повторяет попытки: первая строка устареет, последняя — нет.
        text = ("ERROR: старая причина\ninfo: retry\n"
                "ERROR: свежая причина\ninfo: sleeping")
        self.assertEqual(overview.last_error(text), "ERROR: свежая причина")

    def test_no_complaint_is_an_empty_string(self):
        self.assertEqual(overview.last_error("started\nlistening on 1080"),
                         "")


if __name__ == "__main__":
    unittest.main()
