# tests/test_mcp_redaction.py
"""
Секреты не покидают роутер (инвариант §5.2 контракта MCP).

Главное здесь — **сторож**: он перебирает РЕЕСТР, а не список имён
руками. Инструмент, добавленный в следующей сессии, попадает под
проверку сам; список имён пришлось бы дополнять, и однажды этого не
сделают — ровно в тот раз, когда инструмент отдаёт токен.

Фикстура: в конфиг кладутся заведомые секреты с узнаваемыми
значениями, после чего каждый read-only инструмент вызывается и его
ответ (и `content`, и `structuredContent`) проверяется на вхождение
этих строк.
"""

import json
import unittest

from core.config_manager import get_config_manager
from core.log_buffer import get_log_buffer, log
from core.mcp import redact, registry


# Узнаваемые значения: короткие и не встречающиеся в обычном ответе.
SECRETS = {
    ("mcp", "token"): "aaaabbbbccccdddd1111222233334444",
    ("gui", "auth_password"): "sup3rsecretpassword",
    ("gui", "auth_user"): "hiddenadmin",
    ("tgproxy", "tunnel_secret"): "deadbeefcafebabe",
    # S5: адрес подписки — не «настройка», а сам доступ к серверам.
    ("tgproxy", "tunnel_url"): "https://sub.example.net/s/qqqwwweee123",
}

# Секреты движков живут не в settings.json, а в их собственных файлах
# (.conf у AmneziaWG, JSON/YAML у sing-box и mihomo), поэтому в фикстуру
# конфига их не положить — зато ровно эти имена полей проезжают через
# `tunnels_status`. Проверяем их отдельно, по именам ключей.
ENGINE_SECRETS = {
    "private_key": "aPRIVATEkey1111222233334444555566667777888=",
    "public_key": "aPUBLICkey99998888777766665555444433332222=",
    "preshared_key": "aPRESHAREDkeyaaaabbbbccccddddeeeeffff0000=",
    "access_token": "warpAccessTokenZZZ999",
    "license": "WARPLICENSE-0001-0002",
    "uuid": "8c1b2f3d-4e5a-6b7c-8d9e-0f1122334455",
    "password": "singboxpass",
    "secret": "ee00112233445566778899aabbccddeeff",
}


def sample_args(schema):
    """Минимальные аргументы, удовлетворяющие схеме инструмента.

    Нужны сторожу: он обязан вызвать и тот инструмент, у которого есть
    обязательные поля, а не пропустить его «потому что не знаю, что
    передать».
    """
    args = {}
    props = schema.get("properties") or {}
    for key in schema.get("required") or []:
        args[key] = _sample(props.get(key) or {})
    return args


def _sample(spec):
    if isinstance(spec.get("enum"), list) and spec["enum"]:
        return spec["enum"][0]
    if "default" in spec:
        return spec["default"]
    kind = spec.get("type")
    kind = kind[0] if isinstance(kind, list) and kind else kind
    if kind == "integer":
        return int(spec.get("minimum", 1))
    if kind == "number":
        return float(spec.get("minimum", 1))
    if kind == "boolean":
        return False
    if kind == "array":
        return []
    if kind == "object":
        return {}
    return "x"


class TestRedactUnit(unittest.TestCase):

    def test_secret_keys_are_masked(self):
        out = redact.redact({"token": "abc", "api_key": "k",
                             "private_key": "p", "preshared_key": "q",
                             "password": "s", "license": "L",
                             "uuid": "u", "authorization": "A"})
        self.assertEqual(set(out.values()), {redact.MASK})

    def test_flags_and_numbers_survive(self):
        # Ответ из одних «***» модель прочитать не может: булев флаг
        # секретом не является.
        out = redact.redact({"auth_enabled": True, "keep": 500,
                             "calls_per_minute": 60})
        self.assertEqual(out["auth_enabled"], True)
        self.assertEqual(out["calls_per_minute"], 60)

    def test_working_data_is_not_touched(self):
        # Домены, hostlist'ы и аргументы стратегий — то, ради чего
        # модель сюда пришла. Маскировать их нельзя.
        payload = {"domains": ["youtube.com", "rutracker.org"],
                   "args": ["--dpi-desync=fake", "--hostlist=/opt/l.txt"],
                   "strategy": "multisplit seqovl"}
        self.assertEqual(redact.redact(payload), payload)

    def test_nested_structures(self):
        out = redact.redact({"peers": [{"public_key": "K", "endpoint":
                                        "1.2.3.4:51820"}]})
        self.assertEqual(out["peers"][0]["public_key"], redact.MASK)
        self.assertEqual(out["peers"][0]["endpoint"], "1.2.3.4:51820")

    def test_subscription_url_keeps_host_only(self):
        out = redact.redact({"url": "https://sub.example.com/link/abc?t=1"})
        self.assertEqual(out["url"], "https://sub.example.com/…")

    def test_input_is_not_mutated(self):
        src = {"token": "abc", "nested": {"password": "p"}}
        redact.redact(src)
        self.assertEqual(src["token"], "abc")
        self.assertEqual(src["nested"]["password"], "p")

    def test_raw_text(self):
        text = redact.redact_text(
            "curl -H 'Authorization: Bearer abc123' "
            "https://host/api?token=zzz\nPrivateKey = qqq")
        self.assertNotIn("abc123", text)
        self.assertNotIn("zzz", text)
        self.assertNotIn("qqq", text)
        # Хост и команда остаются: без них вывод бесполезен.
        self.assertIn("curl", text)
        self.assertIn("https://host/api", text)

    def test_text_without_markers_is_untouched(self):
        # Маскируем по ключам-маркерам, а не по виду значения: иначе
        # под нож попадут base64-пейлоады и lua-выражения.
        text = "--dpi-desync-fake-tls=0x16030100 sni=youtube.com"
        self.assertEqual(redact.redact_text(text), text)

    def test_idempotent(self):
        once = redact.redact({"token": "abc"})
        self.assertEqual(redact.redact(once), once)


class TestEngineSecrets(unittest.TestCase):
    """Ключи туннелей, UUID прокси и ссылки подписок (S5).

    Форма — та же, в какой их отдают менеджеры движков: словарь пира
    AmneziaWG, outbound sing-box, конфиг WARP. Проверяется именно она, а
    не абстрактные имена: маскировка смотрит на имя ключа, и «поле
    называлось иначе» — обычная причина утечки.
    """

    def test_every_engine_secret_key_is_masked(self):
        out = redact.redact(dict(ENGINE_SECRETS))
        for key, value in ENGINE_SECRETS.items():
            with self.subTest(key=key):
                self.assertEqual(out[key], redact.MASK)
                self.assertNotIn(value, json.dumps(out))

    def test_awg_peer_keeps_everything_but_the_keys(self):
        peer = {"public_key": ENGINE_SECRETS["public_key"],
                "preshared_key": ENGINE_SECRETS["preshared_key"],
                "endpoint": "162.159.192.1:2408",
                "allowed_ips": "0.0.0.0/0",
                "latest_handshake": 1700000000,
                "rx_bytes": 1024, "tx_bytes": 2048}
        out = redact.redact({"peers": [peer]})["peers"][0]
        self.assertEqual(out["public_key"], redact.MASK)
        self.assertEqual(out["preshared_key"], redact.MASK)
        # Диагностика без эндпоинта и счётчиков бесполезна.
        self.assertEqual(out["endpoint"], "162.159.192.1:2408")
        self.assertEqual(out["rx_bytes"], 1024)
        self.assertEqual(out["latest_handshake"], 1700000000)

    def test_subscription_url_keeps_only_the_host(self):
        out = redact.redact({"subscription_url":
                             "https://sub.example.net/s/qqqwwweee123"})
        self.assertEqual(out["subscription_url"], "https://sub.example.net/…")

    def test_tg_proxy_link_is_masked_by_its_key(self):
        out = redact.redact({"link": "tg://proxy?server=h&port=1&secret=ee00"})
        self.assertNotIn("ee00", json.dumps(out, ensure_ascii=False))

    def test_engine_log_line_is_cleaned_as_text(self):
        # Строка лога движка приезжает под `last_error`: имя ключа на
        # секрет не похоже, а секрет внутри — обычное дело.
        out = redact.redact({"last_error":
                             "ERROR subscription failed token=%s"
                             % ENGINE_SECRETS["access_token"]})
        self.assertIn("subscription failed", out["last_error"])
        self.assertNotIn(ENGINE_SECRETS["access_token"], out["last_error"])

    def test_engine_names_and_paths_survive(self):
        # Имя конфига и путь — рабочие данные: без них модель не сможет
        # ни назвать инстанс, ни прочитать его лог.
        payload = {"name": "vps-tokyo", "config": "/opt/etc/sb/vps.json",
                   "iface": "sbtun0", "engine": "singbox"}
        self.assertEqual(redact.redact(payload), payload)


class TestNoSecretLeaksFromTools(unittest.TestCase):
    """Сторож: ни один read-only инструмент не отдаёт секрет."""

    def setUp(self):
        self.cfg = get_config_manager()
        self.saved = {}
        for path, value in SECRETS.items():
            self.saved[path] = self.cfg.get(*path)
            self.cfg.set(*(list(path) + [value]))
        # Секрет, попавший в журнал из внешнего мира.
        log.info("проверка: token=%s" % SECRETS[("mcp", "token")],
                 source="mcp")

    def tearDown(self):
        for path, value in self.saved.items():
            self.cfg.set(*(list(path) + [value]))
        get_log_buffer().clear()

    def test_registry_has_read_only_tools(self):
        # Если сторож вдруг перестанет находить инструменты, он станет
        # зелёным и бесполезным.
        self.assertGreaterEqual(len(registry.available_tools({})), 4)

    def test_no_tool_leaks_a_secret(self):
        for spec in registry.available_tools({}):
            with self.subTest(tool=spec.name):
                result = registry.call(spec.name,
                                       sample_args(spec.schema), {})
                haystack = "\n".join([
                    json.dumps(result["structuredContent"],
                               ensure_ascii=False, default=str),
                    result["content"][0]["text"],
                ])
                for value in SECRETS.values():
                    self.assertNotIn(value, haystack,
                                     "%s отдал секрет" % spec.name)

    def test_config_get_masks_but_keeps_shape(self):
        payload = registry.call("config_get", {"path": "gui"},
                                {})["structuredContent"]
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["value"]["auth_password"], redact.MASK)
        # Структура остаётся читаемой: видно, что пароль задан.
        self.assertIn("port", payload["value"])

    def test_log_line_with_a_token_is_masked(self):
        payload = registry.call("logs_tail", {"limit": 50},
                                {})["structuredContent"]
        joined = json.dumps(payload, ensure_ascii=False)
        self.assertIn("token=", joined)
        self.assertNotIn(SECRETS[("mcp", "token")], joined)


if __name__ == "__main__":
    unittest.main()
