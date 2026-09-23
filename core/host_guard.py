# core/host_guard.py
"""
Защита от DNS-rebinding: белый список заголовка ``Host``.

Чем это грозит без него. Страница злоумышленника на ``evil.example``
перепривязывает своё имя на адрес роутера, и браузер считает запросы к
GUI **своими**: ``Origin`` и ``Host`` совпадают (оба ``evil.example``),
и проверка «same-origin» в ``app.py`` пропускает их. При выключенной
авторизации GUI (``gui.auth_enabled=false`` — по умолчанию) такая
страница читает ``GET /api/mcp/ui/token`` и раздаёт себе разрешения
через ``/api/mcp/ui/permissions`` вплоть до ``shell_full``, а заодно
всё остальное API.

Лечится не проверкой ``Origin`` (при rebinding он честный), а проверкой
**имени, по которому пришли**: к роутеру ходят по его IP. Имя
злоумышленника в список не попадёт никогда.

Что пускаем:

* IP-литералы (v4 и v6, с портом и без) — основной способ входа;
* ``localhost`` и ``*.localhost`` — они всегда резолвятся в петлю и
  перепривязать их нельзя;
* имена из ``gui.allowed_hosts`` — для тех, кто ходит по имени
  (``my.keenetic.net``, запись в локальном DNS). ``"*"`` в этом списке
  выключает проверку целиком — осознанно и явно;
* имена хостов из ``gui.cors_origins`` — их владелец уже объявил
  доверенными.

Запрос без ``Host`` (HTTP/1.0, внутренний вызов) не из браузера — его
пропускаем.

Модуль **чистый**: настройки приходят аргументами.
"""

import ipaddress
import urllib.parse


def host_name(host_header: str) -> str:
    """Имя из заголовка ``Host`` без порта, в нижнем регистре."""
    text = (host_header or "").strip().lower()
    if not text:
        return ""
    if text.startswith("["):                    # [::1]:8080
        end = text.find("]")
        return text[1:end] if end > 0 else text
    if text.count(":") == 1:                    # host:port
        return text.split(":", 1)[0]
    return text                                 # без порта или голый IPv6


def is_ip(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return False
    return True


def host_allowed(host_header: str, allowed_hosts=None,
                 cors_origins=None) -> bool:
    """Можно ли обслужить запрос, пришедший по этому ``Host``."""
    name = host_name(host_header).rstrip(".")
    if not name:
        return True
    if is_ip(name):
        return True
    if name == "localhost" or name.endswith(".localhost"):
        return True
    allowed = {str(h).strip().lower().rstrip(".")
               for h in (allowed_hosts or []) if str(h).strip()}
    if "*" in allowed or name in allowed:
        return True
    for origin in cors_origins or []:
        try:
            origin_host = urllib.parse.urlparse(str(origin)).hostname
        except ValueError:
            continue
        if origin_host and origin_host.lower() == name:
            return True
    return False
