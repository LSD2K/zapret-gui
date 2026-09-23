# Форк zapret-gui для роутера gw (Debian 13, ветка debian-gw)

Зачем форк: панель управляет nfqws2 (zapret2) и sing-box на домашнем роутере `gw`
(Debian 13, systemd, nftables, AdGuard Home на :53). Апстрим ориентирован на
Keenetic/OpenWrt, часть вещей под generic Linux не работает или не нужна.

Что уже поправлено в форке: `gui.hidden_pages`, systemd-юнит после nftables,
`install.sh` (бэкап через sudo, tmp), цепочка `predefrag notrack` в nftables-пути
(POSTNAT для транзита), пресет `keenetic_vidnoe`.

Правила для правок:
- минимальные диффы, апстрим сливаем регулярно; новые вещи в отдельных
  модулях/файлах, существующие функции не переписывать без нужды
- никакого dnsmasq и правок `/etc/resolv.conf`; DNS фронт на gw это AdGuard Home
- новые настройки в `core/config_manager.DEFAULT_CONFIG` с комментарием
- каждый шаг с тестами: `.venv/bin/python -m pytest -q tests` (на macOS 23
  падения из-за окружения: tcpdump, mcp shell, opera proxy, tgproxy autostart,
  это baseline), `node tests/test_nfqws2_lint.js`
- язык кода и комментариев как в апстриме (русские комментарии, docstring)
- в коммитах не упоминать AI-инструменты

Спеки задач: `spec-b1-mieru.md`, `spec-b2-fakeip-front.md`, `spec-b3-agh-routes.md`.
Целевая схема сети описана в `spec-b3-agh-routes.md`, раздел «Схема».
