# T1. Ужимание форка, первый проход

## Цель
Панель на gw управляет: nfqws2/zapret2, sing-box (туннель, FakeIP, «Домены → outbound»),
WARP/MASQUE (usque, warp-in-warp), Telegram Tunnel (tgproxy), списки (hostlists,
ipsets, named lists), диагностика (blockcheck, blockcheck2, block detector, diagnostics,
logs), система (обновления панели, установка zapret2, автозапуск, настройки).
Всё остальное выпиливается физически (код, API, страницы, тесты, скилы, доки),
а не прячется.

## Удалить целиком
- AmneziaWG: `core/awg_*.py`, `core/awg_platform.py`, `api/awg.py`, страницы
  `web/js/pages/awg_*.js`, скил `.claude/skills/awg`, пункты меню, ссылки в дашборде,
  автозапуск/watchdog AWG в `app.py`, настройки `awg` в `DEFAULT_CONFIG`, тесты `test_awg*`,
  `test_api_awg*`. `core/routing` при этом остаётся (нужен usque/warp-in-warp и
  unified), но всё, что в нём завязано только на AWG-интерфейсы, упростить до общего
  `target_iface`
- mihomo: `core/mihomo_*.py`, `core/clash_yaml.py` (проверить: если используется только
  mihomo и экспортом clash-подписок, удалить; если sing-box-подписки зависят, оставить
  минимум), `api/mihomo.py`, страницы `mihomo*.js`, скил `mihomo`, настройки, тесты
- Opera Proxy: `core/opera_proxy_*.py`, `api/opera_proxy.py`, страница, скил, настройки,
  тесты; из `core/ext_binary_installer.py` убрать opera
- MCP-сервер и встроенный агент: `core/mcp/`, `api/mcp.py`, `api/mcp_ui.py`, `api/agent.py`,
  `core/agent_runner.py`, `core/llm_client.py`, `core/code_editor.py`, `core/shell_exec.py`,
  `core/code_guard.py`, `core/host_guard.py` (если только для MCP; иначе оставить),
  `core/strategy_experiment.py`/`probe_runner.py`/`traffic_capture.py`/`pcap_reader.py`,
  если ими пользуется только MCP (проверить grep-ом), страницы `mcp.js`, `agent.js`,
  `docs/mcp/`, `docs/mcp-*.md`, скил `mcp`, секции `mcp` и `agent` в настройках,
  Bearer-ветка авторизации в `app.py`, тесты `test_mcp*`, `test_agent*`, `test_api_agent*`.
  `core/mcp/redact.py` и `core/mcp/auth.py` (secret_equal, маскировка) нужны панели:
  перенести нужные функции в `core/redact.py` / `core/auth_utils.py`
- Keenetic/NDMS-специфика: `core/ndms/`, `core/routing/ndms_backend.py`, ветки
  `is_keenetic()` там, где без них код проще. Entware/OpenWrt-упаковку (`packaging/`,
  `install.sh` ветки opkg/apk) оставить: форк может вернуться апстриму
- `tests/` из установки: `install.sh` больше не копирует `tests/`; самодиагностика
  (`core/selfcheck.py`) прогон юнит-тестов пропускает с пометкой «тесты не установлены»
- страница/логика `update_checker` про обновления **системы** (opkg/apk upgrade), если
  такая есть; обновление самой панели из GitHub-релизов (`gui_updater`) оставить, но
  источник по умолчанию должен быть форк `LSD2K/zapret-gui` и теги `v0.25.3-gw.N`
  (проверить, как он ищет релизы; если жёстко `avatardd/zapret-gui`, вынести в настройку
  `gui.update_repo`)
- `catalogs/` не трогать (стратегии nfqws2), `import/` не трогать

## Оставить
nfqws2-модули, стратегии, каталоги, blockcheck/blockcheck2/scanner, block_detector,
diagnostics, logs, hostlists/ipsets/named_lists/list_updater, sing-box целиком (с B1-B3),
usque + warp_in_warp, tgproxy, unified (только nfqws2 и sing-box/usque методы),
routing (без ndms), autostart, gui_updater, config, backup, healthcheck,
auto_remediation (без tunnel_priority на удалённые движки), system_info, network_env.

## Меню
Группы: «Обход DPI (nfqws2)» (Управление, Стратегии, Подбор стратегий, Домены → outbound),
«Туннели» (sing-box + дети, WARP/MASQUE + дети, Telegram Tunnel, Маршрутизация,
Мониторинг), «Списки и данные», «Диагностика», «Система» (Обновления, Zapret2 (установка),
Автозапуск, Настройки). `gui.hidden_pages` оставить как функцию.

## Требования
- после каждого крупного удаления: `.venv/bin/python -m pytest -q -p no:cacheprovider tests`
  зелёный, кроме известных macOS-падений (tcpdump/af_packet/ext installer/archive/openwrt
  docs); тесты удалённых модулей удаляются вместе с ними, тесты живых модулей не ослаблять
- `node --check` всех .js, `node tests/test_nfqws2_lint.js`
- `python3 -c "import app"` не падает; `python3 app.py --help` работает
- ни одного «висячего» импорта (grep по удалённым модулям пуст), ни одной мёртвой ссылки
  в `web/index.html`, `app.js`, `sidebar.js`, `dashboard.js`
- `AGENTS.md`, `CoderManual.md`, `README.md`: убрать разделы про удалённые движки,
  коротко, без переписывания остального
- отчёт: строки Python до/после, число файлов до/после, список удалённого по группам
- коммиты по группам (awg / mihomo / opera / mcp+agent / ndms / tests / меню / доки),
  без AI-упоминаний, без Co-Authored-By, не пушить
