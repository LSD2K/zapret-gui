# Спека T4: форк под обновления, которые ведёт gw-panel

Ветка `debian-gw`. Форк работает движком под панелью gw-panel на роутере gw. Панель
берёт на себя обновления nfqws2, sing-box-extended, движка и себя (спека панели
`gw-panel/docs/spec-ui-3.md`, раздел «Обновления с откатом»). В форке три правки,
каждая отдельным коммитом с тестами.

## 1. Замок обновлений `updates.locked`

Проблема: кнопки установки и обновления в вебке движка на gw опасны.
`POST /api/gui/update` качает апстрим avatarDD поверх форка, `POST /api/zapret/update`
убивает nfqws2, снимает nft и не поднимает обратно, `POST /api/singbox/install` ставит
сборку без mieru.

Сделать:
- `core/config_manager.DEFAULT_CONFIG`: секция `"updates": {"locked": False}`.
  Включается `PUT /api/config {"updates": {"locked": true}}` или правкой `settings.json`.
- При `updates.locked == true` эндпоинты отвечают `403`
  `{"ok": false, "error": "locked", "message": "обновления на этом хосте делает gw-panel"}`
  и ничего не запускают:
  - `POST /api/gui/update`
  - `POST /api/zapret/install`, `POST /api/zapret/update`, `POST /api/zapret/uninstall`
  - `POST /api/singbox/install`, `POST /api/singbox/install/local`,
    `POST /api/singbox/uninstall`
- Проверка идёт до разбора тела и до любого обращения к установщику.
- `GET /api/updates/lock` → `{"ok": true, "locked": bool, "message": str}` для вебки.
- Вебка: на страницах «Управление zapret2» и «sing-box, установка» при замке вместо
  кнопок установки, обновления, удаления, выбора версии и загрузки файла плашка с замком
  и текстом. Баннеры «доступно обновление» с кнопками прячутся. Версии показываются
  как раньше.
- GET-эндпоинты (версии, релизы, прогресс) не закрываются: панель их читает.
- Тесты `tests/test_updates_lock.py`: 403 и тело на каждом из семи при замке,
  установщик не вызывается; без замка ответ не 403; `GET /api/updates/lock`;
  дефолт `locked: false`; `PUT /api/config` включает замок.

## 2. `argv` в `POST /api/strategies/preview`

Панель гоняет dry-run новым бинарём nfqws2 тем же argv, что у движка, и не должна
разбирать строку `command` с кавычками inline-Lua.

Сделать:
- `StrategyManager.build_preview_argv(strategy, hostlist_path=None) -> list`: полный
  argv через `NFQWSManager.compose_command` (единый источник истины: base-args,
  lua-init, единый `--hostlist`-слой, аргументы стратегии с подставленными путями
  списков). `build_preview_command` склеивает его, как раньше.
- Ответ preview: новое поле `argv: [str]`, это полный argv без первого элемента (путь к
  бинарю). `command` и `args` без изменений. `command` это склейка `[бинарь] + argv`.
- Тесты `tests/test_strategies_preview_argv.py`: `argv` список строк, без бинаря,
  совпадает с `compose_command(args)[1:]`, токены inline-Lua с пробелами и кавычками
  приходят одним элементом, склейка `command` сходится с `argv`.

## 3. `ZG_NONINTERACTIVE=1` в `install.sh`

Драйвер обновления движка в панели зовёт `ZG_NONINTERACTIVE=1 sh install.sh` без tty.
Сейчас скрипт падает на вопросе «Запустить сейчас?» (`read </dev/tty` под `set -e`).

Сделать:
- `prompt_read`: при `ZG_NONINTERACTIVE=1` не читает `/dev/tty`, ответ `n`, в вывод
  пишется `n (ZG_NONINTERACTIVE=1)`. Это покрывает оба вопроса скрипта: «Запустить
  сейчас?» (движок не стартует, рестарт делает драйвер через systemctl) и «Продолжить?»
  у `--uninstall` (отмена).
- При `ZG_NONINTERACTIVE=1` `DEBIAN_FRONTEND=noninteractive` для apt.
- Остальное как сейчас: бэкап `settings.json`, остановка на пустом бэкапе.
- Тесты `tests/test_install_noninteractive.py`: функции из `install.sh` исполняются в
  `sh` без управляющего терминала; с флагом ответ `n` и `systemctl start` не зовётся;
  без флага прежнее поведение (читается `/dev/tty`, без терминала
  это ошибка, из-за неё скрипт и падал); `/dev/tty` читается только
  внутри `prompt_read`.
