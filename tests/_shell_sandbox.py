# tests/_shell_sandbox.py
"""
Песочница для тестов S12 (shell, файлы, пакеты, службы).

Подчёркивание в имени — чтобы ``unittest discover`` не считал файл
набором тестов (та же роль, что у ``tests/_wsgi_client.py``).

Что она обеспечивает и почему это важно:

* **конфиг во временном каталоге.** Туда же ложатся журнал MCP,
  снимки для отката и файл дедмен-свитчей. Тест, пишущий в настоящий
  ``/opt/etc``, портит машину, на которой его запустили;
* **разрешения, которые видит инструмент.** ``shell_exec`` и
  ``service_control`` спрашивают ``shell_full`` у КОНФИГА (по месту), и
  карты, переданной в ``registry.call``, им мало;
* **чистое состояние модуля.** Токены подтверждения, ярлыки задач и
  таймеры дедменов живут в памяти процесса: не сбросив их, соседний
  тест получает чужое.
"""

import os
import shutil
import tempfile

from core import shell_exec
from core.mcp import registry


class Sandbox:
    """Временный конфиг + разрешения + чистый ``core/shell_exec``."""

    def __init__(self, case, permissions=None, shell=None):
        import core.config_manager as cm

        self.case = case
        self.dir = tempfile.mkdtemp(prefix="mcp-shell-")
        case.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

        saved = cm._config_manager
        case.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        self.cfg = cm._config_manager

        before = os.environ.get("ZAPRET_GUI_CONFIG_DIR")
        case.addCleanup(_restore_env, before)
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = self.dir

        # Рабочий каталог по умолчанию — свой: /opt на машине
        # разработчика может отсутствовать, а запуск команды в чужом
        # каталоге делает тест зависимым от окружения.
        settings = {"workdir": self.dir,
                    "allow_write_paths": [self.dir]}
        settings.update(shell or {})
        self.cfg.set("mcp", "shell", settings)
        self.permissions(**(permissions or {}))

        case.addCleanup(shell_exec.reset_jobs)
        case.addCleanup(shell_exec.reset_confirms)
        case.addCleanup(shell_exec.reset_guards)
        shell_exec.reset_jobs()
        shell_exec.reset_confirms()
        shell_exec.reset_guards()

    def permissions(self, **granted):
        """Выставить разрешения так, как их увидит инструмент."""
        self.cfg.set("mcp", "permissions", dict(granted))
        return dict(granted)

    def path(self, name: str) -> str:
        return os.path.join(self.dir, name)

    def write(self, name: str, text: str) -> str:
        path = self.path(name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def read(self, path: str) -> str:
        with open(path, encoding="utf-8") as f:
            return f.read()

    def call(self, name, args=None, perms=None):
        """Вызов инструмента через реестр (как это делает сервер)."""
        if perms is None:
            perms = self.cfg.get("mcp", "permissions", default={})
        return registry.call(name, args or {}, perms)

    def data(self, name, args=None, perms=None):
        return self.call(name, args, perms)["structuredContent"]


def _restore_env(value):
    if value is None:
        os.environ.pop("ZAPRET_GUI_CONFIG_DIR", None)
    else:
        os.environ["ZAPRET_GUI_CONFIG_DIR"] = value
