# tests/_code_sandbox.py
"""
Песочница для тестов S13 (самоправка кода GUI).

Подчёркивание в имени — чтобы ``unittest discover`` не считал файл
набором тестов (та же роль, что у ``tests/_shell_sandbox.py``, на
котором она и построена).

Что добавлено к shell-песочнице:

* **отдельный «проект»** во временном каталоге — маленький, но
  настоящий: пакет ``core`` с ``__init__.py``, пара модулей, ``.js`` и
  ``.json``. Проверки самоправки импортируют модуль подпроцессом, и
  делать это на настоящем дереве репозитория нельзя: тест, который
  правит собственные исходники, портит машину, на которой запущен;
* **``mcp.self_edit.root``**, указывающий на этот каталог, — границы
  правки считаются от него;
* **снимки и staging** ложатся в конфиг песочницы (он же
  ``ZAPRET_GUI_CONFIG_DIR``), то есть тоже во временный каталог.
"""

import os

from tests._shell_sandbox import Sandbox


# Маленький проект: ровно то, что нужно проверкам — пакет, модуль,
# защищённый файл, не-python файлы.
FILES = {
    "core/__init__.py": "# core/__init__.py\n",
    "core/demo.py": (
        '"""Демо-модуль песочницы."""\n'
        "\n"
        "VALUE = 1\n"
        "\n"
        "\n"
        "def compose(prefix):\n"
        '    """Собрать строку."""\n'
        '    return "%s-%d" % (prefix, VALUE)\n'
    ),
    "core/other.py": (
        "from core.demo import compose\n"
        "\n"
        "\n"
        "def greet():\n"
        '    return compose("hi")\n'
    ),
    "core/config_manager.py": "# защищённый файл песочницы\nX = 1\n",
    "web/js/pages/demo.js": "export const demo = 1;\n",
    "config/sample.json": '{"a": 1}\n',
    "README.md": "# demo\n",
}


class CodeSandbox(Sandbox):
    """Временный конфиг + временный «проект» + разрешения."""

    def __init__(self, case, permissions=None, self_edit=None,
                 files=None):
        super().__init__(case, permissions=permissions)
        self.root = os.path.join(self.dir, "project")
        for rel, text in dict(FILES, **(files or {})).items():
            self.put(rel, text)
        settings = {"root": self.root, "snapshots_keep": 3,
                    "restart_timeout_sec": 2, "commit_ttl_sec": 2,
                    "run_tests": False,
                    "protected": ["core/config_manager.py"]}
        settings.update(self_edit or {})
        self.cfg.set("mcp", "self_edit", settings)

    # ── файлы «проекта» ──────────────────────────────────────────
    def put(self, rel: str, text: str) -> str:
        """Положить файл в проект (мимо самоправки)."""
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def text(self, rel: str) -> str:
        """Прочитать файл проекта как он лежит на диске."""
        with open(os.path.join(self.root, rel), encoding="utf-8") as f:
            return f.read()

    def exists(self, rel: str) -> bool:
        return os.path.exists(os.path.join(self.root, rel))

    def full(self, rel: str) -> str:
        return os.path.join(self.root, rel)


class Clock:
    """Часы, которые двигает сам ``sleep``.

    Сторож ждёт секундами; гонять тест в реальном времени значит
    добавить к прогону минуты и получить хлопающий тест на медленной
    машине.
    """

    def __init__(self, start: float = 1000.0):
        self.now = float(start)
        self.slept = 0.0

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float):
        self.now += float(seconds)
        self.slept += float(seconds)


class Health:
    """Поддельная проверка «GUI жив»: список ответов по порядку.

    Последнее значение повторяется — так описывается «упал и больше не
    поднялся» одной строкой.
    """

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = 0

    def __call__(self) -> bool:
        self.calls += 1
        if not self.answers:
            return True
        if len(self.answers) == 1:
            return bool(self.answers[0])
        return bool(self.answers.pop(0))
