# tests/test_install_noninteractive.py
"""
install.sh: ZG_NONINTERACTIVE=1 (debian-gw, docs/gw/spec-t4-updates.md).

Драйвер обновления движка в gw-panel зовёт `ZG_NONINTERACTIVE=1 sh
install.sh` без терминала. Раньше скрипт падал на вопросе «Запустить
сейчас?»: `read </dev/tty` без управляющего терминала под `set -e`.

Функции берутся из самого install.sh (вырезаются по имени) и исполняются
в `sh` в новой сессии, то есть без управляющего терминала, как у
systemd-run или subprocess панели. systemctl и init-скрипт подменены
заглушками, которые пишут вызов в файл.
"""

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL_SH = os.path.join(REPO, "install.sh")


def _source():
    with open(INSTALL_SH, encoding="utf-8") as f:
        return f.read()


def _function(name):
    """Текст shell-функции `name() { ... }` из install.sh."""
    m = re.search(r"^%s\(\) \{\n.*?^\}\n" % re.escape(name), _source(),
                  re.S | re.M)
    if not m:
        raise AssertionError("в install.sh нет функции %s" % name)
    return m.group(0)


@unittest.skipUnless(shutil.which("sh"), "нет sh")
class _ShellBase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.calls = os.path.join(self.tmp, "calls.log")
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        stub = "#!/bin/sh\necho \"$(basename \"$0\") $*\" >> %s\n" % self.calls
        for name in ("systemctl", "S99zapret-gui"):
            path = os.path.join(bindir, name)
            with open(path, "w") as f:
                f.write(stub)
            os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        self.bindir = bindir

    def run_sh(self, body, env_extra=None):
        script = "set -e\n" + body
        env = {"PATH": self.bindir + os.pathsep + os.environ.get("PATH", ""),
               "HOME": self.tmp}
        env.update(env_extra or {})
        # Новая сессия: нет управляющего терминала, /dev/tty не открыть.
        return subprocess.run(["sh", "-c", script], env=env,
                              stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=20,
                              start_new_session=True)

    def called(self):
        if not os.path.exists(self.calls):
            return []
        with open(self.calls) as f:
            return f.read().split("\n")[:-1]


class TestPromptRead(_ShellBase):

    def test_noninteractive_answers_n_without_tty(self):
        r = self.run_sh(_function("prompt_read")
                        + 'prompt_read answer "y"\necho "answer=$answer"\n',
                        {"ZG_NONINTERACTIVE": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("n (ZG_NONINTERACTIVE=1)", r.stdout)
        self.assertIn("answer=n", r.stdout)

    def test_noninteractive_overrides_any_default(self):
        for default in ("y", "Y", ""):
            with self.subTest(default=default):
                r = self.run_sh(_function("prompt_read")
                                + 'prompt_read answer "%s"\n'
                                  'echo "answer=$answer"\n' % default,
                                {"ZG_NONINTERACTIVE": "1"})
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("answer=n", r.stdout)

    def test_other_values_keep_old_behaviour(self):
        # Флаг только "1". Без него скрипт по-прежнему идёт в /dev/tty:
        # без терминала это ошибка (из-за неё и нужен флаг) или, если
        # /dev/tty нечитаем, ответ по умолчанию. Но не принудительное «n».
        for value in (None, "0", "yes"):
            with self.subTest(value=value):
                env = {} if value is None else {"ZG_NONINTERACTIVE": value}
                r = self.run_sh(_function("prompt_read")
                                + 'prompt_read answer "y"\n'
                                  'echo "answer=$answer"\n', env)
                self.assertNotIn("ZG_NONINTERACTIVE=1", r.stdout)
                if r.returncode == 0:
                    self.assertIn("answer=y", r.stdout)


class TestOfferStart(_ShellBase):

    def _body(self, prompt_override=""):
        return (_function("prompt_read") + prompt_override
                + _function("offer_start")
                + 'ENV_TYPE=generic\nSUDO=""\n'
                  'INITD_SCRIPT=S99zapret-gui\noffer_start\necho done\n')

    def test_noninteractive_does_not_start(self):
        r = self.run_sh(self._body(), {"ZG_NONINTERACTIVE": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Запустить сейчас? [Y/n] n (ZG_NONINTERACTIVE=1)",
                      r.stdout)
        self.assertNotIn("автозапуск", r.stdout)
        self.assertIn("done", r.stdout)
        self.assertEqual(self.called(), [])

    def test_noninteractive_does_not_start_initd_either(self):
        body = self._body().replace("ENV_TYPE=generic", "ENV_TYPE=entware")
        r = self.run_sh(body, {"ZG_NONINTERACTIVE": "1"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.called(), [])

    def test_yes_still_starts(self):
        # Ответ «y» (терминал есть) по-прежнему запускает сервис.
        yes = 'prompt_read() { eval "$1=y"; }\n'
        r = self.run_sh(self._body(yes))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.called(), ["systemctl start zapret-gui"])

    def test_no_does_not_start(self):
        no = 'prompt_read() { eval "$1=n"; }\n'
        r = self.run_sh(self._body(no))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.called(), [])


class TestStatic(unittest.TestCase):

    def test_syntax(self):
        if not shutil.which("sh"):
            self.skipTest("нет sh")
        r = subprocess.run(["sh", "-n", INSTALL_SH], capture_output=True,
                           text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_tty_is_read_only_inside_prompt_read(self):
        # Любой вопрос скрипта идёт через prompt_read, иначе флаг его не
        # закроет. Прямое чтение /dev/tty вне функции запрещено.
        src = _source()
        body = _function("prompt_read")
        rest = src.replace(body, "")
        self.assertIn("/dev/tty", body)
        for line in rest.splitlines():
            if line.lstrip().startswith("#"):
                continue
            self.assertFalse(re.search(r"\bread\b.*</dev/tty", line),
                             line)

    def test_every_question_goes_through_prompt_read(self):
        # Строки-вопросы ([y/N], [Y/n]) сразу перед prompt_read.
        lines = _source().splitlines()
        for i, line in enumerate(lines):
            if re.search(r"\[[yY]/[nN]\]", line) and "printf" in line:
                self.assertIn("prompt_read", lines[i + 1], line)

    def test_offer_start_is_called_from_main(self):
        main = _function("main")
        self.assertIn("offer_start", main)

    def test_apt_is_noninteractive_under_flag(self):
        src = _source()
        m = re.search(r'if \[ "\$\{ZG_NONINTERACTIVE:-\}" = "1" \]; then\n'
                      r"\s+export DEBIAN_FRONTEND=noninteractive\nfi", src)
        self.assertIsNotNone(m)


if __name__ == "__main__":
    unittest.main()
