# core/mcp/tools/system.py
"""
Перезагрузка устройства — единственный инструмент под ``dangerous``.

Три вещи, которые делают её безопасной настолько, насколько
перезагрузка вообще может быть безопасной:

1. **Отдельное разрешение.** ``dangerous`` не включается «заодно»: это
   то же разрешение, под которым живут бинарники и автозапуск.
2. **Подтверждение.** Первый вызов возвращает ``confirm_token`` и
   описание последствий, исполняет — ``shell_confirm``. Токен помнит,
   какое разрешение нужно, и оно проверяется **на обоих шагах**.
3. **Отложенный запуск в отвязанном процессе.** Команду даёт
   ``core/system_control.py`` (на Keenetic — ``ndmc``, штатный путь
   прошивки с корректным размонтированием), и уходит она через пару
   секунд после ответа: иначе клиент видел бы обрыв соединения вместо
   подтверждения и не знал, приняли команду или нет.

Инструмента ``teardown`` здесь нет и не будет (инвариант §5.7): снос
runtime-артефактов делается осознанно, через shell при полном доступе.
"""

from core import shell_exec as shell
from core.mcp import audit
from core.mcp.registry import tool


@tool(
    name="system_reboot",
    scope="dangerous",
    mutating=True,
    title="Reboot the device",
    description=("Reboot the router. Two-step: this call returns a "
                 "confirm_token, shell_confirm actually reboots. "
                 "Connectivity is lost for 1-2 minutes and unsaved "
                 "state is gone. / Перезагрузить устройство."),
    schema={
        "type": "object",
        "properties": {
            "reason": {"type": "string", "maxLength": 200,
                       "description": "Why, for the audit log. / Зачем — "
                                      "строка для журнала."},
        },
        "additionalProperties": False,
    },
)
def system_reboot(args: dict) -> dict:
    """Запросить перезагрузку: ответ — токен подтверждения."""
    from core import system_control

    caps = system_control.capabilities()
    if not caps.get("reboot"):
        return {"ok": False,
                "error": "команда перезагрузки на этом устройстве не "
                         "найдена (нет ни ndmc, ни reboot)",
                "hint": "перезагрузите роутер штатным способом"}

    reason = str(args.get("reason") or "").strip()
    return shell.pending_confirm(
        "reboot", caps.get("reboot_command", "reboot"),
        "устройство перезагрузится: связь пропадёт на 1–2 минуты, "
        "незавершённые прогоны и несохранённые изменения будут "
        "потеряны%s" % (" (причина: %s)" % reason if reason else ""),
        scope="dangerous",
        payload={"reason": reason,
                 "command": caps.get("reboot_command", "")},
        action=_do_reboot,
        rules=({"code": "reboot"},))


def _do_reboot(record: dict) -> dict:
    """Собственно перезагрузка — после подтверждения."""
    from core import system_control

    payload = record.get("payload") or {}
    outcome = system_control.reboot_device()
    audit.note(action="reboot", reason=payload.get("reason", ""),
               command=outcome.get("command", ""),
               ok=bool(outcome.get("ok")))
    result = dict(outcome)
    result["confirmed"] = True
    result["reason"] = payload.get("reason", "")
    if outcome.get("ok"):
        result["hint"] = ("команда отдана с задержкой %s с — ответ "
                          "успевает уйти до разрыва связи; дальше "
                          "устройство недоступно 1–2 минуты"
                          % outcome.get("delay_sec", 2))
    return result
