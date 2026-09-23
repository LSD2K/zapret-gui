# core/llm_client.py
"""
Клиент к OpenAI-совместимому API: ``/chat/completions`` и ``/models``.

Зачем свой, а не библиотека. Код едет на роутер с ``python3-light``, где
нет ни ``openai``, ни ``requests``, и ставить их ради двух POST'ов
нельзя (принцип §1 CoderManual). Нужного здесь ровно два вызова, и оба
описываются сорока строками ``urllib``.

К кому ходим. К **локальному** серверу: LM Studio (``http://127.0.0.1:
1234/v1``), Ollama (``http://127.0.0.1:11434/v1``), llama.cpp server,
vLLM — всё, что отвечает по схеме OpenAI. Отсюда две особенности:

* **прокси по умолчанию не используем для локальных адресов.** На
  роутере в окружении часто стоит ``HTTPS_PROXY`` (обход блокировок
  настраивает сам GUI), и запрос к ``127.0.0.1`` через прокси —
  гарантированная ошибка там, где всё рядом. Для внешнего адреса
  наоборот: прокси окружения оставляем, иначе туда не пройти;
* **таймаут большой.** Локальная модель на роутере или ноутбуке думает
  десятки секунд, и ``timeout=10`` означал бы «никогда не работает».

Формат запроса и ответа — как в OpenAI Chat Completions: ``messages``,
``tools`` (функции), ответ в ``choices[0].message`` с ``content`` и
``tool_calls``. Разница между серверами начинается дальше (кто как
считает токены, кто присылает ``reasoning``), и её мы не трогаем:
берём то, что нужно, остальное не интерпретируем.

Ответ модели — **недоверенные данные**: это текст, который сочинил
кто-то другой, и имена инструментов в нём проверяются реестром, а не
принимаются на слово.
"""

import json
import socket
import urllib.error
import urllib.request


# Сколько ждём ответа по умолчанию (сек). Модель на роутере думает
# долго; вызов, отвалившийся по таймауту, выглядит как «агент сломан».
DEFAULT_TIMEOUT_SEC = 120

# Потолок тела ответа. Локальный сервер может отдать мегабайт
# «размышлений»; читать их целиком на 128 МБ RAM незачем.
MAX_BODY_BYTES = 4 * 1024 * 1024

# Адреса, к которым ходим МИМО прокси окружения.
_LOCAL_PREFIXES = ("127.", "10.", "192.168.", "169.254.", "172.16.",
                   "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
                   "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                   "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")
_LOCAL_NAMES = ("localhost", "::1", "[::1]")


class LLMError(RuntimeError):
    """Сервер не ответил или ответил не тем. Текст — для человека."""


def normalize_base_url(url: str) -> str:
    """Привести адрес к виду ``http://host:port/v1`` (без хвостового /).

    Человек вставляет в поле и ``http://127.0.0.1:1234``, и адрес с
    ``/v1/chat/completions`` на конце. Молча склеить это с ``/models``
    значит получить 404 и сообщение, по которому ничего не понятно.
    """
    text = (url or "").strip().rstrip("/")
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    for tail in ("/chat/completions", "/completions", "/responses"):
        if text.endswith(tail):
            text = text[:-len(tail)]
            break
    return text.rstrip("/")


def is_local(url: str) -> bool:
    """Локальный ли адрес (для решения про прокси)."""
    host = _host_of(url)
    if not host:
        return False
    host = host.lower()
    if host in _LOCAL_NAMES:
        return True
    return host.startswith(_LOCAL_PREFIXES)


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlsplit
        return (urlsplit(url).hostname or "")
    except Exception:                           # noqa: BLE001 — граница
        return ""


class LLMClient:
    """Минимальный клиент: список моделей и один чат-запрос."""

    __slots__ = ("base_url", "api_key", "timeout", "_opener")

    def __init__(self, base_url: str, api_key: str = "", timeout: int = 0):
        self.base_url = normalize_base_url(base_url)
        self.api_key = (api_key or "").strip()
        self.timeout = int(timeout or DEFAULT_TIMEOUT_SEC)
        # Прокси окружения — только для внешних адресов (см. docstring).
        handlers = [urllib.request.ProxyHandler({})] if \
            is_local(self.base_url) else []
        self._opener = urllib.request.build_opener(*handlers)

    # ─────────────────────────── вызовы ─────────────────────────────

    def models(self) -> list:
        """Список моделей сервера (``GET /models``)."""
        payload = self._request("GET", "/models", None,
                                timeout=min(self.timeout, 20))
        items = payload.get("data")
        if not isinstance(items, list):
            return []
        out = []
        for item in items:
            name = (item or {}).get("id") if isinstance(item, dict) else item
            if isinstance(name, str) and name.strip():
                out.append(name.strip())
        return sorted(set(out))

    def chat(self, messages, tools=None, model: str = "",
             temperature=None, max_tokens=None) -> dict:
        """Один ход разговора. Возвращает ``message`` и ``usage``.

        Ответ приводится к общей форме: ``text`` (что модель сказала),
        ``tool_calls`` (что она хочет вызвать) и ``raw`` — само
        сообщение, как его вернул сервер: в историю диалога кладётся
        именно оно, иначе сервер потеряет привязку ``tool_call_id``.
        """
        body = {
            "model": model or "",
            "messages": list(messages or []),
            "stream": False,
        }
        if tools:
            body["tools"] = list(tools)
            body["tool_choice"] = "auto"
        if temperature is not None:
            body["temperature"] = float(temperature)
        if max_tokens:
            body["max_tokens"] = int(max_tokens)

        payload = self._request("POST", "/chat/completions", body)
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LLMError("сервер вернул ответ без choices: %s"
                           % _short(payload))
        message = (choices[0] or {}).get("message")
        if not isinstance(message, dict):
            raise LLMError("сервер вернул choice без message: %s"
                           % _short(choices[0]))
        return {
            "text": _text_of(message),
            "tool_calls": _tool_calls_of(message),
            "finish_reason": (choices[0] or {}).get("finish_reason", ""),
            "usage": payload.get("usage") or {},
            "raw": message,
        }

    # ─────────────────────────── транспорт ──────────────────────────

    def _request(self, method: str, path: str, body, timeout: int = 0):
        if not self.base_url:
            raise LLMError("адрес сервера не задан (agent.base_url)")
        url = self.base_url + path
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key

        request = urllib.request.Request(url, data=data, headers=headers,
                                         method=method)
        try:
            with self._opener.open(request,
                                   timeout=timeout or self.timeout) as answer:
                raw = answer.read(MAX_BODY_BYTES)
        except urllib.error.HTTPError as e:
            raise LLMError(_http_error(url, e))
        except urllib.error.URLError as e:
            raise LLMError(
                "%s недоступен: %s. Проверьте, что сервер модели запущен "
                "и слушает этот адрес (LM Studio: Developer → Start "
                "Server; Ollama: OLLAMA_HOST)"
                % (url, getattr(e, "reason", e)))
        except socket.timeout:
            raise LLMError("%s не ответил за %d с — модель ещё думает или "
                           "сервер завис" % (url, timeout or self.timeout))
        except OSError as e:
            raise LLMError("%s: ошибка соединения: %s" % (url, e))

        try:
            return json.loads(raw.decode("utf-8", "replace") or "{}")
        except ValueError as e:
            raise LLMError("%s ответил не JSON'ом (%s): %s"
                           % (url, e, _short(raw[:200])))


# ───────────────────────────── частности ────────────────────────────

def _http_error(url: str, error) -> str:
    """Понятный текст вместо «HTTP Error 404»."""
    try:
        body = error.read(4096).decode("utf-8", "replace")
    except Exception:                           # noqa: BLE001 — граница
        body = ""
    detail = ""
    try:
        parsed = json.loads(body or "{}")
        detail = str((parsed.get("error") or {}).get("message")
                     or parsed.get("error") or "")
    except ValueError:
        detail = body[:200]
    hint = ""
    if error.code == 404:
        hint = (" — адрес должен оканчиваться на /v1 (LM Studio: "
                "http://127.0.0.1:1234/v1, Ollama: "
                "http://127.0.0.1:11434/v1)")
    elif error.code in (401, 403):
        hint = " — сервер требует ключ (agent.api_key)"
    return "%s ответил %s%s%s" % (url, error.code,
                                  (": " + detail) if detail else "", hint)


def _text_of(message: dict) -> str:
    """Текст сообщения; некоторые серверы шлют его списком частей."""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text") or ""))
            elif isinstance(item, str):
                parts.append(item)
        return "".join(parts)
    return ""


def _tool_calls_of(message: dict) -> list:
    """Вызовы инструментов в общей форме ``{id, name, arguments}``.

    Аргументы приезжают СТРОКОЙ с JSON внутри — таков формат. Разбор
    здесь же: дальше с ним работают как со словарём, а неразобранная
    строка остаётся в ``arguments_raw``, чтобы было что показать в
    ошибке.
    """
    calls = message.get("tool_calls")
    if not isinstance(calls, list):
        return []
    out = []
    for index, item in enumerate(calls):
        if not isinstance(item, dict):
            continue
        function = item.get("function") or {}
        name = str(function.get("name") or "").strip()
        if not name:
            continue
        raw = function.get("arguments")
        parsed, error = {}, ""
        if isinstance(raw, dict):
            parsed = raw
        elif isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
            except ValueError as e:
                error = "аргументы не разобраны как JSON: %s" % e
            if not isinstance(parsed, dict):
                parsed, error = {}, error or "аргументы не объект JSON"
        out.append({
            "id": str(item.get("id") or "call_%d" % index),
            "name": name,
            "arguments": parsed,
            "arguments_raw": raw if isinstance(raw, str) else "",
            "error": error,
        })
    return out


def _short(value, limit: int = 200) -> str:
    try:
        text = value if isinstance(value, str) else json.dumps(
            value, ensure_ascii=False, default=str)
    except Exception:                           # noqa: BLE001 — граница
        text = str(value)
    return text[:limit]
