# core/mcp/__init__.py
"""
MCP-сервер zapret-gui (Model Context Protocol, ревизия 2025-06-18).

Внешняя модель (Claude Desktop/Code, LM Studio, Cline) ходит в
``POST /api/mcp`` и управляет GUI: читает статус, подбирает стратегии
nfqws2 и видит результат каждого своего изменения.

Состав пакета:

  ``schema.py``  — сборка JSON Schema инструмента и мини-валидатор
                   аргументов (без ``jsonschema``: на роутере stdlib);
  ``auth.py``    — Bearer-токен, Origin-check, bind, рейт-лимит;
  ``server.py``  — диспетчер JSON-RPC и реестр инструментов.

HTTP-слой живёт в ``api/mcp.py`` и обслуживается тем же веб-сервером,
что и GUI (адрес/порт/TLS — это ``gui.host``/``gui.port``).

Ограничение, действующее на весь пакет: **только stdlib**. Код едет на
роутер с ``python3-light``, где нет ни ``mcp``, ни ``pydantic``, ни
``jsonschema``.
"""

from core.mcp.server import PROTOCOL_VERSION, dispatch  # noqa: F401

__all__ = ["PROTOCOL_VERSION", "dispatch"]
