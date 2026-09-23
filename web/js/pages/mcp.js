/**
 * mcp.js — Страница «MCP-сервер».
 *
 * Здесь у человека руль и тормоз: включить точку доступа, выдать токен,
 * раздать разрешения, увидеть, что натворила модель, и всё это отобрать
 * одной кнопкой.
 *
 * Три правила, из которых сделана вся страница:
 *
 *   1. **Один роут — один ответ.** Всё состояние приезжает из
 *      `GET /api/mcp/ui/state`. Собирать его из шести вызовов нельзя:
 *      на роутере со 128 МБ страница будет мигать.
 *   2. **Токен не логируем и не кладём в URL.** Он приходит только по
 *      явному клику («Показать») отдельным запросом и живёт в памяти
 *      страницы до ухода с неё.
 *   3. **Один таймер на страницу**, и тот останавливается в `destroy()`
 *      и на скрытой вкладке. Роутер слабый.
 *
 * Тексты предупреждений — в `web/js/i18n/*.js` (ключи `mcp.warn.*` и
 * `mcp.risk.*`), а не в разметке: их же слово в слово переиспользует
 * README.
 */

const McpPage = (() => {
    // ══════════════════ Состояние ══════════════════

    const POLL_MS = 5000;

    let _container = null;
    let _timer = null;
    let _state = null;

    // Токен живёт только в памяти страницы и только после явного клика.
    let _token = "";
    let _tokenVisible = false;

    // Идёт действие пользователя — опрос на это время замолкает, иначе
    // ответ опроса перерисует блок под рукой и снимет галочку обратно.
    let _busy = false;

    // GUI перезапускается после правки кода: разрыв связи здесь —
    // ожидаемое состояние, а не ошибка сети.
    let _restarting = false;

    // Открытый черновик issue: текст и ссылка — по клику «Показать».
    let _issue = null;

    // Подписи блоков: перерисовываем только то, что изменилось.
    const _sig = {};

    // Разрешения в том порядке, в котором их читает человек: сначала
    // безобидные, ниже — те, после которых роутер уже не ваш. Порядок —
    // как PERMISSIONS в core/mcp/permissions.py: разрешение, забытое
    // здесь, не получает переключателя вовсе (так было с `secrets`),
    // поэтому полноту списка сторожит tests/test_mcp_page.js.
    const PERM_ORDER = [
        'control', 'strategies_write', 'config_write', 'probes',
        'experiments', 'tunnels_write', 'dangerous',
        'shell_readonly', 'shell_full', 'self_edit', 'self_edit_core',
        'secrets',
    ];

    // Разрешения, у которых своя рамка и своё предупреждение.
    const PERM_SHELL = ['shell_readonly', 'shell_full'];
    const PERM_CODE = ['self_edit', 'self_edit_core'];

    // ══════════════════ Рендер ══════════════════

    async function render(container) {
        _container = container;
        _token = '';
        _tokenVisible = false;
        _restarting = false;
        _issue = null;
        Object.keys(_sig).forEach(k => delete _sig[k]);

        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">MCP-сервер</h1>
                    <p class="page-description">
                        Управление роутером из внешней модели
                        (Claude, LM Studio, Cline) по протоколу MCP
                    </p>
                </div>
            </div>

            <div id="mcp-banner"></div>

            <div class="card" id="mcp-status-card">
                <div class="card-title">Точка доступа</div>
                <div id="mcp-status">${_loading()}</div>
            </div>

            <div class="card" id="mcp-token-card">
                <div class="card-title">Токен</div>
                <div id="mcp-token">${_loading()}</div>
            </div>

            <div class="card" id="mcp-perms-card">
                <div class="card-title">Разрешения</div>
                <div id="mcp-perms">${_loading()}</div>
            </div>

            <div class="card" id="mcp-snippets-card">
                <div class="card-title">Как подключить клиента</div>
                <div id="mcp-snippets">${_loading()}</div>
            </div>

            <div class="card" id="mcp-exp-card" style="display:none;">
                <div class="card-title">Эксперимент со стратегиями</div>
                <div id="mcp-exp"></div>
            </div>

            <div class="card" id="mcp-code-card" style="display:none;">
                <div class="card-title">Правка кода GUI (self-edit): только файлы GUI</div>
                <div id="mcp-code"></div>
            </div>

            <div class="card" id="mcp-shell-card" style="display:none;">
                <div class="card-title">Shell-доступ: вся система от root</div>
                <div id="mcp-shell"></div>
            </div>

            <div class="card" id="mcp-issues-card" style="display:none;">
                <div class="card-title">Черновики issue</div>
                <div id="mcp-issues"></div>
                <div id="mcp-issue-preview" style="display:none;margin-top:10px;">
                    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;">
                        <button class="btn btn-sm btn-primary" data-action="issueOpen">Открыть на GitHub</button>
                        <button class="btn btn-sm" data-action="issueCopy">Скопировать текст</button>
                        <button class="btn btn-sm" data-action="issueClose">Скрыть</button>
                    </div>
                    <pre id="mcp-issue-text" class="text-mono"
                         style="padding:10px;border-radius:6px;max-height:420px;overflow:auto;
                                font-size:12px;white-space:pre-wrap;word-break:break-word;
                                background:var(--bg-input,rgba(0,0,0,.2));"></pre>
                </div>
            </div>

            <div class="card" id="mcp-audit-card">
                <div class="card-title">Журнал вызовов</div>
                <div id="mcp-audit">${_loading()}</div>
            </div>
        `;

        container.addEventListener('click', _onClick);
        container.addEventListener('change', _onChange);

        await _tick();
    }

    function destroy() {
        if (_timer) { clearTimeout(_timer); _timer = null; }
        _container = null;
        _state = null;
        // Токен не переживает уход со страницы: он и так живёт в
        // settings.json, а в памяти вкладки ему делать нечего.
        _token = '';
        _tokenVisible = false;
        _issue = null;
    }

    // ══════════════════ Опрос ══════════════════

    async function _tick() {
        if (!_container) return;
        if (_busy || (typeof document !== 'undefined' && document.hidden)) {
            _schedule();
            return;
        }
        try {
            const data = await API.get('/api/mcp/ui/state');
            if (!_container) return;
            if (_restarting) { _restarting = false; _banner(''); }
            _state = data;
            _paint(data);
        } catch (e) {
            if (!_container) return;
            if (_restarting) {
                // Ожидаемое состояние: GUI поднимается после code_apply.
                _banner(_t('mcp.warn.restart'), 'warning');
            } else {
                _banner('Не удалось получить состояние: ' + String(e.message || e),
                        'danger');
            }
        }
        _schedule();
    }

    function _schedule() {
        if (_timer) clearTimeout(_timer);
        _timer = setTimeout(_tick, POLL_MS);
    }

    /** Перерисовать только те блоки, чьё содержимое изменилось. */
    function _paint(state) {
        const info = state.info || {};
        const access = state.access || {};

        _section('mcp-status', _statusHtml(info, access),
                 [info.enabled, info.active, info.token_set,
                  info.tools_available, info.tools_total,
                  JSON.stringify(info.tools_by_scope || {}),
                  JSON.stringify(info.sse || {}), access.loopback_only,
                  JSON.stringify(info.transports || {})]);

        _section('mcp-token', _tokenHtml(info),
                 [info.token_set, _tokenVisible, _token.length]);

        _section('mcp-perms', _permsHtml(info),
                 [JSON.stringify(info.permissions_info || [])]);

        _section('mcp-snippets', _snippetsHtml(info),
                 [_tokenVisible, _token.length, (info.sse || {}).enabled]);

        _block('mcp-exp', state.experiment, _experimentHtml);
        _block('mcp-code', _withPerms(state, state.code,
                                     ['self_edit', 'self_edit_core']),
               _codeHtml);
        _block('mcp-shell', _withPerms(state, state.shell,
                                       ['shell_readonly', 'shell_full']),
               _shellHtml);

        // Карточка черновиков видна, когда в ней есть что показать:
        // пустой блок «модель ничего не сообщала» — шум на каждой
        // странице.
        const issues = state.issues || {};
        _block('mcp-issues', Object.assign({}, issues, {
            available: !!(issues.available && ((issues.drafts || []).length
                                               || (issues.crashes || []).length)),
        }), _issuesHtml);

        _section('mcp-audit', _auditHtml(state.audit || {}),
                 [JSON.stringify((state.audit || {}).records || []),
                  JSON.stringify((state.audit || {}).undoable || [])]);
    }

    /** Блок 6–8: карточка целиком скрыта, если сессии на устройстве нет. */
    function _block(id, data, builder) {
        const card = document.getElementById(id + '-card');
        if (!card) return;
        if (!data || !data.available) {
            card.style.display = 'none';
            return;
        }
        card.style.display = '';
        _section(id, builder(data), [JSON.stringify(data)]);
    }

    /** Подмешать в блок его переключатели-разрешения.

     * Они живут в `info.permissions`, а рисуются здесь: тормоз должен
     * быть рядом с тем, что он гасит, а не через три карточки.
     */
    function _withPerms(state, block, keys) {
        if (!block || !block.available) return block;
        const perms = (state.info || {}).permissions || {};
        const out = Object.assign({}, block);
        keys.forEach(key => { out[key] = !!perms[key]; });
        return out;
    }

    function _section(id, html, signature) {
        const key = String(signature.join('\u0001'));
        if (_sig[id] === key) return;
        const el = document.getElementById(id);
        if (!el) return;
        el.innerHTML = html;
        _sig[id] = key;
    }

    // ══════════════════ Блок 1: включение и статус ══════════════════

    function _statusHtml(info, access) {
        const total = info.tools_total || 0;
        const available = info.tools_available || 0;
        const scopes = info.tools_by_scope || {};
        const scopeRow = Object.keys(scopes).sort()
            .map(k => `<span class="badge badge-muted" style="margin-right:6px;">${esc(k)}: ${scopes[k]}</span>`)
            .join('');

        const warnings = [];
        if (info.enabled && !info.active) {
            warnings.push(['warning',
                'Точка включена, но пускать некого: токен не задан. ' +
                'Сгенерируйте его ниже.']);
        }
        if (access.loopback_only) {
            warnings.push(['info', _t('mcp.warn.loopback')]);
        } else if (_isPlainHttp()) {
            warnings.push(['danger', _t('mcp.warn.http')]);
        }

        const sse = info.sse || {};
        const transports = info.transports || {};
        // Ключа нет — транспорт включён: он был всегда, и обновление GUI
        // не должно выключать его молча (core/mcp/auth.http_enabled).
        const httpOn = transports.http !== false;
        if (!httpOn) {
            warnings.push(['warning',
                'Основной транспорт (POST /api/mcp) выключен: клиенты ' +
                'получают 503. Работают только stdio-мост и, если ' +
                'включён, старый SSE.']);
        }

        return `
            <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:14px;">
                <label class="settings-toggle" for="mcp-enabled">
                    <input type="checkbox" id="mcp-enabled" ${info.enabled ? 'checked' : ''}
                           data-action="toggleEnabled">
                    <span class="settings-toggle-slider"></span>
                    <span class="settings-toggle-label">
                        ${info.enabled ? 'Включён' : 'Выключен'}
                    </span>
                </label>
                <div style="flex:1;min-width:220px;">
                    <div class="text-muted" style="font-size:12px;">Адрес точки доступа</div>
                    <div class="text-mono" id="mcp-endpoint">${esc(_endpoint(info))}</div>
                </div>
                <div style="text-align:right;min-width:170px;">
                    <div class="text-muted" style="font-size:12px;">Публикуется инструментов</div>
                    <div style="font-size:26px;font-weight:600;line-height:1.1;">
                        ${available}<span class="text-muted" style="font-size:15px;"> / ${total}</span>
                    </div>
                </div>
            </div>

            <div style="margin-bottom:12px;">${scopeRow || ''}</div>

            ${warnings.map(([kind, text]) =>
                `<div class="alert alert-${kind}">${esc(text)}</div>`).join('')}

            <div style="display:flex;gap:18px;flex-wrap:wrap;font-size:13px;"
                 class="text-muted">
                <span>Версия протокола: <span class="text-mono">${esc(info.protocol_version || '')}</span></span>
                <span>Справочников: ${info.resources || 0}</span>
                <span>Сценариев: ${info.prompts || 0}</span>
                <span>Журнал: ${info.audit && info.audit.enabled ? 'ведётся' : 'выключен'}</span>
            </div>

            <div style="margin-top:14px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                <label class="settings-toggle" for="mcp-http">
                    <input type="checkbox" id="mcp-http" ${httpOn ? 'checked' : ''}
                           data-action="toggleHttp">
                    <span class="settings-toggle-slider"></span>
                    <span class="settings-toggle-label">Основной транспорт (POST)</span>
                </label>
                <span class="text-muted" style="font-size:12px;max-width:520px;">
                    Обычный путь всех клиентов. Выключение закрывает
                    точку для них, но не эту страницу — включить обратно
                    можно отсюда же. Stdio-мост работает независимо.
                </span>
            </div>

            <div style="margin-top:14px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                <label class="settings-toggle" for="mcp-sse">
                    <input type="checkbox" id="mcp-sse" ${sse.enabled ? 'checked' : ''}
                           data-action="toggleSse">
                    <span class="settings-toggle-slider"></span>
                    <span class="settings-toggle-label">Старый транспорт SSE</span>
                </label>
                <span class="text-muted" style="font-size:12px;max-width:520px;">
                    Нужен клиентам, которые не умеют ничего другого
                    (часть сборок LM Studio, старые Cline). Открыто
                    потоков: ${sse.sessions || 0} из ${sse.max_sessions || 0}.
                    Только здесь работает подписка на ресурсы
                    (<code>resources/subscribe</code>): модель узнаёт о
                    прогрессе долгих операций уведомлением, а не опросом.
                </span>
            </div>
        `;
    }

    // ══════════════════ Блок 2: токен ══════════════════

    function _tokenHtml(info) {
        const shown = _tokenVisible && _token;
        return `
            <div class="alert alert-warning">${esc(_t('mcp.warn.token'))}</div>

            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
                <code class="text-mono" id="mcp-token-value"
                      style="flex:1;min-width:260px;padding:8px 10px;border-radius:6px;
                             background:var(--bg-input,rgba(0,0,0,.2));word-break:break-all;">
                    ${shown ? esc(_token)
                            : (info.token_set ? '••••••••••••••••••••••••••••••••'
                                              : 'токен не задан')}
                </code>
            </div>

            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                ${info.token_set ? `
                    <button class="btn btn-sm" data-action="${shown ? 'tokenHide' : 'tokenShow'}">
                        ${shown ? 'Скрыть' : 'Показать'}
                    </button>
                    <button class="btn btn-sm" data-action="tokenCopy">Скопировать</button>
                    <button class="btn btn-sm btn-warning" data-action="tokenRotate">Ротировать</button>
                    <button class="btn btn-sm btn-danger" data-action="tokenClear">Стереть</button>
                ` : `
                    <button class="btn btn-sm btn-primary" data-action="tokenRotate">Сгенерировать</button>
                `}
            </div>
        `;
    }

    // ══════════════════ Блок 3: разрешения ══════════════════

    function _permsHtml(info) {
        const items = {};
        (info.permissions_info || []).forEach(p => { items[p.key] = p; });

        const rows = PERM_ORDER.filter(k => items[k]).map(k => _permRow(items[k]));

        return `
            <p class="text-muted" style="margin-top:0;">
                Чтение доступно всегда и переключателя не имеет. Всё
                остальное выключено по умолчанию; изменения действуют
                сразу, перезапускать GUI не нужно.
            </p>
            ${rows.join('')}
        `;
    }

    function _permRow(item) {
        const key = item.key;
        const blocked = item.granted && (item.missing || []).length > 0;
        const risky = PERM_SHELL.indexOf(key) >= 0 || PERM_CODE.indexOf(key) >= 0
                      || key === 'dangerous' || key === 'secrets';

        let note = '';
        if (blocked) {
            note = `<div class="text-warning" style="font-size:12px;margin-top:4px;">
                        Не действует: сначала включите
                        ${esc((item.missing || []).join(', '))}
                    </div>`;
        } else if ((item.implied_by || []).length) {
            note = `<div class="text-muted" style="font-size:12px;margin-top:4px;">
                        Уже открыто разрешением
                        ${esc((item.implied_by || []).join(', '))}
                    </div>`;
        } else if ((item.requires || []).length) {
            note = `<div class="text-muted" style="font-size:12px;margin-top:4px;">
                        Требует: ${esc((item.requires || []).join(', '))}
                    </div>`;
        }

        // Разрешение, которое стоит, но не действует, показываем
        // явно: иначе человек видит включённый флаг и выключенные
        // инструменты и идёт чинить то, что не сломано.
        const state = item.effective
            ? '<span class="badge badge-success">действует</span>'
            : (item.granted ? '<span class="badge badge-warning">не действует</span>' : '');

        return `
            <div style="display:flex;gap:12px;padding:10px 0;align-items:flex-start;
                        border-top:1px solid var(--border,rgba(255,255,255,.07));">
                <label class="settings-toggle" for="mcp-perm-${esc(key)}" style="flex:0 0 auto;">
                    <input type="checkbox" id="mcp-perm-${esc(key)}"
                           ${item.granted ? 'checked' : ''}
                           data-action="togglePerm" data-perm="${esc(key)}">
                    <span class="settings-toggle-slider"></span>
                </label>
                <div style="flex:1;min-width:0;">
                    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                        <span class="text-mono ${risky ? 'text-error' : ''}"
                              style="font-weight:600;">${esc(key)}</span>
                        ${state}
                    </div>
                    <div style="font-size:13px;margin-top:2px;">${esc(item.title || '')}</div>
                    <div class="${risky ? 'text-warning' : 'text-muted'}"
                         style="font-size:12px;margin-top:2px;">
                        ${esc(_t('mcp.risk.' + key))}
                    </div>
                    ${note}
                </div>
            </div>
        `;
    }

    // ══════════════════ Блок 4: сниппеты подключения ══════════════════

    function _snippetsHtml(info) {
        const url = _endpoint(info);
        const token = (_tokenVisible && _token) ? _token : '<ваш-токен>';
        const sseUrl = url.replace(/\/api\/mcp$/, '/api/mcp/sse');

        const snippets = [
            ['Claude Code',
             `claude mcp add --transport http zapret-gui ${url} \\\n` +
             `  --header "Authorization: Bearer ${token}"`],
            ['Claude Desktop / LM Studio (mcpServers)',
             JSON.stringify({
                 mcpServers: {
                     'zapret-gui': {
                         url: url,
                         headers: { Authorization: 'Bearer ' + token },
                     },
                 },
             }, null, 2)],
            ['VS Code — .vscode/mcp.json',
             JSON.stringify({
                 inputs: [{
                     type: 'promptString',
                     id: 'zapret-token',
                     description: 'Токен MCP zapret-gui',
                     password: true,
                 }],
                 servers: {
                     'zapret-gui': {
                         type: 'http',
                         url: url,
                         headers: {
                             Authorization: 'Bearer ${input:zapret-token}',
                         },
                     },
                 },
             }, null, 2)],
            ['По ssh, без токена и без открытого порта',
             'ssh router zapret-gui mcp --stdio'],
        ];

        if ((info.sse || {}).enabled) {
            snippets.splice(3, 0, ['Старый клиент (SSE)',
                `${sseUrl}\nAuthorization: Bearer ${token}`]);
        }

        return `
            <p class="text-muted" style="margin-top:0;">
                ${_tokenVisible && _token
                    ? 'Токен подставлен в примеры — не выкладывайте их никуда.'
                    : 'Нажмите «Показать» в блоке токена, чтобы подставить его в примеры.'}
                В файле VS Code токена нет намеренно: редактор спросит его сам
                и не положит в репозиторий.
            </p>
            <p class="text-muted" style="font-size:12px;margin-top:0;">
                Если модель локальная и внешний клиент не нужен — есть
                страница <a href="#agent">«Агент»</a>: она ходит теми же
                инструментами и под этими же разрешениями, но без токена
                и без открытого порта.
            </p>
            ${snippets.map(([title, text], i) => `
                <div style="margin-bottom:12px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
                        <span style="font-size:13px;font-weight:600;">${esc(title)}</span>
                        <button class="btn btn-sm" data-action="copySnippet"
                                data-index="${i}">Копировать</button>
                    </div>
                    <pre class="text-mono" id="mcp-snippet-${i}"
                         style="margin:6px 0 0;padding:10px;border-radius:6px;overflow:auto;
                                background:var(--bg-input,rgba(0,0,0,.2));font-size:12px;
                                white-space:pre-wrap;word-break:break-all;">${esc(text)}</pre>
                </div>
            `).join('')}
        `;
    }

    // ══════════════════ Блок 5: журнал ══════════════════

    function _auditHtml(audit) {
        if (!audit.enabled) {
            return `<p class="text-muted">Журнал выключен
                    (<span class="text-mono">mcp.audit.enabled</span>).</p>`;
        }
        const records = audit.records || [];
        const undoable = audit.undoable || [];

        const head = `
            <div style="display:flex;justify-content:space-between;align-items:center;
                        gap:8px;flex-wrap:wrap;margin-bottom:10px;">
                <span class="text-muted" style="font-size:12px;">
                    Последние ${records.length} вызовов ·
                    <span class="text-mono">${esc(audit.path || '')}</span>
                </span>
                <button class="btn btn-sm ${undoable.length ? 'btn-warning' : ''}"
                        data-action="undoLast" ${undoable.length ? '' : 'disabled'}>
                    Отменить последнее изменение${undoable.length
                        ? ' (' + esc(undoable[0].kind || '') + ')' : ''}
                </button>
            </div>`;

        if (!records.length) {
            return head + `<p class="text-muted">Вызовов ещё не было.</p>`;
        }

        const rows = records.map(r => `
            <tr>
                <td class="text-mono" style="white-space:nowrap;">${esc(r.time || '')}</td>
                <td class="text-mono">${esc(r.tool || '')}</td>
                <td>${_statusBadge(r)}</td>
                <td class="text-muted" style="font-size:12px;">
                    ${esc(r.scope || 'read')}${r.mutating ? ' · меняет' : ''}
                </td>
                <td class="text-muted" style="font-size:12px;word-break:break-all;">
                    ${esc(r.error || _args(r.args))}
                </td>
            </tr>`).join('');

        return head + `
            <div style="overflow:auto;">
                <table class="table" style="font-size:13px;">
                    <thead><tr>
                        <th>Время</th><th>Инструмент</th><th>Итог</th>
                        <th>Разрешение</th><th>Аргументы / ошибка</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>`;
    }

    function _statusBadge(record) {
        const map = {
            ok: ['badge-success', 'ок'],
            error: ['badge-danger', 'ошибка'],
            denied: ['badge-warning', 'отказано'],
            invalid: ['badge-warning', 'аргументы'],
            unknown: ['badge-muted', 'нет такого'],
        };
        const [cls, label] = map[record.status] || ['badge-muted', record.status || ''];
        return `<span class="badge ${cls}">${esc(label)}</span>`;
    }

    function _args(args) {
        if (!args || typeof args !== 'object') return '';
        const text = JSON.stringify(args);
        return text.length > 160 ? text.slice(0, 160) + '…' : text;
    }

    // ══════════════════ Блок 6: эксперимент ══════════════════

    function _experimentHtml(block) {
        if (block.error) {
            return `<div class="alert alert-warning">${esc(block.error)}</div>`;
        }
        const s = block.status || {};
        if (!s.state || s.state === 'idle') {
            return `<p class="text-muted">Прогонов нет. Эксперимент
                    запускает модель инструментом
                    <span class="text-mono">strategy_experiment_start</span>.</p>`;
        }

        const running = s.state === 'running';
        const total = s.total || 0;
        const done = s.progress || 0;
        const percent = total ? Math.round((done / total) * 100) : 0;

        const ttl = s.awaiting_commit && s.ttl_left_sec
            ? `<div class="alert alert-warning">
                   Вариант <span class="text-mono">${esc(s.applied_variant || '')}</span>
                   остаётся применённым ещё ${s.ttl_left_sec} с, потом
                   состояние вернётся к снимку само.
               </div>`
            : '';

        return `
            ${ttl}
            <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:10px;">
                <div><div class="text-muted" style="font-size:12px;">Состояние</div>
                     <div>${esc(s.state)} · ${esc(s.phase || '')}</div></div>
                <div><div class="text-muted" style="font-size:12px;">Вариант</div>
                     <div class="text-mono">${esc(s.variant || '—')}</div></div>
                <div><div class="text-muted" style="font-size:12px;">Прогресс</div>
                     <div>${done} / ${total}${total ? ' (' + percent + '%)' : ''}</div></div>
                ${s.eta_sec ? `<div><div class="text-muted" style="font-size:12px;">Осталось</div>
                     <div>~${Math.round(s.eta_sec)} с</div></div>` : ''}
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                <button class="btn btn-sm btn-primary" data-action="expCommit"
                        ${s.awaiting_commit ? '' : 'disabled'}>Закоммитить</button>
                <button class="btn btn-sm btn-danger" data-action="expRollback"
                        ${running || s.awaiting_commit ? '' : 'disabled'}>Откатить сейчас</button>
            </div>
        `;
    }

    // ══════════════════ Блок 7: правка кода ══════════════════

    function _codeHtml(block) {
        if (block.error) {
            return `<div class="alert alert-warning">${esc(block.error)}</div>`;
        }
        const waiting = block.waiting || {};
        const snapshots = block.snapshots || [];
        const local = block.local_changes || [];
        const staging = block.staging || {};

        const waitingHtml = waiting.snapshot_id ? `
            <div class="alert alert-warning">
                Применена правка <span class="text-mono">${esc(waiting.snapshot_id)}</span>
                (${esc((waiting.files || []).join(', '))}) — ждёт подтверждения:
                осталось ${waiting.left_sec} с, потом сторож вернёт прежние файлы.
                <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
                    <button class="btn btn-sm btn-primary" data-action="codeCommit"
                            data-id="${esc(waiting.snapshot_id)}">Подтвердить</button>
                    <button class="btn btn-sm btn-danger" data-action="codeRollback"
                            data-id="${esc(waiting.snapshot_id)}">Откатить сейчас</button>
                </div>
            </div>` : '';

        const rows = snapshots.map(s => `
            <tr>
                <td class="text-mono" style="white-space:nowrap;">${esc(s.snapshot_id || '')}</td>
                <td class="text-muted" style="white-space:nowrap;">${esc(s.created || '')}</td>
                <td>${esc(s.state || '')}</td>
                <td class="text-muted" style="font-size:12px;">
                    ${esc((s.files || []).join(', '))}
                </td>
                <td style="white-space:nowrap;">
                    <button class="btn btn-sm" data-action="codeDiff"
                            data-id="${esc(s.snapshot_id)}">Показать diff</button>
                    <button class="btn btn-sm btn-danger" data-action="codeRollback"
                            data-id="${esc(s.snapshot_id)}">Откатить</button>
                </td>
            </tr>`).join('');

        return `
            <div class="alert alert-danger">${esc(_t('mcp.warn.self_edit'))}</div>

            <div style="display:flex;gap:20px;flex-wrap:wrap;align-items:center;margin-bottom:12px;">
                <label class="settings-toggle" for="mcp-perm-self_edit-2">
                    <input type="checkbox" id="mcp-perm-self_edit-2"
                           ${block.self_edit ? 'checked' : ''}
                           data-action="togglePerm" data-perm="self_edit">
                    <span class="settings-toggle-slider"></span>
                    <span class="settings-toggle-label">Правка модулей GUI</span>
                </label>
                <label class="settings-toggle" for="mcp-perm-self_edit_core-2">
                    <input type="checkbox" id="mcp-perm-self_edit_core-2"
                           ${block.self_edit_core ? 'checked' : ''}
                           data-action="togglePerm" data-perm="self_edit_core">
                    <span class="settings-toggle-slider"></span>
                    <span class="settings-toggle-label">Защищённое ядро</span>
                </label>
            </div>

            ${waitingHtml}

            <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:10px;"
                 class="text-muted">
                <span style="font-size:12px;">Не применено (staging): ${staging.count || 0}</span>
                <span style="font-size:12px;">Файлов изменено локально: ${local.length}</span>
                <button class="btn btn-sm" data-action="codePatch"
                        ${local.length ? '' : 'disabled'}>Выгрузить патч</button>
            </div>

            ${snapshots.length ? `
                <div style="overflow:auto;">
                    <table class="table" style="font-size:13px;">
                        <thead><tr>
                            <th>Снимок</th><th>Когда</th><th>Состояние</th>
                            <th>Файлы</th><th></th>
                        </tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
                <pre id="mcp-code-diff" class="text-mono"
                     style="display:none;margin-top:10px;padding:10px;border-radius:6px;
                            max-height:360px;overflow:auto;font-size:12px;
                            background:var(--bg-input,rgba(0,0,0,.2));"></pre>
            ` : `<p class="text-muted">Правок не было.</p>`}
        `;
    }

    // ══════════════════ Черновики issue ══════════════════

    function _issuesHtml(block) {
        if (block.error) {
            return `<div class="alert alert-warning">${esc(block.error)}</div>`;
        }
        const drafts = block.drafts || [];
        const crashes = block.crashes || [];
        const kinds = {
            crash: 'падение', wrong_result: 'неверный результат',
            contract: 'не по описанию', docs_mismatch: 'документация',
            other: 'другое',
        };

        const rows = drafts.map(d => `
            <tr>
                <td class="text-muted" style="white-space:nowrap;">${esc(d.updated || d.time || '')}</td>
                <td>${esc(d.title || '')}
                    ${(d.occurrences || 1) > 1 ? `<span class="badge badge-warning">×${d.occurrences}</span>` : ''}
                </td>
                <td class="text-muted" style="font-size:12px;">
                    ${esc(kinds[d.kind] || d.kind || '')}${d.tool ? ' · <span class="text-mono">' + esc(d.tool) + '</span>' : ''}
                </td>
                <td>${d.status === 'sent'
                        ? '<span class="badge badge-success">отправлен</span>'
                        : '<span class="badge badge-muted">черновик</span>'}</td>
                <td>
                    <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;">
                        <button class="btn btn-sm" data-action="issueShow"
                                data-id="${esc(d.id)}">Показать</button>
                        ${d.status === 'sent' ? '' : `<button class="btn btn-sm" data-action="issueSent"
                                data-id="${esc(d.id)}">Отправлен</button>`}
                        <button class="btn btn-sm btn-danger" data-action="issueDelete"
                                data-id="${esc(d.id)}">Удалить</button>
                    </div>
                </td>
            </tr>`).join('');

        const crashHtml = crashes.length ? `
            <div class="alert alert-warning" style="margin-top:10px;">
                Падения инструментов без черновика: ${crashes.length}.
                Попросите модель составить отчёт (сценарий
                <span class="text-mono">report_problem</span>) или посмотрите
                <span class="text-mono">zapret-gui mcp issues crashes</span>.
                <ul style="margin:6px 0 0 18px;font-size:12px;">
                    ${crashes.slice(0, 5).map(c => `<li>
                        <span class="text-mono">${esc(c.tool || '')}</span>:
                        ${esc(c.error || '')}
                        <span class="text-muted text-mono">(${esc(c.where || '')})</span>
                    </li>`).join('')}
                </ul>
            </div>` : '';

        return `
            <p class="text-muted" style="font-size:13px;">${esc(_t('mcp.warn.issues'))}</p>
            ${drafts.length ? `
                <div style="overflow:auto;">
                    <table class="table" style="font-size:13px;">
                        <thead><tr>
                            <th>Когда</th><th>Заголовок</th><th>Вид</th>
                            <th>Статус</th><th></th>
                        </tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>` : ''}
            ${crashHtml}`;
    }

    // ══════════════════ Блок 8: shell ══════════════════

    function _shellHtml(block) {
        if (block.error) {
            return `<div class="alert alert-warning">${esc(block.error)}</div>`;
        }
        const jobs = block.jobs || [];
        const pending = block.pending || [];
        const guards = block.guards || [];
        const on = block.shell_readonly || block.shell_full;

        const pendingHtml = pending.length ? `
            <div class="alert alert-warning">
                <div style="font-weight:600;margin-bottom:6px;">
                    Ждут вашего решения (${pending.length})
                </div>
                ${pending.map(p => `
                    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;
                                padding:4px 0;">
                        <code class="text-mono" style="flex:1;min-width:200px;word-break:break-all;">
                            ${esc(p.summary || '')}
                        </code>
                        <span class="text-muted" style="font-size:12px;">${p.expires_in_sec} с</span>
                        <button class="btn btn-sm btn-primary" data-action="shellApprove"
                                data-token="${esc(p.token)}">Подтвердить</button>
                        <button class="btn btn-sm" data-action="shellReject"
                                data-token="${esc(p.token)}">Отклонить</button>
                    </div>`).join('')}
            </div>` : '';

        const jobsHtml = jobs.length ? `
            <div style="overflow:auto;margin-top:10px;">
                <table class="table" style="font-size:13px;">
                    <thead><tr><th>Команда</th><th>Состояние</th><th>Код</th></tr></thead>
                    <tbody>${jobs.map(j => `
                        <tr>
                            <td class="text-mono" style="word-break:break-all;">${esc(j.command || '')}</td>
                            <td>${j.running ? '<span class="badge badge-accent">работает</span>'
                                            : '<span class="badge badge-muted">завершена</span>'}</td>
                            <td class="${j.returncode ? 'text-error' : ''}">
                                ${j.returncode === null || j.returncode === undefined
                                    ? '—' : j.returncode}
                            </td>
                        </tr>`).join('')}</tbody>
                </table>
            </div>` : '<p class="text-muted">Команд не было.</p>';

        return `
            <div class="alert alert-danger">${esc(_t('mcp.warn.shell'))}</div>

            <div style="display:flex;gap:20px;flex-wrap:wrap;align-items:center;margin-bottom:12px;">
                <label class="settings-toggle" for="mcp-perm-shell_readonly-2">
                    <input type="checkbox" id="mcp-perm-shell_readonly-2"
                           ${block.shell_readonly ? 'checked' : ''}
                           data-action="togglePerm" data-perm="shell_readonly">
                    <span class="settings-toggle-slider"></span>
                    <span class="settings-toggle-label">Безопасные команды</span>
                </label>
                <label class="settings-toggle" for="mcp-perm-shell_full-2">
                    <input type="checkbox" id="mcp-perm-shell_full-2"
                           ${block.shell_full ? 'checked' : ''}
                           data-action="togglePerm" data-perm="shell_full">
                    <span class="settings-toggle-slider"></span>
                    <span class="settings-toggle-label">Любая команда от root</span>
                </label>
                <button class="btn btn-danger" data-action="shellPanic" ${on ? '' : 'disabled'}>
                    Запретить shell немедленно
                </button>
            </div>

            ${pendingHtml}
            ${guards.length ? `
                <p class="text-muted" style="font-size:12px;">
                    Заряжено дедменов: ${guards.length} — если подтверждение не
                    придёт, команда откатится сама.
                </p>` : ''}
            ${jobsHtml}
        `;
    }

    // ══════════════════ Действия ══════════════════

    async function _onChange(e) {
        const input = e.target.closest('[data-action]');
        if (!input || input.tagName !== 'INPUT') return;
        const action = input.dataset.action;

        if (action === 'toggleEnabled') {
            await _act(() => API.post('/api/mcp/ui/enabled',
                                      { enabled: input.checked }),
                       input.checked ? 'MCP включён' : 'MCP выключен');
        } else if (action === 'toggleHttp') {
            await _act(() => API.post('/api/mcp/ui/transports',
                                      { http: input.checked }),
                       'Основной транспорт ' +
                       (input.checked ? 'включён' : 'выключен'));
        } else if (action === 'toggleSse') {
            await _act(() => API.post('/api/mcp/ui/transports',
                                      { sse: input.checked }),
                       'Транспорт SSE ' + (input.checked ? 'включён' : 'выключен'));
        } else if (action === 'togglePerm') {
            const key = input.dataset.perm;
            if (input.checked && (key === 'shell_full' || key === 'self_edit_core')) {
                const ok = await Confirm.show(
                    'Включить ' + key + '?',
                    esc(_t(key === 'shell_full' ? 'mcp.warn.shell'
                                                : 'mcp.warn.self_edit')),
                    { danger: true, confirmLabel: 'Понимаю, включить' });
                if (!ok) { input.checked = false; return; }
            }
            const payload = {};
            payload[key] = input.checked;
            await _act(() => API.post('/api/mcp/ui/permissions',
                                      { permissions: payload }),
                       'Разрешение ' + key + ' ' +
                       (input.checked ? 'включено' : 'выключено'));
        }
    }

    async function _onClick(e) {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const action = btn.dataset.action;

        if (action === 'tokenShow') {
            await _tokenShow();
        } else if (action === 'tokenHide') {
            _tokenVisible = false;
            _token = '';
            _repaint();
        } else if (action === 'tokenCopy') {
            await _tokenCopy();
        } else if (action === 'tokenRotate') {
            await _tokenRotate();
        } else if (action === 'tokenClear') {
            await _tokenClear();
        } else if (action === 'copySnippet') {
            const node = document.getElementById('mcp-snippet-' + btn.dataset.index);
            if (node) Clipboard.copyWithToast(node.textContent, { node });
        } else if (action === 'undoLast') {
            await _undoLast();
        } else if (action === 'expCommit') {
            await _act(() => API.post('/api/mcp/ui/experiment/commit'),
                       'Вариант оставлен, авто-откат снят');
        } else if (action === 'expRollback') {
            await _act(() => API.post('/api/mcp/ui/experiment/rollback'),
                       'Состояние возвращено к снимку');
        } else if (action === 'codeDiff') {
            await _codeDiff(btn.dataset.id);
        } else if (action === 'codeCommit') {
            await _act(() => API.post('/api/mcp/ui/code/commit',
                                      { snapshot_id: btn.dataset.id }),
                       'Правка подтверждена, сторож снят');
        } else if (action === 'codeRollback') {
            await _codeRollback(btn.dataset.id);
        } else if (action === 'codePatch') {
            await _codePatch();
        } else if (action === 'shellPanic') {
            await _shellPanic();
        } else if (action === 'issueShow') {
            await _issueShow(btn.dataset.id);
        } else if (action === 'issueCopy') {
            if (_issue) Clipboard.copyWithToast(_issue.markdown || '',
                                                { okText: 'Текст скопирован' });
        } else if (action === 'issueOpen') {
            _issueOpen();
        } else if (action === 'issueClose') {
            _issue = null;
            const box = document.getElementById('mcp-issue-preview');
            if (box) box.style.display = 'none';
        } else if (action === 'issueSent') {
            await _act(() => API.post('/api/mcp/ui/issues/status',
                                      { id: btn.dataset.id, status: 'sent' }),
                       'Отмечен отправленным');
        } else if (action === 'issueDelete') {
            await _issueDelete(btn.dataset.id);
        } else if (action === 'shellApprove') {
            await _shellDecide(btn.dataset.token, 'approve');
        } else if (action === 'shellReject') {
            await _shellDecide(btn.dataset.token, 'reject');
        }
    }

    // ── токен ──

    async function _tokenShow() {
        try {
            const data = await API.get('/api/mcp/ui/token');
            _token = data.token || '';
            _tokenVisible = !!_token;
            _repaint();
        } catch (e) {
            Toast.error(String(e.message || e));
        }
    }

    async function _tokenCopy() {
        if (!_token) {
            try {
                const data = await API.get('/api/mcp/ui/token');
                _token = data.token || '';
            } catch (e) {
                Toast.error(String(e.message || e));
                return;
            }
        }
        Clipboard.copyWithToast(_token, { okText: 'Токен скопирован' });
    }

    async function _tokenRotate() {
        const had = _state && _state.info && _state.info.token_set;
        if (had) {
            const ok = await Confirm.show('Ротировать токен?',
                                          esc(_t('mcp.warn.rotate')),
                                          { danger: true,
                                            confirmLabel: 'Ротировать' });
            if (!ok) return;
        }
        try {
            _busy = true;
            const data = await API.post('/api/mcp/ui/token', { action: 'rotate' });
            _token = data.token || '';
            _tokenVisible = true;
            Toast.success('Токен выдан — скопируйте его сейчас');
        } catch (e) {
            Toast.error(String(e.message || e));
        } finally {
            _busy = false;
        }
        await _tick();
    }

    async function _tokenClear() {
        const ok = await Confirm.show(
            'Стереть токен?',
            'Подключённые клиенты оборвутся, а новые не смогут авторизоваться.',
            { danger: true, confirmLabel: 'Стереть' });
        if (!ok) return;
        _token = '';
        _tokenVisible = false;
        await _act(() => API.post('/api/mcp/ui/token', { action: 'clear' }),
                   'Токен стёрт');
    }

    // ── журнал ──

    async function _undoLast() {
        const ok = await Confirm.show(
            'Отменить последнее изменение?',
            'Состояние вернётся к снимку, который модель сделала перед ' +
            'изменением.', { danger: true, confirmLabel: 'Отменить' });
        if (!ok) return;
        try {
            _busy = true;
            const data = await API.post('/api/mcp/ui/undo', {});
            Toast.success(data.reason || 'Изменение отменено');
        } catch (e) {
            Toast.error(String(e.message || e));
        } finally {
            _busy = false;
        }
        await _tick();
    }

    // ── правка кода ──

    async function _codeDiff(snapshotId) {
        const box = document.getElementById('mcp-code-diff');
        if (!box) return;
        box.style.display = '';
        box.textContent = 'Загрузка…';
        try {
            const data = await API.get('/api/mcp/ui/code/diff?snapshot_id='
                                       + encodeURIComponent(snapshotId));
            box.textContent = data.diff || '(пусто — файлы совпадают)';
        } catch (e) {
            box.textContent = String(e.message || e);
        }
    }

    async function _codePatch() {
        try {
            const data = await API.get('/api/mcp/ui/code/patch');
            const patch = data.patch || '';
            if (!patch) { Toast.info('Локальных правок нет'); return; }
            const box = document.getElementById('mcp-code-diff');
            if (box) { box.style.display = ''; box.textContent = patch; }
            Clipboard.copyWithToast(patch, { okText: 'Патч скопирован' });
        } catch (e) {
            Toast.error(String(e.message || e));
        }
    }

    async function _codeRollback(snapshotId) {
        const ok = await Confirm.show(
            'Откатить правку ' + esc(snapshotId) + '?',
            'Файлы снимка вернутся на место, GUI перезапустится — ' +
            'страница на несколько секунд потеряет связь.',
            { danger: true, confirmLabel: 'Откатить' });
        if (!ok) return;
        try {
            _busy = true;
            await API.post('/api/mcp/ui/code/rollback', { snapshot_id: snapshotId });
            Toast.success('Откат запущен');
        } catch (e) {
            Toast.error(String(e.message || e));
        } finally {
            _busy = false;
        }
        // GUI перезапускается — потеря связи здесь ожидаема.
        _restarting = true;
        _banner(_t('mcp.warn.restart'), 'warning');
        await _tick();
    }

    // ── черновики issue ──

    async function _issueShow(id) {
        const box = document.getElementById('mcp-issue-preview');
        const text = document.getElementById('mcp-issue-text');
        if (!box || !text) return;
        box.style.display = '';
        text.textContent = 'Загрузка…';
        try {
            const data = await API.get('/api/mcp/ui/issues/draft?id='
                                       + encodeURIComponent(id));
            _issue = { id: id, markdown: data.markdown || '',
                       url: data.open_on_github || '',
                       shortened: !!data.body_shortened };
            text.textContent = _issue.markdown;
        } catch (e) {
            _issue = null;
            text.textContent = String(e.message || e);
        }
    }

    /** Открыть /issues/new; не влезший в адрес текст — в буфер обмена. */
    function _issueOpen() {
        if (!_issue || !_issue.url) return;
        if (_issue.shortened) {
            Clipboard.copyWithToast(_issue.markdown, {
                okText: 'Текст длинный для ссылки — полный скопирован, '
                        + 'вставьте его в issue' });
        }
        window.open(_issue.url, '_blank', 'noopener');
    }

    async function _issueDelete(id) {
        const ok = await Confirm.show('Удалить черновик?',
                                      'Черновик и собранный к нему контекст '
                                      + 'пропадут с устройства.',
                                      { danger: true, confirmLabel: 'Удалить' });
        if (!ok) return;
        if (_issue && _issue.id === id) {
            _issue = null;
            const box = document.getElementById('mcp-issue-preview');
            if (box) box.style.display = 'none';
        }
        await _act(() => API.post('/api/mcp/ui/issues/delete', { id: id }),
                   'Черновик удалён');
    }

    // ── shell ──

    async function _shellPanic() {
        const ok = await Confirm.show('Запретить shell немедленно?',
                                      esc(_t('mcp.warn.panic')),
                                      { danger: true, confirmLabel: 'Запретить' });
        if (!ok) return;
        try {
            _busy = true;
            const data = await API.post('/api/mcp/ui/shell/panic');
            Toast.success('Shell запрещён; снято задач: '
                          + (data.stopped || []).length);
        } catch (e) {
            Toast.error(String(e.message || e));
        } finally {
            _busy = false;
        }
        await _tick();
    }

    async function _shellDecide(token, decision) {
        if (decision === 'approve') {
            const ok = await Confirm.show(
                'Выполнить команду?',
                'Команду попросила выполнить модель. Подтверждение ' +
                'исполняет её прямо сейчас.',
                { danger: true, confirmLabel: 'Выполнить' });
            if (!ok) return;
        }
        await _act(() => API.post('/api/mcp/ui/shell/confirm',
                                  { token: token, decision: decision }),
                   decision === 'approve' ? 'Команда выполнена'
                                          : 'Команда отклонена');
    }

    // ══════════════════ Частности ══════════════════

    /** Выполнить действие, показать результат и обновить состояние. */
    async function _act(call, okText) {
        try {
            _busy = true;
            await call();
            if (okText) Toast.success(okText);
        } catch (e) {
            Toast.error(String(e.message || e));
        } finally {
            _busy = false;
        }
        await _tick();
    }

    /** Перерисовать из последнего снимка, не ходя на сервер. */
    function _repaint() {
        if (_state) _paint(_state);
    }

    function _banner(text, kind) {
        const el = document.getElementById('mcp-banner');
        if (!el) return;
        el.innerHTML = text
            ? `<div class="alert alert-${kind || 'info'}">${esc(text)}</div>` : '';
    }

    function _endpoint(info) {
        const path = (info && info.endpoint) || '/api/mcp';
        try {
            return window.location.origin + path;
        } catch (_) {
            return path;
        }
    }

    /** Обычный HTTP — значит токен уезжает открытым текстом. */
    function _isPlainHttp() {
        try {
            return window.location.protocol === 'http:';
        } catch (_) {
            return true;
        }
    }

    function _loading() {
        return '<p class="text-muted">Загрузка…</p>';
    }

    /** Перевод с запасным вариантом: ключ без словаря читать нельзя. */
    function _t(key) {
        const text = (typeof i18n !== 'undefined') ? i18n.t(key) : key;
        return text === key ? '' : text;
    }

    function esc(s) {
        return String(s === null || s === undefined ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { render, destroy };
})();
