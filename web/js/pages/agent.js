/**
 * agent.js — Страница «Агент».
 *
 * Локальная модель (LM Studio, Ollama, llama.cpp) работает с роутером
 * прямо отсюда: человек нажимает «подбери стратегию сам», модель зовёт
 * те же инструменты, что и внешний клиент по MCP, а на странице видно
 * каждый её шаг.
 *
 * Три правила страницы — те же, что у страницы MCP:
 *
 *   1. **Один роут — один ответ.** Состояние приезжает из
 *      `GET /api/agent/state`; пока идёт прогон, транскрипт
 *      доливается из `GET /api/agent/run`. Собирать это из пяти
 *      вызовов нельзя: на роутере со 128 МБ страница будет мигать.
 *   2. **Ключ не показываем и не логируем.** С сервера приезжает
 *      только факт «задан / не задан»; пустое поле при сохранении
 *      означает «не менять».
 *   3. **Один таймер**, и тот замолкает на скрытой вкладке и в
 *      `destroy()`. Пока прогон идёт — опрос чаще, в покое — реже.
 *
 * Разрешения у агента не свои: он ходит под `mcp.permissions`. Поэтому
 * страница показывает их и отправляет за ними на «MCP-сервер», а не
 * заводит второй переключатель.
 */

const AgentPage = (() => {
    // ══════════════════ Состояние ══════════════════

    const POLL_IDLE_MS = 5000;
    const POLL_RUN_MS = 1500;

    let _container = null;
    let _timer = null;
    let _state = null;
    let _busy = false;

    // Последний выбранный сценарий и модели, полученные кнопкой
    // «Проверить связь» (в settings.json они не попадают).
    let _preset = '';
    let _models = [];

    const _sig = {};

    // ══════════════════ Рендер ══════════════════

    async function render(container) {
        _container = container;
        _models = [];
        _preset = '';
        Object.keys(_sig).forEach(k => delete _sig[k]);

        container.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Агент</h1>
                    <p class="page-description">
                        Локальная модель (LM Studio, Ollama) подбирает
                        стратегию сама — теми же инструментами, что
                        внешний клиент по MCP
                    </p>
                </div>
            </div>

            <div id="agent-banner"></div>

            <div class="card">
                <div class="card-title">Сервер модели</div>
                <div id="agent-setup">${_loading()}</div>
            </div>

            <div class="card">
                <div class="card-title">Задача</div>
                <div id="agent-task">${_loading()}</div>
            </div>

            <div class="card">
                <div class="card-title">Что делает агент</div>
                <div id="agent-run">${_loading()}</div>
            </div>

            <div class="card">
                <div class="card-title">Права и инструменты</div>
                <div id="agent-perms">${_loading()}</div>
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
        _models = [];
    }

    // ══════════════════ Опрос ══════════════════

    async function _tick() {
        if (!_container) return;
        if (_busy || (typeof document !== 'undefined' && document.hidden)) {
            _schedule();
            return;
        }
        try {
            const data = await API.get('/api/agent/state');
            if (!_container) return;
            _state = data;
            _paint(data);
        } catch (e) {
            if (!_container) return;
            _banner('Не удалось получить состояние: '
                    + String(e.message || e), 'danger');
        }
        _schedule();
    }

    function _schedule() {
        if (_timer) clearTimeout(_timer);
        const running = _state && _state.run && _state.run.running;
        _timer = setTimeout(_tick, running ? POLL_RUN_MS : POLL_IDLE_MS);
    }

    function _paint(state) {
        const s = state.settings || {};
        const run = state.run || {};

        _section('agent-setup', _setupHtml(s, state),
                 [s.enabled, s.base_url, s.model, s.api_key_set, s.tools,
                  s.max_steps, s.temperature, _models.join(',')]);
        _section('agent-task', _taskHtml(state),
                 [state.available, run.running, _preset,
                  (state.presets || []).length]);
        _section('agent-run', _runHtml(run),
                 [run.run_id, run.state, run.steps_total, run.tool_calls,
                  run.answer ? run.answer.length : 0]);
        _section('agent-perms', _permsHtml(state),
                 [JSON.stringify(state.permissions_effective || {}),
                  (state.tools || {}).count, (state.tools || {}).mode]);
    }

    // ══════════════════ Блок 1: сервер модели ══════════════════

    function _setupHtml(s, state) {
        const models = _models.length
            ? `<datalist id="agent-model-list">${
                  _models.map(m => `<option value="${esc(m)}"></option>`)
                      .join('')}</datalist>`
            : '';
        return `
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px;">
                <label class="settings-toggle" for="agent-enabled">
                    <input type="checkbox" id="agent-enabled" ${s.enabled ? 'checked' : ''}
                           data-action="toggleEnabled">
                    <span class="settings-toggle-slider"></span>
                    <span class="settings-toggle-label">Агент включён</span>
                </label>
                <span class="text-muted" style="font-size:12px;max-width:560px;">
                    Отдельный переключатель: MCP-сервер он не включает и
                    не выключает. Агент ходит к модели по адресу ниже и
                    работает <b>под разрешениями MCP</b> — без них он
                    только читает.
                </span>
            </div>

            <div class="form-group">
                <label class="form-label" for="agent-base-url">Адрес сервера (OpenAI-совместимый)</label>
                <input type="text" class="form-input" id="agent-base-url"
                       value="${esc(s.base_url || '')}"
                       placeholder="http://127.0.0.1:1234/v1">
                <div class="form-hint">
                    LM Studio — <code>http://127.0.0.1:1234/v1</code>,
                    Ollama — <code>http://127.0.0.1:11434/v1</code>.
                    К локальным адресам ходим мимо прокси.
                </div>
            </div>

            <div class="form-group">
                <label class="form-label" for="agent-model">Модель</label>
                <input type="text" class="form-input" id="agent-model"
                       list="agent-model-list"
                       value="${esc(s.model || '')}"
                       placeholder="пусто — что отдаст сервер">
                ${models}
            </div>

            <div class="form-group">
                <label class="form-label" for="agent-key">Ключ API</label>
                <input type="password" class="form-input" id="agent-key"
                       placeholder="${s.api_key_set ? 'задан — оставьте пустым, чтобы не менять' : 'локальным серверам не нужен'}">
            </div>

            <div style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:12px;">
                <div class="form-group" style="min-width:150px;">
                    <label class="form-label" for="agent-steps">Шагов максимум</label>
                    <input type="number" class="form-input" id="agent-steps"
                           min="1" max="40" value="${s.max_steps || 12}">
                </div>
                <div class="form-group" style="min-width:150px;">
                    <label class="form-label" for="agent-timeout">Таймаут, с</label>
                    <input type="number" class="form-input" id="agent-timeout"
                           min="5" max="900" value="${s.timeout_sec || 120}">
                </div>
                <div class="form-group" style="min-width:220px;">
                    <label class="form-label" for="agent-tools">Набор инструментов</label>
                    <select class="form-input" id="agent-tools">
                        <option value="scenarios" ${s.tools !== 'all' ? 'selected' : ''}>
                            Только для сценариев (${(state.tools || {}).count || 0})
                        </option>
                        <option value="all" ${s.tools === 'all' ? 'selected' : ''}>
                            Все доступные
                        </option>
                    </select>
                </div>
            </div>

            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                <button class="btn btn-primary btn-sm" data-action="saveSettings">Сохранить</button>
                <button class="btn btn-ghost btn-sm" data-action="testConnection">Проверить связь</button>
            </div>
        `;
    }

    // ══════════════════ Блок 2: задача ══════════════════

    function _taskHtml(state) {
        if (!state.available) {
            return `<p class="text-muted">Агент выключен или не задан
                    адрес сервера модели — включите его выше.</p>`;
        }
        const run = state.run || {};
        const presets = state.presets || [];
        const chosen = presets.find(p => p.id === _preset);
        const buttons = presets.map(p => `
            <button class="btn btn-sm ${p.id === _preset ? 'btn-primary' : 'btn-ghost'}"
                    data-action="pickPreset" data-preset="${esc(p.id)}">
                ${esc(p.title)}
            </button>`).join('');

        const argument = chosen && chosen.argument ? `
            <div class="form-group">
                <label class="form-label" for="agent-argument">${esc(chosen.label)}</label>
                <input type="text" class="form-input" id="agent-argument"
                       placeholder="${esc(chosen.placeholder || '')}">
            </div>` : '';

        return `
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
                ${buttons}
                <button class="btn btn-sm ${_preset ? 'btn-ghost' : 'btn-primary'}"
                        data-action="pickPreset" data-preset="">Своя задача</button>
            </div>
            ${argument}
            ${_preset ? '' : `
            <div class="form-group">
                <label class="form-label" for="agent-goal">Что сделать</label>
                <textarea class="form-textarea" id="agent-goal" rows="3"
                          placeholder="Например: проверь, открывается ли youtube.com, и если нет — подбери стратегию"></textarea>
            </div>`}
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
                <button class="btn btn-primary" data-action="start"
                        ${run.running ? 'disabled' : ''}>Запустить</button>
                <button class="btn btn-danger" data-action="stop"
                        ${run.running ? '' : 'disabled'}>Остановить</button>
            </div>
        `;
    }

    // ══════════════════ Блок 3: транскрипт ══════════════════

    function _runHtml(run) {
        if (!run || !run.run_id) {
            return `<p class="text-muted">Прогонов ещё не было. Модель
                    зовёт инструменты сама — здесь будет видно каждый
                    её вызов и что он вернул.</p>`;
        }
        const head = `
            <div style="display:flex;gap:18px;flex-wrap:wrap;margin-bottom:12px;">
                <div><div class="text-muted" style="font-size:12px;">Состояние</div>
                     <div>${esc(_stateLabel(run.state))}</div></div>
                <div><div class="text-muted" style="font-size:12px;">Вызовов</div>
                     <div>${run.tool_calls || 0}</div></div>
                <div><div class="text-muted" style="font-size:12px;">Время</div>
                     <div>${Math.round(run.elapsed_sec || 0)} с</div></div>
                ${(run.usage && run.usage.total_tokens) ? `
                <div><div class="text-muted" style="font-size:12px;">Токенов</div>
                     <div>${run.usage.total_tokens}</div></div>` : ''}
            </div>`;

        const error = run.error
            ? `<div class="alert alert-warning">${esc(run.error)}</div>` : '';

        const steps = (run.steps || []).map(_stepHtml).join('');
        return head + error + `<div class="agent-steps">${steps}</div>`;
    }

    function _stepHtml(step) {
        if (step.kind === 'user') {
            return `<div class="agent-step"><b>Задача</b>
                    <pre class="text-mono" style="white-space:pre-wrap;font-size:12px;margin:4px 0 0;">${esc(step.text)}</pre></div>`;
        }
        if (step.kind === 'model') {
            return `<div class="agent-step"><b>Модель</b>
                    <div>${esc(step.text)}</div></div>`;
        }
        if (step.kind === 'tool') {
            const mark = step.ok ? '✓' : '✗';
            const args = JSON.stringify(step.args || {});
            return `<div class="agent-step">
                <b>${mark} <span class="text-mono">${esc(step.name)}</span></b>
                <span class="text-muted" style="font-size:12px;">
                    ${esc(args.length > 200 ? args.slice(0, 200) + '…' : args)}
                </span>
                <div class="text-muted" style="font-size:12px;">
                    ${esc(step.error || step.summary || '')}
                </div>
            </div>`;
        }
        if (step.kind === 'answer') {
            return `<div class="alert alert-success"><b>Итог</b>
                    <div>${esc(step.text)}</div></div>`;
        }
        return `<div class="alert alert-warning">${esc(step.text || '')}</div>`;
    }

    function _stateLabel(state) {
        return ({
            running: 'идёт', done: 'готово', failed: 'ошибка',
            stopped: 'остановлен', idle: 'простой',
        })[state] || state || '';
    }

    // ══════════════════ Блок 4: права ══════════════════

    function _permsHtml(state) {
        const tools = state.tools || {};
        const info = state.permissions_info || [];
        const granted = info.filter(p => p.active).map(p => p.name);
        const names = (tools.names || []).slice(0, 60)
            .map(n => `<span class="badge badge-muted" style="margin:2px;">${esc(n)}</span>`)
            .join('');
        return `
            <p class="text-muted" style="font-size:13px;">
                Агент работает под разрешениями MCP — своих у него нет.
                Включить или отобрать их можно на странице
                <a href="#mcp">MCP-сервер</a>; там же видно, что именно
                делала модель (журнал вызовов).
            </p>
            <p>${granted.length
                    ? 'Разрешено на запись: <b>' + esc(granted.join(', ')) + '</b>'
                    : 'Разрешений на запись нет — агент только читает и предлагает.'}</p>
            <p class="text-muted" style="font-size:12px;">
                Модели объявлено инструментов: <b>${tools.count || 0}</b>
                (${tools.mode === 'all' ? 'все доступные' : 'набор сценариев'}).
            </p>
            <div>${names}</div>
        `;
    }

    // ══════════════════ Действия ══════════════════

    async function _onClick(e) {
        const el = e.target.closest('[data-action]');
        if (!el) return;
        const action = el.dataset.action;
        if (action === 'saveSettings') {
            await _saveSettings();
        } else if (action === 'testConnection') {
            await _testConnection();
        } else if (action === 'pickPreset') {
            _preset = el.dataset.preset || '';
            _sig['agent-task'] = '';
            _paint(_state || {});
        } else if (action === 'start') {
            await _start();
        } else if (action === 'stop') {
            await _stop();
        }
    }

    async function _onChange(e) {
        const el = e.target.closest('[data-action]');
        if (!el) return;
        if (el.dataset.action === 'toggleEnabled') {
            await _act(() => API.post('/api/agent/settings',
                                      { enabled: el.checked }),
                       el.checked ? 'Агент включён' : 'Агент выключен');
        }
    }

    function _value(id) {
        const el = document.getElementById(id);
        return el ? String(el.value || '').trim() : '';
    }

    async function _saveSettings() {
        const body = {
            base_url: _value('agent-base-url'),
            model: _value('agent-model'),
            tools: _value('agent-tools'),
            max_steps: parseInt(_value('agent-steps'), 10) || 12,
            timeout_sec: parseInt(_value('agent-timeout'), 10) || 120,
        };
        // Пустое поле ключа — «не менять»: так решено на сервере, и
        // страница не должна вести себя иначе.
        const key = _value('agent-key');
        if (key) body.api_key = key;
        await _act(() => API.post('/api/agent/settings', body),
                   'Настройки сохранены');
    }

    async function _testConnection() {
        _busy = true;
        try {
            const res = await API.post('/api/agent/test', {
                base_url: _value('agent-base-url'),
                api_key: _value('agent-key'),
            });
            if (res && res.ok) {
                _models = res.models || [];
                _sig['agent-setup'] = '';
                Toast.success('Связь есть, моделей: ' + (res.count || 0));
            } else {
                Toast.error((res && res.error) || 'Сервер не ответил');
            }
        } catch (e) {
            Toast.error('Проверка не удалась: ' + String(e.message || e));
        } finally {
            _busy = false;
            await _tick();
        }
    }

    async function _start() {
        const body = _preset
            ? { preset: _preset, argument: _value('agent-argument') }
            : { goal: _value('agent-goal') };
        await _act(() => API.post('/api/agent/start', body),
                   'Агент запущен');
    }

    async function _stop() {
        await _act(() => API.post('/api/agent/stop', {}),
                   'Останавливается…');
    }

    async function _act(call, okMessage) {
        _busy = true;
        try {
            const res = await call();
            if (res && res.ok === false) {
                Toast.error(res.error || 'Не получилось');
            } else if (okMessage) {
                Toast.success(okMessage);
            }
        } catch (e) {
            Toast.error(String(e.message || e));
        } finally {
            _busy = false;
            Object.keys(_sig).forEach(k => delete _sig[k]);
            await _tick();
        }
    }

    // ══════════════════ Утилиты ══════════════════

    function _section(id, html, signature) {
        const key = String(signature.join('\u0001'));
        if (_sig[id] === key) return;
        const el = document.getElementById(id);
        if (!el) return;
        el.innerHTML = html;
        _sig[id] = key;
    }

    function _banner(text, kind) {
        const el = document.getElementById('agent-banner');
        if (!el) return;
        el.innerHTML = text
            ? `<div class="alert alert-${kind || 'warning'}">${esc(text)}</div>`
            : '';
    }

    function _loading() {
        return '<p class="text-muted">Загрузка…</p>';
    }

    function esc(s) {
        return String(s === null || s === undefined ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { render, destroy };
})();
