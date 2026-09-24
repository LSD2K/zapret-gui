/**
 * agh_routes.js, «Туннель: домены → outbound».
 *
 * Одно место правды для схемы gw: правила «списки доменов → outbound
 * sing-box». Из них бэкенд (core/agh_routes.py) раскладывает route rules
 * в конфиг sing-box и upstream-строки [/домены/]127.0.0.1:1053 в AdGuard
 * Home (глобально или поклиентно).
 *
 * Страница правит настройки (PUT /api/agh-routes), показывает план
 * (GET /api/agh-routes/plan) и применяет его (POST /api/agh-routes/apply).
 * «План» и «Применить» сначала сохраняют несохранённые правки формы.
 */

const AghRoutesPage = (() => {
    // ══════════════════ State ══════════════════

    let st = null;              // настройки из GET /api/agh-routes
    let sources = { hostlists: [], named_lists: [], geosite: [], outbounds: [] };
    let configs = [];           // /api/singbox/configs
    let pw = '';                // введённый пароль (пусто = не менять)
    let dirty = false;
    let busy = false;
    let lastPlan = null;

    const LONG = { timeout: 120000 };   // план/применение: geosite, рестарт sing-box

    // ══════════════════ Render ══════════════════

    function render(container) {
        st = null; pw = ''; dirty = false; busy = false; lastPlan = null;
        container.innerHTML = `
            <div class="page-header" style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
                <div>
                    <h1 class="page-title">Туннель: домены → outbound</h1>
                    <p class="page-description">
                        Правила «списки доменов → outbound sing-box»: из них ставятся
                        route rules в конфиг sing-box и upstream-строки в AdGuard Home
                    </p>
                </div>
                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                    <span class="badge badge-warning" id="agr-dirty" style="display:none;">не сохранено</span>
                    <button class="btn btn-ghost btn-sm" data-action="save">Сохранить</button>
                    <button class="btn btn-ghost btn-sm" data-action="plan">План</button>
                    <button class="btn btn-primary btn-sm" data-action="apply">Применить</button>
                </div>
            </div>
            <div id="agr-body">
                <div class="page-loading"><div class="spinner"></div><span>Загрузка...</span></div>
            </div>
            <div class="card" id="agr-plan-card" style="display:none;">
                <div class="card-title">План</div>
                <div id="agr-plan"></div>
            </div>
        `;
        container.addEventListener('click', onClick);
        container.addEventListener('input', onInput);
        container.addEventListener('change', onChange);
        load();
    }

    function destroy() {
        st = null;
        lastPlan = null;
    }

    // ══════════════════ Data ══════════════════

    async function load() {
        try {
            const [sr, cr] = await Promise.all([
                API.get('/api/agh-routes'),
                API.get('/api/singbox/configs').catch(() => null),
            ]);
            st = sr.settings;
            configs = (cr && cr.configs) || [];
            await loadSources();
            renderForm();
        } catch (e) {
            const body = document.getElementById('agr-body');
            if (body) body.innerHTML = `<div class="card text-error">Ошибка загрузки: ${esc(e.message)}</div>`;
        }
    }

    async function loadSources() {
        const q = st && st.singbox_config
            ? '?config=' + encodeURIComponent(st.singbox_config) : '';
        try {
            const r = await API.get('/api/agh-routes/sources' + q);
            sources = {
                hostlists: r.hostlists || [], named_lists: r.named_lists || [],
                geosite: r.geosite || [], outbounds: r.outbounds || [],
            };
        } catch (e) {
            Toast.error('Источники: ' + e.message);
        }
    }

    // ══════════════════ Form ══════════════════

    function renderForm() {
        const body = document.getElementById('agr-body');
        if (!body || !st) return;
        const cfgOpts = configs.map(c =>
            `<option value="${escAttr(c.name)}" ${c.name === st.singbox_config ? 'selected' : ''}>`
            + `${esc(c.name)}${c.running ? ' (запущен)' : ''}</option>`).join('');
        const missingCfg = st.singbox_config && !configs.some(c => c.name === st.singbox_config)
            ? `<option value="${escAttr(st.singbox_config)}" selected>${esc(st.singbox_config)} (не найден)</option>` : '';

        body.innerHTML = `
            <div class="card">
                <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
                    <label class="settings-toggle" for="agr-enabled">
                        <input type="checkbox" id="agr-enabled" data-field="enabled" ${st.enabled ? 'checked' : ''}>
                        <span class="settings-toggle-slider"></span>
                        <span class="settings-toggle-label">Маршруты включены</span>
                    </label>
                    <span class="text-muted" style="font-size:12px;" id="agr-applied">${appliedText()}</span>
                </div>
                <div class="form-hint">
                    Ничего не меняется, пока не нажата «Применить». Выключить и применить:
                    снять из sing-box и AdGuard всё, что поставлено здесь.
                </div>
            </div>

            <div class="card">
                <div class="card-title">AdGuard Home</div>
                <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:0 12px;">
                    <div class="form-group">
                        <label class="form-label" for="agr-url">Адрес API</label>
                        <input type="text" class="form-input" id="agr-url" data-field="agh_url"
                               value="${escAttr(st.agh_url)}" placeholder="http://127.0.0.1:3000" spellcheck="false">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="agr-user">Логин</label>
                        <input type="text" class="form-input" id="agr-user" data-field="agh_user"
                               value="${escAttr(st.agh_user)}" autocomplete="off" spellcheck="false">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="agr-pw">Пароль</label>
                        <input type="password" class="form-input" id="agr-pw" data-field="agh_password"
                               placeholder="${st.has_password ? 'сохранён, пусто = не менять' : ''}" autocomplete="new-password">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="agr-target">Цель DNS для доменов правил</label>
                        <input type="text" class="form-input" id="agr-target" data-field="dns_target"
                               value="${escAttr(st.dns_target)}" placeholder="127.0.0.1:1053" spellcheck="false">
                    </div>
                </div>
                <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                    <button class="btn btn-ghost btn-sm" data-action="test">Проверить</button>
                    <span id="agr-test" class="text-muted" style="font-size:12px;"></span>
                </div>
                <div class="form-hint">
                    Цель: dns-in sing-box (fakeip). Наши строки в AdGuard это те, что
                    заканчиваются на <code>]${esc(st.dns_target)}</code>, остальные upstream'ы не трогаются.
                </div>
            </div>

            <div class="card">
                <div class="card-title">sing-box</div>
                <div class="form-group" style="max-width:360px;">
                    <label class="form-label" for="agr-config">Конфиг</label>
                    <select class="form-input" id="agr-config" data-field="singbox_config">
                        <option value="">- не выбран -</option>${missingCfg}${cfgOpts}
                    </select>
                </div>
                <div class="form-hint">
                    Правила <code>{"domain_suffix": [...], "outbound": "…"}</code> встают сразу после
                    <code>hijack-dns</code> и до <code>{"inbound": ["tun-in"], …}</code>. Конфиг
                    проверяется <code>sing-box check</code>, запущенный инстанс перезапускается.
                </div>
            </div>

            <div class="card">
                <div class="card-title">Клиенты AdGuard</div>
                <textarea class="form-textarea" id="agr-clients" data-field="clients" rows="3"
                          placeholder="10.10.10.5&#10;10.10.11.0/24" spellcheck="false">${esc((st.clients || []).join('\n'))}</textarea>
                <div class="form-hint">
                    Пусто: строки ставятся в глобальные upstream'ы AdGuard (для всех).
                    Иначе IP или подсети по одному в строке: только этим клиентам ставятся
                    поклиентные upstream'ы (текущие глобальные + наши строки), глобальные не трогаются.
                </div>
            </div>

            <div class="card">
                <div class="card-title" style="justify-content:space-between;">
                    <span>Правила <span class="text-muted">(порядок = приоритет: домен берётся первым правилом)</span></span>
                    <button class="btn btn-ghost btn-sm" data-action="addRule">+ Правило</button>
                </div>
                <div id="agr-rules"></div>
            </div>
        `;
        renderRules();
        setDirty(dirty);
    }

    function appliedText() {
        const a = (st && st.applied) || {};
        if (!a.at) return 'ещё не применялось';
        const when = new Date(a.at * 1000).toLocaleString();
        const where = a.mode === 'clients' ? `клиентам AdGuard: ${a.clients}` : 'глобально в AdGuard';
        return `применено ${esc(when)}: ${a.singbox_rules} правил в «${esc(a.singbox_config || '-')}», ${where}`;
    }

    function listLabel(id) {
        if (id.startsWith('hl:')) {
            const h = sources.hostlists.find(x => x.id === id);
            return `${id.slice(3)} (nfqws2${h ? ', ' + h.count : ''})`;
        }
        if (id.startsWith('geosite:')) {
            const g = sources.geosite.find(x => x.id === id);
            return id + (g && g.count ? ` (${g.count})` : '');
        }
        const n = sources.named_lists.find(x => x.id === id);
        return n ? `${n.name} (${n.count})` : `${id} (?)`;
    }

    function listOptions() {
        const grp = (label, items, fmt) => items.length
            ? `<optgroup label="${escAttr(label)}">${items.map(x =>
                `<option value="${escAttr(x.id)}">${esc(fmt(x))}</option>`).join('')}</optgroup>` : '';
        return '<option value="">+ список…</option>'
            + grp('Хостлисты nfqws2', sources.hostlists, x => `${x.name} (${x.count})`)
            + grp('Списки маршрутизации', sources.named_lists, x => `${x.name} (${x.count})`)
            + grp('geosite', sources.geosite, x => x.name + (x.cached ? ` (${x.count})` : ''))
            + '<option value="__geosite">geosite: другое имя…</option>';
    }

    function outboundOptions(cur) {
        const tags = sources.outbounds || [];
        let html = '<option value="">- outbound -</option>';
        html += tags.map(t => `<option value="${escAttr(t.tag)}" ${t.tag === cur ? 'selected' : ''}>`
            + `${esc(t.tag)}${t.type ? ' · ' + esc(t.type) : ''}</option>`).join('');
        if (cur && !tags.some(t => t.tag === cur)) {
            html += `<option value="${escAttr(cur)}" selected>${esc(cur)} (нет в конфиге)</option>`;
        }
        return html;
    }

    function renderRules() {
        const box = document.getElementById('agr-rules');
        if (!box || !st) return;
        const rules = st.rules || [];
        if (!rules.length) {
            box.innerHTML = '<p class="text-muted" style="font-size:12px;">Правил нет. Добавьте первое кнопкой «+ Правило».</p>';
            return;
        }
        const opts = listOptions();
        const rows = rules.map((r, i) => {
            const chips = (r.lists || []).map(id => `
                <span class="badge badge-ghost" style="margin:0 4px 4px 0; gap:4px;">
                    ${esc(listLabel(id))}
                    <button type="button" class="btn-icon" data-action="rmList" data-idx="${i}" data-list="${escAttr(id)}"
                            title="Убрать" style="background:none; border:none; color:inherit; cursor:pointer; padding:0 2px;">×</button>
                </span>`).join('');
            return `
                <tr>
                    <td style="white-space:nowrap;">
                        <button class="btn btn-ghost btn-sm" data-action="up" data-idx="${i}" ${i === 0 ? 'disabled' : ''} title="Выше">↑</button>
                        <button class="btn btn-ghost btn-sm" data-action="down" data-idx="${i}" ${i === rules.length - 1 ? 'disabled' : ''} title="Ниже">↓</button>
                    </td>
                    <td><input type="checkbox" data-rule="enabled" data-idx="${i}" ${r.enabled !== false ? 'checked' : ''} title="Вкл/выкл"></td>
                    <td><input type="text" class="form-input form-input-sm" data-rule="name" data-idx="${i}" value="${escAttr(r.name)}" placeholder="AI-сервисы"></td>
                    <td><select class="form-input form-input-sm" data-rule="outbound" data-idx="${i}">${outboundOptions(r.outbound)}</select></td>
                    <td>
                        <div>${chips || '<span class="text-muted" style="font-size:12px;">нет</span>'}</div>
                        <select class="form-input form-input-sm" data-rule="addList" data-idx="${i}" style="margin-top:4px;">${opts}</select>
                    </td>
                    <td><textarea class="form-textarea" rows="3" data-rule="domains" data-idx="${i}"
                                  placeholder="example.org" spellcheck="false">${esc((r.domains || []).join('\n'))}</textarea></td>
                    <td><button class="btn btn-ghost btn-sm" data-action="rmRule" data-idx="${i}" title="Удалить правило" style="color:var(--error);">✕</button></td>
                </tr>`;
        }).join('');
        box.innerHTML = `
            <div style="overflow-x:auto;">
                <table class="table" style="min-width:860px;">
                    <thead><tr>
                        <th style="width:84px;">Порядок</th>
                        <th style="width:40px;">Вкл</th>
                        <th style="width:17%;">Имя</th>
                        <th style="width:17%;">Outbound</th>
                        <th>Списки</th>
                        <th style="width:24%;">Свои домены</th>
                        <th style="width:44px;"></th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
            ${sources.outbounds.length ? '' : '<div class="form-hint">Outbound\'ы появятся после выбора конфига sing-box.</div>'}`;
    }

    // ══════════════════ Events ══════════════════

    function setDirty(v) {
        dirty = !!v;
        const el = document.getElementById('agr-dirty');
        if (el) el.style.display = dirty ? '' : 'none';
    }

    // Построчно: сначала срезаем комментарий «# …» в каждой строке, потом
    // делим по пробелам/запятым (иначе слова комментария стали бы доменами).
    function splitLines(text) {
        return String(text || '').split(/\r?\n/)
            .map(line => line.replace(/#.*$/, ''))
            .flatMap(line => line.split(/[\s,;]+/))
            .map(s => s.trim()).filter(Boolean);
    }

    function onInput(e) {
        const t = e.target;
        if (!st) return;
        if (t.dataset.field) {
            const f = t.dataset.field;
            if (f === 'enabled' || f === 'singbox_config') return;   // в change
            if (f === 'agh_password') pw = t.value;
            else if (f === 'clients') st.clients = splitLines(t.value);
            else st[f] = t.value;
            setDirty(true);
            return;
        }
        if (t.dataset.rule) {
            const r = (st.rules || [])[+t.dataset.idx];
            if (!r) return;
            if (t.dataset.rule === 'name') r.name = t.value;
            else if (t.dataset.rule === 'domains') r.domains = splitLines(t.value);
            else return;
            setDirty(true);
        }
    }

    async function onChange(e) {
        const t = e.target;
        if (!st) return;
        if (t.dataset.field === 'enabled') {
            st.enabled = t.checked;
            setDirty(true);
            return;
        }
        if (t.dataset.field === 'singbox_config') {
            st.singbox_config = t.value;
            setDirty(true);
            await loadSources();
            renderRules();
            return;
        }
        if (!t.dataset.rule) return;
        const i = +t.dataset.idx;
        const r = (st.rules || [])[i];
        if (!r) return;
        if (t.dataset.rule === 'enabled') {
            r.enabled = t.checked;
        } else if (t.dataset.rule === 'outbound') {
            r.outbound = t.value;
        } else if (t.dataset.rule === 'addList') {
            let id = t.value;
            if (id === '__geosite') {
                const name = (window.prompt('Имя geosite (как в v2fly/domain-list-community), например openai') || '')
                    .trim().toLowerCase();
                id = name ? 'geosite:' + name.replace(/^geosite:/, '') : '';
            }
            if (id) {
                r.lists = r.lists || [];
                if (!r.lists.includes(id)) r.lists.push(id);
            }
            renderRules();
        } else {
            return;
        }
        setDirty(true);
    }

    function onClick(e) {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const a = btn.dataset.action;
        const i = +btn.dataset.idx;
        if (a === 'save') { save(); return; }
        if (a === 'plan') { showPlan(); return; }
        if (a === 'apply') { apply(); return; }
        if (a === 'test') { testConnection(); return; }
        if (!st) return;
        const rules = st.rules || (st.rules = []);
        if (a === 'addRule') {
            rules.push({ id: '', name: '', enabled: true, outbound: '', lists: [], domains: [] });
        } else if (a === 'rmRule') {
            rules.splice(i, 1);
        } else if (a === 'up' && i > 0) {
            [rules[i - 1], rules[i]] = [rules[i], rules[i - 1]];
        } else if (a === 'down' && i < rules.length - 1) {
            [rules[i + 1], rules[i]] = [rules[i], rules[i + 1]];
        } else if (a === 'rmList') {
            const r = rules[i];
            if (r) r.lists = (r.lists || []).filter(x => x !== btn.dataset.list);
        } else {
            return;
        }
        setDirty(true);
        renderRules();
    }

    // ══════════════════ Actions ══════════════════

    function payload() {
        const p = {
            enabled: !!st.enabled,
            agh_url: st.agh_url || '',
            agh_user: st.agh_user || '',
            dns_target: st.dns_target || '',
            singbox_config: st.singbox_config || '',
            clients: st.clients || [],
            rules: (st.rules || []).map(r => ({
                id: r.id || '', name: r.name || '', enabled: r.enabled !== false,
                outbound: r.outbound || '', lists: r.lists || [], domains: r.domains || [],
                // подсетей на странице нет, но при сохранении их не теряем
                subnets: r.subnets || [],
            })),
        };
        if (pw) p.agh_password = pw;
        return p;
    }

    async function save(quiet) {
        if (!st) return false;
        try {
            const r = await API.put('/api/agh-routes', payload());
            st = r.settings;
            pw = '';
            setDirty(false);
            renderForm();
            (r.warnings || []).forEach(w => Toast.warning(w, 8000));
            if (!quiet) Toast.success('Сохранено');
            return true;
        } catch (e) {
            Toast.error('Не сохранено: ' + e.message);
            return false;
        }
    }

    // На время плана/применения форма недоступна: правка посреди запроса
    // разошлась бы с тем, что уже ушло на сервер.
    function lockForm(on) {
        const body = document.getElementById('agr-body');
        if (!body) return;
        body.inert = !!on;
        body.style.opacity = on ? '0.6' : '';
    }

    async function withBusy(fn) {
        if (busy) return;
        busy = true;
        const btns = document.querySelectorAll('[data-action="plan"], [data-action="apply"], [data-action="save"]');
        btns.forEach(b => { b.disabled = true; });
        try {
            await fn();
        } finally {
            busy = false;
            lockForm(false);
            btns.forEach(b => { b.disabled = false; });
        }
    }

    function showPlan() {
        return withBusy(async () => {
            if (dirty && !(await save(true))) return;
            lockForm(true);
            try {
                const r = await API.get('/api/agh-routes/plan', LONG);
                lastPlan = r.plan;
                renderPlan(lastPlan);
            } catch (e) {
                Toast.error('План: ' + e.message);
            }
        });
    }

    function apply() {
        return withBusy(async () => {
            if (dirty && !(await save(true))) return;
            const cfg = st.singbox_config || '-';
            const ok = await Confirm.show('Применить маршруты?',
                `Конфиг sing-box «${esc(cfg)}» будет перезаписан (запущенный инстанс перезапустится), `
                + 'в AdGuard Home заменятся наши upstream-строки. Чужие строки и правила не трогаются.',
                { confirmLabel: 'Применить' });
            if (!ok) return;
            lockForm(true);
            let r;
            try {
                r = await API.post('/api/agh-routes/apply', {}, LONG);
            } catch (e) {
                Toast.error('Применение: ' + e.message);
                return;
            }
            // После успешной записи показываем уже новое состояние
            // (план «изменений нет»), а не то, что было до применения.
            let shown = r.plan;
            if (r.ok && r.changed) {
                try {
                    shown = (await API.get('/api/agh-routes/plan', LONG)).plan || shown;
                } catch (_) {}
            }
            if (shown) { lastPlan = shown; renderPlan(lastPlan, r); }
            if (!r.ok) {
                Toast.error(r.error || 'Применение не удалось', 10000);
            } else if (!r.changed) {
                Toast.info('Изменений нет, ничего не записано');
            } else {
                Toast.success('Применено');
                const sb = r.singbox || {};
                // Ни процесс панели, ни юнит sing-box-gui этот конфиг не
                // крутят, перезапускать больше некому.
                if (sb.saved && !sb.restarted && !sb.restart_via) {
                    Toast.warning(`Конфиг «${sb.config}» сохранён, но не запущен ни панелью, ни юнитом sing-box-gui: перезапустите sing-box вручную`, 10000);
                }
                if (sb.warning) Toast.warning(sb.warning, 8000);
            }
            try {
                const s = await API.get('/api/agh-routes');
                st = s.settings;
                const el = document.getElementById('agr-applied');
                if (el) el.innerHTML = appliedText();
            } catch (_) {}
        });
    }

    async function testConnection() {
        const out = document.getElementById('agr-test');
        if (out) { out.textContent = 'проверяю…'; out.className = 'text-muted'; }
        try {
            const r = await API.post('/api/agh-routes/test', {
                agh_url: st ? st.agh_url : '', agh_user: st ? st.agh_user : '', agh_password: pw,
            });
            if (!out) return;
            if (r.ok) {
                out.className = 'text-success';
                out.textContent = `AdGuard Home ${r.version || '?'}`
                    + (r.running ? '' : ', DNS не запущен')
                    + (r.protection_enabled ? '' : ', защита выключена');
            } else {
                out.className = 'text-error';
                out.textContent = r.error || 'нет связи';
            }
        } catch (e) {
            if (out) { out.className = 'text-error'; out.textContent = e.message; }
        }
        if (out) out.style.fontSize = '12px';
    }

    // ══════════════════ Plan ══════════════════

    function linesBlock(title, lines) {
        if (!lines || !lines.length) return '';
        return `<details style="margin-top:6px;">
            <summary style="cursor:pointer; font-size:12px;">${esc(title)} (${lines.length})</summary>
            <pre class="text-mono" style="margin:6px 0 0; padding:8px; background:var(--bg-input); border-radius:var(--radius-sm);
                 font-size:11px; max-height:260px; overflow:auto; white-space:pre-wrap; word-break:break-all;">${esc(lines.join('\n'))}</pre>
        </details>`;
    }

    function renderPlan(p, result) {
        const card = document.getElementById('agr-plan-card');
        const box = document.getElementById('agr-plan');
        if (!card || !box || !p) return;
        card.style.display = '';
        const agh = p.agh || {};
        const sb = p.singbox || {};
        const errs = (result && result.errors && result.errors.length) ? result.errors : (p.errors || []);

        const list = (items, cls) => items.length
            ? `<ul style="margin:0 0 10px; padding-left:18px; font-size:12.5px;">${items.map(x =>
                `<li class="${cls}">${esc(x)}</li>`).join('')}</ul>` : '';

        const mode = agh.mode === 'clients' ? 'поклиентно' : 'глобально';
        const changed = p.changed
            ? '<span class="badge badge-warning">есть изменения</span>'
            : '<span class="badge badge-success">изменений нет</span>';

        const ruleRows = (p.rules || []).map(r => `
            <tr>
                <td>${esc(r.name)}</td>
                <td>${esc(r.outbound || '-')}</td>
                <td>${r.skipped ? `<span class="text-muted">${esc(r.skipped)}</span>` : r.domains}</td>
                <td class="text-muted" style="font-size:11px;">${esc((r.sample || []).join(', '))}</td>
            </tr>`).join('');

        const clientRows = (agh.clients || []).map(c => {
            const act = { add: 'создать', update: 'обновить', remove: 'снять наши строки',
                          delete: 'удалить (создан здесь)', none: 'без изменений' }[c.action] || c.action;
            return `<tr><td>${esc(c.name)}</td><td class="text-muted">${esc(c.id || '')}</td>
                <td>${esc(act)}</td><td>${c.current} → ${c.desired}</td></tr>`;
        }).join('');

        const sbState = sb.found
            ? (sb.running ? '<span class="badge badge-success">запущен панелью</span>'
                : sb.systemd ? '<span class="badge badge-success">запущен юнитом sing-box-gui</span>'
                : '<span class="badge badge-muted">не запущен</span>')
            : '<span class="badge badge-danger">нет конфига</span>';
        const sbRules = (sb.rules_desired || []).map(r =>
            `${r.outbound}: ${(r.domain_suffix || []).length} доменов`);

        let resultHtml = '';
        if (result && result.ok && result.changed) {
            const s = result.singbox || {};
            const parts = [];
            const via = { panel: 'панелью', systemd: 'через systemd (sing-box-gui)' }[s.restart_via] || '';
            if (s.saved) parts.push(`sing-box «${s.config}» сохранён` + (s.restarted ? ` и перезапущен ${via}` : ''));
            if (result.agh && result.agh.global_updated) parts.push('AdGuard: upstream_dns обновлён');
            if (result.agh && result.agh.clients && result.agh.clients.length) {
                parts.push('AdGuard: клиентов изменено ' + result.agh.clients.length);
            }
            resultHtml = `<div class="text-success" style="font-size:12.5px; margin-bottom:10px;">Применено. ${esc(parts.join('; '))}</div>`;
        }

        box.innerHTML = `
            ${resultHtml}
            ${list(errs, 'text-error')}
            ${list(p.warnings || [], 'text-warning')}
            <div style="font-size:13px; margin-bottom:10px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
                ${changed}
                <span>доменов всего: <strong>${p.domains_total || 0}</strong></span>
                <span>AdGuard: <strong>${mode}</strong>${agh.reachable ? '' : ' <span class="text-error">(нет связи)</span>'}</span>
                ${p.enabled ? '' : '<span class="badge badge-muted">выключено</span>'}
            </div>

            ${ruleRows ? `<table class="table" style="margin-bottom:12px;">
                <thead><tr><th>Правило</th><th style="width:18%;">Outbound</th><th style="width:12%;">Доменов</th><th>Примеры</th></tr></thead>
                <tbody>${ruleRows}</tbody></table>` : ''}

            <div class="card-title" style="margin:8px 0 4px;">sing-box «${esc(sb.config || '-')}» ${sbState}
                ${sb.changed ? '<span class="badge badge-warning">будет изменён</span>' : ''}</div>
            <div style="font-size:12.5px;">
                наших правил сейчас: ${(sb.rules_current || []).length}, после применения: ${(sb.rules_desired || []).length}
                ${sb.cleanup_config ? `<br>из прежнего конфига «${esc(sb.cleanup_config)}» наши правила будут сняты` : ''}
            </div>
            ${linesBlock('Правила после применения', sbRules)}

            <div class="card-title" style="margin:14px 0 4px;">AdGuard Home
                ${agh.global_changed ? '<span class="badge badge-warning">upstream_dns изменится</span>' : ''}</div>
            <div style="font-size:12.5px;">
                наших строк в глобальных upstream'ах: ${(agh.current || []).length} → ${(agh.desired || []).length}
                · доменов +${(agh.domains_add || []).length} / −${(agh.domains_remove || []).length}
            </div>
            ${linesBlock('Строки добавятся', agh.add)}
            ${linesBlock('Строки уйдут', agh.remove)}
            ${linesBlock('Домены добавятся', agh.domains_add)}
            ${linesBlock('Домены уйдут', agh.domains_remove)}
            ${clientRows ? `<table class="table" style="margin-top:10px;">
                <thead><tr><th>Клиент AdGuard</th><th>ids</th><th>Действие</th><th style="width:14%;">Наших строк</th></tr></thead>
                <tbody>${clientRows}</tbody></table>` : ''}
            ${linesBlock('Все наши строки', agh.lines)}
        `;
    }

    // ══════════════════ Helpers ══════════════════

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function escAttr(s) {
        return esc(s).replace(/"/g, '&quot;');
    }

    return { render, destroy };
})();
