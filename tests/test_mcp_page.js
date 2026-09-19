/**
 * test_mcp_page.js — страница «MCP-сервер» (web/js/pages/mcp.js, S15).
 *
 * Страницы проекта — не модули: это IIFE, которые кладут себя в
 * глобальную константу и живут в браузере рядом с API/Toast/Confirm.
 * Поэтому тест поднимает их так же, как это делает index.html —
 * выполняет исходник в `node:vm` поверх мини-DOM и подменённого API,
 * — и проверяет ровно то, из-за чего страница вообще существует:
 *
 *   - она отдаёт `render`/`destroy` и не ходит в сеть сама по себе;
 *   - число публикуемых инструментов видно на экране (это самая
 *     наглядная обратная связь во всём интерфейсе);
 *   - токен в общем состоянии НЕ показывается — только точки;
 *   - блоки 6–8 скрыты, когда соответствующего модуля на устройстве
 *     нет, а не висят надписью «в разработке»;
 *   - предупреждения приходят из i18n-словаря, а не из разметки.
 */

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const WEB = path.join(__dirname, '..', 'web', 'js');

// ─────────────────────────── мини-DOM ───────────────────────────
// Полноценный jsdom тянуть некуда (в проекте нет npm-зависимостей).
// Странице нужны ровно getElementById, innerHTML и addEventListener.

function makeElement(id) {
    return {
        id,
        innerHTML: '',
        textContent: '',
        style: {},
        dataset: {},
        addEventListener() {},
        closest() { return null; },
    };
}

function makeSandbox(state) {
    const elements = new Map();
    const calls = { get: [], post: [] };

    const document = {
        hidden: false,
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, makeElement(id));
            return elements.get(id);
        },
    };

    const sandbox = {
        console,
        document,
        window: { location: { origin: 'http://192.168.1.1:8080',
                              protocol: 'http:' } },
        localStorage: { getItem: () => 'ru', setItem() {} },
        // Таймер не заводим по-настоящему: тест не должен висеть, а
        // планирование проверяется тем, что destroy() его снимает.
        setTimeout: () => 1,
        clearTimeout: () => {},
        API: {
            get(url) {
                calls.get.push(url);
                if (url === '/api/mcp/ui/token') {
                    return Promise.resolve({ ok: true, token: 'T'.repeat(64) });
                }
                return Promise.resolve(state);
            },
            post(url, body) {
                calls.post.push([url, body]);
                return Promise.resolve({ ok: true, info: state.info });
            },
        },
        Toast: { success() {}, error() {}, info() {}, warning() {} },
        Confirm: { show: () => Promise.resolve(true) },
        Clipboard: { copyWithToast() {} },
    };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);

    // Порядок — как в index.html: словари, обёртка i18n, страница.
    for (const rel of ['i18n/ru.js', 'i18n/en.js', 'utils/i18n.js',
                       'pages/mcp.js']) {
        vm.runInContext(fs.readFileSync(path.join(WEB, rel), 'utf8'),
                        sandbox, { filename: rel });
    }
    // Объявления `const` не становятся свойствами globalThis — достаём
    // страницу явно, ровно как её достаёт app.js по имени.
    vm.runInContext('globalThis.__page = McpPage;'
                    + 'globalThis.__i18n = i18n;', sandbox);

    return { sandbox, elements, calls, page: sandbox.__page,
             i18n: sandbox.__i18n };
}

function fixture(overrides) {
    const base = {
        ok: true,
        info: {
            ok: true,
            enabled: true,
            active: true,
            token_set: true,
            bind: 'inherit',
            protocol_version: '2025-06-18',
            tools_total: 93,
            tools_available: 41,
            tools_by_scope: { read: 32, control: 9 },
            permissions: { control: true, probes: false, experiments: true },
            permissions_effective: { control: true, probes: false,
                                     experiments: false },
            permissions_info: [
                { key: 'control', title: 'управление движками',
                  granted: true, effective: true, requires: [], missing: [] },
                { key: 'experiments', title: 'движок экспериментов',
                  granted: true, effective: false,
                  requires: ['control', 'probes'], missing: ['probes'] },
                { key: 'shell_full', title: 'произвольная команда от root',
                  granted: false, effective: false, requires: [],
                  missing: [] },
            ],
            audit: { enabled: true },
            resources: 12,
            prompts: 5,
            endpoint: '/api/mcp',
            sse: { enabled: false, sessions: 0, max_sessions: 4 },
        },
        access: { gui_host: '0.0.0.0', gui_port: 8080, loopback_only: false,
                  tls_builtin: false, endpoint: '/api/mcp' },
        audit: { enabled: true, path: '/opt/etc/zapret-gui/mcp-audit.jsonl',
                 records: [], undoable: [] },
        experiment: { available: false },
        code: { available: false },
        shell: { available: false },
    };
    return Object.assign(base, overrides || {});
}

// ──────────────────────────── тесты ─────────────────────────────

test('страница отдаёт render и destroy', () => {
    const { page } = makeSandbox(fixture());
    assert.equal(typeof page.render, 'function');
    assert.equal(typeof page.destroy, 'function');
});

test('состояние берётся одним запросом', async () => {
    const { page, calls, sandbox } = makeSandbox(fixture());
    await page.render(makeElement('page-container'));
    assert.deepEqual(calls.get, ['/api/mcp/ui/state']);
    page.destroy();
    assert.ok(sandbox);
});

test('число публикуемых инструментов видно на экране', async () => {
    const { page, elements } = makeSandbox(fixture());
    await page.render(makeElement('page-container'));
    const html = elements.get('mcp-status').innerHTML;
    assert.match(html, /Публикуется инструментов/);
    assert.match(html, /41/);
    assert.match(html, /93/);
    page.destroy();
});

test('токен в общем состоянии заменён точками', async () => {
    const { page, elements } = makeSandbox(fixture());
    await page.render(makeElement('page-container'));
    const html = elements.get('mcp-token').innerHTML;
    assert.match(html, /•/);
    assert.ok(!html.includes('T'.repeat(64)), 'токен не показывается сам');
    assert.match(html, /Показать/);
    page.destroy();
});

test('предупреждение о токене приходит из i18n-словаря', async () => {
    const { page, elements, i18n } = makeSandbox(fixture());
    await page.render(makeElement('page-container'));
    const expected = i18n.t('mcp.warn.token');
    assert.notEqual(expected, 'mcp.warn.token', 'ключа нет в словаре');
    assert.ok(elements.get('mcp-token').innerHTML.includes(
        expected.slice(0, 40)));
    page.destroy();
});

test('обычный HTTP — предупреждение, что токен виден в каждом запросе',
     async () => {
    const { page, elements, i18n } = makeSandbox(fixture());
    await page.render(makeElement('page-container'));
    const warn = i18n.t('mcp.warn.http');
    assert.ok(elements.get('mcp-status').innerHTML.includes(warn.slice(0, 40)));
    page.destroy();
});

test('разрешение, которое стоит, но не действует, помечено', async () => {
    const { page, elements } = makeSandbox(fixture());
    await page.render(makeElement('page-container'));
    const html = elements.get('mcp-perms').innerHTML;
    assert.match(html, /experiments/);
    assert.match(html, /не действует/);
    assert.match(html, /сначала включите\s+probes/);
    page.destroy();
});

test('блоки 6–8 скрыты, когда сессии на устройстве нет', async () => {
    const { page, elements } = makeSandbox(fixture());
    await page.render(makeElement('page-container'));
    for (const id of ['mcp-exp-card', 'mcp-code-card', 'mcp-shell-card']) {
        assert.equal(elements.get(id).style.display, 'none', id);
    }
    page.destroy();
});

test('блок shell показывается и несёт кнопку аварийного запрета',
     async () => {
    const state = fixture({
        shell: { available: true, jobs: [], pending: [], guards: [] },
    });
    state.info.permissions.shell_full = true;
    const { page, elements } = makeSandbox(state);
    await page.render(makeElement('page-container'));
    assert.equal(elements.get('mcp-shell-card').style.display, '');
    const html = elements.get('mcp-shell').innerHTML;
    assert.match(html, /Запретить shell немедленно/);
    assert.match(html, /data-action="shellPanic"/);
    page.destroy();
});

test('ожидающая подтверждения команда предлагает решение человеку',
     async () => {
    const state = fixture({
        shell: {
            available: true, jobs: [], guards: [],
            pending: [{ token: 'cf-1', summary: 'rm -rf /tmp/x',
                        scope: 'shell_full', expires_in_sec: 42 }],
        },
    });
    const { page, elements } = makeSandbox(state);
    await page.render(makeElement('page-container'));
    const html = elements.get('mcp-shell').innerHTML;
    assert.match(html, /rm -rf \/tmp\/x/);
    assert.match(html, /data-action="shellApprove"/);
    assert.match(html, /data-action="shellReject"/);
    page.destroy();
});

test('идущий эксперимент показывает, сколько осталось до авто-отката',
     async () => {
    const state = fixture({
        experiment: {
            available: true,
            status: { state: 'running', phase: 'вариант', variant: 'B',
                      progress: 1, total: 3, ttl_left_sec: 97,
                      awaiting_commit: true, applied_variant: 'B' },
        },
    });
    const { page, elements } = makeSandbox(state);
    await page.render(makeElement('page-container'));
    const html = elements.get('mcp-exp').innerHTML;
    assert.match(html, /97 с/);
    assert.match(html, /data-action="expCommit"/);
    assert.match(html, /data-action="expRollback"/);
    page.destroy();
});

test('правка, ждущая подтверждения, показана как ожидание, а не ошибка',
     async () => {
    const state = fixture({
        code: {
            available: true, snapshots: [], local_changes: [],
            staging: { count: 0 },
            waiting: { snapshot_id: 'snap-20260919-120000', state: 'applied',
                       files: ['core/mcp/server.py'], left_sec: 240 },
        },
    });
    const { page, elements } = makeSandbox(state);
    await page.render(makeElement('page-container'));
    const html = elements.get('mcp-code').innerHTML;
    assert.match(html, /snap-20260919-120000/);
    assert.match(html, /осталось 240 с/);
    assert.match(html, /data-action="codeCommit"/);
    // Тормоз — рядом с тем, что он гасит: переключатели самоправки
    // живут в разрешениях, но рисуются здесь же.
    assert.match(html, /data-perm="self_edit"/);
    assert.match(html, /data-perm="self_edit_core"/);
    page.destroy();
});

test('сниппеты подключения не содержат токена, пока его не показали',
     async () => {
    const { page, elements } = makeSandbox(fixture());
    await page.render(makeElement('page-container'));
    const html = elements.get('mcp-snippets').innerHTML;
    assert.match(html, /claude mcp add --transport http/);
    assert.match(html, /mcpServers/);
    assert.match(html, /&lt;ваш-токен&gt;/);
    // В примере для VS Code токена нет намеренно: редактор спросит сам.
    assert.match(html, /input:zapret-token/);
    assert.match(html, /zapret-gui mcp --stdio/);
    page.destroy();
});

test('в mcpServers нет поля type: клиенты Claude Desktop его не ждут',
     async () => {
    const { page, elements } = makeSandbox(fixture());
    await page.render(makeElement('page-container'));
    const html = elements.get('mcp-snippets').innerHTML;
    const block = html.slice(html.indexOf('mcpServers'),
                             html.indexOf('.vscode/mcp.json'));
    assert.ok(!/"type"/.test(block), 'поле type в mcpServers лишнее');
    page.destroy();
});

test('журнал вызовов показывает инструмент и итог', async () => {
    const state = fixture({
        audit: {
            enabled: true, path: '/tmp/mcp-audit.jsonl', undoable: [],
            records: [{ time: '2026-09-19 12:00:00', tool: 'nfqws_status',
                        scope: 'read', status: 'ok', ok: true, args: {} },
                      { time: '2026-09-19 12:01:00', tool: 'shell_exec',
                        scope: 'shell_full', status: 'denied', ok: false,
                        error: 'нужно разрешение shell_full' }],
        },
    });
    const { page, elements } = makeSandbox(state);
    await page.render(makeElement('page-container'));
    const html = elements.get('mcp-audit').innerHTML;
    assert.match(html, /nfqws_status/);
    assert.match(html, /отказано/);
    assert.match(html, /нужно разрешение shell_full/);
    page.destroy();
});
