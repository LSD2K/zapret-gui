/**
 * test_updates_lock_ui.js: замок обновлений в вебке (debian-gw,
 * docs/gw/spec-t4-updates.md, components/updates_lock.js).
 *
 * Страницы поднимаются как в index.html: исходники в `node:vm` поверх
 * мини-DOM и подменённого API. Проверяется, что при замке вместо кнопок
 * установки, обновления, удаления и загрузки файла стоит плашка с замком,
 * а без замка кнопки на месте.
 *
 * Запуск: node --test tests/test_updates_lock_ui.js
 */

const assert = require('node:assert');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const WEB = path.join(__dirname, '..', 'web', 'js');

function makeElement(id) {
    // Как в разметке страниц: баннеры и карточки стартуют скрытыми.
    const classes = new Set(['hidden']);
    return {
        id, innerHTML: '', textContent: '', style: {}, dataset: {}, href: '',
        className: '',
        classList: {
            add: (c) => classes.add(c),
            remove: (c) => classes.delete(c),
            contains: (c) => classes.has(c),
        },
        addEventListener() {},
        closest() { return null; },
    };
}

function makeSandbox(locked, responses) {
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
        console, document,
        window: { location: { hash: '' } },
        setTimeout: () => 1, clearTimeout() {},
        setInterval: () => 1, clearInterval() {},
        API: {
            get(url) {
                calls.get.push(url);
                if (url === '/api/updates/lock') {
                    return Promise.resolve({
                        ok: true, locked,
                        message: locked ? 'обновления на этом хосте делает gw-panel' : '',
                    });
                }
                return Promise.resolve(responses[url] || { ok: true });
            },
            post(url, body) {
                calls.post.push([url, body]);
                return Promise.resolve(responses[url] || { ok: true });
            },
        },
        TransportSelect: { load: () => Promise.resolve([]) },
        Expert: { noteHtml: () => '' },
        Toast: { success() {}, error() {}, info() {}, warning() {} },
        Confirm: { show: () => Promise.resolve(true) },
    };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    for (const rel of ['components/updates_lock.js', 'components/setup_ui.js',
                       'pages/singbox_setup.js', 'pages/zapret_manager.js']) {
        vm.runInContext(fs.readFileSync(path.join(WEB, rel), 'utf8'),
                        sandbox, { filename: rel });
    }
    vm.runInContext('globalThis.__sb = SingboxSetupPage;'
                    + 'globalThis.__zm = ZapretManagerPage;'
                    + 'globalThis.__lock = UpdatesLock;', sandbox);
    return { sandbox, elements, calls };
}

const flush = () => new Promise((r) => setImmediate(r));

const SINGBOX = {
    '/api/singbox/environment/refresh': {
        ok: true, ready: true, platform: { kind: 'generic' },
        tun: { available: true },
        binary: { installed: true, version: '1.14.1-extended',
                  path: '/usr/local/bin/sing-box' },
    },
    '/api/singbox/version': {
        ok: true, installed: { version: '1.14.1' },
        latest: { version: '1.14.2' },
    },
};

const ZAPRET = {
    '/api/zapret': {
        ok: true, installed: { installed: true, version: 'v1.0.5.2' },
        latest: { ok: true, version: 'v1.0.6' }, update_available: true,
        nfqws_running: { running: true, pid: 1 }, operation: {},
        platform: 'generic', arch: 'x86_64',
    },
    '/api/gui/check': {
        ok: true, installed_version: '0.25.3', latest_version: '0.26.0',
        update_available: true,
    },
};

async function renderSingbox(locked) {
    const ctx = makeSandbox(locked, SINGBOX);
    ctx.sandbox.__sb.render(ctx.sandbox.document.getElementById('page'));
    for (let i = 0; i < 5; i++) await flush();
    return { ...ctx, html: ctx.elements.get('sb-setup-content').innerHTML };
}

async function renderZapret(locked) {
    const ctx = makeSandbox(locked, ZAPRET);
    ctx.sandbox.__zm.render(ctx.sandbox.document.getElementById('page'));
    for (let i = 0; i < 5; i++) await flush();
    const el = (id) => ctx.sandbox.document.getElementById(id);
    return { ...ctx, el };
}

test('sing-box: при замке плашка вместо установки, удаления и загрузки', async () => {
    const { html, calls } = await renderSingbox(true);
    assert.ok(calls.get.includes('/api/updates/lock'));
    assert.match(html, /data-updates-lock/);
    assert.match(html, /обновления на этом хосте делает gw-panel/);
    assert.doesNotMatch(html, /SingboxSetupPage\.install\(\)/);
    assert.doesNotMatch(html, /SingboxSetupPage\.uninstall\(\)/);
    assert.doesNotMatch(html, /\.upload\(\)/);
    // Версия видна как раньше.
    assert.match(html, /1\.14\.1-extended/);
});

test('sing-box: без замка кнопки на месте', async () => {
    const { html } = await renderSingbox(false);
    assert.doesNotMatch(html, /data-updates-lock/);
    assert.match(html, /SingboxSetupPage\.install\(\)/);
    assert.match(html, /SingboxSetupPage\.uninstall\(\)/);
});

test('zapret2 и GUI: при замке плашки, баннеры обновления спрятаны', async () => {
    const { el } = await renderZapret(true);
    for (const id of ['zm-actions', 'zm-gui-actions']) {
        assert.match(el(id).innerHTML, /data-updates-lock/, id);
    }
    assert.doesNotMatch(el('zm-actions').innerHTML, /doUpdate|doInstall|showUninstallPlan/);
    assert.doesNotMatch(el('zm-gui-actions').innerHTML, /updateGui/);
    assert.equal(el('zm-nfqws-extras').innerHTML, '');
    assert.equal(el('zm-gui-extras').innerHTML, '');
    // Баннеры с кнопками «Обновить» остались скрытыми.
    assert.ok(el('zm-update-banner').classList.contains('hidden'));
    assert.ok(el('gui-update-banner').classList.contains('hidden'));
});

test('zapret2 и GUI: без замка кнопки на месте', async () => {
    const { el } = await renderZapret(false);
    assert.match(el('zm-actions').innerHTML, /ZapretManagerPage\.doUpdate\(\)/);
    assert.match(el('zm-actions').innerHTML, /showUninstallPlan/);
    assert.match(el('zm-gui-actions').innerHTML, /ZapretManagerPage\.updateGui\(\)/);
    assert.ok(!el('zm-update-banner').classList.contains('hidden'));
    assert.ok(!el('gui-update-banner').classList.contains('hidden'));
    assert.equal(el('gui-update-version').textContent, '0.26.0');
});

test('noticeHtml экранирует текст сервера', async () => {
    const ctx = makeSandbox(true, {});
    ctx.sandbox.API.get = () => Promise.resolve({ locked: true, message: '<b>x</b>' });
    await ctx.sandbox.__lock.load();
    assert.ok(ctx.sandbox.__lock.isLocked());
    assert.match(ctx.sandbox.__lock.noticeHtml(), /&lt;b&gt;x&lt;\/b&gt;/);
});

test('load без эндпоинта не включает замок', async () => {
    const ctx = makeSandbox(false, {});
    ctx.sandbox.API.get = () => Promise.reject(new Error('HTTP 404'));
    await ctx.sandbox.__lock.load();
    assert.equal(ctx.sandbox.__lock.isLocked(), false);
});
