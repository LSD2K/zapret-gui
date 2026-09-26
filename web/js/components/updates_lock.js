/**
 * updates_lock.js: замок обновлений (debian-gw, docs/gw/spec-t4-updates.md).
 *
 * При `updates.locked` в settings.json бэкенд отвечает 403 на установку,
 * обновление и удаление nfqws2, sing-box и самого GUI. Страницы с такими
 * кнопками спрашивают состояние (GET /api/updates/lock) и вместо кнопок
 * показывают плашку с замком.
 *
 *   await UpdatesLock.load();
 *   if (UpdatesLock.isLocked()) box.innerHTML = UpdatesLock.noticeHtml();
 */

const UpdatesLock = (() => {
    let state = { locked: false, message: '' };

    async function load() {
        try {
            const r = await API.get('/api/updates/lock');
            state = { locked: !!(r && r.locked), message: (r && r.message) || '' };
        } catch (_) {
            // Старый бэкенд без эндпоинта или нет связи: состояние не меняем,
            // сервер всё равно ответит 403, если замок есть.
        }
        return state;
    }

    function isLocked() { return !!state.locked; }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function noticeHtml() {
        const msg = state.message || 'обновления на этом хосте делает gw-panel';
        return `
            <div class="updates-lock" data-updates-lock
                 style="display:flex; align-items:center; gap:8px; padding:8px 12px;
                        border-radius:6px; border:1px solid var(--border, rgba(128,128,128,.4));
                        color:var(--text-secondary); font-size:13px;">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                     width="16" height="16" aria-hidden="true">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
                <span>Установка и обновление закрыты: ${esc(msg)}</span>
            </div>`;
    }

    return { load, isLocked, noticeHtml };
})();
