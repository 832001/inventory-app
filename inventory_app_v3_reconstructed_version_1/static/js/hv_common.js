/* =====================================================================
 *  hv_common.js  —  shared helpers for the inventory pages
 *  Install as:  static/js/hv_common.js     (load it in each page, see usage)
 *
 *  Gives every page (hosts, clusters, datastores, vms ...):
 *    - platform registry built from the API (no hardcoded hypervisors)
 *    - hypervisor -> run picker + pinned-run chips (state kept in the URL)
 *    - platform filter buttons built from the rows on screen
 *    - environment select (multi-value ?vcenter=a,b supported)
 *
 *  Page usage:
 *    HV.init({ pickerBox:'runPickerBox', filterBox:'platformFilter', envSelect:'envSelect',
 *              onRunChange: loadData,      // called when a run is picked/reset
 *              onFilterChange: renderTable // called when the platform filter changes
 *            }).then(loadData);
 * ===================================================================== */
window.HV = (function () {
    const PLATFORM_META = {
        vmware:  { label: "VMware",  color: "#1d7bb8", icon: "bi-server" },
        hyperv:  { label: "Hyper-V", color: "#4f46e5", icon: "bi-windows" },
        proxmox: { label: "Proxmox", color: "#e57000", icon: "bi-boxes" },
        nutanix: { label: "Nutanix", color: "#6aa300", icon: "bi-cloud" }
    };
    const AUTO_COLORS = ["#0ea5e9", "#d946ef", "#14b8a6", "#f59e0b", "#84cc16", "#f43f5e", "#8b5cf6", "#06b6d4"];

    const S = { platforms: {}, runsByPlatform: {}, selectedRuns: {}, runTarget: null,
                platformFilter: "all", envList: [], rows: [] };
    let CFG = {};

    /* ---------- tiny helpers ---------- */
    function toNum(v) { return (v === undefined || v === null) ? 0 : parseFloat(v) || 0; }
    function esc(s) {
        return String(s === undefined || s === null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function platformKey(name) { return String(name || 'unknown').toLowerCase().replace(/[^a-z0-9]/g, '') || 'unknown'; }
    function fmtGB(gb, dec) { const n = toNum(gb), d = dec === undefined ? 2 : dec; return n >= 1024 ? (n / 1024).toFixed(d) + " TB" : n.toFixed(1) + " GB"; }
    function fmtMB(mb, dec) { return fmtGB(toNum(mb) / 1024, dec); }
    function barColor(p) { const n = toNum(p); return n > 90 ? "#dc2626" : n > 70 ? "#f97316" : "#10b981"; }
    function bar(pct) {
        const n = toNum(pct);
        return `${n.toFixed(1)}%<div class="progress-micro"><div class="progress-fill-micro" style="width:0;background:${barColor(n)};" data-target-width="${Math.min(100, n)}%"></div></div>`;
    }
    function animateBars(container) {
        const bars = container.querySelectorAll('.progress-fill-micro[data-target-width]');
        requestAnimationFrame(() => requestAnimationFrame(() => bars.forEach(b => { b.style.width = b.dataset.targetWidth; })));
    }
    function flag(v) {       // tri-state: unknown / yes / no
        if (v === null || v === undefined) return '<span class="text-muted">-</span>';
        return v ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>';
    }
    const GOOD = ['poweredon', 'on', 'online', 'running', 'connected', 'up', 'normal', 'accessible', 'true'];
    const BAD  = ['poweredoff', 'off', 'offline', 'disconnected', 'notresponding', 'down', 'unknown', 'inaccessible', 'false'];
    function stateBadge(value, icon) {
        if (value === null || value === undefined || value === '') return '-';
        const v = String(value).toLowerCase().replace(/[^a-z]/g, '');
        const cls = GOOD.includes(v) ? 'text-success' : BAD.includes(v) ? 'text-danger' : 'text-warning';
        return `<span class="${cls}"><i class="bi ${icon || 'bi-circle-fill'}"></i> ${esc(value)}</span>`;
    }

    // run key "20261031020300" -> "2026-10-31 02:03"   (anything else is shown as-is)
    function fmtRunKey(key) {
        const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})\d{2}(?:-\d+)?$/.exec(String(key || ''));
        return m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}` : String(key || '');
    }
    const VM_ON  = ['poweredon', 'on', 'online', 'running', 'up'];
    const VM_OFF = ['poweredoff', 'off', 'offline', 'stopped', 'shutoff', 'shutdown', 'down'];
    function powerBadge(state) {
        if (!state) return '<span class="badge bg-secondary">Unknown</span>';
        const v = String(state).toLowerCase().replace(/[^a-z]/g, '');
        if (VM_ON.includes(v))  return '<span class="badge bg-success">On</span>';
        if (VM_OFF.includes(v)) return '<span class="badge bg-danger">Off</span>';
        return `<span class="badge bg-secondary">${esc(state)}</span>`;
    }

    /* ---------- platforms ---------- */
    function registerPlatform(key, label) {
        if (S.platforms[key]) return S.platforms[key];
        const meta = PLATFORM_META[key] || {};
        const idx = Object.keys(S.platforms).length;
        S.platforms[key] = {
            key: key,
            label: meta.label || label || (key.charAt(0).toUpperCase() + key.slice(1)),
            color: meta.color || AUTO_COLORS[idx % AUTO_COLORS.length],
            icon: meta.icon || "bi-hdd-rack"
        };
        return S.platforms[key];
    }
    function tagRows(rows) {
        rows.forEach(r => {
            const key = r.platform_key || platformKey(r.platform);
            registerPlatform(key, r.platform);
            r._pkey = key;
        });
        return rows;
    }
    function platformCell(key) {
        const p = S.platforms[key] || registerPlatform(key);
        return `<span class="platform-badge" style="--pc:${p.color}"><i class="bi ${p.icon} me-1"></i>${esc(p.label)}</span>`;
    }

    /* ---------- URL state (run_id_<type>, vcenter) ---------- */
    function urlParam(name) { return new URLSearchParams(window.location.search).get(name) || ""; }
    function readRunsFromUrl() {
        new URLSearchParams(window.location.search).forEach((val, name) => {
            if (name.indexOf('run_id_') === 0 && val) S.selectedRuns[name.slice(7)] = val;
        });
    }
    function syncUrl() {
        const url = new URL(window.location.href);
        Array.from(url.searchParams.keys()).filter(k => k.indexOf('run_id_') === 0).forEach(k => url.searchParams.delete(k));
        Object.keys(S.selectedRuns).forEach(k => { if (S.selectedRuns[k]) url.searchParams.set('run_id_' + k, S.selectedRuns[k]); });
        history.replaceState(null, '', url.toString());
    }
    function runParams() {
        return Object.keys(S.selectedRuns).filter(k => S.selectedRuns[k])
            .map(k => `run_id_${encodeURIComponent(k)}=${encodeURIComponent(S.selectedRuns[k])}`);
    }
    // API query string: pinned runs + ?vcenter= from the page URL + any extras
    function apiQuery(extra) {
        const qs = runParams();
        const v = urlParam('vcenter');
        if (v) qs.push('vcenter=' + encodeURIComponent(v));
        Object.keys(extra || {}).forEach(k => { if (extra[k]) qs.push(k + '=' + encodeURIComponent(extra[k])); });
        return qs.length ? '?' + qs.join('&') : '';
    }
    // link to another inventory page, carrying the pinned runs.  extra.vcenter overrides the URL one.
    function pageUrl(path, extra) {
        const p = {};
        const v = urlParam('vcenter'); if (v) p.vcenter = v;
        Object.assign(p, extra || {});
        const qs = runParams();
        Object.keys(p).forEach(k => { if (p[k]) qs.push(k + '=' + encodeURIComponent(p[k])); });
        return path + (qs.length ? '?' + qs.join('&') : '');
    }
    function exportUrl(path, fmt) {
        const q = apiQuery({ cluster: urlParam('cluster'), datastore: urlParam('datastore') });
        return path + (q ? q + '&' : '?') + 'format=' + encodeURIComponent(fmt);
    }

    const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];
    // all runs of one hypervisor, grouped by month:  <optgroup label="October 2026 (12)">
    function runOptionsHtml(list, selectedKey) {
        let html = '', lastMonth = null, buf = [];
        const flush = () => {
            if (!buf.length) return;
            const [y, m] = lastMonth.split('-');
            html += `<optgroup label="${esc((MONTHS[+m - 1] || lastMonth) + ' ' + y)} (${buf.length})">${buf.join('')}</optgroup>`;
            buf = [];
        };
        list.forEach((r, i) => {
            const ts = r.run_timestamp || fmtRunKey(r.run_id);
            const month = ts.slice(0, 7);
            if (month !== lastMonth) { flush(); lastMonth = month; }
            const sel = String(selectedKey || '') === String(r.run_id) ? 'selected' : '';
            buf.push(`<option value="${esc(r.run_id)}" ${sel}>${esc(ts)}${i === 0 ? ' \u00B7 latest' : ''}</option>`);
        });
        flush();
        return html;
    }

    function runLabel(k, key) {
        const hit = (S.runsByPlatform[k] || []).find(r => String(r.run_id) === String(key));
        return hit && hit.run_timestamp ? hit.run_timestamp : fmtRunKey(key);
    }

    /* ---------- run picker ---------- */
    function renderRunPicker() {
        const box = document.getElementById(CFG.pickerBox);
        const keys = Object.keys(S.platforms);
        if (!box) return;
        if (!keys.length) { box.innerHTML = ''; return; }
        if (!S.runTarget || !S.platforms[S.runTarget]) S.runTarget = keys[0];
        const p = S.platforms[S.runTarget];
        const list = S.runsByPlatform[S.runTarget] || [];

        const hvOpts = keys.map(k => `<option value="${esc(k)}" ${k === S.runTarget ? 'selected' : ''}>${esc(S.platforms[k].label)}${S.selectedRuns[k] ? ' \u25CF' : ''}</option>`).join('');
        const runOpts = `<option value="">Latest ${esc(p.label)} run</option>` + runOptionsHtml(list, S.selectedRuns[S.runTarget]);
        const chips = keys.filter(k => S.selectedRuns[k]).map(k =>
            `<span class="run-chip" style="--pc:${S.platforms[k].color}">${esc(S.platforms[k].label)} &middot; ${esc(runLabel(k, S.selectedRuns[k]))}
                <i class="bi bi-x-lg chip-x" data-reset="${esc(k)}" title="Back to latest"></i></span>`).join('');

        box.innerHTML = `<label class="text-muted small mb-0 fw-semibold text-nowrap">Run:</label>
            <div class="run-select-wrap" style="--pc:${p.color}">
                <select class="form-select form-select-sm hv-select" id="hvPicker" title="Choose hypervisor">${hvOpts}</select>
                <i class="bi bi-chevron-right run-arrow"></i>
                <select class="form-select form-select-sm run-select" id="runPicker" title="Runs of ${esc(p.label)} only">${runOpts}</select>
            </div>${chips}`;

        document.getElementById('hvPicker').addEventListener('change', e => { S.runTarget = e.target.value; renderRunPicker(); });
        document.getElementById('runPicker').addEventListener('change', e => {
            if (e.target.value) S.selectedRuns[S.runTarget] = e.target.value; else delete S.selectedRuns[S.runTarget];
            syncUrl(); if (CFG.onRunChange) CFG.onRunChange();
        });
        box.querySelectorAll('.chip-x').forEach(x => x.addEventListener('click', () => {
            delete S.selectedRuns[x.dataset.reset]; syncUrl(); if (CFG.onRunChange) CFG.onRunChange();
        }));
    }

    function loadRuns() {
        return fetch("/api/dashboard/runs").then(r => r.json()).then(data => {
            S.runsByPlatform = {};
            (data.platforms || []).forEach(p => registerPlatform(p.key, p.label));
            (data.runs || []).forEach(r => {
                const k = r.platform_key || platformKey(r.platform);
                registerPlatform(k, r.platform);
                (S.runsByPlatform[k] = S.runsByPlatform[k] || []).push(r);
            });
            const first = Object.keys(S.selectedRuns)[0];
            if (first && S.platforms[first]) S.runTarget = first;
            renderRunPicker();
        }).catch(err => console.error("Failed to load runs:", err));
    }

    /* ---------- platform filter ---------- */
    function setPlatformFilter(key) {
        S.platformFilter = key;
        if (key !== 'all' && S.platforms[key]) { S.runTarget = key; renderRunPicker(); }
        renderPlatformFilter();
        if (CFG.onFilterChange) CFG.onFilterChange();
    }
    function renderPlatformFilter(rows) {
        if (rows) S.rows = rows;
        const box = document.getElementById(CFG.filterBox);
        if (!box) return;
        const present = CFG.filterFromPlatforms ? Object.keys(S.platforms) : Object.keys(S.platforms).filter(k => S.rows.some(r => r._pkey === k));
        if (S.platformFilter !== 'all' && !present.includes(S.platformFilter)) S.platformFilter = 'all';
        box.innerHTML = [`<span class="platform-filter-btn ${S.platformFilter === 'all' ? 'active' : ''}" data-platform="all">All</span>`]
            .concat(present.map(k => `<span class="platform-filter-btn ${S.platformFilter === k ? 'active' : ''}" data-platform="${esc(k)}">${esc(S.platforms[k].label)}</span>`)).join('');
        box.querySelectorAll('.platform-filter-btn').forEach(b => b.addEventListener('click', () => setPlatformFilter(b.dataset.platform)));
    }

    /* ---------- environment select ---------- */
    function populateEnvSelect(rows, field) {
        field = field || 'vcenter_name';
        const vcenterParam = urlParam('vcenter');
        S.envList = vcenterParam ? vcenterParam.split(',').map(s => s.trim()).filter(Boolean) : [];
        const envSet = new Set();
        rows.forEach(r => { if (r[field]) envSet.add(r[field]); });
        const select = document.getElementById(CFG.envSelect);
        if (!select) return;
        select.innerHTML = '<option value="">— All Environments —</option>';
        Array.from(envSet).sort().forEach(env => {
            const opt = document.createElement('option');
            opt.value = env; opt.textContent = env;
            if (S.envList.length === 1 && env === S.envList[0]) opt.selected = true;
            select.appendChild(opt);
        });
        if (S.envList.length > 1) {
            const opt = document.createElement('option');
            opt.value = vcenterParam; opt.textContent = "Multiple (" + vcenterParam + ")"; opt.selected = true;
            select.appendChild(opt);
        } else if (S.envList.length === 1 && !envSet.has(S.envList[0])) {
            const opt = document.createElement('option');
            opt.value = S.envList[0]; opt.textContent = S.envList[0] + " (filtered)"; opt.selected = true;
            select.appendChild(opt);
        }
    }
    function onEnvChange() {
        const url = new URL(window.location.href);      // run_id_* already live in the URL (syncUrl)
        const v = document.getElementById(CFG.envSelect).value;
        if (v) url.searchParams.set('vcenter', v); else url.searchParams.delete('vcenter');
        window.location.href = url.toString();
    }

    // platform filter + environment filter. Pages add their own search on top.
    function rowMatches(row, envField) {
        if (S.platformFilter !== 'all' && row._pkey !== S.platformFilter) return false;
        if (S.envList.length > 0 && !S.envList.includes(row[envField || 'vcenter_name'])) return false;
        return true;
    }

    /* ---------- styles (injected once, so pages need no extra CSS) ---------- */
    function injectStyles() {
        if (document.getElementById('hv-common-css')) return;
        const st = document.createElement('style');
        st.id = 'hv-common-css';
        st.textContent = `
            .run-select-wrap{display:flex;align-items:center;gap:4px;padding:2px 6px 2px 8px;border-radius:10px;
                border:1px solid var(--border-color,#dee2e6);border-left:4px solid var(--pc,#1a4a6e);}
            .run-select-wrap .hv-select{min-width:140px;font-weight:600;}
            .run-select-wrap .run-select{min-width:170px;max-width:230px;}
            .run-select-wrap .run-arrow{color:#6b7280;font-size:.8rem;}
            .run-chip{display:inline-flex;align-items:center;gap:4px;font-size:.65rem;font-weight:600;
                padding:2px 4px 2px 9px;border-radius:14px;border:1px solid var(--border-color,#dee2e6);
                border-left:4px solid var(--pc,#1a4a6e);white-space:nowrap;}
            .run-chip .chip-x{cursor:pointer;padding:0 5px;color:#6b7280;}
            .run-chip .chip-x:hover{color:#dc2626;}
            .platform-badge{display:inline-block;background:var(--pc,#6b7280);color:#fff;font-size:.65rem;
                font-weight:700;padding:1px 8px;border-radius:10px;white-space:nowrap;}
        `;
        document.head.appendChild(st);
    }

    function init(cfg) {
        CFG = cfg || {};
        injectStyles();
        readRunsFromUrl();
        const e = document.getElementById(CFG.envSelect);
        if (e) e.addEventListener('change', onEnvChange);
        return loadRuns();
    }

    return {
        init, tagRows, platformCell, renderPlatformFilter, populateEnvSelect, rowMatches,
        apiQuery, pageUrl, exportUrl, runParams, state: S,
        toNum, esc, fmtGB, fmtMB, bar, animateBars, flag, stateBadge, powerBadge, fmtRunKey, barColor
    };
})();
