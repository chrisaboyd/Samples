// DC2 Invention Planner — vanilla JS, data from data.js (window.DC2_DATA).
(() => {
  'use strict';

  const DATA = window.DC2_DATA || { photos: [], inventions: [], items: [] };
  const STORE_KEY = 'dc2planner.v1';
  const CHAPTERS = [1, 2, 3, 4, 5, 6, 7, 8];

  const photoById = new Map(DATA.photos.map(s => [s.id, s]));
  const itemById = new Map(DATA.items.map(i => [i.id, i]));
  const invById = new Map(DATA.inventions.map(i => [i.id, i]));

  // photo id -> inventions that use it in any recipe
  const usedBy = new Map();
  for (const inv of DATA.inventions) {
    for (const sid of new Set(inv.recipes.flat())) {
      if (!usedBy.has(sid)) usedBy.set(sid, []);
      usedBy.get(sid).push(inv);
    }
  }

  // ---------- progress state ----------
  const state = load();
  function load() {
    try {
      const s = JSON.parse(localStorage.getItem(STORE_KEY));
      if (s && typeof s === 'object') {
        return { photos: s.photos || {}, inventions: s.inventions || {}, chapter: s.chapter ?? 1 };
      }
    } catch (_) { /* storage unavailable or corrupt */ }
    return { photos: {}, inventions: {}, chapter: 1 };
  }
  function save() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(state)); } catch (_) {}
  }
  const hasPhoto = id => !!state.photos[id];
  const isInvented = id => !!state.inventions[id];

  // ---------- availability ----------
  const itemChapter = id => {
    const chs = (itemById.get(id)?.sources || []).map(s => s.chapter).filter(Number.isInteger);
    return chs.length ? Math.min(...chs) : null;
  };
  const maxKnown = arr => (arr.some(c => c == null) ? null : Math.max(0, ...arr));

  // Earliest chapter an invention can be *invented*: inventing needs only the photos, so materials
  // don't gate it (their chest/drop data is too patchy anyway). Falls back to the guide's chapter.
  const invChapterCache = new Map();
  function invChapter(inv) {
    if (invChapterCache.has(inv.id)) return invChapterCache.get(inv.id);
    const recipeChs = inv.recipes.map(r => maxKnown(r.map(id => photoById.get(id)?.chapter ?? null)));
    const known = recipeChs.filter(c => c != null);
    const ch = known.length ? Math.min(...known) : (inv.chapter ?? null);
    invChapterCache.set(inv.id, ch);
    return ch;
  }
  // Earliest chapter every material has a documented source (a hint for building, not a gate).
  const buildChapter = inv => maxKnown(inv.materials.map(m => itemChapter(m.id)));
  const inChapter = ch => ch == null || state.chapter === 0 || ch <= state.chapter;

  // Fewest missing photos across an invention's recipes.
  function missingCount(inv) {
    if (!inv.recipes.length) return Infinity;
    return Math.min(...inv.recipes.map(r => r.filter(id => !hasPhoto(id)).length));
  }
  function invStatus(inv) {
    if (isInvented(inv.id)) return 'done';
    const m = missingCount(inv);
    if (m === 0) return 'ready';
    if (m === 1) return 'near';
    return 'todo';
  }

  // ---------- helpers ----------
  const $view = document.getElementById('view');
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const chLabel = ch => (ch == null ? 'Ch ?' : `Ch ${ch}`);
  const norm = s => String(s || '').toLowerCase();
  const ui = { invFilter: 'all', invCat: 'all', invQuery: '', photoFilter: 'open', photoSort: 'value', photoQuery: '', checkKind: 'all', checkMissable: false, checkHideDone: false };

  function tagsForPhoto(s) {
    let t = s.kind === 'scoop' ? '<span class="tag scoop">SCOOP</span>' : '';
    if (s.missable) t += '<span class="tag missable">MISSABLE</span>';
    else if (s.maybe_missable) t += '<span class="tag near">MAYBE MISSABLE</span>';
    if (s.ghost) t += '<span class="tag">GHOST</span>';
    if (!s.verified) t += '<span class="tag unverified">unverified</span>';
    return t;
  }
  function statusTag(st) {
    return { done: '<span class="tag done">INVENTED</span>', ready: '<span class="tag ready">READY</span>', near: '<span class="tag near">1 AWAY</span>' }[st] || '';
  }
  function photoCard(s, extra = '') {
    return `<li class="card">
      <input type="checkbox" class="check" data-photo="${esc(s.id)}" ${hasPhoto(s.id) ? 'checked' : ''} aria-label="Have ${esc(s.name)}">
      <div class="body">
        <a class="title" href="#/photo/${encodeURIComponent(s.id)}">${esc(s.name)}</a>
        <div class="meta">${tagsForPhoto(s)}${chLabel(s.chapter)} · ${esc(s.location || 'Location unknown')}${extra}</div>
      </div></li>`;
  }
  function invCard(inv) {
    const st = invStatus(inv);
    const miss = missingCount(inv);
    const missTxt = st === 'todo' && Number.isFinite(miss) ? ` · ${miss} photos missing` : '';
    return `<li class="card">
      <input type="checkbox" class="check" data-inv="${esc(inv.id)}" ${isInvented(inv.id) ? 'checked' : ''} aria-label="Invented ${esc(inv.name)}">
      <div class="body">
        <a class="title" href="#/invention/${encodeURIComponent(inv.id)}">${esc(inv.name)}</a>
        <div class="meta">${statusTag(st)}${inv.verified ? '' : '<span class="tag unverified">unverified</span>'}${chLabel(invChapter(inv))} · ${esc(inv.category || '')}${missTxt}</div>
      </div></li>`;
  }
  const chipRow = (group, options, current) =>
    `<div class="chips">${options.map(([v, label]) => `<button class="chip ${current === v ? 'on' : ''}" data-chip="${group}" data-value="${esc(v)}">${esc(label)}</button>`).join('')}</div>`;

  // ---------- views ----------
  function viewInventions() {
    const cats = [...new Set(DATA.inventions.map(i => i.category).filter(Boolean))].sort();
    const q = norm(ui.invQuery);
    const list = DATA.inventions
      .filter(inv => inChapter(invChapter(inv)))
      .filter(inv => ui.invCat === 'all' || inv.category === ui.invCat)
      .filter(inv => ui.invFilter === 'all' || invStatus(inv) === ui.invFilter)
      .filter(inv => !q || norm(inv.name).includes(q))
      .sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
    function rank(inv) { return { ready: 0, near: 1, todo: 2, done: 3 }[invStatus(inv)]; }

    $view.innerHTML = `
      <div class="controls">
        <input type="search" id="q" placeholder="Search inventions" value="${esc(ui.invQuery)}">
        <select id="cat"><option value="all">All categories</option>${cats.map(c => `<option ${c === ui.invCat ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select>
      </div>
      ${chipRow('invFilter', [['all', 'All'], ['ready', 'Ready'], ['near', '1 away'], ['todo', 'Needs photos'], ['done', 'Invented']], ui.invFilter)}
      <p class="summary">${list.length} inventions available ${state.chapter ? `by Chapter ${state.chapter}` : 'in all chapters'}</p>
      ${list.length ? `<ul class="list">${list.map(invCard).join('')}</ul>` : '<p class="empty">Nothing matches.</p>'}`;
    bindSearch('q', v => (ui.invQuery = v));
    document.getElementById('cat').onchange = e => { ui.invCat = e.target.value; render(); };
  }

  function viewPhotos() {
    const q = norm(ui.photoQuery);
    const value = s => (usedBy.get(s.id) || []).filter(i => !isInvented(i.id)).length;
    const list = DATA.photos
      .filter(s => inChapter(s.chapter))
      .filter(s => ui.photoFilter === 'all' || (ui.photoFilter === 'open' ? !hasPhoto(s.id) : ui.photoFilter === 'missable' ? s.missable || s.maybe_missable : hasPhoto(s.id)))
      .filter(s => !q || norm(s.name).includes(q) || norm(s.location).includes(q))
      .sort(ui.photoSort === 'value' ? (a, b) => value(b) - value(a) || a.name.localeCompare(b.name) : (a, b) => a.name.localeCompare(b.name));

    $view.innerHTML = `
      <div class="controls">
        <input type="search" id="q" placeholder="Search photos or locations" value="${esc(ui.photoQuery)}">
        <select id="sort"><option value="value" ${ui.photoSort === 'value' ? 'selected' : ''}>Most useful first</option><option value="name" ${ui.photoSort === 'name' ? 'selected' : ''}>A–Z</option></select>
      </div>
      ${chipRow('photoFilter', [['open', 'Not taken'], ['have', 'Taken'], ['missable', 'Missable'], ['all', 'All']], ui.photoFilter)}
      <p class="summary">${list.length} photos · "used in" counts inventions you haven't made yet</p>
      ${list.length ? `<ul class="list">${list.map(s => photoCard(s, ` · used in ${value(s)}`)).join('')}</ul>` : '<p class="empty">Nothing matches.</p>'}`;
    bindSearch('q', v => (ui.photoQuery = v));
    document.getElementById('sort').onchange = e => { ui.photoSort = e.target.value; render(); };
  }

  function viewChecklist() {
    const groups = new Map();
    for (const s of DATA.photos.filter(p => ui.checkKind === 'all' || p.kind === ui.checkKind)) {
      const k = s.chapter ?? 'unknown';
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(s);
    }
    const keys = [...groups.keys()].sort((a, b) => (a === 'unknown') - (b === 'unknown') || a - b);
    const html = keys.map(k => {
      const all = groups.get(k);
      const shown = all
        .filter(s => !ui.checkMissable || s.missable || s.maybe_missable)
        .filter(s => !ui.checkHideDone || !hasPhoto(s.id))
        .sort((a, b) => b.missable - a.missable || a.name.localeCompare(b.name));
      const done = all.filter(s => hasPhoto(s.id)).length;
      if (!shown.length) return '';
      return `<section class="chapter-group">
        <h2><span>${k === 'unknown' ? 'Chapter unknown' : `Chapter ${k}`}</span><small class="summary">${done}/${all.length}</small></h2>
        <div class="bar"><span style="width:${(100 * done / all.length).toFixed(1)}%"></span></div>
        <ul class="list">${shown.map(s => photoCard(s, s.missable && s.missable_note ? ` · ⚠ ${esc(s.missable_note)}` : s.maybe_missable && s.maybe_missable_note ? ` · ${esc(s.maybe_missable_note)}` : '')).join('')}</ul>
      </section>`;
    }).join('');
    $view.innerHTML = `
      ${chipRow('checkKind', [['all', 'Ideas + Scoops'], ['idea', 'Ideas'], ['scoop', 'Scoops']], ui.checkKind)}
      ${chipRow('checkMissable', [['false', 'Everything'], ['true', 'Missable only']], String(ui.checkMissable))}
      ${chipRow('checkHideDone', [['false', 'Show taken'], ['true', 'Hide taken']], String(ui.checkHideDone))}
      ${html || '<p class="empty">Nothing left here. Nice.</p>'}`;
  }

  function viewProgress() {
    const sTotal = DATA.photos.length, sHave = DATA.photos.filter(s => hasPhoto(s.id)).length;
    const iTotal = DATA.inventions.length, iHave = DATA.inventions.filter(i => isInvented(i.id)).length;
    const missOpen = DATA.photos.filter(s => s.missable && !hasPhoto(s.id) && inChapter(s.chapter));
    $view.innerHTML = `
      <div class="stat-grid">
        <div class="stat"><b>${sHave}/${sTotal}</b><span>Photos taken</span></div>
        <div class="stat"><b>${iHave}/${iTotal}</b><span>Inventions made</span></div>
        <div class="stat"><b>${DATA.inventions.filter(i => invStatus(i) === 'ready').length}</b><span>Ready to invent</span></div>
        <div class="stat"><b>${missOpen.length}</b><span>Missable photos still open (to Ch ${state.chapter || 8})</span></div>
      </div>
      <h2>Backup</h2>
      <p class="summary">Progress lives in this browser only. Export now and then so a cleared cache can't wipe it, or to move it between phone and PC.</p>
      <div class="row">
        <button class="primary" id="export">Export progress</button>
        <label><button id="importBtn">Import progress</button><input type="file" id="import" accept="application/json" hidden></label>
        <button id="reset">Reset all</button>
      </div>
      <h2>Data</h2>
      <p class="summary">${sTotal} photos, ${iTotal} inventions, ${DATA.items.length} materials. Built ${esc(DATA.generated || '?')}.
      Entries marked <span class="tag unverified">unverified</span> had missing or conflicting info in the sources.</p>`;
    document.getElementById('export').onclick = exportProgress;
    document.getElementById('importBtn').onclick = () => document.getElementById('import').click();
    document.getElementById('import').onchange = importProgress;
    document.getElementById('reset').onclick = () => {
      if (confirm('Clear all photo and invention progress?')) { state.photos = {}; state.inventions = {}; save(); render(); }
    };
  }

  function viewInvention(id) {
    const inv = invById.get(id);
    if (!inv) return notFound();
    const recipes = inv.recipes.map((r, i) => {
      const missing = r.filter(sid => !hasPhoto(sid)).length;
      return `<div class="recipe">
        <div class="recipe-head">${inv.recipes.length > 1 ? `Recipe ${i + 1} · ` : ''}${missing ? `${missing} missing` : 'All photos taken'}</div>
        <ul class="list">${r.map(sid => photoCard(photoById.get(sid) || stubPhoto(sid))).join('')}</ul></div>`;
    }).join('') || '<p class="empty">No recipe recorded.</p>';
    const mats = inv.materials.map(m => {
      const it = itemById.get(m.id);
      const srcs = (it?.sources || []).map(s => `${esc(s.type)}: ${esc(s.where)}${s.chapter ? ` (Ch ${s.chapter})` : ''}${s.note ? ` — ${esc(s.note)}` : ''}`).join('<br>');
      const sub = invById.get(m.id);
      return `<li class="card"><div class="body">
        <span class="title">${m.qty}× ${sub ? `<a href="#/invention/${encodeURIComponent(sub.id)}">${esc(m.name)}</a>` : esc(m.name)}</span>
        <div class="meta">${srcs || (sub ? 'Invention — tap for its recipe' : 'Source unknown')}</div></div></li>`;
    }).join('');
    $view.innerHTML = `<div class="detail">
      <a class="back" href="#/inventions">← Inventions</a>
      <h1>${esc(inv.name)}</h1>
      <div class="meta">${statusTag(invStatus(inv))}${chLabel(invChapter(inv))} · ${esc(inv.category || '')}
        ${inv.chapter != null && inv.chapter !== invChapter(inv) ? ` · guide lists Ch ${inv.chapter}` : ''}</div>
      <div class="row"><button class="${isInvented(inv.id) ? '' : 'primary'}" id="toggleInv">${isInvented(inv.id) ? 'Mark not invented' : 'Mark invented'}</button></div>
      ${inv.description ? `<p>${esc(inv.description)}</p>` : ''}
      ${inv.notes ? `<p class="note">${esc(inv.notes)}</p>` : ''}
      <h2>Photos needed</h2>${recipes}
      <h2>Materials</h2>${buildChapter(inv) > (invChapter(inv) ?? 0) ? `<p class="summary">Earliest documented source for all materials: Ch ${buildChapter(inv)} (chest and drop data is incomplete, so it may be sooner).</p>` : ''}${mats ? `<ul class="list">${mats}</ul>` : '<p class="empty">No materials recorded.</p>'}
      ${sourcesBlock(inv.sources)}</div>`;
    document.getElementById('toggleInv').onclick = () => { toggle(state.inventions, inv.id); render(); };
  }

  function viewPhoto(id) {
    const s = photoById.get(id);
    if (!s) return notFound();
    const invs = (usedBy.get(id) || []).slice().sort((a, b) => a.name.localeCompare(b.name));
    $view.innerHTML = `<div class="detail">
      <a class="back" href="#/photos">← Photos</a>
      <h1>${esc(s.name)}</h1>
      <div class="meta">${tagsForPhoto(s)}${chLabel(s.chapter)}${s.category ? ` · ${esc(s.category)}` : ''}</div>
      <div class="row"><button class="${hasPhoto(id) ? '' : 'primary'}" id="togglePhoto">${hasPhoto(id) ? 'Mark not taken' : 'Mark taken'}</button></div>
      <h2>Where</h2><p>${esc(s.location || 'Unknown')}</p>
      ${s.how ? `<p>${esc(s.how)}</p>` : ''}
      ${s.missable ? `<p class="note">Missable${s.missable_note ? `: ${esc(s.missable_note)}` : ''}</p>` : ''}
      ${s.maybe_missable ? `<p class="note">The GameFAQs guide doesn't list this as missable, but another source says: ${esc(s.maybe_missable_note || 'it can be missed')}</p>` : ''}
      <h2>Used in ${invs.length} invention${invs.length === 1 ? '' : 's'}</h2>
      ${invs.length ? `<ul class="list">${invs.map(invCard).join('')}</ul>` : '<p class="empty">Not part of any recorded recipe.</p>'}
      ${sourcesBlock(s.sources)}</div>`;
    document.getElementById('togglePhoto').onclick = () => { toggle(state.photos, id); render(); };
  }

  const stubPhoto = id => ({ id, name: id, chapter: null, location: 'Not in photo list', verified: false });
  const sourcesBlock = srcs => (srcs?.length ? `<h2>Sources</h2><p class="sources">${srcs.map(u => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a>`).join('<br>')}</p>` : '');
  function notFound() { $view.innerHTML = '<p class="empty">Not found. <a href="#/inventions">Back</a></p>'; }

  // ---------- actions ----------
  function toggle(map, id) { if (map[id]) delete map[id]; else map[id] = 1; save(); }

  function exportProgress() {
    const blob = new Blob([JSON.stringify({ app: 'dc2planner', version: 1, exported: new Date().toISOString(), ...state }, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `dc2-progress-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  function importProgress(e) {
    const file = e.target.files[0];
    if (!file) return;
    file.text().then(txt => {
      const d = JSON.parse(txt);
      if (d.app !== 'dc2planner') throw new Error('Not a DC2 Planner export');
      state.photos = d.photos || {}; state.inventions = d.inventions || {}; state.chapter = d.chapter ?? state.chapter;
      save(); syncChapter(); render(); alert('Progress imported.');
    }).catch(err => alert(`Import failed: ${err.message}`));
  }

  function bindSearch(id, set) {
    const el = document.getElementById(id);
    el.oninput = () => {
      set(el.value);
      const pos = el.selectionStart;
      render();
      const again = document.getElementById(id);
      again.focus();
      again.setSelectionRange(pos, pos);
    };
  }

  // Delegated handlers survive re-renders.
  $view.addEventListener('change', e => {
    const t = e.target;
    if (t.dataset.photo) { toggle(state.photos, t.dataset.photo); render(); }
    else if (t.dataset.inv) { toggle(state.inventions, t.dataset.inv); render(); }
  });
  $view.addEventListener('click', e => {
    const chip = e.target.closest('[data-chip]');
    if (!chip) return;
    const k = chip.dataset.chip, v = chip.dataset.value;
    ui[k] = v === 'true' ? true : v === 'false' ? false : v;
    render();
  });

  // ---------- chapter picker & routing ----------
  const $chapter = document.getElementById('chapter');
  $chapter.innerHTML = CHAPTERS.map(c => `<option value="${c}">${c}</option>`).join('') + '<option value="0">All</option>';
  function syncChapter() { $chapter.value = String(state.chapter); }
  $chapter.onchange = () => { state.chapter = Number($chapter.value); save(); render(); };
  syncChapter();

  function render() {
    const [, route = 'inventions', arg] = (location.hash || '#/inventions').split('/');
    const scrollY = window.scrollY;
    const tab = { invention: 'inventions', photo: 'photos' }[route] || route;
    document.querySelectorAll('#tabs a').forEach(a => a.classList.toggle('active', a.dataset.tab === tab));
    const id = arg && decodeURIComponent(arg);
    ({ inventions: viewInventions, photos: viewPhotos, checklist: viewChecklist, progress: viewProgress,
       invention: () => viewInvention(id), photo: () => viewPhoto(id) }[route] || viewInventions)();
    if (render.lastHash === location.hash) window.scrollTo(0, scrollY);
    else window.scrollTo(0, 0);
    render.lastHash = location.hash;
  }
  window.addEventListener('hashchange', render);
  render();
})();
