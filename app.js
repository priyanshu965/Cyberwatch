/**
 * CYBERWATCH DASHBOARD — app.js
 * Loads data/intel.json and renders the threat intelligence feed.
 * No external dependencies — pure vanilla JavaScript.
 *
 * Loading strategy (in order):
 *   1. Try fetch('data/intel.json') — works on GitHub Pages & local server
 *   2. Fall back to window.INTEL_DATA — embedded in index.html, works when
 *      opening the file directly (file:// protocol, no server needed)
 *
 * Visual Intelligence features (NEW):
 *   - Click an intel-card to toggle the .expanded class
 *   - An .analysis-section reveals: AI Summary, Severity Score meter,
 *     and a Mermaid.js attack-workflow graph
 *   - Mermaid is loaded lazily from CDN only on first card expansion
 */

// ─── State ──────────────────────────────────────────────────────────────────
let allItems      = [];
let filteredItems = [];
let activeFilter  = 'all';
let searchQuery   = '';

// ─── Mermaid Lazy-Loader ────────────────────────────────────────────────────
let _mermaidLoaded   = false;
let _mermaidReady    = false;
const _mermaidQueue  = [];   // callbacks waiting for Mermaid to initialise

/**
 * Loads Mermaid from CDN the first time it is needed, then fires all queued
 * callbacks. Subsequent calls fire the callback immediately.
 */
function loadMermaid(callback) {
  if (_mermaidReady) { callback(); return; }
  _mermaidQueue.push(callback);
  if (_mermaidLoaded) return;          // already loading — just queued
  _mermaidLoaded = true;

  const script   = document.createElement('script');
  script.src     = 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js';
  script.async   = true;
  script.onload  = () => {
    mermaid.initialize({
      startOnLoad: false,
      theme:       'base',
      themeVariables: {
        darkMode:            true,
        background:          '#0d1117',
        primaryColor:        '#0d2233',
        primaryBorderColor:  '#00ffe1',
        primaryTextColor:    '#c9d8e8',
        secondaryColor:      '#111820',
        secondaryBorderColor:'#1e2d3d',
        secondaryTextColor:  '#5f7a94',
        tertiaryColor:       '#16202e',
        tertiaryBorderColor: '#1e2d3d',
        tertiaryTextColor:   '#5f7a94',
        lineColor:           '#3b9eff',
        edgeLabelBackground: '#0d1117',
        clusterBkg:          '#111820',
        titleColor:          '#00ffe1',
        fontFamily:          "'JetBrains Mono', 'Courier New', monospace",
        fontSize:            '11px',
      },
    });
    _mermaidReady = true;
    _mermaidQueue.forEach(cb => cb());
    _mermaidQueue.length = 0;
  };
  script.onerror = () => {
    console.warn('Mermaid CDN failed to load — workflow graphs will be unavailable');
    _mermaidQueue.length = 0;
  };
  document.head.appendChild(script);
}

/**
 * Renders the Mermaid graph inside a specific card.
 * Runs only once per card (guarded by data-rendered attribute).
 */
async function renderMermaidForCard(card) {
  const container = card.querySelector('.analysis-mermaid');
  if (!container || container.dataset.rendered === 'true') return;

  const graphDef = container.dataset.graph;
  if (!graphDef) return;

  container.innerHTML = '<span class="analysis-graph-loading">▸ rendering graph…</span>';

  try {
    const uid      = 'mmd-' + Math.random().toString(36).slice(2, 9);
    const { svg }  = await mermaid.render(uid, graphDef);
    container.innerHTML = svg;
    // Make SVG responsive
    const svgEl = container.querySelector('svg');
    if (svgEl) { svgEl.style.maxWidth = '100%'; svgEl.style.height = 'auto'; }
    container.dataset.rendered = 'true';
  } catch (err) {
    console.warn('Mermaid render error:', err);
    container.innerHTML = '<span class="analysis-error">⚠ Workflow graph unavailable</span>';
  }
}

// ─── Entry Point ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initFilters();
  initSearch();
  loadIntelData();
});

// ─── Load Data ────────────────────────────────────────────────────────────────
async function loadIntelData() {
  try {
    let data;
    if (window.location.protocol !== 'file:') {
      const response = await fetch(`data/intel.json?v=${Date.now()}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      data = await response.json();
    } else {
      if (window.INTEL_DATA) {
        data = window.INTEL_DATA;
        const meta = document.getElementById('last-updated');
        if (meta) {
          meta.textContent = '⚠ Preview mode (open via server or GitHub Pages for live data)';
          meta.style.color = '#f5c518';
        }
      } else {
        throw new Error('No data available');
      }
    }

    allItems = data.items || [];

    if (data.last_updated) {
      const date = new Date(data.last_updated);
      const utc  = date.toUTCString();
      const ist  = date.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', dateStyle: 'medium', timeStyle: 'medium' });
      document.getElementById('last-updated').textContent = `Last updated: ${utc} | IST: ${ist}`;
    }

    renderSidebar();
    renderDailySummary();
    applyFilters();
    showContent();
  } catch (err) {
    console.error('Failed to load intel.json:', err);
    showError();
  }
}

// ─── Filter & Search Logic ────────────────────────────────────────────────────
function applyFilters() {
  if (activeFilter === 'matrix') { showMatrixView(); return; }

  filteredItems = allItems.filter(item => {
    const categoryMatch = activeFilter === 'all' || item.category === activeFilter;
    const q             = searchQuery.toLowerCase();
    const searchMatch   = !q
      || (item.title       && item.title.toLowerCase().includes(q))
      || (item.description && item.description.toLowerCase().includes(q))
      || (item.cve_id      && item.cve_id.toLowerCase().includes(q))
      || (item.source      && item.source.toLowerCase().includes(q))
      || (item.ttps        && item.ttps.some(t => t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)));
    return categoryMatch && searchMatch;
  });

  renderCards();
  updateHeaderStats();
}

// ─── Event Listeners ──────────────────────────────────────────────────────────
function initFilters() {
  document.getElementById('filter-tabs').addEventListener('click', e => {
    const btn = e.target.closest('.filter-btn');
    if (!btn) return;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.filter;
    applyFilters();
  });
}

function initSearch() {
  const input = document.getElementById('search-input');
  let timer;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => { searchQuery = input.value.trim(); applyFilters(); }, 250);
  });
}

// ─── Render Cards ─────────────────────────────────────────────────────────────
function renderCards() {
  const container = document.getElementById('cards-container');
  const noResults = document.getElementById('no-results');
  const feedCount = document.getElementById('feed-count');

  container.innerHTML = '';

  if (filteredItems.length === 0) {
    noResults.style.display = 'block';
    feedCount.textContent   = 'No items found';
    return;
  }

  noResults.style.display = 'none';
  feedCount.textContent   = `${filteredItems.length} item${filteredItems.length !== 1 ? 's' : ''} in feed`;

  const sorted = [...filteredItems].sort((a, b) => new Date(b.published || 0) - new Date(a.published || 0));
  sorted.forEach((item, index) => container.appendChild(buildCard(item, index)));
}

// ─── Card Builder ─────────────────────────────────────────────────────────────
function buildCard(item, index) {
  const card  = document.createElement('div');
  const isNew = item.published && (Date.now() - new Date(item.published)) < 86400000;

  card.className = 'intel-card';
  if (isNew) card.classList.add('new-item');
  card.dataset.category    = item.category || 'news';
  card.style.animationDelay = `${index * 0.04}s`;

  const badgeHTML   = item.severity
    ? `<span class="badge ${item.severity}">${item.severity.toUpperCase()}</span>`
    : `<span class="badge info">${(item.category || 'INFO').toUpperCase()}</span>`;

  const newBadgeHTML = isNew ? `<span class="badge-new">NEW</span>` : '';
  const cveIdHTML    = item.cve_id ? `<span class="cve-id">${item.cve_id}</span> · ` : '';
  const descriptionHTML = item.description
    ? `<p class="card-description">${escapeHTML(item.description)}</p>` : '';
  const dateStr = item.published ? timeAgo(new Date(item.published)) : '';
  const cvssHTML = item.cvss_score
    ? `<span class="meta-tag meta-cvss">CVSS ${item.cvss_score}</span>` : '';

  // TTP pills
  const ttps = item.ttps || [];
  let ttpHTML = '';
  if (ttps.length > 0) {
    const shown  = ttps.slice(0, 4);
    const hidden = ttps.length - shown.length;
    const pills  = shown.map(t => `<span class="ttp-pill" title="${escapeHTML(t.name)}">${escapeHTML(t.id)}</span>`).join('');
    const more   = hidden > 0 ? `<span class="ttp-pill ttp-more">+${hidden}</span>` : '';
    ttpHTML = `<div class="card-ttps">${pills}${more}</div>`;
  }

  // ── Analysis Section (Visual Intelligence) ────────────────────────────────
  const hasAI    = item.ai_summary || item.workflow_graph || item.severity_score != null;
  let analysisHTML = '';

  if (hasAI) {
    const score     = item.severity_score != null ? parseFloat(item.severity_score) : null;
    const scoreColor = score != null
      ? (score >= 9 ? 'var(--critical)' : score >= 7 ? 'var(--high)' : score >= 4 ? 'var(--medium)' : 'var(--low)')
      : 'var(--text-secondary)';

    const scoreHTML = score != null ? `
      <div class="analysis-block">
        <div class="analysis-label">▸ SEVERITY SCORE</div>
        <div class="severity-meter">
          <div class="severity-meter-fill" style="width:${(score/10*100).toFixed(1)}%;background:${scoreColor};box-shadow:0 0 6px ${scoreColor}40;"></div>
          <div class="severity-meter-ticks"></div>
        </div>
        <span class="severity-score-val" style="color:${scoreColor};">${score.toFixed(1)} / 10.0</span>
      </div>` : '';

    const summaryHTML = item.ai_summary ? `
      <div class="analysis-block">
        <div class="analysis-label">▸ AI SUMMARY <span class="analysis-model-tag">gemini-1.5-flash</span></div>
        <p class="analysis-summary-text">${escapeHTML(item.ai_summary)}</p>
      </div>` : '';

    const graphHTML = item.workflow_graph ? `
      <div class="analysis-block">
        <div class="analysis-label">▸ ATTACK WORKFLOW</div>
        <div class="analysis-mermaid" data-graph="${escapeAttr(item.workflow_graph)}" data-rendered="false"></div>
      </div>` : '';

    analysisHTML = `
      <div class="analysis-section">
        <div class="analysis-header">
          <span class="analysis-tag">⬡ VISUAL INTELLIGENCE</span>
          <span class="analysis-collapse-hint">▴ collapse</span>
        </div>
        ${scoreHTML}
        ${summaryHTML}
        ${graphHTML}
      </div>`;
  }

  // ── AI indicator shown on collapsed card ──────────────────────────────────
  const aiIndicatorHTML = hasAI
    ? `<span class="ai-indicator" title="AI analysis available — click to expand">⬡ AI</span>` : '';

  card.innerHTML = `
    <div class="card-top">
      <div class="card-title">
        ${cveIdHTML}${item.url ? `<a href="${escapeAttr(item.url)}" target="_blank" rel="noopener noreferrer">${escapeHTML(item.title)}</a>` : escapeHTML(item.title)}
        ${newBadgeHTML}
      </div>
      ${badgeHTML}
    </div>
    ${descriptionHTML}
    <div class="card-meta">
      <span class="meta-tag meta-source">${escapeHTML(item.source || '')}</span>
      <span class="meta-tag meta-cat">${(item.category || '').toUpperCase()}</span>
      ${cvssHTML}
      ${aiIndicatorHTML}
      <span class="meta-date">${dateStr}</span>
    </div>
    ${ttpHTML}
    ${analysisHTML}`;

  // ── Click-to-expand handler ───────────────────────────────────────────────
  if (hasAI) {
    card.addEventListener('click', e => {
      // Don't expand/collapse when clicking an external link
      if (e.target.closest('a')) return;

      const expanding = !card.classList.contains('expanded');
      card.classList.toggle('expanded');

      if (expanding) {
        loadMermaid(() => renderMermaidForCard(card));
      }
    });
  }

  return card;
}

// ─── Utility Helpers ──────────────────────────────────────────────────────────
function escapeHTML(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/** Escape a string for use in an HTML attribute value (double-quoted). */
function escapeAttr(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function timeAgo(date) {
  const secs = Math.floor((Date.now() - date) / 1000);
  if (secs < 60)    return `${secs}s ago`;
  if (secs < 3600)  return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

// ─── Sidebar & Stats (unchanged from original) ────────────────────────────────
function renderSidebar() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  const sourceMap = {};
  const catMap    = {};

  allItems.forEach(item => {
    if (item.severity && counts[item.severity] !== undefined) counts[item.severity]++;
    sourceMap[item.source]   = (sourceMap[item.source]   || 0) + 1;
    catMap[item.category]    = (catMap[item.category]    || 0) + 1;
  });

  const total = allItems.length || 1;

  // Severity bars
  ['critical','high','medium','low'].forEach(sev => {
    const bar   = document.querySelector(`.sev-bar.${sev}`);
    const count = document.querySelector(`.sev-count[data-sev="${sev}"]`);
    if (bar)   bar.style.width   = `${(counts[sev] / total * 100).toFixed(0)}%`;
    if (count) count.textContent = counts[sev];
  });

  // Source list
  const sourceList = document.getElementById('source-list');
  if (sourceList) {
    sourceList.innerHTML = Object.entries(sourceMap)
      .sort((a, b) => b[1] - a[1])
      .map(([name, cnt]) => `
        <div class="source-item">
          <span class="source-name">${escapeHTML(name)}</span>
          <span class="source-badge">${cnt}</span>
        </div>`).join('');
  }

  // Category list
  const catList = document.getElementById('cat-list');
  if (catList) {
    catList.innerHTML = Object.entries(catMap)
      .sort((a, b) => b[1] - a[1])
      .map(([cat, cnt]) => `
        <div class="cat-item" data-filter="${cat}">
          <span class="cat-name">${cat.toUpperCase()}</span>
          <span class="cat-count">${cnt}</span>
        </div>`).join('');
    catList.querySelectorAll('.cat-item').forEach(item => {
      item.addEventListener('click', () => {
        const filter = item.dataset.filter;
        document.querySelectorAll('.filter-btn').forEach(b => {
          b.classList.toggle('active', b.dataset.filter === filter);
        });
        activeFilter = filter;
        applyFilters();
      });
    });
  }
}

function renderDailySummary() {
  const summaryEl = document.getElementById('daily-summary');
  if (!summaryEl) return;
  const critical = allItems.filter(i => i.severity === 'critical').length;
  const high      = allItems.filter(i => i.severity === 'high').length;
  const cves      = allItems.filter(i => i.category === 'cve').length;
  const aiItems   = allItems.filter(i => i.ai_summary).length;
  summaryEl.innerHTML = `
    <span class="summary-item">
      <span class="summary-label">CRITICAL</span>
      <span class="summary-val critical">${critical}</span>
    </span>
    <span class="summary-sep">·</span>
    <span class="summary-item">
      <span class="summary-label">HIGH</span>
      <span class="summary-val high">${high}</span>
    </span>
    <span class="summary-sep">·</span>
    <span class="summary-item">
      <span class="summary-label">CVEs</span>
      <span class="summary-val">${cves}</span>
    </span>
    <span class="summary-sep">·</span>
    <span class="summary-item">
      <span class="summary-label">AI-ENRICHED</span>
      <span class="summary-val ai">${aiItems}</span>
    </span>`;
}

function updateHeaderStats() {
  const shown    = filteredItems.length;
  const critical = filteredItems.filter(i => i.severity === 'critical').length;
  const high      = filteredItems.filter(i => i.severity === 'high').length;

  const statCritEl = document.querySelector('#stat-critical .stat-value');
  const statHighEl = document.querySelector('#stat-high .stat-value');
  const statTotalEl = document.querySelector('#stat-total .stat-value');

  if (statCritEl)  statCritEl.textContent  = critical;
  if (statHighEl)  statHighEl.textContent  = high;
  if (statTotalEl) statTotalEl.textContent = shown;
}

function showContent() {
  const loading = document.getElementById('loading-state');
  const content = document.getElementById('content-state');
  if (loading) loading.style.display = 'none';
  if (content) content.style.display = 'block';
  updateHeaderStats();
}

function showError() {
  const loading = document.getElementById('loading-state');
  const errEl   = document.getElementById('error-state');
  if (loading) loading.style.display = 'none';
  if (errEl)   errEl.style.display   = 'block';
}

// ─── MITRE Matrix View (unchanged) ────────────────────────────────────────────
function showMatrixView() {
  const container    = document.getElementById('cards-container');
  const noResults    = document.getElementById('no-results');
  const feedCount    = document.getElementById('feed-count');
  noResults.style.display = 'none';
  feedCount.textContent   = 'MITRE ATT&CK Matrix';
  container.innerHTML     = buildMatrixHTML();
}

function buildMatrixHTML() {
  const tacticMap = {};
  allItems.forEach(item => {
    (item.ttps || []).forEach(ttp => {
      const tactic = ttp.tactic || 'Unknown';
      if (!tacticMap[tactic]) tacticMap[tactic] = {};
      if (!tacticMap[tactic][ttp.id]) tacticMap[tactic][ttp.id] = { ...ttp, count: 0, items: [] };
      tacticMap[tactic][ttp.id].count++;
      tacticMap[tactic][ttp.id].items.push(item.title);
    });
  });

  if (!Object.keys(tacticMap).length) {
    return '<div class="no-results"><p>No TTP data available</p></div>';
  }

  return `<div class="matrix-grid">${
    Object.entries(tacticMap).map(([tactic, techniques]) => `
      <div class="matrix-col">
        <div class="matrix-tactic">${escapeHTML(tactic)}</div>
        ${Object.values(techniques).map(t => `
          <div class="matrix-cell" title="${escapeHTML(t.name)} (${t.count} item${t.count !== 1 ? 's' : ''})">
            <span class="matrix-id">${escapeHTML(t.id)}</span>
            <span class="matrix-name">${escapeHTML(t.name)}</span>
            <span class="matrix-count">${t.count}</span>
          </div>`).join('')}
      </div>`).join('')
  }</div>`;
}
