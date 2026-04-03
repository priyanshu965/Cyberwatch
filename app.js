/**
 * CYBERWATCH DASHBOARD — app.js
 * ─────────────────────────────
 * Features:
 *  • Time-range filters (24h / 7d / 30d / all)
 *  • Sort options (newest / oldest / severity / source)
 *  • Export filtered results (JSON / CSV)
 *  • Top-trends sidebar widget
 *  • Card click → expand with AI analysis panel
 *  • Mermaid.js workflow diagram (lazy-loaded per card)
 *  • ATT&CK Matrix view
 *  • TTP Clusters view
 *  • Attack Flow Graph (SVG, no backend)
 *  • Trends view with attack pattern detection
 */

// ─── State ───────────────────────────────────────────────────────────────────
let allItems     = [];
let filteredItems = [];
let activeFilter  = 'all';
let searchQuery   = '';
let timeRange     = 'all';   // 'all' | '24h' | '7d' | '30d'
let sortMode      = 'date-desc'; // 'date-desc' | 'date-asc' | 'severity' | 'source'
let exportMenuOpen = false;

// Mermaid state
let mermaidInitialized = false;
let mermaidCounter     = 0;

// Severity order for sorting
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

// ─── Entry Point ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initFilters();
  initTimeRange();
  initSort();
  initSearch();
  initExportMenu();
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
          meta.textContent = '⚠ Preview mode — open via server for live data';
          meta.style.color = '#f5c518';
        }
      } else {
        throw new Error('No data — place intel.json in data/ and open via a server');
      }
    }

    allItems = data.items || [];

    if (data.last_updated) {
      const date = new Date(data.last_updated);
      const utc  = date.toUTCString();
      const ist  = date.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        dateStyle: 'medium',
        timeStyle: 'medium'
      });
      const el = document.getElementById('last-updated');
      if (el) el.textContent = `Last updated: ${utc} | IST: ${ist}`;
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

// ─── Filtering & Sorting ──────────────────────────────────────────────────────

function applyFilters() {
  // Special view modes
  if (activeFilter === 'matrix')   { showMatrixView();   return; }
  if (activeFilter === 'clusters') { showClustersView(); return; }
  if (activeFilter === 'flow')     { showFlowView();     return; }
  if (activeFilter === 'trends')   { showTrendsView();   return; }

  // Normal filtering
  filteredItems = allItems.filter(item => {
    // Category
    if (activeFilter !== 'all' && item.category !== activeFilter) return false;

    // Time range
    if (!checkTimeRange(item)) return false;

    // Search
    const q = searchQuery.toLowerCase();
    if (q) {
      const inTitle  = item.title       && item.title.toLowerCase().includes(q);
      const inDesc   = item.description && item.description.toLowerCase().includes(q);
      const inCve    = item.cve_id      && item.cve_id.toLowerCase().includes(q);
      const inSource = item.source      && item.source.toLowerCase().includes(q);
      const inTtps   = item.ttps        && item.ttps.some(t =>
        t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
      );
      const inAi     = item.ai_summary  && item.ai_summary.toLowerCase().includes(q);
      if (!inTitle && !inDesc && !inCve && !inSource && !inTtps && !inAi) return false;
    }

    return true;
  });

  // Sort
  const sorted = [...filteredItems];
  switch (sortMode) {
    case 'date-asc':
      sorted.sort((a, b) => new Date(a.published || 0) - new Date(b.published || 0));
      break;
    case 'severity':
      sorted.sort((a, b) =>
        (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) ||
        new Date(b.published || 0) - new Date(a.published || 0)
      );
      break;
    case 'source':
      sorted.sort((a, b) => (a.source || '').localeCompare(b.source || ''));
      break;
    default: // date-desc
      sorted.sort((a, b) => new Date(b.published || 0) - new Date(a.published || 0));
  }

  filteredItems = sorted;
  renderCards();
  updateHeaderStats();
}

function checkTimeRange(item) {
  if (timeRange === 'all') return true;
  if (!item.published) return false;
  const ago = Date.now() - new Date(item.published).getTime();
  if (timeRange === '24h') return ago <= 86_400_000;
  if (timeRange === '7d')  return ago <= 7  * 86_400_000;
  if (timeRange === '30d') return ago <= 30 * 86_400_000;
  return true;
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

function initTimeRange() {
  const tabs = document.getElementById('time-tabs');
  if (!tabs) return;
  tabs.addEventListener('click', e => {
    const btn = e.target.closest('.time-btn');
    if (!btn) return;
    document.querySelectorAll('.time-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    timeRange = btn.dataset.range;
    // Refresh current view
    if (['matrix','clusters','flow','trends'].includes(activeFilter)) return;
    applyFilters();
  });
}

function initSort() {
  const sel = document.getElementById('sort-select');
  if (!sel) return;
  sel.addEventListener('change', () => {
    sortMode = sel.value;
    if (!['matrix','clusters','flow','trends'].includes(activeFilter)) applyFilters();
  });
}

function initSearch() {
  const input = document.getElementById('search-input');
  if (!input) return;
  let timer;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      searchQuery = input.value.trim();
      if (!['matrix','clusters','flow','trends'].includes(activeFilter)) applyFilters();
    }, 250);
  });
}

function initExportMenu() {
  // Close dropdown when clicking outside
  document.addEventListener('click', e => {
    if (exportMenuOpen && !e.target.closest('.export-wrap')) {
      setExportMenu(false);
    }
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
    feedCount.textContent = 'No items found';
    return;
  }

  noResults.style.display = 'none';
  feedCount.textContent = `${filteredItems.length} item${filteredItems.length !== 1 ? 's' : ''} in feed`;

  filteredItems.forEach((item, index) => {
    container.appendChild(buildCard(item, index));
  });
}

function buildCard(item, index) {
  const card = document.createElement('div');
  const isNew = item.published &&
    (Date.now() - new Date(item.published)) < 86_400_000;

  card.className = 'intel-card';
  if (isNew) card.classList.add('new-item');
  card.dataset.category = item.category || 'news';
  card.style.animationDelay = `${index * 0.03}s`;

  const badgeHTML = item.severity
    ? `<span class="badge ${item.severity.toLowerCase()}">${item.severity.toUpperCase()}</span>`
    : `<span class="badge info">${(item.category || 'INFO').toUpperCase()}</span>`;

  const newBadgeHTML = isNew ? `<span class="new-item-badge">NEW</span>` : '';

  const cveIdHTML = item.cve_id
    ? `<span class="cve-id">${item.cve_id}</span> · ` : '';

  const descriptionHTML = item.description
    ? `<p class="card-description">${escapeHTML(item.description)}</p>` : '';

  const cvssHTML = item.cvss_score != null
    ? `<span class="meta-tag meta-cvss">CVSS ${item.cvss_score.toFixed(1)}</span>` : '';

  const aiScoreHTML = item.severity_score != null && !item.cvss_score
    ? `<span class="meta-tag meta-cvss">AI ${item.severity_score.toFixed(1)}</span>` : '';

  const ttps = item.ttps || [];
  let ttpHTML = '';
  if (ttps.length > 0) {
    const shown  = ttps.slice(0, 4);
    const hidden = ttps.length - shown.length;
    const pills  = shown.map(t =>
      `<span class="ttp-pill"
             title="${escapeHTML(t.tactic)}: ${escapeHTML(t.name)}"
             onclick="event.stopPropagation();filterByTechnique('${t.id}')"
       >${escapeHTML(t.id)}</span>`
    ).join('');
    const more = hidden > 0
      ? `<span class="ttp-more" title="${ttps.slice(4).map(t=>t.id).join(', ')}">+${hidden}</span>`
      : '';
    ttpHTML = `<div class="card-ttps">${pills}${more}</div>`;
  }

  // Show expand icon if there's AI data or ttps
  const hasAnalysis = item.ai_summary || item.workflow_graph || item.severity_score != null || ttps.length > 0;
  const expandIcon  = hasAnalysis
    ? `<span class="card-expand-icon" title="Click to expand analysis">▼</span>` : '';

  // Analysis section (hidden by default)
  const analysisHTML = `<div class="analysis-section" style="display:none;"></div>`;

  card.innerHTML = `
    <div class="card-top">
      <p class="card-title">
        ${item.url
          ? `<a href="${escapeHTML(item.url)}" target="_blank" rel="noopener"
               onclick="event.stopPropagation()">${escapeHTML(item.title)}</a>`
          : escapeHTML(item.title)
        }
        ${newBadgeHTML}
      </p>
      <div style="display:flex;align-items:center;gap:5px;flex-shrink:0;">
        ${badgeHTML}
        ${expandIcon}
      </div>
    </div>
    ${descriptionHTML}
    <div class="card-meta">
      ${cveIdHTML}
      <span class="meta-tag meta-source">${escapeHTML(item.source || 'unknown')}</span>
      <span class="meta-tag meta-cat">${escapeHTML(item.category || 'general')}</span>
      ${cvssHTML}${aiScoreHTML}
      <span class="meta-date">${item.published ? timeAgo(new Date(item.published)) : ''}</span>
    </div>
    ${ttpHTML}
    ${analysisHTML}
  `;

  // Click handler — toggle expand
  if (hasAnalysis) {
    card.addEventListener('click', e => {
      if (e.target.tagName === 'A') return;
      toggleCardExpand(card, item);
    });
  }

  return card;
}

// ─── Card Expand / Analysis ───────────────────────────────────────────────────

function toggleCardExpand(card, item) {
  const wasExpanded = card.classList.contains('expanded');

  // Collapse any other open cards
  document.querySelectorAll('.intel-card.expanded').forEach(c => {
    if (c !== card) collapseCard(c);
  });

  if (wasExpanded) {
    collapseCard(card);
  } else {
    expandCard(card, item);
  }
}

function collapseCard(card) {
  card.classList.remove('expanded');
  const section = card.querySelector('.analysis-section');
  if (section) section.style.display = 'none';
}

function expandCard(card, item) {
  card.classList.add('expanded');
  const section = card.querySelector('.analysis-section');
  if (!section) return;
  section.style.display = 'flex';
  section.innerHTML = '';
  populateAnalysis(section, item);
  // Smooth scroll so the card is visible
  setTimeout(() => card.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 50);
}

async function populateAnalysis(section, item) {
  // ── Block 1: AI Summary ──────────────────────────────────────────
  if (item.ai_summary) {
    const block = document.createElement('div');
    block.className = 'analysis-block';
    block.innerHTML = `
      <span class="analysis-label">🤖 AI BLUF ANALYSIS</span>
      <p class="ai-summary-text">${escapeHTML(item.ai_summary)}</p>
    `;
    section.appendChild(block);
  }

  // ── Block 2: AI Severity Score ───────────────────────────────────
  if (item.severity_score != null) {
    const s = item.severity_score;
    const color = s >= 9 ? 'var(--critical)' : s >= 7 ? 'var(--high)'
                : s >= 4 ? 'var(--medium)'   : 'var(--low)';
    const block = document.createElement('div');
    block.className = 'analysis-block';
    block.innerHTML = `
      <span class="analysis-label">⚡ AI SEVERITY SCORE</span>
      <div class="score-row">
        <div class="score-bar-wrap">
          <div class="score-fill" style="width:${(s/10)*100}%;"></div>
        </div>
        <span class="score-value" style="color:${color}">${s.toFixed(1)}</span>
      </div>
    `;
    section.appendChild(block);
  }

  // ── Block 3: Mermaid Workflow Graph ──────────────────────────────
  if (item.workflow_graph) {
    const block = document.createElement('div');
    block.className = 'analysis-block';
    const containerId = `mermaid-wrap-${++mermaidCounter}`;
    block.innerHTML = `
      <span class="analysis-label">🔗 ATTACK WORKFLOW</span>
      <div class="mermaid-container" id="${containerId}">
        <p class="mermaid-loading">⏳ Rendering diagram...</p>
      </div>
    `;
    section.appendChild(block);
    // Async render after DOM insertion
    await renderMermaid(document.getElementById(containerId), item.workflow_graph);
  }

  // ── Block 4: Related Items (sharing TTPs) ────────────────────────
  const related = findRelatedItems(item);
  if (related.length > 0) {
    const block = document.createElement('div');
    block.className = 'analysis-block';
    const links = related.slice(0, 5).map(r => {
      const catColor = {
        cve: 'var(--critical)', incident: 'var(--accent-orange)',
        advisory: 'var(--high)', news: 'var(--accent-blue)'
      }[r.item.category] || 'var(--text-muted)';
      return `
        <div class="related-item" onclick="highlightItem(${r.index})">
          <span class="related-item-dot" style="background:${catColor}"></span>
          <span class="related-item-title">${escapeHTML(r.item.title)}</span>
          <span class="related-shared">${r.shared} TTP${r.shared>1?'s':''}</span>
        </div>`;
    }).join('');
    block.innerHTML = `
      <span class="analysis-label">🔗 RELATED THREATS (shared TTPs)</span>
      <div class="related-items-list">${links}</div>
    `;
    section.appendChild(block);
  }
}

function findRelatedItems(item) {
  const myTtps = new Set((item.ttps || []).map(t => t.id));
  if (myTtps.size === 0) return [];

  return allItems
    .map((other, index) => {
      if (other === item) return null;
      const otherTtps = new Set((other.ttps || []).map(t => t.id));
      const shared = [...myTtps].filter(id => otherTtps.has(id)).length;
      return shared > 0 ? { item: other, index, shared } : null;
    })
    .filter(Boolean)
    .sort((a, b) => b.shared - a.shared);
}

// Scroll-to + highlight a card by index in allItems
window.highlightItem = function(index) {
  const item = allItems[index];
  if (!item) return;

  // Switch to ALL view and search by title fragment
  activeFilter = 'all';
  searchQuery  = item.title.substring(0, 35);
  document.querySelectorAll('.filter-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.filter === 'all')
  );
  const si = document.getElementById('search-input');
  if (si) si.value = searchQuery;
  showContent();
  applyFilters();

  // Highlight the card after render
  setTimeout(() => {
    const cards = document.querySelectorAll('.intel-card');
    if (cards[0]) {
      cards[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
      cards[0].style.outline = '2px solid var(--accent-cyan)';
      setTimeout(() => { if (cards[0]) cards[0].style.outline = ''; }, 2000);
    }
  }, 200);
};

// ─── Mermaid.js ───────────────────────────────────────────────────────────────

function initMermaid() {
  if (mermaidInitialized || !window.mermaid) return;
  window.mermaid.initialize({
    startOnLoad: false,
    theme: 'dark',
    themeVariables: {
      primaryColor:       '#0d2038',
      primaryTextColor:   '#c9d8e8',
      primaryBorderColor: '#1e4d73',
      lineColor:          '#00ffe1',
      secondaryColor:     '#111820',
      background:         '#080b0f',
      mainBkg:            '#0d1117',
      nodeBorder:         '#1e2d3d',
      fontFamily:         'JetBrains Mono, Courier New, monospace',
      fontSize:           '12px',
      edgeLabelBackground: '#0d1117',
    },
    flowchart: { htmlLabels: true, curve: 'basis', padding: 14 },
    securityLevel: 'loose',
  });
  mermaidInitialized = true;
}

async function renderMermaid(container, definition) {
  try {
    initMermaid();
    if (!window.mermaid) {
      container.innerHTML = '<p class="mermaid-error">Mermaid.js not available</p>';
      return;
    }
    const id = `mermaid-${mermaidCounter}`;
    const cleaned = definition.trim();
    const { svg } = await window.mermaid.render(id, cleaned);
    container.innerHTML = svg;
  } catch (err) {
    console.warn('Mermaid render error:', err);
    // Show the raw syntax as fallback (useful for debugging)
    container.innerHTML = `<pre class="mermaid-raw">${escapeHTML(definition)}</pre>`;
  }
}

// ─── Render Sidebar ───────────────────────────────────────────────────────────

function renderSidebar() {
  renderSeverityBars();
  renderSourceList();
  renderCategoryList();
  renderTopTrends();
}

function renderSeverityBars() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  allItems.forEach(item => {
    const s = (item.severity || '').toLowerCase();
    if (s in counts) counts[s]++;
  });
  const max = Math.max(...Object.values(counts), 1);
  Object.entries(counts).forEach(([sev, count]) => {
    const bar   = document.getElementById(`bar-${sev}`);
    const label = document.getElementById(`sev-count-${sev}`);
    if (bar)   bar.style.width = `${(count / max) * 100}%`;
    if (label) label.textContent = count;
  });
}

function renderSourceList() {
  const counts = {};
  allItems.forEach(item => {
    const src = item.source || 'unknown';
    counts[src] = (counts[src] || 0) + 1;
  });
  const el = document.getElementById('source-list');
  if (!el) return;
  el.innerHTML = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => `
      <div class="source-item">
        <span class="source-name">${escapeHTML(name)}</span>
        <span class="source-badge">${count}</span>
      </div>`)
    .join('');
}

function renderCategoryList() {
  const counts = {};
  allItems.forEach(item => {
    const cat = item.category || 'general';
    counts[cat] = (counts[cat] || 0) + 1;
  });
  const el = document.getElementById('cat-list');
  if (!el) return;
  el.innerHTML = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([cat, count]) => `
      <div class="cat-item" onclick="filterByCategory('${cat}')">
        <span class="cat-name">${escapeHTML(cat)}</span>
        <span class="cat-count">${count}</span>
      </div>`)
    .join('');
}

function renderTopTrends() {
  const el = document.getElementById('trends-list');
  if (!el) return;

  // Count TTP technique hits
  const ttpCounts = {};
  allItems.forEach(item => {
    (item.ttps || []).forEach(t => {
      ttpCounts[t.id] = ttpCounts[t.id] || { name: t.name, count: 0 };
      ttpCounts[t.id].count++;
    });
  });

  const top = Object.entries(ttpCounts)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 6);

  if (top.length === 0) {
    el.innerHTML = '<div class="trend-item"><span class="trend-name">No TTP data yet</span></div>';
    return;
  }

  const maxCount = top[0][1].count;
  el.innerHTML = top.map(([id, data]) => `
    <div class="trend-item" title="${escapeHTML(id)}: ${escapeHTML(data.name)}"
         onclick="filterByTechnique('${id}')" style="cursor:pointer">
      <span class="trend-name">${escapeHTML(id)}</span>
      <div class="trend-bar-wrap">
        <div class="trend-bar" style="width:${(data.count/maxCount)*100}%"></div>
      </div>
      <span class="trend-val">${data.count}</span>
    </div>`
  ).join('');
}

window.filterByCategory = function(cat) {
  activeFilter = cat;
  document.querySelectorAll('.filter-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.filter === cat)
  );
  applyFilters();
};

// ─── Header Stats ─────────────────────────────────────────────────────────────

function updateHeaderStats() {
  const critical = filteredItems.filter(i => (i.severity||'').toLowerCase() === 'critical').length;
  const high     = filteredItems.filter(i => (i.severity||'').toLowerCase() === 'high').length;
  document.getElementById('count-critical').textContent = critical;
  document.getElementById('count-high').textContent     = high;
  document.getElementById('count-total').textContent    = filteredItems.length;
}

// ─── Daily Summary Bar ────────────────────────────────────────────────────────

function renderDailySummary() {
  const bar   = document.getElementById('daily-summary');
  const stats = document.getElementById('summary-stats');
  const top   = document.getElementById('summary-top-threat');
  if (!bar || !stats) return;

  const critical   = allItems.filter(i => i.severity === 'critical').length;
  const high       = allItems.filter(i => i.severity === 'high').length;
  const medium     = allItems.filter(i => i.severity === 'medium').length;
  const newCount   = allItems.filter(i => i.published && (Date.now()-new Date(i.published)) < 86400000).length;
  const incidents  = allItems.filter(i => i.category === 'incident').length;
  const cves       = allItems.filter(i => i.category === 'cve').length;
  const advisories = allItems.filter(i => i.category === 'advisory').length;
  const aiCount    = allItems.filter(i => i.ai_summary).length;

  stats.innerHTML = `
    <span class="summary-stat"><span class="summary-stat-val c">${critical}</span><span class="summary-stat-lbl">CRITICAL</span></span>
    <span class="summary-stat"><span class="summary-stat-val h">${high}</span><span class="summary-stat-lbl">HIGH</span></span>
    <span class="summary-stat"><span class="summary-stat-val m">${medium}</span><span class="summary-stat-lbl">MEDIUM</span></span>
    <span class="summary-divider">·</span>
    <span class="summary-stat"><span class="summary-stat-val n">${cves}</span><span class="summary-stat-lbl">CVEs</span></span>
    <span class="summary-stat"><span class="summary-stat-val n">${incidents}</span><span class="summary-stat-lbl">INCIDENTS</span></span>
    <span class="summary-stat"><span class="summary-stat-val n">${advisories}</span><span class="summary-stat-lbl">ADVISORIES</span></span>
    <span class="summary-divider">·</span>
    <span class="summary-stat"><span class="summary-stat-val" style="color:var(--accent-cyan)">${newCount}</span><span class="summary-stat-lbl">NEW TODAY</span></span>
    ${aiCount > 0 ? `<span class="summary-stat"><span class="summary-stat-val" style="color:#b47aff">${aiCount}</span><span class="summary-stat-lbl">AI ANALYSED</span></span>` : ''}
  `;

  const topThreat = allItems.find(i => i.severity === 'critical') ||
                    allItems.find(i => i.severity === 'high');
  if (top && topThreat) {
    top.innerHTML = `🔴 Top threat: <strong>${escapeHTML(topThreat.title.substring(0, 80))}${topThreat.title.length > 80 ? '…' : ''}</strong>`;
  }

  bar.style.display = 'block';
}

// ─── UI State Transitions ─────────────────────────────────────────────────────

function showContent() {
  document.getElementById('loading-state').style.display    = 'none';
  document.getElementById('error-state').style.display      = 'none';
  document.getElementById('matrix-view').style.display      = 'none';
  document.getElementById('clusters-view').style.display    = 'none';
  document.getElementById('flow-view').style.display        = 'none';
  document.getElementById('trends-view').style.display      = 'none';
  document.getElementById('no-results').style.display       = 'none';
  document.getElementById('cards-container').style.display  = 'flex';
}

function showError() {
  document.getElementById('loading-state').style.display = 'none';
  document.getElementById('error-state').style.display   = 'block';
}

function hideAllViews() {
  ['loading-state','error-state','matrix-view','clusters-view',
   'flow-view','trends-view','no-results','cards-container'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
}

// ─── MITRE ATT&CK Matrix ─────────────────────────────────────────────────────

const TACTIC_ORDER = [
  { id: "TA0043", name: "Reconnaissance" },
  { id: "TA0042", name: "Resource Dev" },
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Esc" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0011", name: "Command & Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" },
];

function showMatrixView() {
  hideAllViews();
  const mv = document.getElementById('matrix-view');
  mv.style.display = 'block';
  renderMatrixGrid();
  document.getElementById('feed-count').textContent =
    'MITRE ATT&CK Coverage Map — click any technique to filter feed';
}

function renderMatrixGrid() {
  const grid = document.getElementById('matrix-grid');
  if (!grid) return;

  const tacticMap = {};
  TACTIC_ORDER.forEach(t => { tacticMap[t.id] = {}; });

  allItems.forEach(item => {
    (item.ttps || []).forEach(ttp => {
      if (!tacticMap[ttp.tactic_id]) tacticMap[ttp.tactic_id] = {};
      if (!tacticMap[ttp.tactic_id][ttp.id]) {
        tacticMap[ttp.tactic_id][ttp.id] = { name: ttp.name, count: 0, items: [] };
      }
      tacticMap[ttp.tactic_id][ttp.id].count++;
      tacticMap[ttp.tactic_id][ttp.id].items.push(item.title);
    });
  });

  grid.innerHTML = TACTIC_ORDER.map(tactic => {
    const techniques  = tacticMap[tactic.id] || {};
    const techEntries = Object.entries(techniques).sort((a, b) => b[1].count - a[1].count);
    const totalCount  = techEntries.reduce((s, [, d]) => s + d.count, 0);

    const cells = techEntries.map(([techId, data]) => {
      const intensity = data.count >= 3 ? 'high' : 'med';
      const tooltip   = `${data.count} item(s): ${data.items.slice(0, 2).join(' | ')}${data.items.length > 2 ? '...' : ''}`;
      return `
        <div class="tech-cell active-${intensity}"
             title="${escapeHTML(tooltip)}"
             onclick="filterByTechnique('${techId}')">
          <span class="tech-id">${escapeHTML(techId)}</span>
          <span class="tech-name">${escapeHTML(data.name)}</span>
          <span class="tech-count">${data.count}</span>
        </div>`;
    }).join('');

    return `
      <div class="tactic-col">
        <div class="tactic-header">
          <span class="tactic-name">${escapeHTML(tactic.name)}</span>
          <span class="tactic-count">${techEntries.length > 0 ? totalCount : '—'}</span>
        </div>
        <div class="tactic-cells">
          ${cells || `<div class="tech-cell inactive"><span class="tech-name">No hits</span></div>`}
        </div>
      </div>`;
  }).join('');
}

window.filterByTechnique = function(techId) {
  activeFilter = 'all';
  searchQuery  = techId;
  document.querySelectorAll('.filter-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.filter === 'all')
  );
  const si = document.getElementById('search-input');
  if (si) si.value = techId;
  showContent();
  applyFilters();
};

// ─── TTP Clusters View ────────────────────────────────────────────────────────

function showClustersView() {
  hideAllViews();
  const view = document.getElementById('clusters-view');
  view.style.display = 'block';
  renderClusters();
  document.getElementById('feed-count').textContent =
    'TTP CLUSTERS — items grouped by dominant ATT&CK tactic';
}

function renderClusters() {
  const view = document.getElementById('clusters-view');
  if (!view) return;

  // Group items by their first TTP's tactic
  const groups = {};
  const ungrouped = [];

  allItems.forEach(item => {
    const ttps = item.ttps || [];
    if (ttps.length === 0) {
      ungrouped.push(item);
      return;
    }
    const tactic = ttps[0].tactic;
    if (!groups[tactic]) groups[tactic] = { items: [], ttps: new Set() };
    groups[tactic].items.push(item);
    ttps.forEach(t => groups[tactic].ttps.add(t.id));
  });

  const catColor = {
    cve: 'var(--critical)', incident: 'var(--accent-orange)',
    advisory: 'var(--high)', news: 'var(--accent-blue)'
  };

  const groupsSorted = Object.entries(groups).sort((a, b) => b[1].items.length - a[1].items.length);

  view.innerHTML = `
    <div class="clusters-header">
      <span class="clusters-title">◉ TTP CLUSTERS</span>
      <span class="clusters-subtitle">${allItems.length} items grouped by ATT&CK tactic</span>
    </div>
    ${groupsSorted.map(([tactic, data]) => {
      const ttpTags = [...data.ttps].slice(0, 4).map(id =>
        `<span class="cluster-ttp-tag" onclick="filterByTechnique('${id}')">${escapeHTML(id)}</span>`
      ).join('');
      const moreTag = data.ttps.size > 4
        ? `<span class="cluster-ttp-tag">+${data.ttps.size - 4}</span>` : '';

      const items = data.items.slice(0, 6).map(item => {
        const dot = catColor[item.category] || 'var(--text-muted)';
        return `
          <div class="cluster-item" onclick="jumpToItem('${escapeHTML(item.title.substring(0,40))}')">
            <span style="width:6px;height:6px;border-radius:50%;background:${dot};flex-shrink:0"></span>
            <span class="cluster-item-title">${escapeHTML(item.title)}</span>
            <span class="meta-tag meta-cat">${escapeHTML(item.category||'')}</span>
            <span class="badge ${(item.severity||'low').toLowerCase()}" style="font-size:8px;padding:1px 5px;">
              ${(item.severity||'?').toUpperCase()}
            </span>
          </div>`;
      }).join('');

      const more = data.items.length > 6
        ? `<div class="cluster-item" style="color:var(--text-muted);font-size:10px;font-style:italic;cursor:default">
             + ${data.items.length - 6} more items in this tactic group
           </div>` : '';

      return `
        <div class="cluster-group">
          <div class="cluster-group-header">
            <span class="cluster-tactic">${escapeHTML(tactic)}</span>
            <div class="cluster-ttps">${ttpTags}${moreTag}</div>
            <span class="cluster-count">${data.items.length} items</span>
          </div>
          <div class="cluster-items">${items}${more}</div>
        </div>`;
    }).join('')}
    ${ungrouped.length > 0 ? `
      <div class="cluster-group">
        <div class="cluster-group-header">
          <span class="cluster-tactic" style="color:var(--text-muted)">NO TTPS MAPPED</span>
          <span class="cluster-count">${ungrouped.length} items</span>
        </div>
        <div class="cluster-items">
          ${ungrouped.slice(0,4).map(item => `
            <div class="cluster-item" onclick="jumpToItem('${escapeHTML(item.title.substring(0,40))}')">
              <span style="width:6px;height:6px;border-radius:50%;background:var(--text-muted);flex-shrink:0"></span>
              <span class="cluster-item-title">${escapeHTML(item.title)}</span>
            </div>`).join('')}
        </div>
      </div>` : ''}
  `;
}

window.jumpToItem = function(titleFrag) {
  activeFilter = 'all';
  searchQuery  = titleFrag;
  document.querySelectorAll('.filter-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.filter === 'all')
  );
  const si = document.getElementById('search-input');
  if (si) si.value = titleFrag;
  showContent();
  applyFilters();
};

// ─── Attack Flow Graph (SVG) ──────────────────────────────────────────────────

function showFlowView() {
  hideAllViews();
  const view = document.getElementById('flow-view');
  view.style.display = 'block';
  renderFlowGraph();
  document.getElementById('feed-count').textContent =
    'ATTACK FLOW GRAPH — items by time (x) and severity (y), lines = shared TTPs';
}

function renderFlowGraph() {
  const view = document.getElementById('flow-view');
  if (!view) return;

  if (allItems.length === 0) {
    view.innerHTML = '<div class="no-results"><p>No items to graph.</p></div>';
    return;
  }

  const W   = Math.max(view.clientWidth - 32, 600);
  const H   = 420;
  const PAD = { top: 44, right: 24, bottom: 52, left: 72 };
  const PW  = W - PAD.left - PAD.right;
  const PH  = H - PAD.top - PAD.bottom;

  // Date range
  const dates = allItems.filter(i => i.published).map(i => +new Date(i.published));
  const minT  = Math.min(...dates);
  const maxT  = Math.max(...dates);
  const tSpan = maxT - minT || 1;

  // Severity Y positions
  const sevLevels = ['critical','high','medium','low'];
  const sevY = {};
  sevLevels.forEach((s, i) => { sevY[s] = PAD.top + (i / (sevLevels.length - 1)) * PH; });

  const catColor = {
    cve: '#ff3b5c', incident: '#ff8c42', advisory: '#f5c518', news: '#3b9eff'
  };

  // Build nodes
  const nodes = allItems.map((item, idx) => ({
    item,
    idx,
    x: PAD.left + ((+new Date(item.published || minT) - minT) / tSpan) * PW,
    y: sevY[(item.severity || 'medium').toLowerCase()] || sevY.medium,
    color: catColor[item.category] || '#5f7a94',
  }));

  // Build edges (shared TTPs)
  const edges = [];
  for (let i = 0; i < nodes.length; i++) {
    const setA = new Set((nodes[i].item.ttps || []).map(t => t.id));
    for (let j = i + 1; j < nodes.length; j++) {
      const setB = new Set((nodes[j].item.ttps || []).map(t => t.id));
      const shared = [...setA].filter(id => setB.has(id)).length;
      if (shared > 0) edges.push({ a: nodes[i], b: nodes[j], w: shared });
    }
  }

  // Format date axis labels
  const formatDate = ts => {
    const d = new Date(ts);
    return `${d.getMonth()+1}/${d.getDate()}`;
  };

  // X axis ticks (up to 6)
  const tickCount = Math.min(6, Math.ceil(PW / 80));
  const xTicks = Array.from({ length: tickCount }, (_, i) => ({
    x: PAD.left + (i / (tickCount - 1)) * PW,
    label: formatDate(minT + (i / (tickCount - 1)) * tSpan),
  }));

  const edgeSVG = edges.map(e => {
    const opacity = Math.min(0.08 + e.w * 0.1, 0.55);
    return `<line x1="${e.a.x.toFixed(1)}" y1="${e.a.y.toFixed(1)}"
                  x2="${e.b.x.toFixed(1)}" y2="${e.b.y.toFixed(1)}"
                  stroke="#4da6ff" stroke-width="${e.w}"
                  opacity="${opacity.toFixed(2)}"
                  stroke-dasharray="${e.w > 1 ? 'none' : '3,3'}"/>`;
  }).join('\n');

  const gridSVG = sevLevels.map(s => {
    const color = catColor[s] || '#5f7a94';
    return `
      <line x1="${PAD.left}" y1="${sevY[s]}" x2="${W - PAD.right}" y2="${sevY[s]}"
            stroke="${color}" stroke-width="1" opacity="0.15" stroke-dasharray="5,5"/>
      <text x="${PAD.left - 6}" y="${sevY[s] + 4}"
            text-anchor="end" fill="${color}" font-size="9"
            font-family="JetBrains Mono,monospace" font-weight="700">
        ${s.toUpperCase()}
      </text>`;
  }).join('');

  const xAxisSVG = xTicks.map(t => `
    <line x1="${t.x.toFixed(1)}" y1="${H - PAD.bottom}"
          x2="${t.x.toFixed(1)}" y2="${H - PAD.bottom + 4}"
          stroke="#2e4057" stroke-width="1"/>
    <text x="${t.x.toFixed(1)}" y="${H - PAD.bottom + 14}"
          text-anchor="middle" fill="#2e4057" font-size="9"
          font-family="JetBrains Mono,monospace">${t.label}</text>`
  ).join('');

  const nodesSVG = nodes.map(n => `
    <g onclick="jumpToItem('${escapeHTML(n.item.title.substring(0,35)).replace(/'/g,"\\'")}');"
       style="cursor:pointer" class="flow-node-group">
      <circle cx="${n.x.toFixed(1)}" cy="${n.y.toFixed(1)}" r="9"
              fill="${n.color}" opacity="0.1"/>
      <circle cx="${n.x.toFixed(1)}" cy="${n.y.toFixed(1)}" r="5"
              fill="${n.color}" opacity="0.85"
              stroke="${n.color}" stroke-width="0.5"/>
      <title>${escapeHTML(n.item.title)}</title>
    </g>`
  ).join('');

  const legendHTML = Object.entries(catColor).map(([cat, color]) => `
    <div class="flow-legend-item">
      <span class="flow-dot" style="background:${color}"></span>
      <span>${cat.toUpperCase()}</span>
    </div>`).join('');

  view.innerHTML = `
    <div class="flow-view-header">
      <div class="flow-view-title">⬡ ATTACK RELATIONSHIP GRAPH</div>
      <div class="flow-view-subtitle">
        Items plotted by publication time (x-axis) and severity (y-axis).
        Lines connect items sharing MITRE ATT&CK techniques. Click any node.
      </div>
    </div>
    <div class="flow-legend">${legendHTML}</div>
    <div class="flow-svg-wrap">
      <svg width="${W}" height="${H}" class="flow-svg"
           xmlns="http://www.w3.org/2000/svg" style="display:block">
        <!-- Grid -->
        ${gridSVG}
        <!-- X Axis -->
        ${xAxisSVG}
        <text x="${W/2}" y="${H - 8}" text-anchor="middle"
              fill="#2e4057" font-size="9" font-family="JetBrains Mono,monospace">
          TIME →
        </text>
        <!-- Edges -->
        ${edgeSVG}
        <!-- Nodes -->
        ${nodesSVG}
      </svg>
    </div>
    <div class="flow-stats">
      <span>${nodes.length} items</span>
      <span>·</span>
      <span>${edges.length} TTP connections</span>
      <span>·</span>
      <span>Click any dot to find item in feed</span>
    </div>
  `;
}

// ─── Trends View ──────────────────────────────────────────────────────────────

function showTrendsView() {
  hideAllViews();
  const view = document.getElementById('trends-view');
  view.style.display = 'block';
  renderTrends();
  document.getElementById('feed-count').textContent =
    'TRENDS — top sources, techniques, and detected attack patterns';
}

function renderTrends() {
  const view = document.getElementById('trends-view');
  if (!view) return;

  // ── Source stats ──────────────────────────────────────────────────
  const sourceCounts = {};
  allItems.forEach(i => {
    sourceCounts[i.source || 'unknown'] = (sourceCounts[i.source||'unknown'] || 0) + 1;
  });
  const topSources = Object.entries(sourceCounts).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const maxSrc = topSources[0]?.[1] || 1;

  // ── TTP stats ─────────────────────────────────────────────────────
  const ttpCounts = {};
  allItems.forEach(i => {
    (i.ttps || []).forEach(t => {
      ttpCounts[t.id] = ttpCounts[t.id] || { name: t.name, count: 0 };
      ttpCounts[t.id].count++;
    });
  });
  const topTtps = Object.entries(ttpCounts).sort((a,b)=>b[1].count-a[1].count).slice(0,10);
  const maxTtp  = topTtps[0]?.[1].count || 1;

  // ── Tactic stats ──────────────────────────────────────────────────
  const tacticCounts = {};
  allItems.forEach(i => {
    (i.ttps || []).forEach(t => {
      tacticCounts[t.tactic] = (tacticCounts[t.tactic] || 0) + 1;
    });
  });
  const topTactics = Object.entries(tacticCounts).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const maxTac = topTactics[0]?.[1] || 1;

  // ── Attack pattern detection ──────────────────────────────────────
  const patterns = detectAttackPatterns();

  const barColor = {
    sources: '#00ffe1', ttps: '#4da6ff', tactics: '#b47aff'
  };

  const makeBarChart = (entries, maxVal, color) =>
    entries.map(([label, val]) => {
      const count = typeof val === 'object' ? val.count : val;
      return `
        <div class="bar-chart-row">
          <span class="bar-chart-label" title="${escapeHTML(label)}">${escapeHTML(label)}</span>
          <div class="bar-chart-wrap">
            <div class="bar-chart-fill" style="width:${(count/maxVal)*100}%;background:${color}"></div>
          </div>
          <span class="bar-chart-val">${count}</span>
        </div>`;
    }).join('');

  const patternHTML = patterns.length === 0
    ? '<p style="color:var(--text-muted);font-size:11px;font-style:italic">No strong attack patterns detected in current feed.</p>'
    : patterns.slice(0, 5).map(p => `
        <div class="pattern-card">
          <div class="pattern-header">
            <span class="pattern-title">⚠ POSSIBLE CAMPAIGN (${p.commonTtps.length} shared TTP${p.commonTtps.length>1?'s':''})</span>
            <span class="pattern-count">${p.items.length} related items</span>
          </div>
          <div class="pattern-ttps">
            ${p.commonTtps.slice(0,5).map(t =>
              `<span class="cluster-ttp-tag" onclick="filterByTechnique('${t.id}')"
                     title="${escapeHTML(t.name)}">${escapeHTML(t.id)}</span>`
            ).join('')}
          </div>
          <div class="pattern-items">
            ${p.items.slice(0,4).map(item =>
              `<a class="pattern-item-link"
                  onclick="jumpToItem('${escapeHTML(item.title.substring(0,35)).replace(/'/g,'\\'')}')">
                 ${escapeHTML(item.title.substring(0, 90))}${item.title.length > 90 ? '…' : ''}
               </a>`
            ).join('')}
          </div>
        </div>`
    ).join('');

  view.innerHTML = `
    <div class="trends-section" style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;margin-bottom:24px;">
      <div>
        <div class="trends-section-title">TOP SOURCES</div>
        ${makeBarChart(topSources, maxSrc, barColor.sources)}
      </div>
      <div>
        <div class="trends-section-title">TOP ATT&CK TACTICS</div>
        ${topTactics.length > 0
          ? makeBarChart(topTactics, maxTac, barColor.tactics)
          : '<p style="color:var(--text-muted);font-size:11px">No TTP data</p>'}
      </div>
      <div>
        <div class="trends-section-title">TOP TECHNIQUES</div>
        ${topTtps.length > 0
          ? makeBarChart(topTtps, maxTtp, barColor.ttps)
          : '<p style="color:var(--text-muted);font-size:11px">No TTP data</p>'}
      </div>
    </div>

    <div class="trends-section">
      <div class="trends-section-title">⚠ ATTACK PATTERN DETECTION</div>
      <p style="font-size:10px;color:var(--text-muted);margin-bottom:12px;">
        Groups of items sharing 2+ MITRE ATT&CK techniques — possible coordinated campaigns.
      </p>
      ${patternHTML}
    </div>
  `;
}

function detectAttackPatterns() {
  const groups  = [];
  const visited = new Set();

  allItems.forEach((item, i) => {
    if (visited.has(i)) return;
    const myTtps = new Set((item.ttps || []).map(t => t.id));
    if (myTtps.size < 2) return;

    const related = [];
    allItems.forEach((other, j) => {
      if (j === i || visited.has(j)) return;
      const otherTtps = new Set((other.ttps || []).map(t => t.id));
      const shared    = [...myTtps].filter(id => otherTtps.has(id));
      if (shared.length >= 2) {
        related.push({ item: other, idx: j });
        visited.add(j);
      }
    });

    if (related.length >= 1) {
      const allGroupItems = [item, ...related.map(r => r.item)];
      // Find TTPs common to ALL items in the group
      const commonTtps = (item.ttps || []).filter(t =>
        allGroupItems.every(g => (g.ttps || []).some(gt => gt.id === t.id))
      );
      if (commonTtps.length >= 1) {
        groups.push({
          items:      allGroupItems,
          commonTtps,
          score:      allGroupItems.length * commonTtps.length,
        });
        visited.add(i);
      }
    }
  });

  return groups.sort((a, b) => b.score - a.score);
}

// ─── Export ───────────────────────────────────────────────────────────────────

window.toggleExportMenu = function() {
  setExportMenu(!exportMenuOpen);
};

function setExportMenu(open) {
  exportMenuOpen = open;
  const menu = document.getElementById('export-menu');
  if (menu) menu.style.display = open ? 'block' : 'none';
}

window.exportData = function(format) {
  const items = filteredItems.length > 0 ? filteredItems : allItems;
  const ts    = new Date().toISOString().slice(0, 10);

  if (format === 'json') {
    const blob = new Blob([JSON.stringify({ exported: ts, count: items.length, items }, null, 2)],
      { type: 'application/json' });
    downloadBlob(blob, `cyberwatch-export-${ts}.json`);
  }

  if (format === 'csv') {
    const cols = ['title','source','category','severity','cvss_score','severity_score','cve_id','published','url','ai_summary'];
    const rows = [cols.join(',')];
    items.forEach(item => {
      rows.push(cols.map(c => {
        const val = item[c] ?? '';
        const str = String(val).replace(/"/g, '""');
        return str.includes(',') || str.includes('"') || str.includes('\n')
          ? `"${str}"` : str;
      }).join(','));
    });
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    downloadBlob(blob, `cyberwatch-export-${ts}.csv`);
  }

  setExportMenu(false);
};

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ─── Mobile Sidebar Toggle ────────────────────────────────────────────────────

window.toggleMobileSidebar = function() {
  const sidebar = document.querySelector('.sidebar');
  const label   = document.getElementById('toggle-label');
  if (!sidebar) return;
  const isOpen = sidebar.classList.toggle('mobile-open');
  if (label) label.textContent = isOpen ? '▲ HIDE STATS' : '▼ SHOW STATS';
};

// ─── Utilities ────────────────────────────────────────────────────────────────

function timeAgo(date) {
  const diff  = Date.now() - date;
  const mins  = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days  = Math.floor(diff / 86400000);
  if (isNaN(diff)) return '';
  if (mins  <  1)  return 'just now';
  if (mins  < 60)  return `${mins}m ago`;
  if (hours < 24)  return `${hours}h ago`;
  if (days  <  7)  return `${days}d ago`;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function escapeHTML(str) {
  if (!str) return '';
  return str
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#039;');
}