/**
 * CYBERWATCH DASHBOARD — app.js
 *
 * Loading strategy:
 *  1. fetch('data/intel.json') — GitHub Pages / local server
 *  2. window.INTEL_DATA fallback — file:// protocol
 *
 * AI Features:
 *  - Cards expand on click → AI analysis panel (summary + severity + graph)
 *  - Mermaid attack-flow diagram lazily rendered via mermaid.render()
 *  - TTP Detail Cards: parsed from graph edge labels + item ttps[]
 *    Each card shows tactic phase, technique name, and all feed items
 *    that share that TTP. Clicking any item scrolls to it in the feed.
 */

// ─── Mermaid Config (dark terminal theme) ─────────────────────────────────────
if (typeof mermaid !== 'undefined') {
  mermaid.initialize({
    startOnLoad:   false,
    theme:         'dark',
    securityLevel: 'loose',
    themeVariables: {
      background:          '#080b0f',
      mainBkg:             '#0d1117',
      primaryColor:        '#0d2038',
      primaryTextColor:    '#c9d8e8',
      primaryBorderColor:  '#1e4d73',
      lineColor:           '#4da6ff',
      secondaryColor:      '#111820',
      tertiaryColor:       '#080b0f',
      edgeLabelBackground: '#080b0f',
      fontFamily:          "'JetBrains Mono', 'Courier New', monospace",
      fontSize:            '12px',
      nodeBorder:          '#1e2d3d',
      clusterBkg:          '#0d1117',
    },
    flowchart: { htmlLabels: false, curve: 'Linear', padding: 24 },
  });
}

// ─── State ────────────────────────────────────────────────────────────────────
let allItems     = [];
let filteredItems = [];
let activeFilter  = 'all';
let searchQuery   = '';
let mermaidSeq    = 0;   // unique ID counter for each mermaid diagram

// ─── Entry Point ──────────────────────────────────────────────────────────────
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
          meta.textContent = '⚠ Preview mode (open via server for live data)';
          meta.style.color = '#f5c518';
        }
      } else {
        throw new Error('No data — open via a server or GitHub Pages');
      }
    }

    allItems = data.items || [];

    if (data.last_updated) {
      const date = new Date(data.last_updated);
      const utc  = date.toUTCString();
      const ist  = date.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata', dateStyle: 'medium', timeStyle: 'medium'
      });
      document.getElementById('last-updated').textContent =
        `Last updated: ${utc} | IST: ${ist}`;
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
  if (activeFilter === 'matrix') {
    showMatrixView();
    return;
  }

  filteredItems = allItems.filter(item => {
    const catMatch = activeFilter === 'all' || item.category === activeFilter;
    if (!catMatch) return false;

    const q = searchQuery.toLowerCase();
    if (!q) return true;
    return (
      (item.title       && item.title.toLowerCase().includes(q))       ||
      (item.description && item.description.toLowerCase().includes(q)) ||
      (item.cve_id      && item.cve_id.toLowerCase().includes(q))      ||
      (item.source      && item.source.toLowerCase().includes(q))      ||
      (item.ai_summary  && item.ai_summary.toLowerCase().includes(q))  ||
      (item.ttps && item.ttps.some(t =>
        t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
      ))
    );
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
    timer = setTimeout(() => {
      searchQuery = input.value.trim();
      applyFilters();
    }, 250);
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
  feedCount.textContent = `${filteredItems.length} item${filteredItems.length !== 1 ? 's' : ''} in feed`;

  const sorted = [...filteredItems].sort(
    (a, b) => new Date(b.published || 0) - new Date(a.published || 0)
  );

  sorted.forEach((item, index) => container.appendChild(buildCard(item, index)));
}

// ─── Build Card ───────────────────────────────────────────────────────────────
function buildCard(item, index) {
  const card  = document.createElement('div');
  const mySeq = ++mermaidSeq;

  const isNew = item.published &&
    (Date.now() - new Date(item.published)) < 86_400_000;

  card.className = 'intel-card';
  if (isNew) card.classList.add('new-item');

  // ── FIX: was item.aisummary (wrong) → now item.ai_summary (correct) ────────
  const hasAI = item.ai_summary &&
                item.ai_summary !== 'AI analysis pending' &&
                item.ai_summary !== '';

  if (hasAI) card.classList.add('ai-enriched');

  card.dataset.category = item.category || 'news';
  card.style.animationDelay = `${index * 0.04}s`;

  const severity       = (item.severity || 'medium').toLowerCase();
  const providerLabel  = (item.ai_provider || 'AI').toUpperCase();
  const modelLabel     = item.ai_model || item.ai_provider || 'AI';

  const badgeHTML    = `<span class="badge ${severity}">${severity.toUpperCase()}</span>`;
  const newBadgeHTML = isNew ? `<span class="new-item-badge">NEW</span>` : '';
  const aiBadgeHTML  = hasAI
    ? `<span class="ai-badge" title="Enriched by ${escapeHTML(providerLabel)}: ${escapeHTML(modelLabel)}">${escapeHTML(providerLabel)}</span>`
    : '';

  const cveIdHTML  = item.cve_id ? `<span class="cve-id">${item.cve_id}</span> · ` : '';
  const descHTML   = item.description
    ? `<p class="card-description">${escapeHTML(item.description)}</p>` : '';
  const dateStr    = item.published ? timeAgo(new Date(item.published)) : '';
  const cvssHTML   = item.cvss_score
    ? `<span class="meta-tag meta-cvss">CVSS ${item.cvss_score.toFixed(1)}</span>` : '';
  const aiScoreHTML = (item.severity_score != null)
    ? `<span class="meta-tag meta-ai-score" title="AI severity score: ${escapeHTML(modelLabel)}">✦ AI ${item.severity_score.toFixed(1)}</span>`
    : '';

  // TTP pills
  const ttps   = item.ttps || [];
  let ttpHTML  = '';
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

  // Analysis section — graph source is unescaped for Mermaid
  const graphSource    = (item.workflow_graph || '').replace(/\\n/g, '\n');
  const aiSummaryText  = item.ai_summary || '';

  const analysisHTML = `
    <div class="analysis-section" id="analysis-${mySeq}">
      <div class="analysis-header">
        <span class="analysis-label">AI THREAT ANALYSIS</span>
        <span class="analysis-model">${escapeHTML(modelLabel)}</span>
      </div>
      <p class="analysis-summary">${escapeHTML(aiSummaryText)}</p>
      ${graphSource ? `
      <div class="analysis-graph-wrap">
        <div class="analysis-graph-label">ATTACK FLOW — click any TTP node for related items</div>
        <div class="mermaid-container" id="mermaid-${mySeq}" data-graph="${escapeHTML(graphSource)}" data-rendered="false">
          <div class="mermaid-spinner">
            <div class="mermaid-spinner-ring"></div>
            <span>Rendering diagram…</span>
          </div>
        </div>
        <div class="ttp-detail-cards" id="ttp-cards-${mySeq}">
          <!-- populated after mermaid renders -->
        </div>
      </div>` : ''}
    </div>
  `;

  const expandHintHTML = `
    <div class="card-expand-hint">
      ${hasAI ? '▼ EXPAND AI ANALYSIS' : '▼ EXPAND'}
    </div>`;

  card.innerHTML = `
    <div class="card-top">
      <p class="card-title">
        ${item.url
          ? `<a href="${escapeHTML(item.url)}" target="_blank" rel="noopener"
               onclick="event.stopPropagation()">${escapeHTML(item.title)}</a>`
          : escapeHTML(item.title)
        }
        ${newBadgeHTML}${aiBadgeHTML}
      </p>
      ${badgeHTML}
    </div>
    ${descHTML}
    <div class="card-meta">
      ${cveIdHTML}
      <span class="meta-tag meta-source">${escapeHTML(item.source || 'unknown')}</span>
      <span class="meta-tag meta-cat">${escapeHTML(item.category || 'general')}</span>
      ${cvssHTML}${aiScoreHTML}
      <span class="meta-date">${dateStr}</span>
    </div>
    ${ttpHTML}
    ${analysisHTML}
    ${expandHintHTML}
  `;

  // ── Card click → toggle expand + lazy-render Mermaid ────────────────────────
  card.addEventListener('click', e => {
    if (
      e.target.closest('a') ||
      e.target.closest('.ttp-pill') ||
      e.target.closest('.ttp-more') ||
      e.target.closest('.ttp-detail-card')
    ) return;

    const wasExpanded = card.classList.contains('expanded');
    card.classList.toggle('expanded');

    if (!wasExpanded && graphSource) {
      const container = card.querySelector(`#mermaid-${mySeq}`);
      if (container && container.dataset.rendered === 'false') {
        container.dataset.rendered = 'true';
        renderMermaidAsync(container, graphSource, mySeq, item);
      }
    }
  });

  return card;
}

// ─── Mermaid Async Renderer ───────────────────────────────────────────────────
async function renderMermaidAsync(container, graphSource, seqId, item) {
  if (typeof mermaid === 'undefined') {
    container.innerHTML = '<p class="mermaid-error">Mermaid.js not loaded</p>';
    return;
  }
  try {
    const diagramId = `mermaid-diagram-${seqId}`;
    const { svg }   = await mermaid.render(diagramId, graphSource);

    container.innerHTML = svg;

    // Make SVG scale properly
    const svgEl = container.querySelector('svg');
    if (svgEl) {
      svgEl.style.maxWidth  = '100%';
      svgEl.style.height    = 'auto';
      svgEl.style.display   = 'block';
      svgEl.removeAttribute('width');
      svgEl.removeAttribute('height');
    }

    // Build TTP detail cards after diagram renders
    const ttpCardContainer = document.getElementById(`ttp-cards-${seqId}`);
    if (ttpCardContainer) {
      buildTtpDetailCards(ttpCardContainer, graphSource, item);
    }

  } catch (err) {
    console.warn('Mermaid render error:', err);
    // Show cleaned graph source as readable fallback
    const pre  = document.createElement('pre');
    pre.className   = 'mermaid-raw-fallback';
    pre.textContent = graphSource;
    container.innerHTML = '';
    container.appendChild(pre);

    // Still build TTP detail cards even if graph fails
    const ttpCardContainer = document.getElementById(`ttp-cards-${seqId}`);
    if (ttpCardContainer) {
      buildTtpDetailCards(ttpCardContainer, graphSource, item);
    }
  }
}

// ─── TTP Detail Cards ─────────────────────────────────────────────────────────
/**
 * Parses TTP IDs from the graph edge labels (e.g. |T1566.001| → "T1566.001")
 * and the item's own ttps[] array, then builds interactive detail cards for each.
 *
 * Each card shows:
 *  - TTP ID badge  (clickable → filters feed)
 *  - Technique name + tactic phase
 *  - Count of OTHER feed items sharing this TTP
 *  - Scrollable list of those items (clickable → filters feed to that item)
 */
function buildTtpDetailCards(container, graphSource, sourceItem) {
  // 1. Extract TTP IDs from graph edge labels like |T1566|, |T1059.001|
  const edgeTtpIds = new Set();
  const edgeMatches = graphSource.matchAll(/\|([^|\n]{1,20})\|/g);
  for (const m of edgeMatches) {
    const candidate = m[1].trim();
    if (/^T\d{4}(\.\d{3})?$/.test(candidate)) {
      edgeTtpIds.add(candidate);
    }
  }

  // 2. Merge with item's mapped ttps[]
  const ttpMap = {};
  (sourceItem.ttps || []).forEach(t => {
    ttpMap[t.id] = { id: t.id, name: t.name, tactic: t.tactic, tactic_id: t.tactic_id };
  });
  // Add any graph-only TTP IDs (may not be in the mapped list)
  edgeTtpIds.forEach(id => {
    if (!ttpMap[id]) ttpMap[id] = { id, name: id, tactic: '—', tactic_id: '—' };
  });

  const allTtps = Object.values(ttpMap);
  if (allTtps.length === 0) return;

  // 3. Sort: graph-referenced first, then by id
  allTtps.sort((a, b) => {
    const aInGraph = edgeTtpIds.has(a.id) ? 0 : 1;
    const bInGraph = edgeTtpIds.has(b.id) ? 0 : 1;
    return aInGraph - bInGraph || a.id.localeCompare(b.id);
  });

  // 4. Build the section
  const sectionHeader = document.createElement('div');
  sectionHeader.className = 'ttp-detail-section-header';
  sectionHeader.innerHTML = `
    <span class="ttp-detail-section-label">TTP BREAKDOWN</span>
    <span class="ttp-detail-section-hint">Click any technique to filter the feed</span>
  `;
  container.appendChild(sectionHeader);

  allTtps.forEach(ttp => {
    // Find feed items that share this TTP (excluding the source item itself)
    const relatedItems = allItems.filter(other =>
      other !== sourceItem &&
      (other.ttps || []).some(t => t.id === ttp.id)
    );

    const card = document.createElement('div');
    card.className    = 'ttp-detail-card';
    card.dataset.ttpId = ttp.id;

    // Tactic badge colour
    const tacticColor = tacticColor_forId(ttp.tactic_id);

    // Related items list (max 4 shown)
    const relatedHTML = relatedItems.length > 0
      ? `<div class="ttp-related-list">
           ${relatedItems.slice(0, 4).map(other => `
             <div class="ttp-related-item"
                  onclick="event.stopPropagation();jumpToItem(${JSON.stringify(other.title.substring(0,40))})"
                  title="${escapeHTML(other.title)}">
               <span class="ttp-related-cat" style="background:${catColor(other.category)}"></span>
               <span class="ttp-related-title">${escapeHTML(other.title.substring(0,72))}${other.title.length>72?'…':''}</span>
             </div>`
           ).join('')}
           ${relatedItems.length > 4 ? `<div class="ttp-related-more">+${relatedItems.length-4} more items</div>` : ''}
         </div>`
      : `<div class="ttp-related-empty">No other items in feed share this technique</div>`;

    card.innerHTML = `
      <div class="ttp-detail-header">
        <button class="ttp-detail-id" onclick="event.stopPropagation();filterByTechnique('${ttp.id}')"
                title="Filter feed by ${escapeHTML(ttp.id)}">${escapeHTML(ttp.id)}</button>
        <div class="ttp-detail-info">
          <span class="ttp-detail-name">${escapeHTML(ttp.name)}</span>
          <span class="ttp-detail-tactic" style="color:${tacticColor}">${escapeHTML(ttp.tactic)}</span>
        </div>
        <span class="ttp-detail-count">${relatedItems.length} match${relatedItems.length!==1?'es':''}</span>
      </div>
      ${relatedHTML}
    `;

    container.appendChild(card);
  });
}

// Colour helpers for TTP cards
function tacticColor_forId(tacticId) {
  const map = {
    'TA0043': '#5f7a94', 'TA0042': '#a78bfa', 'TA0001': '#ff3b5c',
    'TA0002': '#ff8c42', 'TA0003': '#f5c518', 'TA0004': '#ff8c42',
    'TA0005': '#00ffe1', 'TA0006': '#ff3b5c', 'TA0007': '#3b9eff',
    'TA0008': '#a78bfa', 'TA0009': '#3b9eff', 'TA0011': '#00ffe1',
    'TA0010': '#ff8c42', 'TA0040': '#ff3b5c',
  };
  return map[tacticId] || '#4da6ff';
}

function catColor(cat) {
  return { cve: '#ff3b5c', incident: '#ff8c42', advisory: '#f5c518', news: '#3b9eff' }[cat] || '#5f7a94';
}

// Jump to a card in the feed by title fragment
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
  // Briefly highlight the first result
  setTimeout(() => {
    const first = document.querySelector('.intel-card');
    if (first) {
      first.scrollIntoView({ behavior: 'smooth', block: 'center' });
      first.style.outline = '2px solid var(--accent-cyan)';
      setTimeout(() => { if (first) first.style.outline = ''; }, 2500);
    }
  }, 150);
};

// ─── Render Sidebar ───────────────────────────────────────────────────────────
function renderSidebar() {
  renderSeverityBars();
  renderSourceList();
  renderCategoryList();
}

function renderSeverityBars() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  allItems.forEach(i => {
    const s = (i.severity || '').toLowerCase();
    if (s in counts) counts[s]++;
  });
  const max = Math.max(...Object.values(counts), 1);
  Object.entries(counts).forEach(([sev, count]) => {
    document.getElementById(`bar-${sev}`).style.width = `${(count / max) * 100}%`;
    document.getElementById(`sev-count-${sev}`).textContent = count;
  });
}

function renderSourceList() {
  const counts = {};
  allItems.forEach(i => { const s = i.source || 'unknown'; counts[s] = (counts[s] || 0) + 1; });
  document.getElementById('source-list').innerHTML =
    Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, count]) => `
      <div class="source-item">
        <span class="source-name">${escapeHTML(name)}</span>
        <span class="source-badge">${count}</span>
      </div>`).join('');
}

function renderCategoryList() {
  const counts = {};
  allItems.forEach(i => { const c = i.category || 'general'; counts[c] = (counts[c] || 0) + 1; });
  document.getElementById('cat-list').innerHTML =
    Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([cat, count]) => `
      <div class="cat-item" onclick="filterByCategory('${cat}')">
        <span class="cat-name">${escapeHTML(cat)}</span>
        <span class="cat-count">${count}</span>
      </div>`).join('');
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

// ─── UI State Transitions ─────────────────────────────────────────────────────
function showContent() {
  document.getElementById('loading-state').style.display   = 'none';
  document.getElementById('error-state').style.display     = 'none';
  document.getElementById('matrix-view').style.display     = 'none';
  document.getElementById('cards-container').style.display = 'flex';
}

function showError() {
  document.getElementById('loading-state').style.display = 'none';
  document.getElementById('error-state').style.display   = 'block';
}

function showMatrixView() {
  document.getElementById('loading-state').style.display   = 'none';
  document.getElementById('error-state').style.display     = 'none';
  document.getElementById('cards-container').style.display = 'none';
  document.getElementById('no-results').style.display      = 'none';
  document.getElementById('matrix-view').style.display     = 'block';
  renderMatrixGrid();
  document.getElementById('feed-count').textContent =
    'MITRE ATT&CK Coverage Map — click any technique to filter feed';
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
  const newItems   = allItems.filter(i => i.published && Date.now()-new Date(i.published)<86400000).length;
  const incidents  = allItems.filter(i => i.category === 'incident').length;
  const cves       = allItems.filter(i => i.category === 'cve').length;
  const advisories = allItems.filter(i => i.category === 'advisory').length;
  // ── FIX: was item.aisummary (wrong) → now item.ai_summary (correct) ────────
  const aiEnriched = allItems.filter(i =>
    i.ai_summary && i.ai_summary !== 'AI analysis pending' && i.ai_summary !== ''
  ).length;

  stats.innerHTML = `
    <span class="summary-stat"><span class="summary-stat-val c">${critical}</span><span class="summary-stat-lbl">CRITICAL</span></span>
    <span class="summary-stat"><span class="summary-stat-val h">${high}</span><span class="summary-stat-lbl">HIGH</span></span>
    <span class="summary-stat"><span class="summary-stat-val m">${medium}</span><span class="summary-stat-lbl">MEDIUM</span></span>
    <span class="summary-divider">·</span>
    <span class="summary-stat"><span class="summary-stat-val n">${cves}</span><span class="summary-stat-lbl">CVEs</span></span>
    <span class="summary-stat"><span class="summary-stat-val n">${incidents}</span><span class="summary-stat-lbl">INCIDENTS</span></span>
    <span class="summary-stat"><span class="summary-stat-val n">${advisories}</span><span class="summary-stat-lbl">ADVISORIES</span></span>
    <span class="summary-divider">·</span>
    <span class="summary-stat"><span class="summary-stat-val" style="color:var(--accent-cyan)">${newItems}</span><span class="summary-stat-lbl">NEW TODAY</span></span>
    <span class="summary-stat"><span class="summary-stat-val" style="color:#a78bfa">${aiEnriched}</span><span class="summary-stat-lbl">AI ENRICHED</span></span>
  `;

  const topThreat = allItems.find(i => i.severity === 'critical') ||
                    allItems.find(i => i.severity === 'high');
  if (top && topThreat) {
    top.innerHTML = `🔴 Top threat: <strong>${escapeHTML(topThreat.title.substring(0,80))}${topThreat.title.length>80?'…':''}</strong>`;
  }
  bar.style.display = 'block';
}

// ─── Mobile Sidebar Toggle ────────────────────────────────────────────────────
window.toggleMobileSidebar = function() {
  const sidebar = document.querySelector('.sidebar');
  const label   = document.getElementById('toggle-label');
  if (!sidebar) return;
  const isOpen = sidebar.classList.toggle('mobile-open');
  if (label) label.textContent = isOpen ? '▲ HIDE STATS' : '▼ SHOW STATS';
};

// ─── MITRE ATT&CK Matrix ─────────────────────────────────────────────────────
const TACTIC_ORDER = [
  { id: "TA0043", name: "Reconnaissance"    },
  { id: "TA0042", name: "Resource Dev"      },
  { id: "TA0001", name: "Initial Access"    },
  { id: "TA0002", name: "Execution"         },
  { id: "TA0003", name: "Persistence"       },
  { id: "TA0004", name: "Privilege Esc"     },
  { id: "TA0005", name: "Defense Evasion"   },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery"         },
  { id: "TA0008", name: "Lateral Movement"  },
  { id: "TA0009", name: "Collection"        },
  { id: "TA0011", name: "Command & Control" },
  { id: "TA0010", name: "Exfiltration"      },
  { id: "TA0040", name: "Impact"            },
];

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
      const tooltip   = `${data.count} item(s): ${data.items.slice(0,2).join(' | ')}${data.items.length>2?'...':''}`;
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
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}