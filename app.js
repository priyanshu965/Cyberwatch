/**
 * CYBERWATCH DASHBOARD — app.js
 * Loads data/intel.json and renders the threat intelligence feed.
 * No external dependencies — pure vanilla JavaScript.
 *
 * Loading strategy (in order):
 *  1. Try fetch('data/intel.json')  — works on GitHub Pages & local server
 *  2. Fall back to window.INTEL_DATA — embedded in index.html, works when
 *     opening the file directly (file:// protocol, no server needed)
 */

// ─── State ───────────────────────────────────────────────────────────────────
let allItems = [];        // All intel items loaded from JSON
let filteredItems = [];   // Currently visible items after search/filter
let activeFilter = 'all'; // Current category filter
let searchQuery = '';     // Current search string

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

    // ── Strategy 1: HTTP fetch (GitHub Pages / local server) ─────────────────
    // This is the primary path. It works on GitHub Pages and when you run
    // `python -m http.server 8080` locally.
    if (window.location.protocol !== 'file:') {
      const response = await fetch(`data/intel.json?v=${Date.now()}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      data = await response.json();
    } else {
      // ── Strategy 2: Embedded fallback (file:// — opening HTML directly) ────
      // When the file is opened directly in a browser (double-click), fetch()
      // is blocked by CORS. We use the data embedded in index.html instead.
      if (window.INTEL_DATA) {
        data = window.INTEL_DATA;
        // Show a subtle notice that embedded data is being used
        const meta = document.getElementById('last-updated');
        if (meta) {
          meta.textContent = '⚠ Preview mode (open via server or GitHub Pages for live data)';
          meta.style.color = '#f5c518';
        }
      } else {
        throw new Error('No data available — place intel.json in the data/ folder and open via a server');
      }
    }

    // Store all items
    allItems = data.items || [];
	const summary = generateSummary(allItems);
	document.getElementById("feed-count").textContent = summary;
    // Update the "last updated" header
    if (data.last_updated) {
      const date = new Date(data.last_updated);
      const utc = date.toUTCString();

	const ist = date.toLocaleString('en-IN', {
  	timeZone: 'Asia/Kolkata',
  	dateStyle: 'medium',
  	timeStyle: 'medium'
		});

document.getElementById('last-updated').textContent =
  `Last updated: ${utc} | IST: ${ist}`;
    }

    // Render everything
    renderSidebar();
    applyFilters();
    showContent();

  } catch (err) {
    console.error('Failed to load intel.json:', err);
    showError();
  }
}

// ─── Filter & Search Logic ────────────────────────────────────────────────────

function applyFilters() {
  filteredItems = allItems.filter(item => {
    // Category filter
    const categoryMatch =
      activeFilter === 'all' || item.category === activeFilter;

    // Search filter (title + description)
    const q = searchQuery.toLowerCase();
    const searchMatch =
      !q ||
      (item.title  && item.title.toLowerCase().includes(q)) ||
      (item.description && item.description.toLowerCase().includes(q)) ||
      (item.cve_id && item.cve_id.toLowerCase().includes(q)) ||
      (item.source && item.source.toLowerCase().includes(q));

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

    // Update active state
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    activeFilter = btn.dataset.filter;
    applyFilters();
  });
}

function initSearch() {
  const input = document.getElementById('search-input');
  let debounceTimer;

  input.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      searchQuery = input.value.trim();
      applyFilters();
    }, 250); // debounce 250ms
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

  // Sort by published date descending (newest first)
  const sorted = [...filteredItems].sort((a, b) => {
    return new Date(b.published || 0) - new Date(a.published || 0);
  });

  sorted.forEach((item, index) => {
    const card = buildCard(item, index);
    container.appendChild(card);
  });
}

function buildCard(item, index) {
  const card = document.createElement('div');
	const isNew =
	  item.published &&
 	 (Date.now() - new Date(item.published)) < (24 * 60 * 60 * 1000);

	if (isNew) {
  	card.classList.add('new-item');
		}
  card.className = 'intel-card';
  card.dataset.category = item.category || 'news';
  card.style.animationDelay = `${index * 0.04}s`;

  const badgeHTML = item.severity
    ? `<span class="badge ${item.severity.toLowerCase()}">${item.severity.toUpperCase()}</span>`
    : `<span class="badge info">${(item.category || 'INFO').toUpperCase()}</span>`;

  const cveIdHTML = item.cve_id
    ? `<span class="cve-id">${item.cve_id}</span> · `
    : '';

  const descriptionHTML = item.description
    ? `<p class="card-description">${escapeHTML(item.description)}</p>`
    : '';

  const dateStr = item.published
    ? timeAgo(new Date(item.published))
    : '';

  card.innerHTML = `
    <div class="card-top">
      <p class="card-title">
        ${item.url
          ? `<a href="${escapeHTML(item.url)}" target="_blank" rel="noopener">${escapeHTML(item.title)}</a>`
          : escapeHTML(item.title)
        }
      </p>
      ${badgeHTML}
    </div>
    ${descriptionHTML}
    <div class="card-meta">
      ${cveIdHTML}
      <span class="meta-tag meta-source">${escapeHTML(item.source || 'unknown')}</span>
      <span class="meta-tag meta-cat">${escapeHTML(item.category || 'general')}</span>
      <span class="meta-date">${dateStr}</span>
    </div>
  `;

  return card;
}

// ─── Render Sidebar ───────────────────────────────────────────────────────────

function renderSidebar() {
  renderSeverityBars();
  renderSourceList();
  renderCategoryList();
}

function renderSeverityBars() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };

  allItems.forEach(item => {
    const s = (item.severity || '').toLowerCase();
    if (counts.hasOwnProperty(s)) counts[s]++;
  });

  const max = Math.max(...Object.values(counts), 1);

  Object.entries(counts).forEach(([sev, count]) => {
    document.getElementById(`bar-${sev}`).style.width = `${(count / max) * 100}%`;
    document.getElementById(`sev-count-${sev}`).textContent = count;
  });
}

function renderSourceList() {
  const sourceCounts = {};

  allItems.forEach(item => {
    const src = item.source || 'unknown';
    sourceCounts[src] = (sourceCounts[src] || 0) + 1;
  });

  const sorted = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]);

  const container = document.getElementById('source-list');
  container.innerHTML = sorted.map(([name, count]) => `
    <div class="source-item">
      <span class="source-name">${escapeHTML(name)}</span>
      <span class="source-badge">${count}</span>
    </div>
  `).join('');
}

function renderCategoryList() {
  const catCounts = {};

  allItems.forEach(item => {
    const cat = item.category || 'general';
    catCounts[cat] = (catCounts[cat] || 0) + 1;
  });

  const container = document.getElementById('cat-list');
  container.innerHTML = Object.entries(catCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([cat, count]) => `
      <div class="cat-item" onclick="filterByCategory('${cat}')">
        <span class="cat-name">${escapeHTML(cat)}</span>
        <span class="cat-count">${count}</span>
      </div>
    `).join('');
}

// Click a category in the sidebar to filter
window.filterByCategory = function(cat) {
  activeFilter = cat;
  document.querySelectorAll('.filter-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.filter === cat);
  });
  applyFilters();
};

// ─── Header Stats ─────────────────────────────────────────────────────────────

function updateHeaderStats() {
  const critical = filteredItems.filter(
    i => (i.severity || '').toLowerCase() === 'critical'
  ).length;

  const high = filteredItems.filter(
    i => (i.severity || '').toLowerCase() === 'high'
  ).length;

  document.getElementById('count-critical').textContent = critical;
  document.getElementById('count-high').textContent     = high;
  document.getElementById('count-total').textContent    = filteredItems.length;
}

// ─── UI State Transitions ─────────────────────────────────────────────────────

function showContent() {
  document.getElementById('loading-state').style.display = 'none';
  document.getElementById('error-state').style.display   = 'none';
  document.getElementById('cards-container').style.display = 'flex';
}

function showError() {
  document.getElementById('loading-state').style.display = 'none';
  document.getElementById('error-state').style.display   = 'block';
}

// ─── Utility: Time Ago ────────────────────────────────────────────────────────

function timeAgo(date) {
  const now = new Date();
  const diff = now - date;
  const mins   = Math.floor(diff / 60000);
  const hours  = Math.floor(diff / 3600000);
  const days   = Math.floor(diff / 86400000);

  if (isNaN(diff))   return '';
  if (mins  <  1)    return 'just now';
  if (mins  < 60)    return `${mins}m ago`;
  if (hours < 24)    return `${hours}h ago`;
  if (days  <  7)    return `${days}d ago`;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

// ─── Utility: Escape HTML ─────────────────────────────────────────────────────

function escapeHTML(str) {
  if (!str) return '';
  return str
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#039;');
}

function generateSummary(items) {
  const critical = items.filter(i => i.severity === 'critical').length;
  const high = items.filter(i => i.severity === 'high').length;

  const incidents = items.filter(i => i.category === 'incident').length;
  const cves = items.filter(i => i.category === 'cve').length;

  return `🚨 ${critical} critical, ⚠️ ${high} high threats | ${incidents} incidents | ${cves} CVEs`;
}
