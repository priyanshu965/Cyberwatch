const DATA_URL = "data/intel.json";

// LOAD DATA
async function loadData() {
  const res = await fetch(DATA_URL + "?t=" + Date.now());
  const data = await res.json();

  document.getElementById("last-updated").textContent =
    "Last Updated: " + new Date(data.last_updated).toLocaleString();

  render(data.items);
}

// =====================
// ATTACK FLOW
// =====================
function buildAttackFlow(item) {
  if (!item.ttps) return "";
  const tactics = item.ttps.map(t => t.tactic);
  return [...new Set(tactics)].join(" → ");
}

// =====================
// TTP CLUSTER
// =====================
function getTTPClusters(items) {
  const map = {};
  items.forEach(item => {
    (item.ttps || []).forEach(t => {
      map[t.id] = {
        name: t.name,
        count: (map[t.id]?.count || 0) + 1
      };
    });
  });

  return Object.entries(map)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 5);
}

// =====================
// PATTERNS
// =====================
function detectPatterns(items) {
  const keys = ["phishing", "ransomware", "supply chain", "backdoor"];
  const result = {};

  keys.forEach(k => {
    result[k] = items.filter(i =>
      (i.title + i.description).toLowerCase().includes(k)
    ).length;
  });

  return result;
}

// =====================
// GRAPH
// =====================
function renderGraph(item) {
  if (!item.ttps) return;

  const nodes = [];
  const edges = [];

  item.ttps.forEach((t, i) => {
    nodes.push({ id: i, label: t.tactic });
    if (i > 0) edges.push({ from: i - 1, to: i });
  });

  const container = document.getElementById("attack-graph");

  const data = {
    nodes: new vis.DataSet(nodes),
    edges: new vis.DataSet(edges)
  };

  new vis.Network(container, data, {});
}

// =====================
// MAIN RENDER
// =====================
function render(items) {
  const feed = document.getElementById("feed");
  feed.innerHTML = "";

  // SUMMARY
  const critical = items.filter(i => i.severity === "critical").length;
  const high = items.filter(i => i.severity === "high").length;

  document.getElementById("summary").innerHTML =
    `🚨 ${critical} Critical | ⚠️ ${high} High threats`;

  // TTP CLUSTERS
  const clusters = getTTPClusters(items);
  document.getElementById("ttp-clusters").innerHTML =
    clusters.map(([id, d]) => `<div>${id} (${d.count})</div>`).join("");

  // PATTERNS
  const patterns = detectPatterns(items);
  let html = "";
  for (let k in patterns) {
    if (patterns[k] > 2) html += `<div>${k}: ${patterns[k]}</div>`;
  }
  document.getElementById("pattern-box").innerHTML = html;

  // CARDS
  items.forEach(item => {
    const div = document.createElement("div");
    div.className = "card";

    const flow = buildAttackFlow(item);

    div.innerHTML = `
      <h3>${item.title}</h3>
      <p>${item.description}</p>
      <div class="meta">${item.source} | ${item.severity}</div>
      <div class="flow">${flow}</div>
    `;

    div.onclick = () => renderGraph(item);

    feed.appendChild(div);
  });
}

loadData();