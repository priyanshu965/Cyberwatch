const DATA_URL = "data/intel.json";

async function loadData() {
  const res = await fetch(DATA_URL + "?t=" + Date.now());
  const data = await res.json();

  document.getElementById("last-updated").textContent =
    "Last Updated: " + new Date(data.last_updated).toLocaleString();

  render(data.items);
}

// ================= ATTACK FLOW =================
function buildAttackFlow(item) {
  if (!item.ttps) return "";
  const tactics = item.ttps.map(t => t.tactic);
  return [...new Set(tactics)].join(" → ");
}

// ================= TTP CLUSTERS =================
function getTTPClusters(items) {
  const map = {};

  items.forEach(item => {
    (item.ttps || []).forEach(t => {
      map[t.id] = (map[t.id] || 0) + 1;
    });
  });

  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
}

// ================= PATTERNS =================
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

// ================= GRAPH =================
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

  new vis.Network(container, data, {
    nodes: { color: "#00ffe1" },
    edges: { color: "#3b9eff" }
  });
}

// ================= MAIN RENDER =================
function render(items) {

  const container = document.getElementById("cards-container");
  container.innerHTML = "";

  // SUMMARY
  const critical = items.filter(i => i.severity === "critical").length;
  const high = items.filter(i => i.severity === "high").length;

  document.getElementById("summary").innerHTML =
    `🚨 ${critical} Critical<br>⚠️ ${high} High`;

  // TTP
  const clusters = getTTPClusters(items);
  document.getElementById("ttp-clusters").innerHTML =
    clusters.map(([id, count]) => `<div>${id} (${count})</div>`).join("");

  // PATTERNS
  const patterns = detectPatterns(items);
  let html = "";
  for (let k in patterns) {
    if (patterns[k] > 2) {
      html += `<div>${k}: ${patterns[k]}</div>`;
    }
  }
  document.getElementById("pattern-box").innerHTML = html;

  // CARDS
  items.forEach(item => {

    const flow = buildAttackFlow(item);

    const card = document.createElement("div");
    card.className = "intel-card";

    card.innerHTML = `
      <h3>${item.title}</h3>
      <p>${item.description}</p>
      <div class="meta">${item.source} | ${item.severity}</div>
      <div class="flow">⚡ ${flow}</div>
    `;

    card.onclick = () => renderGraph(item);

    container.appendChild(card);
  });
}

loadData();