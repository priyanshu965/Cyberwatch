let intelData = [];

async function init() {
    const res = await fetch('data/intel.json');
    const data = await res.json();
    intelData = data.items;
    
    mermaid.initialize({ startOnLoad: false, theme: 'dark' });
    renderGraph();
    renderFeed();
}

// D3.js Force Directed Graph
function renderGraph() {
    const nodes = [];
    const links = [];

    intelData.forEach((item, i) => {
        nodes.push({ id: item.title, group: 'threat', val: item.severity_score });
        item.ttps.forEach(ttp => {
            if (!nodes.find(n => n.id === ttp.id)) nodes.push({ id: ttp.id, group: 'ttp', val: 5 });
            links.push({ source: item.title, target: ttp.id });
        });
    });

    const svg = d3.select("#viz-canvas");
    const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(links).id(d => d.id).distance(100))
        .force("charge", d3.forceManyBody().strength(-200))
        .force("center", d3.forceCenter(window.innerWidth / 2, window.innerHeight / 2));

    const link = svg.append("g").selectAll("line").data(links).enter().append("line").attr("class", "link");

    const node = svg.append("g").selectAll("circle").data(nodes).enter().append("circle")
        .attr("r", d => d.val * 2)
        .attr("fill", d => d.group === 'threat' ? '#00f2ff' : '#ff0055')
        .on("click", (e, d) => {
            const item = intelData.find(i => i.title === d.id);
            if(item) openDrawer(item);
        });

    simulation.on("tick", () => {
        link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
        node.attr("cx", d => d.x).attr("cy", d => d.y);
    });
}

async function openDrawer(item) {
    const drawer = document.getElementById('side-drawer');
    document.getElementById('drawer-title').innerText = item.title;
    document.getElementById('drawer-summary').innerText = item.ai_summary;
    document.getElementById('source-link').href = item.url;
    
    // Render Mermaid Graph
    const mRender = document.getElementById('mermaid-render');
    mRender.innerHTML = item.workflow_graph;
    mRender.removeAttribute('data-processed');
    await mermaid.run({ nodes: [mRender] });

    drawer.classList.add('open');
}

function closeDrawer() {
    document.getElementById('side-drawer').classList.remove('open');
}

init();