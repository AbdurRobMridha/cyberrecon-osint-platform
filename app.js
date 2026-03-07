/**
 * OSINT Recon Engine — Frontend (Real Backend Edition)
 * Uses JWT auth + SSE streaming from Node.js backend
 */

'use strict';

const API = 'http://localhost:3001';

// ─── AUTH ─────────────────────────────────────────────────────
const token = localStorage.getItem('osint_token');
const user = JSON.parse(localStorage.getItem('osint_user') || 'null');

if (!token) { window.location.replace('auth.html'); }

// Show user handle in header
if (user) {
  const nm = document.getElementById('userBadgeName');
  if (nm) nm.textContent = '@' + user.username.toUpperCase();
}

// Logout
document.getElementById('logoutBtn')?.addEventListener('click', () => {
  localStorage.removeItem('osint_token');
  localStorage.removeItem('osint_user');
  window.location.replace('auth.html');
});

// ─── STATE ────────────────────────────────────────────────────
let scanResults = [];   // { name, cat, emoji, url, status, ms }
let scanning = false;
let evtSource = null;
let scanStartTime = 0;
let timerInterval = null;
let activeFilter = 'all';
let graphNodes = [];
let totalPlatforms = 0;

// ─── DOM REFS ─────────────────────────────────────────────────
const usernameInput = document.getElementById('usernameInput');
const scanBtn = document.getElementById('scanBtn');
const scanBtnText = document.getElementById('scanBtnText');
const statusLine = document.getElementById('statusLine');
const timerDisplay = document.getElementById('timerDisplay');
const progressWrap = document.getElementById('progressWrap');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');
const resultsGrid = document.getElementById('resultsGrid');
const filterTabs = document.getElementById('filterTabs');
const resultsSummary = document.getElementById('resultsSummary');
const sumFound = document.getElementById('sumFound');
const sumNotFound = document.getElementById('sumNotFound');
const sumBlocked = document.getElementById('sumBlocked');
const sumScanning = document.getElementById('sumScanning');
const hdrTotal = document.getElementById('hdrTotal');
const hdrFound = document.getElementById('hdrFound');
const hdrBlocked = document.getElementById('hdrBlocked');
const graphSub = document.getElementById('graphSub');

// ─── FOOTER CLOCK ─────────────────────────────────────────────
(function clockTick() {
  document.getElementById('footerTime').textContent =
    new Date().toISOString().replace('T', ' ').split('.')[0] + ' UTC';
  setTimeout(clockTick, 1000);
})();

// ─── SERVER HEALTH CHECK ─────────────────────────────────────
async function checkServer() {
  try {
    const r = await fetch(`${API}/api/health`, { signal: AbortSignal.timeout(3000) });
    return r.ok;
  } catch { return false; }
}

// ─── BACKGROUND PARTICLES ────────────────────────────────────
(function initBg() {
  const canvas = document.getElementById('bgCanvas');
  const ctx = canvas.getContext('2d');
  let W, H, particles = [];
  function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
  resize(); window.addEventListener('resize', resize);
  const PAL = ['#00f5ff', '#00ff88', '#b44bff', '#4b8fff'];
  for (let i = 0; i < 90; i++) particles.push({
    x: Math.random() * 1600, y: Math.random() * 900,
    vx: (Math.random() - .5) * .4, vy: (Math.random() - .5) * .4,
    r: Math.random() * 1.4 + .3, color: PAL[Math.floor(Math.random() * 4)], alpha: Math.random() * .5 + .1
  });
  function draw() {
    ctx.clearRect(0, 0, W, H);
    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = p.color; ctx.globalAlpha = p.alpha; ctx.fill();
    });
    ctx.globalAlpha = 1;
    for (let i = 0; i < particles.length; i++) for (let j = i + 1; j < particles.length; j++) {
      const dx = particles[i].x - particles[j].x, dy = particles[i].y - particles[j].y;
      const d = Math.sqrt(dx * dx + dy * dy);
      if (d < 130) {
        ctx.beginPath(); ctx.strokeStyle = `rgba(0,245,255,${(1 - d / 130) * .08})`; ctx.lineWidth = .5;
        ctx.moveTo(particles[i].x, particles[i].y); ctx.lineTo(particles[j].x, particles[j].y); ctx.stroke();
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
})();

// ─── 3D GRAPH (Three.js) ─────────────────────────────────────
let scene, camera, renderer, graphGroup;
let isDragging = false, prevMouse = { x: 0, y: 0 };
let rotX = 0.3, rotY = 0.4;

(function initGraph() {
  const container = document.getElementById('graphContainer');
  const canvas3d = document.getElementById('graphCanvas');
  const W = container.clientWidth, H = container.clientHeight;

  scene = new THREE.Scene();
  camera = new THREE.PerspectiveCamera(50, W / H, 0.1, 1000);
  camera.position.set(0, 0, 7);

  renderer = new THREE.WebGLRenderer({ canvas: canvas3d, antialias: true, alpha: true });
  renderer.setSize(W, H);
  renderer.setPixelRatio(window.devicePixelRatio);
  renderer.setClearColor(0x000000, 0);

  graphGroup = new THREE.Group();
  scene.add(graphGroup);

  scene.add(new THREE.AmbientLight(0x004466, 1.5));
  const pl = new THREE.PointLight(0x00f5ff, 1.5, 20);
  pl.position.set(3, 3, 3); scene.add(pl);

  const gridGeo = new THREE.SphereGeometry(3.5, 24, 16);
  const gridMat = new THREE.MeshBasicMaterial({ color: 0x002233, wireframe: true, transparent: true, opacity: .07 });
  scene.add(new THREE.Mesh(gridGeo, gridMat));

  // Central target node
  const coreGeo = new THREE.SphereGeometry(0.22, 20, 20);
  const coreMat = new THREE.MeshPhongMaterial({ color: 0x4b8fff, emissive: 0x1a3aff, transparent: true, opacity: .9 });
  const coreNode = new THREE.Mesh(coreGeo, coreMat);
  graphGroup.add(coreNode);

  const ringGeo = new THREE.TorusGeometry(0.35, 0.02, 6, 40);
  const ringMat = new THREE.MeshBasicMaterial({ color: 0x4b8fff, transparent: true, opacity: .5 });
  const ring = new THREE.Mesh(ringGeo, ringMat);
  graphGroup.add(ring);

  canvas3d.addEventListener('mousedown', e => { isDragging = true; prevMouse = { x: e.clientX, y: e.clientY }; });
  window.addEventListener('mouseup', () => isDragging = false);
  window.addEventListener('mousemove', e => {
    if (!isDragging) return;
    rotY += (e.clientX - prevMouse.x) * .008; rotX += (e.clientY - prevMouse.y) * .008;
    prevMouse = { x: e.clientX, y: e.clientY };
  });
  canvas3d.addEventListener('touchstart', e => { isDragging = true; prevMouse = { x: e.touches[0].clientX, y: e.touches[0].clientY }; });
  window.addEventListener('touchend', () => isDragging = false);
  window.addEventListener('touchmove', e => {
    if (!isDragging) return;
    rotY += (e.touches[0].clientX - prevMouse.x) * .008; rotX += (e.touches[0].clientY - prevMouse.y) * .008;
    prevMouse = { x: e.touches[0].clientX, y: e.touches[0].clientY };
  });
  window.addEventListener('resize', () => {
    const nW = container.clientWidth, nH = container.clientHeight;
    camera.aspect = nW / nH; camera.updateProjectionMatrix(); renderer.setSize(nW, nH);
  });

  let t = 0;
  function animate() {
    requestAnimationFrame(animate); t += 0.01;
    if (!isDragging) rotY += 0.004;
    graphGroup.rotation.x = rotX; graphGroup.rotation.y = rotY;
    ring.rotation.z = t * .5; ring.rotation.x = Math.sin(t * .3) * .3;
    const s = 1 + Math.sin(t * 2) * .06;
    coreNode.scale.set(s, s, s);
    graphNodes.forEach(n => {
      n.mesh.position.x = n.basePos.x + Math.sin(t * n.speed + n.phase) * .05;
      n.mesh.position.y = n.basePos.y + Math.cos(t * n.speed + n.phase) * .05;
    });
    renderer.render(scene, camera);
  }
  animate();
})();

function addGraphNode(color) {
  const idx = graphNodes.length;
  const total = totalPlatforms || 49;
  const phi = Math.acos(-1 + (2 * idx) / total);
  const theta = Math.sqrt(total * Math.PI) * phi;
  const r = 2.4 + Math.random() * 0.3;
  const x = r * Math.sin(phi) * Math.cos(theta);
  const y = r * Math.sin(phi) * Math.sin(theta);
  const z = r * Math.cos(phi);

  const geo = new THREE.SphereGeometry(0.1, 12, 12);
  const mat = new THREE.MeshPhongMaterial({ color, emissive: color, transparent: true, opacity: .85 });
  const mesh = new THREE.Mesh(geo, mat);
  mesh.position.set(x, y, z);
  graphGroup.add(mesh);

  const points = [new THREE.Vector3(0, 0, 0), new THREE.Vector3(x, y, z)];
  const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
  const lineMat = new THREE.LineBasicMaterial({ color, transparent: true, opacity: .18 });
  graphGroup.add(new THREE.Line(lineGeo, lineMat));

  const node = { mesh, basePos: { x, y, z }, speed: 0.5 + Math.random(), phase: Math.random() * Math.PI * 2 };
  graphNodes.push(node);
  graphSub.textContent = graphNodes.length + ' NODE' + (graphNodes.length === 1 ? '' : 'S') + ' DETECTED';
}

// ─── UI HELPERS ───────────────────────────────────────────────
function updateSummary() {
  const found = scanResults.filter(r => r.status === 'FOUND').length;
  const notFound = scanResults.filter(r => r.status === 'NOT_FOUND').length;
  const blocked = scanResults.filter(r => r.status === 'BLOCKED').length;
  const uncertain = scanResults.filter(r => r.status === 'UNCERTAIN').length;
  const sc = scanResults.filter(r => r.status === 'SCANNING').length;
  sumFound.textContent = found;
  sumNotFound.textContent = notFound;
  sumBlocked.textContent = blocked + (uncertain > 0 ? ` (+${uncertain}?)` : '');
  sumScanning.textContent = sc;
  hdrTotal.textContent = scanResults.length;
  hdrFound.textContent = found;
  hdrBlocked.textContent = blocked;
}

function getFiltered() {
  return activeFilter === 'all' ? scanResults : scanResults.filter(r => r.cat === activeFilter);
}

function renderResults() {
  const list = getFiltered();
  if (!list.length) {
    resultsGrid.innerHTML = '<div class="empty-state"><div class="empty-icon">◎</div><div class="empty-title">NO RESULTS IN THIS CATEGORY</div></div>';
    return;
  }
  resultsGrid.innerHTML = '';
  list.forEach(r => {
    const card = document.createElement('div');
    const stRaw = (r.status || 'scanning');
    const stCls = stRaw.toLowerCase().replace('_', '-').replace('not-found', 'notfound');
    card.className = 'result-card ' + stCls;

    const timeStr = r.ms != null ? r.ms + 'ms' : '...';
    const httpChip = r.httpStatus
      ? `<span style="font-family:var(--font-mono);font-size:9px;color:var(--text2);padding:2px 6px;border-radius:4px;background:rgba(0,0,0,.3)">HTTP ${r.httpStatus}</span>`
      : '';

    // Always show a link button — style changes per status
    const visitBtn = r.url && r.url !== '' && stRaw !== 'SCANNING'
      ? buildVisitBtn(r.url, stRaw)
      : `<span style="font-family:var(--font-mono);font-size:10px;color:var(--text2)">${timeStr}</span>`;

    const statusLabel = stRaw.replace('_', ' ');

    card.innerHTML = `
      ${stRaw === 'SCANNING' ? '<div class="scan-shimmer"></div>' : ''}
      <div class="card-top">
        <div class="card-icon">${r.emoji}</div>
        <div class="card-meta">
          <div class="card-platform">${r.name}</div>
          <div class="card-category">${r.cat.toUpperCase()}</div>
        </div>
        <div class="card-status ${stCls}">
          <span class="status-dot ${stCls}"></span>
          ${stRaw === 'SCANNING' ? 'SCANNING' : statusLabel}
        </div>
      </div>
      <div class="card-url">
        ${r.url ? `<a href="${r.url}" target="_blank" rel="noopener noreferrer">${r.url}</a>` : ''}
      </div>
      <div class="card-bottom" style="display:flex;align-items:center;justify-content:space-between;gap:8px">
        <span style="font-family:var(--font-mono);font-size:10px;color:var(--text2)">${timeStr}</span>
        ${visitBtn}
      </div>`;
    resultsGrid.appendChild(card);
  });
}

// Returns a styled visit/check/verify button per status
// Uses onclick+window.open for guaranteed new-tab navigation
function buildVisitBtn(url, status) {
  const safeUrl = url.replace(/"/g, '&quot;');
  const open = `onclick="window.open('${safeUrl}','_blank','noopener,noreferrer')"`;

  if (status === 'FOUND') {
    return `<button class="card-link-btn" ${open} title="Open profile in new tab">↗ VISIT</button>`;
  }
  if (status === 'UNCERTAIN') {
    return `<button class="card-link-btn" ${open} title="Result uncertain — verify manually"
      style="border-color:rgba(255,214,0,0.5);color:#ffd600;background:rgba(255,214,0,0.08);cursor:pointer">↗ VERIFY</button>`;
  }
  if (status === 'BLOCKED') {
    return `<button class="card-link-btn" ${open} title="Platform blocked scan — check manually"
      style="border-color:rgba(255,149,0,0.4);color:var(--orange);background:rgba(255,149,0,0.08);cursor:pointer">↗ CHECK</button>`;
  }
  if (status === 'NOT_FOUND') {
    return `<button class="card-link-btn" ${open} title="Not found — check manually to confirm"
      style="border-color:rgba(255,59,92,0.3);color:var(--text2);background:rgba(255,59,92,0.05);cursor:pointer">↗ CHECK</button>`;
  }
  return '';
}


// Update a single card in-place (no full redraw during live scan)
function updateCard(result) {
  const id = 'card-' + result.name.replace(/\W/g, '-');
  const stRaw = result.status;
  const stCls = stRaw.toLowerCase().replace('_', '-').replace('not-found', 'notfound');
  const timeStr = result.ms != null ? result.ms + 'ms' : '';
  const httpChip = result.httpStatus
    ? `<span style="font-family:var(--font-mono);font-size:9px;color:var(--text2);padding:2px 6px;border-radius:4px;background:rgba(0,0,0,.3)">HTTP ${result.httpStatus}</span>`
    : '';
  const visitBtn = result.url ? buildVisitBtn(result.url, stRaw) : '';

  const el = document.getElementById(id);
  if (!el) return;
  el.className = 'result-card ' + stCls;
  el.innerHTML = `
    <div class="card-top">
      <div class="card-icon">${result.emoji}</div>
      <div class="card-meta">
        <div class="card-platform">${result.name}</div>
        <div class="card-category">${result.cat.toUpperCase()}</div>
      </div>
      <div class="card-status ${stCls}">
        <span class="status-dot ${stCls}"></span>
        ${stRaw.replace('_', ' ')}
      </div>
    </div>
    <div class="card-url">
      ${result.url ? `<a href="${result.url}" target="_blank" rel="noopener noreferrer">${result.url}</a>` : ''}
    </div>
    <div class="card-bottom" style="display:flex;align-items:center;justify-content:space-between;gap:8px">
      <span style="font-family:var(--font-mono);font-size:10px;color:var(--text2)">${timeStr}</span>
      ${visitBtn}
    </div>`;
}

// ─── SCAN ─────────────────────────────────────────────────────
async function startScan() {
  const username = usernameInput.value.trim().replace(/^@/, '');
  if (!username) { usernameInput.focus(); return; }

  // Stop existing scan
  if (scanning) {
    if (evtSource) { evtSource.close(); evtSource = null; }
    stopScan('● SCAN CANCELLED', 'status-idle');
    return;
  }

  // Check server is reachable
  statusLine.className = 'status-scanning';
  statusLine.textContent = '● CONNECTING TO BACKEND...';

  const online = await checkServer();
  if (!online) {
    statusLine.className = 'status-idle';
    statusLine.textContent = '⚠ SERVER OFFLINE — run: node server.js';
    return;
  }

  // Reset UI
  scanResults = [];
  graphNodes = [];
  const toRemove = [];
  graphGroup.children.forEach((c, i) => { if (i > 1) toRemove.push(c); });
  toRemove.forEach(c => graphGroup.remove(c));

  scanning = true;
  scanBtn.classList.add('scanning');
  scanBtnText.textContent = 'STOP';
  scanBtn.querySelector('.scan-btn-icon').textContent = '◼';
  filterTabs.style.display = 'none';
  resultsSummary.style.display = 'none';
  progressWrap.style.display = 'flex';
  statusLine.className = 'status-scanning';
  statusLine.textContent = '● SCANNING — TARGET: @' + username.toUpperCase();
  graphSub.textContent = 'NODES APPEAR ON DETECTION';

  scanStartTime = performance.now();
  timerInterval = setInterval(() => {
    timerDisplay.textContent = ((performance.now() - scanStartTime) / 1000).toFixed(1) + 's';
  }, 100);

  // Open SSE stream
  const url = `${API}/api/scan/${encodeURIComponent(username)}?token=${encodeURIComponent(token)}`;
  evtSource = new EventSource(url);

  evtSource.addEventListener('start', e => {
    const data = JSON.parse(e.data);
    totalPlatforms = data.total;
    // Insert stub scanning cards
    for (let i = 0; i < data.total; i++) {
      scanResults.push({ name: '...', cat: '', emoji: '⚙', url: '', status: 'SCANNING', ms: null });
    }
    filterTabs.style.display = 'flex';
    resultsSummary.style.display = 'flex';
    progressText.textContent = '0 / ' + data.total;
    // Will be populated by result events
    renderResults();
  });

  let resultIdx = 0;
  evtSource.addEventListener('result', e => {
    const data = JSON.parse(e.data);

    // Replace or update the scanning stub at this index
    if (resultIdx < scanResults.length) {
      scanResults[resultIdx] = data;
    } else {
      scanResults.push(data);
    }
    resultIdx++;

    // Add 3D node for found/uncertain/blocked
    if (data.status === 'FOUND') addGraphNode(0x00ff88);
    if (data.status === 'UNCERTAIN') addGraphNode(0xffd600);
    if (data.status === 'BLOCKED') addGraphNode(0xff9500);

    // Update progress
    const pct = Math.round((data.done / data.total) * 100);
    progressFill.style.width = pct + '%';
    progressText.textContent = data.done + ' / ' + data.total;

    // Re-render (or targeted update if visible)
    renderResults();
    updateSummary();
  });

  evtSource.addEventListener('complete', e => {
    const data = JSON.parse(e.data);
    evtSource.close(); evtSource = null;
    const found = scanResults.filter(r => r.status === 'FOUND').length;
    stopScan(`● SCAN COMPLETE — ${found} ACCOUNTS FOUND`, 'status-done');
  });

  evtSource.onerror = () => {
    if (evtSource) { evtSource.close(); evtSource = null; }
    if (scanning) {
      stopScan('● CONNECTION ERROR — check server is running', 'status-idle');
    }
  };
}

function stopScan(message, cls) {
  scanning = false;
  clearInterval(timerInterval);
  scanBtn.classList.remove('scanning');
  scanBtnText.textContent = 'SCAN';
  scanBtn.querySelector('.scan-btn-icon').textContent = '▶';
  progressWrap.style.display = 'none';
  timerDisplay.textContent = '';
  statusLine.className = cls;
  statusLine.textContent = message;
  renderResults();
  updateSummary();
}

// ─── EVENTS ───────────────────────────────────────────────────
scanBtn.addEventListener('click', startScan);
usernameInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    activeFilter = tab.dataset.cat;
    renderResults();
  });
});
