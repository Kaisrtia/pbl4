/**
 * ==============================================================================
 * GOD-VIEW SIEM & FIREWALL MONITOR - CLIENT APP
 * Real-time WebSocket Ingestion, Canvas Particle Stream, Defense Controls
 * ==============================================================================
 */

// State Management
const state = {
  logs: [],
  maxLogs: 300,
  defenseL3Active: false,
  autoScroll: true,
  filterTag: 'ALL',
  searchQuery: '',
  selectedLog: null,
  socket: null,
  rttLatency: null,
  warningTimer: null,
};

// ==========================================
// 1. INITIALIZATION & SOCKET.IO SETUP
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
  initSocket();
  initCanvas();
  initEventListeners();
});

function initSocket() {
  const socketUrl = window.location.origin;
  state.socket = io(socketUrl, {
    transports: ['websocket', 'polling'],
  });

  const led = document.getElementById('socket-led');
  const statusText = document.getElementById('socket-status-text');

  state.socket.on('connect', () => {
    led.className = 'pulse-led connected';
    statusText.textContent = `CONNECTED :${window.location.port || '4000'}`;
    startRttHeartbeat();
  });

  state.socket.on('disconnect', () => {
    led.className = 'pulse-led disconnected';
    statusText.textContent = 'DISCONNECTED';
    document.getElementById('rtt-value').textContent = '-- ms';
  });

  // Nhận trạng thái ban đầu và lịch sử khi vừa tải trang
  state.socket.on('INITIAL_STATE', (data) => {
    if (data.history && Array.isArray(data.history)) {
      state.logs = data.history;
      renderTable();
      updateBufferCount();
    }
    if (typeof data.defense_l3_state === 'boolean') {
      updateDefenseUI(data.defense_l3_state);
    }
    if (data.metrics) {
      updateMetricsUI(data.metrics);
    }
  });

  // Nhận bản tin Telemetry thời gian thực từ Target App
  state.socket.on('GOD_VIEW_UPDATE', (payload) => {
    const { log, metrics, defense_l3_state } = payload;
    handleIncomingTelemetry(log);

    if (metrics) updateMetricsUI(metrics);
    if (typeof defense_l3_state === 'boolean') updateDefenseUI(defense_l3_state);
  });

  // Nhận sự kiện đồng bộ khi khiên phòng thủ thay đổi
  state.socket.on('DEFENSE_TOGGLED', (payload) => {
    updateDefenseUI(payload.defense_l3_state);
  });

  // Nhận sự kiện xóa rỗng bộ đệm
  state.socket.on('GOD_VIEW_RESET', () => {
    state.logs = [];
    renderTable();
    updateBufferCount();
    clearParticles();
  });

  // Xử lý đo độ trễ RTT
  state.socket.on('pong_rtt', (data) => {
    const rtt = Date.now() - data.client_time;
    state.rttLatency = rtt;
    document.getElementById('rtt-value').textContent = `${rtt} ms`;
  });
}

function startRttHeartbeat() {
  setInterval(() => {
    if (state.socket && state.socket.connected) {
      state.socket.emit('ping_rtt', { client_time: Date.now() });
    }
  }, 2500);
}

// ==========================================
// 2. INCOMING TELEMETRY & ALERT HANDLING
// ==========================================
function handleIncomingTelemetry(log) {
  state.logs.push(log);
  if (state.logs.length > state.maxLogs) {
    state.logs.shift();
  }

  // Cập nhật số lượng bản tin
  updateBufferCount();

  // Bắn hạt vào Canvas Topology Stream
  spawnPacketParticles(log);

  // Hiển thị Banner cảnh báo nếu là tấn công
  const isAttack = Boolean(log.is_suspicious || (log.attack_tag && log.attack_tag !== 'NORMAL'));
  if (isAttack) {
    triggerWarningBanner(log);
  }

  // Thêm dòng mới vào bảng log
  appendTableRow(log);
}

function updateBufferCount() {
  document.getElementById('buffer-count-badge').textContent = `${state.logs.length} / ${state.maxLogs}`;
  document.getElementById('table-record-count').textContent = `${state.logs.length} entries`;
}

function triggerWarningBanner(log) {
  const banner = document.getElementById('warning-banner');
  const details = document.getElementById('warning-details');

  const tag = log.attack_tag || 'SUSPICIOUS_ACTIVITY';
  details.textContent = `${tag} DETECTED FROM ${log.client_ip} -> ${log.endpoint} [Status: ${log.status_code}]`;
  banner.classList.remove('hidden');

  if (state.warningTimer) clearTimeout(state.warningTimer);
  state.warningTimer = setTimeout(() => {
    banner.classList.add('hidden');
  }, 6000);
}

// ==========================================
// 3. DEFENSE SHIELD & SYSTEM METRICS
// ==========================================
function updateDefenseUI(isActive) {
  state.defenseL3Active = isActive;

  const pill = document.getElementById('defense-state-pill');
  const btn = document.getElementById('btn-toggle-defense');
  const shieldAura = document.getElementById('shield-aura');
  const shieldBadge = document.getElementById('shield-badge-indicator');
  const btnText = document.getElementById('defense-btn-text');

  if (isActive) {
    pill.textContent = 'ACTIVE';
    pill.className = 'pill-active';
    btn.className = 'cyber-btn btn-defense-toggle active';
    btnText.textContent = 'DISABLE L3 DEFENSE';
    shieldAura.classList.remove('inactive');
    shieldBadge.textContent = 'SHIELD: ACTIVE';
    shieldBadge.className = 'badge badge-shield';
  } else {
    pill.textContent = 'BYPASSED';
    pill.className = 'pill-inactive';
    btn.className = 'cyber-btn btn-defense-toggle';
    btnText.textContent = 'ENABLE L3 DEFENSE';
    shieldAura.classList.add('inactive');
    shieldBadge.textContent = 'SHIELD: BYPASSED';
    shieldBadge.className = 'badge badge-shield inactive';
  }
}

function updateMetricsUI(metrics) {
  document.getElementById('metric-established').textContent = metrics.established;
  document.getElementById('metric-syn-recv').textContent = metrics.syn_recv;
  document.getElementById('metric-time-wait').textContent = metrics.time_wait;

  // Cập nhật thanh đo phần trăm
  document.getElementById('meter-established-fill').style.width = `${Math.min(100, (metrics.established / 80) * 100)}%`;
  document.getElementById('meter-syn-recv-fill').style.width = `${Math.min(100, (metrics.syn_recv / 150) * 100)}%`;
  document.getElementById('meter-time-wait-fill').style.width = `${Math.min(100, (metrics.time_wait / 40) * 100)}%`;
}

// ==========================================
// 4. CANVAS TOPOLOGY PARTICLE ENGINE
// ==========================================
let canvas, ctx;
let particles = [];
let shieldImpactSparks = [];
let floatingLabels = [];

function initCanvas() {
  canvas = document.getElementById('topology-canvas');
  ctx = canvas.getContext('2d');

  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);

  // Vòng lặp animation 60 FPS
  requestAnimationFrame(renderCanvasLoop);
}

function resizeCanvas() {
  const wrapper = document.getElementById('canvas-wrapper');
  canvas.width = wrapper.clientWidth;
  canvas.height = wrapper.clientHeight;
}

function clearParticles() {
  particles = [];
  shieldImpactSparks = [];
  floatingLabels = [];
}

/**
 * Tạo hạt di chuyển dựa trên bản tin Telemetry
 */
function spawnPacketParticles(log) {
  const isAttack = Boolean(log.is_suspicious || (log.attack_tag && log.attack_tag !== 'NORMAL'));
  const clientNode = document.getElementById('node-client');
  const serverNode = document.getElementById('node-server');
  const hackerNode = document.getElementById('node-hacker');
  const wrapper = document.getElementById('canvas-wrapper');

  const wrapRect = wrapper.getBoundingClientRect();
  const clientRect = clientNode.getBoundingClientRect();
  const serverRect = serverNode.getBoundingClientRect();
  const hackerRect = hackerNode.getBoundingClientRect();

  // Tọa độ tâm các Node
  const clientPos = {
    x: clientRect.left - wrapRect.left + clientRect.width / 2,
    y: clientRect.top - wrapRect.top + clientRect.height / 2,
  };
  const serverPos = {
    x: serverRect.left - wrapRect.left + serverRect.width / 2,
    y: serverRect.top - wrapRect.top + serverRect.height / 2,
  };
  const hackerPos = {
    x: hackerRect.left - wrapRect.left + hackerRect.width / 2,
    y: hackerRect.top - wrapRect.top + hackerRect.height / 2,
  };

  if (isAttack) {
    // Kẻ tấn công bắn hạt đỏ sang Server
    const particleCount = log.attack_tag === 'SYN_FLOOD' || log.attack_tag === 'HEAVY_DOS' ? 18 : 8;
    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: hackerPos.x,
        y: hackerPos.y + (Math.random() * 20 - 10),
        targetX: serverPos.x,
        targetY: serverPos.y + (Math.random() * 20 - 10),
        startX: hackerPos.x,
        startY: hackerPos.y,
        progress: 0,
        speed: 0.015 + Math.random() * 0.015,
        type: 'ATTACK',
        color: '#ff003c',
        size: 3 + Math.random() * 2.5,
        tag: log.attack_tag || 'ATTACK',
        spread: (Math.random() - 0.5) * 40,
      });
    }

    // Hiệu ứng nhấp nháy Hacker Node
    hackerNode.classList.add('compromised');
    setTimeout(() => hackerNode.classList.remove('compromised'), 500);
  } else {
    // Client gửi hạt xanh lá/cyan sang Server
    for (let i = 0; i < 4; i++) {
      particles.push({
        x: clientPos.x,
        y: clientPos.y + (Math.random() * 16 - 8),
        targetX: serverPos.x,
        targetY: serverPos.y + (Math.random() * 16 - 8),
        startX: clientPos.x,
        startY: clientPos.y,
        progress: 0,
        speed: 0.012 + Math.random() * 0.01,
        type: 'NORMAL',
        color: '#00ff66',
        size: 2.5 + Math.random() * 2,
        tag: 'NORMAL',
        spread: (Math.random() - 0.5) * 30,
      });
    }
  }
}

function renderCanvasLoop() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Vẽ các đường mạch kết nối (Circuit Connection Paths)
  drawNetworkLinks();

  // Cập nhật và vẽ các hạt di chuyển
  updateAndDrawParticles();

  // Cập nhật và vẽ tia lửa va chạm khiên
  updateAndDrawSparks();

  // Cập nhật text nổi (+BLOCKED L3)
  updateAndDrawFloatingLabels();

  requestAnimationFrame(renderCanvasLoop);
}

function drawNetworkLinks() {
  const clientNode = document.getElementById('node-client');
  const serverNode = document.getElementById('node-server');
  const hackerNode = document.getElementById('node-hacker');
  const wrapper = document.getElementById('canvas-wrapper');

  if (!clientNode || !serverNode || !hackerNode) return;

  const wrapRect = wrapper.getBoundingClientRect();
  const cR = clientNode.getBoundingClientRect();
  const sR = serverNode.getBoundingClientRect();
  const hR = hackerNode.getBoundingClientRect();

  const cX = cR.left - wrapRect.left + cR.width / 2;
  const cY = cR.top - wrapRect.top + cR.height / 2;
  const sX = sR.left - wrapRect.left + sR.width / 2;
  const sY = sR.top - wrapRect.top + sR.height / 2;
  const hX = hR.left - wrapRect.left + hR.width / 2;
  const hY = hR.top - wrapRect.top + hR.height / 2;

  // Đường link Client -> Server
  ctx.beginPath();
  ctx.strokeStyle = 'rgba(0, 255, 102, 0.15)';
  ctx.lineWidth = 2;
  ctx.setLineDash([4, 6]);
  ctx.moveTo(cX, cY);
  ctx.quadraticCurveTo((cX + sX) / 2, cY - 40, sX, sY);
  ctx.stroke();

  // Đường link Hacker -> Server
  ctx.beginPath();
  ctx.strokeStyle = 'rgba(255, 0, 60, 0.2)';
  ctx.lineWidth = 2;
  ctx.moveTo(hX, hY);
  ctx.quadraticCurveTo((hX + sX) / 2, hY - 40, sX, sY);
  ctx.stroke();
  ctx.setLineDash([]);
}

function updateAndDrawParticles() {
  for (let i = particles.length - 1; i >= 0; i--) {
    const p = particles[i];
    p.progress += p.speed;

    // Đường cong Bezier
    const cpY = p.startY - 40 + p.spread;
    const cpX = (p.startX + p.targetX) / 2;

    const t = p.progress;
    p.x = (1 - t) * (1 - t) * p.startX + 2 * (1 - t) * t * cpX + t * t * p.targetX;
    p.y = (1 - t) * (1 - t) * p.startY + 2 * (1 - t) * t * cpY + t * t * p.targetY;

    // KIỂM TRA VA CHẠM KHIÊN CHẮN (SHIELD BARRIER INTERACTION)
    // Khiên nằm cách tâm server về phía Hacker (~110px)
    const shieldDistanceThreshold = 115;
    const distToServer = Math.hypot(p.targetX - p.x, p.targetY - p.y);

    if (p.type === 'ATTACK' && state.defenseL3Active && distToServer <= shieldDistanceThreshold) {
      // Hạt tấn công va vào khiên chắn -> VA CHẠM & BỊ DỘI NGƯỢC (DROP)
      spawnShieldDeflection(p.x, p.y);
      particles.splice(i, 1);
      continue;
    }

    // Đã chạm Server
    if (p.progress >= 1) {
      if (p.type === 'ATTACK' && !state.defenseL3Active) {
        // Tấn công trúng đích khi khiên TẮT -> Rung đỏ máy chủ
        triggerServerCompromisedVisual();
      }
      particles.splice(i, 1);
      continue;
    }

    // Vẽ hạt phát sáng
    ctx.save();
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
    ctx.fillStyle = p.color;
    ctx.shadowColor = p.color;
    ctx.shadowBlur = 12;
    ctx.fill();
    ctx.restore();
  }
}

function spawnShieldDeflection(x, y) {
  // Tạo tia lửa dội ngược
  for (let i = 0; i < 8; i++) {
    shieldImpactSparks.push({
      x,
      y,
      vx: (Math.random() * 4 + 2), // Bật ngược về bên phải (hướng Hacker)
      vy: (Math.random() - 0.5) * 6,
      color: '#00f0ff',
      alpha: 1,
      size: Math.random() * 2.5 + 1.5,
    });
  }

  // Thêm nhãn chữ nổi +BLOCKED L3
  if (Math.random() > 0.4) {
    floatingLabels.push({
      x: x + 10,
      y: y - 10,
      text: '🛡️ BLOCKED [L3]',
      alpha: 1,
      color: '#00f0ff',
    });
  }
}

function triggerServerCompromisedVisual() {
  const server = document.getElementById('node-server');
  server.classList.add('compromised');
  setTimeout(() => server.classList.remove('compromised'), 400);
}

function updateAndDrawSparks() {
  for (let i = shieldImpactSparks.length - 1; i >= 0; i--) {
    const s = shieldImpactSparks[i];
    s.x += s.vx;
    s.y += s.vy;
    s.alpha -= 0.04;

    if (s.alpha <= 0) {
      shieldImpactSparks.splice(i, 1);
      continue;
    }

    ctx.save();
    ctx.beginPath();
    ctx.arc(s.x, s.y, s.size, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(0, 240, 255, ${s.alpha})`;
    ctx.shadowColor = '#00f0ff';
    ctx.shadowBlur = 8;
    ctx.fill();
    ctx.restore();
  }
}

function updateAndDrawFloatingLabels() {
  for (let i = floatingLabels.length - 1; i >= 0; i--) {
    const l = floatingLabels[i];
    l.y -= 0.8;
    l.alpha -= 0.02;

    if (l.alpha <= 0) {
      floatingLabels.splice(i, 1);
      continue;
    }

    ctx.save();
    ctx.font = 'bold 11px Orbitron';
    ctx.fillStyle = `rgba(0, 240, 255, ${l.alpha})`;
    ctx.shadowColor = '#00f0ff';
    ctx.shadowBlur = 8;
    ctx.fillText(l.text, l.x, l.y);
    ctx.restore();
  }
}

// ==========================================
// 5. PACKET TABLE RENDERING & FILTERING
// ==========================================
function renderTable() {
  const tbody = document.getElementById('packet-table-body');
  tbody.innerHTML = '';

  const filtered = state.logs.filter((log) => matchFilter(log));

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr class="empty-row">
        <td colspan="9">No packets match current filter (${state.filterTag}).</td>
      </tr>
    `;
    return;
  }

  // Duyệt từ mới nhất tới cũ nhất
  for (let i = filtered.length - 1; i >= 0; i--) {
    const tr = createTableRow(filtered[i]);
    tbody.appendChild(tr);
  }
}

function appendTableRow(log) {
  if (!matchFilter(log)) return;

  const tbody = document.getElementById('packet-table-body');
  const emptyRow = tbody.querySelector('.empty-row');
  if (emptyRow) emptyRow.remove();

  const tr = createTableRow(log);
  tbody.insertBefore(tr, tbody.firstChild);

  // Giới hạn số hàng trên DOM để tránh lag
  if (tbody.children.length > state.maxLogs) {
    tbody.removeChild(tbody.lastChild);
  }

  // Tự động cuộn lên đầu nếu Auto-scroll bật
  if (state.autoScroll) {
    const container = document.getElementById('table-scroll-container');
    container.scrollTop = 0;
  }
}

function createTableRow(log) {
  const tr = document.createElement('tr');
  const isAttack = Boolean(log.is_suspicious || (log.attack_tag && log.attack_tag !== 'NORMAL'));
  if (isAttack) {
    tr.className = 'attack-row';
  }

  // Định dạng thời gian
  let timeStr = '--:--:--';
  if (log.timestamp) {
    const d = new Date(log.timestamp);
    timeStr = d.toTimeString().split(' ')[0] + '.' + String(d.getMilliseconds()).padStart(3, '0');
  }

  // Class cho HTTP Status
  let statusClass = 'status-2xx';
  if (log.status_code >= 500) statusClass = 'status-5xx';
  else if (log.status_code >= 400) statusClass = 'status-4xx';
  else if (log.status_code >= 300) statusClass = 'status-3xx';

  // Định dạng tóm tắt payload
  let payloadStr = '{}';
  if (typeof log.payload_summary === 'object' && log.payload_summary !== null) {
    payloadStr = JSON.stringify(log.payload_summary);
  } else if (typeof log.payload_summary === 'string') {
    payloadStr = log.payload_summary;
  }

  const tag = log.attack_tag || (isAttack ? 'ATTACK' : 'NORMAL');

  tr.innerHTML = `
    <td>${timeStr}</td>
    <td><span class="method-badge method-${log.method}">${log.method}</span></td>
    <td title="${log.endpoint}"><strong>${log.endpoint}</strong></td>
    <td><span class="status-badge ${statusClass}">${log.status_code}</span></td>
    <td>${log.response_time} ms</td>
    <td><code>${log.client_ip}</code></td>
    <td><span class="tag-badge tag-${tag}">${tag}</span></td>
    <td>${log.defense_action || (state.defenseL3Active ? 'sanitized' : 'allowed')}</td>
    <td title="${escapeHtml(payloadStr)}">${truncate(escapeHtml(payloadStr), 25)}</td>
  `;

  // Nhấp vào hàng để xem JSON đầy đủ
  tr.addEventListener('click', () => {
    openInspectorModal(log);
  });

  return tr;
}

function matchFilter(log) {
  const isAttack = Boolean(log.is_suspicious || (log.attack_tag && log.attack_tag !== 'NORMAL'));
  const tag = log.attack_tag || (isAttack ? 'ATTACK' : 'NORMAL');

  // Lọc theo dropdown tag
  if (state.filterTag === 'ATTACK_ONLY' && !isAttack) return false;
  if (state.filterTag === 'NORMAL' && isAttack) return false;
  if (state.filterTag !== 'ALL' && state.filterTag !== 'ATTACK_ONLY' && tag !== state.filterTag) return false;

  // Lọc theo từ khóa tìm kiếm
  if (state.searchQuery) {
    const q = state.searchQuery.toLowerCase();
    const str = `${log.endpoint} ${log.method} ${log.client_ip} ${tag} ${log.status_code}`.toLowerCase();
    return str.includes(q);
  }

  return true;
}

// ==========================================
// 6. EVENT LISTENERS & USER ACTIONS
// ==========================================
function initEventListeners() {
  // Nút Toggle Defense
  document.getElementById('btn-toggle-defense').addEventListener('click', () => {
    toggleDefense();
  });

  // Nút Reset State
  document.getElementById('btn-reset-state').addEventListener('click', () => {
    if (confirm('Bạn có chắc muốn xóa sạch toàn bộ bản tin Telemetry trong Ring Buffer?')) {
      fetch('/api/telemetry/clear', { method: 'DELETE' });
    }
  });

  // Nút Auto-scroll
  const autoScrollBtn = document.getElementById('btn-toggle-autoscroll');
  autoScrollBtn.addEventListener('click', () => {
    state.autoScroll = !state.autoScroll;
    autoScrollBtn.textContent = `AUTO-SCROLL [${state.autoScroll ? 'ON' : 'OFF'}]`;
    autoScrollBtn.classList.toggle('active', state.autoScroll);
  });

  // Nút Clear Table (View Only)
  document.getElementById('btn-clear-table').addEventListener('click', () => {
    document.getElementById('packet-table-body').innerHTML = `
      <tr class="empty-row">
        <td colspan="9">View cleared. New incoming packets will be appended.</td>
      </tr>
    `;
  });

  // Ô tìm kiếm
  document.getElementById('log-search-input').addEventListener('input', (e) => {
    state.searchQuery = e.target.value.trim();
    renderTable();
  });

  // Dropdown lọc Tag
  document.getElementById('log-filter-tag').addEventListener('change', (e) => {
    state.filterTag = e.target.value;
    renderTable();
  });

  // Tắt Warning banner
  document.getElementById('btn-dismiss-warning').addEventListener('click', () => {
    document.getElementById('warning-banner').classList.add('hidden');
  });

  // Đóng Modal Inspector
  document.getElementById('btn-close-modal').addEventListener('click', closeModal);
  document.querySelector('.modal-backdrop').addEventListener('click', closeModal);

  // Quick Demo Traffic Buttons
  document.getElementById('btn-demo-ping').addEventListener('click', () => simulateTraffic('ping'));
  document.getElementById('btn-demo-user').addEventListener('click', () => simulateTraffic('normal-login'));
  document.getElementById('btn-demo-sqli').addEventListener('click', () => simulateTraffic('sqli'));
  document.getElementById('btn-demo-dos').addEventListener('click', () => simulateTraffic('dos'));
}

async function toggleDefense() {
  try {
    const res = await fetch('/api/defense/toggle', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) });
    const data = await res.json();
    if (typeof data.defense_l3_app === 'boolean') {
      updateDefenseUI(data.defense_l3_app);
    }
  } catch (e) {
    // Dự phòng qua socket nếu HTTP lỗi
    if (state.socket) state.socket.emit('TOGGLE_DEFENSE');
  }
}

// Modal Inspector
function openInspectorModal(log) {
  document.getElementById('modal-json-content').textContent = JSON.stringify(log, null, 2);
  document.getElementById('inspector-modal').classList.remove('hidden');
}

function closeModal() {
  document.getElementById('inspector-modal').classList.add('hidden');
}

// ==========================================
// 7. TRAFFIC SIMULATOR (DEMO ASSISTANT)
// ==========================================
async function simulateTraffic(type) {
  let logPayload = null;

  if (type === 'ping') {
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'GET',
      endpoint: '/api/ping',
      status_code: 200,
      response_time: Math.floor(Math.random() * 8) + 2,
      client_ip: '192.168.1.10',
      payload_summary: { query: { t: Date.now() }, echo: 'ping-check' },
      attack_tag: 'NORMAL',
      is_suspicious: false,
    };
  } else if (type === 'normal-login') {
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'POST',
      endpoint: '/api/login',
      status_code: 200,
      response_time: Math.floor(Math.random() * 15) + 10,
      client_ip: '192.168.1.10',
      payload_summary: { body_preview: { username: 'admin', password: '******' } },
      attack_tag: 'NORMAL',
      is_suspicious: false,
    };
  } else if (type === 'sqli') {
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'POST',
      endpoint: '/api/login',
      status_code: state.defenseL3Active ? 401 : 200,
      response_time: Math.floor(Math.random() * 25) + 8,
      client_ip: '192.168.1.200',
      payload_summary: {
        body_preview: { username: "admin' --", password: '******' },
        detected_patterns: ['SQL_INJECTION_PATTERN'],
      },
      attack_tag: 'SQL_INJECTION',
      is_suspicious: true,
      defense_action: state.defenseL3Active ? 'sanitized' : 'allowed',
    };
  } else if (type === 'dos') {
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'GET',
      endpoint: '/api/heavy-load?iterations=500000',
      status_code: state.defenseL3Active ? 429 : 200,
      response_time: Math.floor(Math.random() * 300) + 150,
      client_ip: '192.168.1.200',
      payload_summary: { query: { iterations: 500000 } },
      attack_tag: 'HEAVY_DOS',
      is_suspicious: true,
      defense_action: state.defenseL3Active ? 'rate_limited' : 'allowed',
    };
  }

  if (logPayload) {
    try {
      await fetch('/api/telemetry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(logPayload),
      });
    } catch (e) {
      // Fallback local visual
      handleIncomingTelemetry(logPayload);
    }
  }
}

// Utility Helpers
function truncate(str, max) {
  if (!str) return '';
  return str.length > max ? str.substring(0, max) + '...' : str;
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
