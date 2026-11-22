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
  defenseL3Active: null,
  attackEvents: [],
  autoScroll: true,
  filterTag: 'ALL',
  searchQuery: '',
  selectedLog: null,
  socket: null,
  rttLatency: null,
  warningTimer: null,
  rstBannerTimer: null,
  synPeak: 0,
  networkState: {
    mitm_active: false,
    arp_table: [
      { ip: '172.20.0.10', mac: '02:42:ac:14:00:0a', expected_mac: '02:42:ac:14:00:0a', iface: 'eth0', role: 'CLIENT', spoofed: false },
      { ip: '172.20.0.20', mac: '02:42:ac:14:00:14', expected_mac: '02:42:ac:14:00:14', iface: 'eth0', role: 'TARGET_SERVER', spoofed: false },
      { ip: '172.20.0.66', mac: '02:42:ac:14:00:42', expected_mac: '02:42:ac:14:00:42', iface: 'eth0', role: 'HACKER', spoofed: false },
    ],
    sniffed_packets: [],
    rst_injection: {
      active: false,
      disrupted_sessions: 0,
      last_rst_at: null,
      last_seq_num: null,
      victim_ip: '172.20.0.10',
      target_ip: '172.20.0.20',
    },
    syn_history: Array(16).fill(0),
  },
};

// ==========================================
// 1. INITIALIZATION & SOCKET.IO SETUP
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
  updateDefenseUI(null);
  updateNetworkStateUI(state.networkState);
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
    updateDefenseUI(null);
    document.getElementById('rtt-value').textContent = '-- ms';
  });

  // Nhận trạng thái ban đầu và lịch sử khi vừa tải trang
  state.socket.on('INITIAL_STATE', (data) => {
    if (data.history && Array.isArray(data.history)) {
      state.logs = data.history;
      renderTable();
      updateBufferCount();
    }
    updateDefenseUI(data.defense_l3_state);
    state.attackEvents = data.attack_events || [];
    renderAttackEvents();
    for (const [node, ip] of Object.entries(data.nodes || {})) {
      const element = document.querySelector(`#node-${node === 'target' ? 'server' : node === 'attacker' ? 'hacker' : node} .node-ip`);
      if (element) element.textContent = ip;
    }
    if (data.metrics) {
      updateMetricsUI(data.metrics);
    }
    if (data.network_state) {
      updateNetworkStateUI(data.network_state, data.metrics);
    }
  });

  // Nhận bản tin Telemetry thời gian thực từ Target App
  state.socket.on('GOD_VIEW_UPDATE', (payload) => {
    const { log, metrics, network_state, defense_l3_state } = payload;
    if (network_state) {
      updateNetworkStateUI(network_state, metrics);
    }
    handleIncomingTelemetry(log);

    if (metrics) updateMetricsUI(metrics);
    updateDefenseUI(defense_l3_state);
  });

  // Nhận cập nhật trạng thái mạng L2/L4 trực tiếp (ARP, MitM, SYN, RST)
  state.socket.on('NETWORK_STATE_UPDATE', (payload) => {
    if (payload.metrics) updateMetricsUI(payload.metrics);
    if (payload.network_state) updateNetworkStateUI(payload.network_state, payload.metrics);
  });

  // Nhận sự kiện đồng bộ khi khiên phòng thủ thay đổi
  state.socket.on('DEFENSE_TOGGLED', (payload) => {
    updateDefenseUI(payload.defense_l3_state);
  });

  state.socket.on('ATTACK_EVENT', (event) => {
    if (!state.attackEvents.some(item => item.event_id === event.event_id)) state.attackEvents.push(event);
    state.attackEvents = state.attackEvents.slice(-300);
    renderAttackEvents();
  });
  state.socket.on('DEFENSE_ERROR', payload => {
    document.getElementById('defense-error').textContent = payload.message;
  });

  // Nhận sự kiện xóa rỗng bộ đệm
  state.socket.on('GOD_VIEW_RESET', (payload) => {
    state.logs = [];
    state.attackEvents = [];
    state.synPeak = 0;
    if (payload && payload.metrics) updateMetricsUI(payload.metrics);
    if (payload && payload.network_state) updateNetworkStateUI(payload.network_state, payload.metrics);
    renderAttackEvents();
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

  if (typeof isActive !== 'boolean') {
    pill.textContent = 'UNKNOWN';
    pill.className = 'pill-inactive';
    btn.className = 'cyber-btn btn-defense-toggle';
    btnText.textContent = 'CHECK TARGET STATE';
    shieldAura.classList.add('inactive');
    shieldBadge.textContent = 'SHIELD: UNKNOWN';
    shieldBadge.className = 'badge badge-shield inactive';
    return;
  }
  document.getElementById('defense-error').textContent = '';
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

  if (typeof metrics.syn_recv === 'number' && metrics.syn_recv > state.synPeak) {
    state.synPeak = metrics.syn_recv;
  }
  renderSynBarChart(state.networkState.syn_history, metrics.syn_recv);
}

// ==========================================
// 3B. W3-T1: L2/L4 NETWORK ATTACK VISUALIZATION (ARP, MITM, SYN CHART, RST)
// ==========================================
function updateNetworkStateUI(netState, metrics) {
  if (!netState) return;
  state.networkState = {
    ...state.networkState,
    ...netState,
  };

  const mitmBadge = document.getElementById('mitm-badge-indicator');
  const hackerNode = document.getElementById('node-hacker');
  const hackerStatus = document.getElementById('hacker-status');

  if (state.networkState.mitm_active) {
    mitmBadge.classList.remove('hidden');
    hackerNode.classList.add('mitm-active');
    hackerStatus.textContent = '⚠️ MITM INTERCEPTING';
  } else {
    mitmBadge.classList.add('hidden');
    hackerNode.classList.remove('mitm-active');
    hackerStatus.textContent = 'STANDBY';
  }

  renderArpCacheTable(state.networkState.arp_table, state.networkState.mitm_active);
  renderMitmSnifferWindow(state.networkState.sniffed_packets, state.networkState.mitm_active);
  renderRstMonitor(state.networkState.rst_injection);
  const currentSyn = metrics && typeof metrics.syn_recv === 'number'
    ? metrics.syn_recv
    : (state.networkState.syn_history[state.networkState.syn_history.length - 1] || 0);
  if (currentSyn > state.synPeak) state.synPeak = currentSyn;
  renderSynBarChart(state.networkState.syn_history, currentSyn);
}

function renderArpCacheTable(arpTable, mitmActive) {
  const tbody = document.getElementById('arp-table-body');
  const card = document.getElementById('arp-cache-card');
  const badge = document.getElementById('arp-status-badge');
  const alertBox = document.getElementById('arp-poison-alert');
  const spoofedMacEl = document.getElementById('spoofed-mac-value');
  if (!tbody) return;

  const hasSpoof = Boolean(mitmActive || (Array.isArray(arpTable) && arpTable.some((e) => e.spoofed)));
  if (hasSpoof) {
    card.classList.add('card-alert-red');
    badge.className = 'badge badge-attack';
    badge.textContent = '⚠️ MAC SPOOFED';
    alertBox.classList.remove('hidden');
    const spoofedEntry = (arpTable || []).find((e) => e.spoofed);
    if (spoofedEntry && spoofedMacEl) spoofedMacEl.textContent = spoofedEntry.mac;
  } else {
    card.classList.remove('card-alert-red');
    badge.className = 'badge badge-normal';
    badge.textContent = 'ARP: VERIFIED';
    alertBox.classList.add('hidden');
  }

  tbody.innerHTML = '';
  for (const entry of arpTable || []) {
    const tr = document.createElement('tr');
    if (entry.spoofed) tr.className = 'arp-row-spoofed';
    const expectedInfo = entry.spoofed && entry.expected_mac && entry.expected_mac !== entry.mac
      ? `<span class="mac-expected">Real: ${escapeHtml(entry.expected_mac)}</span>`
      : '';
    const statusBadge = entry.spoofed
      ? '<span class="badge badge-attack">⚠️ POISONED</span>'
      : '<span class="badge badge-normal">DYNAMIC · OK</span>';

    tr.innerHTML = `
      <td><strong>${escapeHtml(entry.role)}</strong></td>
      <td><code>${escapeHtml(entry.ip)}</code></td>
      <td class="mac-cell"><code>${escapeHtml(entry.mac)}</code>${expectedInfo}</td>
      <td>${escapeHtml(entry.iface || 'eth0')}</td>
      <td>${statusBadge}</td>
    `;
    tbody.appendChild(tr);
  }
}

function renderMitmSnifferWindow(packets, mitmActive) {
  const listEl = document.getElementById('mitm-sniffer-list');
  const countBadge = document.getElementById('sniffer-count-badge');
  const statusBadge = document.getElementById('sniffer-status-badge');
  if (!listEl) return;

  const list = Array.isArray(packets) ? packets : [];
  countBadge.textContent = `${list.length} captured`;

  if (mitmActive) {
    statusBadge.className = 'badge badge-attack';
    statusBadge.textContent = '🔴 INTERCEPTING HTTP';
  } else {
    statusBadge.className = 'badge badge-shield inactive';
    statusBadge.textContent = 'STANDBY';
  }

  if (list.length === 0) {
    listEl.innerHTML = `
      <div class="sniffer-empty">
        Chưa có gói tin bị bắt lén. Khi <strong>ARP Spoofing (MitM)</strong> kích hoạt, luồng đăng nhập của Client đi vòng qua Hacker sẽ bị bóc tách mật khẩu tại đây.
      </div>
    `;
    return;
  }

  listEl.innerHTML = '';
  for (const pkt of list.slice(-15).reverse()) {
    const item = document.createElement('div');
    item.className = 'sniffer-entry';
    const timeStr = pkt.timestamp ? new Date(pkt.timestamp).toTimeString().split(' ')[0] : '--:--:--';
    item.innerHTML = `
      <div class="sniffer-entry-top">
        <span>[${escapeHtml(timeStr)}] ${escapeHtml(pkt.src_ip)} &rarr; [MITM] &rarr; ${escapeHtml(pkt.dst_ip)}</span>
        <span>${escapeHtml(pkt.method)} ${escapeHtml(pkt.endpoint)}</span>
      </div>
      <div class="sniffer-creds">
        🔑 USER: <code>${escapeHtml(pkt.username || 'N/A')}</code> | PASS: <code>${escapeHtml(pkt.password || 'N/A')}</code>
      </div>
      <div class="sniffer-token" title="${escapeHtml(pkt.token_preview || pkt.raw_preview)}">
        🪙 TOKEN: ${escapeHtml(pkt.token_preview || pkt.raw_preview)}
      </div>
    `;
    listEl.appendChild(item);
  }
}

function renderSynBarChart(history, currentVal) {
  const chartEl = document.getElementById('syn-bar-chart');
  const currentEl = document.getElementById('syn-chart-current');
  const peakEl = document.getElementById('syn-chart-peak');
  const badgeEl = document.getElementById('syn-backlog-badge');
  const cardEl = document.getElementById('syn-rst-card');
  if (!chartEl) return;

  const series = Array.isArray(history) && history.length > 0 ? history : Array(16).fill(0);
  const latest = typeof currentVal === 'number' ? currentVal : (series[series.length - 1] || 0);

  if (currentEl) currentEl.textContent = String(latest);
  if (peakEl) peakEl.textContent = String(Math.max(state.synPeak, latest));

  if (latest >= 80) {
    badgeEl.className = 'badge badge-attack';
    badgeEl.textContent = '🔥 BACKLOG: FLOODED';
    cardEl.classList.add('card-alert-red');
  } else if (latest >= 35) {
    badgeEl.className = 'badge badge-mitm';
    badgeEl.textContent = '⚠️ BACKLOG: ELEVATED';
    cardEl.classList.remove('card-alert-red');
  } else {
    badgeEl.className = 'badge badge-normal';
    badgeEl.textContent = 'BACKLOG: STABLE';
    cardEl.classList.remove('card-alert-red');
  }

  chartEl.innerHTML = '';
  const maxScale = 250;
  for (const val of series) {
    const col = document.createElement('div');
    col.className = 'syn-bar-col';

    const pct = Math.min(100, Math.max(4, Math.round((val / maxScale) * 100)));
    let colorClass = '';
    if (val >= 80) colorClass = 'syn-critical';
    else if (val >= 35) colorClass = 'syn-warn';

    col.innerHTML = `
      <span class="syn-bar-val">${val > 0 ? val : ''}</span>
      <div class="syn-bar-fill ${colorClass}" style="height: ${pct}%;"></div>
    `;
    chartEl.appendChild(col);
  }
}

function renderRstMonitor(rst) {
  if (!rst) return;
  const box = document.getElementById('rst-status-box');
  const pill = document.getElementById('rst-state-pill');
  const countEl = document.getElementById('rst-disrupted-count');
  const seqEl = document.getElementById('rst-last-seq');
  const timeEl = document.getElementById('rst-last-time');
  const topBadge = document.getElementById('rst-badge-indicator');

  if (countEl) countEl.textContent = String(rst.disrupted_sessions || 0);
  if (seqEl) seqEl.textContent = rst.last_seq_num ? String(rst.last_seq_num) : '--';
  if (timeEl) {
    timeEl.textContent = rst.last_rst_at ? new Date(rst.last_rst_at).toTimeString().split(' ')[0] : '--:--:--';
  }

  if (rst.active && rst.disrupted_sessions > 0) {
    box.classList.add('rst-alert');
    pill.className = 'badge badge-attack';
    pill.textContent = '⚡ RST INJECTED';
  } else {
    box.classList.remove('rst-alert');
    pill.className = 'badge badge-normal';
    pill.textContent = 'SESSION: INTACT';
    topBadge.classList.add('hidden');
  }
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

  if (log.attack_tag === 'ARP_SPOOF') {
    // Hacker phát gói ARP Reply giả mạo sang cả Client và Server
    const targets = [clientPos, serverPos];
    for (const tPos of targets) {
      for (let i = 0; i < 6; i++) {
        particles.push({
          x: hackerPos.x,
          y: hackerPos.y,
          targetX: tPos.x,
          targetY: tPos.y,
          startX: hackerPos.x,
          startY: hackerPos.y,
          progress: 0,
          speed: 0.018 + Math.random() * 0.012,
          type: 'ARP_SPOOF',
          color: '#ffd700',
          size: 3.5 + Math.random() * 2,
          tag: 'ARP_SPOOF',
          spread: (Math.random() - 0.5) * 25,
        });
      }
    }
    floatingLabels.push({
      x: hackerPos.x - 75,
      y: hackerPos.y - 25,
      text: '⚠️ ARP REPLY: SPOOFED MAC!',
      alpha: 1,
      color: '#ffd700',
    });
    // Đồng thời bắn 1 luồng gói tin Client bị bẻ góc đi vòng qua Hacker -> Server
    spawnMitmBentParticles(clientPos, hackerPos, serverPos);
    return;
  }

  if (log.attack_tag === 'RST_INJECTION') {
    // Hacker bắn gói tin TCP RST sắc nhọn ngắt kết nối giữa Client và Server
    const rstBadge = document.getElementById('rst-badge-indicator');
    const clientStatus = document.getElementById('client-status');
    rstBadge.classList.remove('hidden');
    clientStatus.textContent = '⚡ CONN RESET (RST)';
    clientNode.classList.add('compromised');
    if (state.rstBannerTimer) clearTimeout(state.rstBannerTimer);
    state.rstBannerTimer = setTimeout(() => {
      rstBadge.classList.add('hidden');
      clientStatus.textContent = 'IDLE';
      clientNode.classList.remove('compromised');
    }, 4000);

    // Hủy các hạt xanh đang bay trên đường truyền Client <-> Server (hiệu ứng đứt phiên)
    for (let i = particles.length - 1; i >= 0; i--) {
      if (particles[i].type === 'NORMAL') {
        spawnShieldDeflection(particles[i].x, particles[i].y, '#ff003c', '⚡ TCP RST! SESSION DROPPED');
        particles.splice(i, 1);
      }
    }

    const midX = (clientPos.x + serverPos.x) / 2;
    const midY = (clientPos.y + serverPos.y) / 2;
    for (const dst of [clientPos, serverPos, { x: midX, y: midY }]) {
      for (let i = 0; i < 5; i++) {
        particles.push({
          x: hackerPos.x,
          y: hackerPos.y,
          targetX: dst.x,
          targetY: dst.y,
          startX: hackerPos.x,
          startY: hackerPos.y,
          progress: 0,
          speed: 0.025 + Math.random() * 0.015,
          type: 'RST_INJECTION',
          color: '#ff003c',
          size: 4 + Math.random() * 2,
          tag: 'RST_INJECTION',
          spread: (Math.random() - 0.5) * 18,
        });
      }
    }
    floatingLabels.push({
      x: midX - 65,
      y: midY,
      text: '⚡ TCP RST [CONN RESET]',
      alpha: 1,
      color: '#ff003c',
    });
    return;
  }

  if (isAttack) {
    // Kẻ tấn công bắn hạt đỏ/tím sang Server
    const isSynFlood = log.attack_tag === 'SYN_FLOOD';
    const particleCount = isSynFlood ? 24 : log.attack_tag === 'HEAVY_DOS' ? 18 : 8;
    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: hackerPos.x,
        y: hackerPos.y + (Math.random() * 20 - 10),
        targetX: serverPos.x,
        targetY: serverPos.y + (Math.random() * 20 - 10),
        startX: hackerPos.x,
        startY: hackerPos.y,
        progress: 0,
        speed: 0.015 + Math.random() * 0.018,
        type: 'ATTACK',
        color: isSynFlood ? '#cc66ff' : '#ff003c',
        size: 3 + Math.random() * 2.5,
        tag: log.attack_tag || 'ATTACK',
        spread: (Math.random() - 0.5) * 45,
      });
    }
    if (isSynFlood) {
      floatingLabels.push({
        x: (hackerPos.x + serverPos.x) / 2 - 40,
        y: (hackerPos.y + serverPos.y) / 2,
        text: '🌊 SYN FLOOD (+SYN_RECV)',
        alpha: 1,
        color: '#cc66ff',
      });
    }

    // Hiệu ứng nhấp nháy Hacker Node
    hackerNode.classList.add('compromised');
    setTimeout(() => hackerNode.classList.remove('compromised'), 500);
  } else {
    // Lưu lượng Client bình thường:
    // Nếu đang bị ARP Spoofing (MitM), gói tin bị bẻ góc đi vòng qua Node Hacker (Client -> Hacker -> Server)
    if (state.networkState.mitm_active) {
      spawnMitmBentParticles(clientPos, hackerPos, serverPos);
    } else {
      // Đường truyền thẳng bình thường Client -> Server
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
          spread: (Math.random() - 0.5) * 24,
        });
      }
    }
  }
}

/**
 * Tạo hạt di chuyển theo đường gấp khúc bẻ góc qua Node Hacker:
 * Chặng 1: Client -> Hacker (màu xanh lá)
 * Chặng 2: Hacker -> Target Server (đổi sang màu cam #ff9900 báo hiệu đã bị Sniff!)
 */
function spawnMitmBentParticles(clientPos, hackerPos, serverPos) {
  for (let i = 0; i < 5; i++) {
    particles.push({
      x: clientPos.x,
      y: clientPos.y,
      startX: clientPos.x,
      startY: clientPos.y,
      targetX: hackerPos.x,
      targetY: hackerPos.y,
      finalTargetX: serverPos.x,
      finalTargetY: serverPos.y,
      mitmRelay: true,
      leg: 1,
      progress: 0,
      speed: 0.016 + Math.random() * 0.01,
      type: 'NORMAL',
      color: '#00ff66',
      size: 3 + Math.random() * 1.8,
      tag: 'MITM_SNIFFED',
      spread: (Math.random() - 0.5) * 14,
    });
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

  if (state.networkState.mitm_active) {
    // Đường thẳng Client -> Server bị vô hiệu hóa khi bị ARP Spoofing
    ctx.beginPath();
    ctx.strokeStyle = 'rgba(255, 0, 60, 0.22)';
    ctx.lineWidth = 1.5;
    ctx.setLineDash([3, 8]);
    ctx.moveTo(cX, cY);
    ctx.lineTo(sX, sY);
    ctx.stroke();

    ctx.save();
    ctx.font = 'bold 11px Share Tech Mono';
    ctx.fillStyle = 'rgba(255, 80, 100, 0.85)';
    ctx.textAlign = 'center';
    ctx.fillText('✕ DIRECT LINK BYPASSED (ARP POISONED)', (cX + sX) / 2, (cY + sY) / 2 - 10);
    ctx.restore();

    // Vẽ đường truyền BẺ GÓC đi vòng qua Node Hacker (Client -> Hacker -> Server)
    ctx.save();
    ctx.beginPath();
    ctx.strokeStyle = 'rgba(255, 153, 0, 0.85)';
    ctx.lineWidth = 3;
    ctx.setLineDash([8, 5]);
    ctx.shadowColor = '#ff9900';
    ctx.shadowBlur = 12;
    ctx.moveTo(cX, cY);
    ctx.lineTo(hX, hY);
    ctx.lineTo(sX, sY);
    ctx.stroke();

    // Nhãn trên 2 nhánh bẻ góc
    ctx.font = 'bold 11px Orbitron';
    ctx.fillStyle = '#ffd700';
    ctx.textAlign = 'center';
    ctx.fillText('① MITM INTERCEPT', (cX + hX) / 2 - 30, (cY + hY) / 2 + 12);
    ctx.fillStyle = '#ff9900';
    ctx.fillText('② RELAY TO SERVER', (hX + sX) / 2 + 35, (hY + sY) / 2 + 12);
    ctx.restore();
    ctx.setLineDash([]);
  } else {
    // Đường link chuẩn Client -> Server
    ctx.beginPath();
    ctx.strokeStyle = 'rgba(0, 255, 102, 0.25)';
    ctx.lineWidth = 2;
    ctx.setLineDash([4, 6]);
    ctx.moveTo(cX, cY);
    ctx.quadraticCurveTo((cX + sX) / 2, cY - 25, sX, sY);
    ctx.stroke();

    // Đường link Hacker -> Server
    ctx.beginPath();
    ctx.strokeStyle = 'rgba(255, 0, 60, 0.2)';
    ctx.lineWidth = 2;
    ctx.moveTo(hX, hY);
    ctx.quadraticCurveTo((hX + sX) / 2, (hY + sY) / 2, sX, sY);
    ctx.stroke();
    ctx.setLineDash([]);
  }
}

function updateAndDrawParticles() {
  for (let i = particles.length - 1; i >= 0; i--) {
    const p = particles[i];
    p.progress += p.speed;

    if (p.mitmRelay) {
      // Chuyển động thẳng sắc nét trên đường truyền bẻ góc Client -> Hacker -> Server
      const t = Math.min(1, p.progress);
      p.x = p.startX + (p.targetX - p.startX) * t;
      p.y = p.startY + (p.targetY - p.startY) * t + Math.sin(t * Math.PI) * p.spread;
    } else {
      // Đường cong Bezier
      const cpY = (p.startY + p.targetY) / 2 - 20 + p.spread;
      const cpX = (p.startX + p.targetX) / 2;

      const t = p.progress;
      p.x = (1 - t) * (1 - t) * p.startX + 2 * (1 - t) * t * cpX + t * t * p.targetX;
      p.y = (1 - t) * (1 - t) * p.startY + 2 * (1 - t) * t * cpY + t * t * p.targetY;
    }

    // KIỂM TRA VA CHẠM KHIÊN CHẮN (SHIELD BARRIER INTERACTION)
    const shieldDistanceThreshold = 115;
    const distToServer = Math.hypot(p.targetX - p.x, p.targetY - p.y);

    if (p.type === 'ATTACK' && state.defenseL3Active && distToServer <= shieldDistanceThreshold) {
      // Hạt tấn công va vào khiên chắn -> VA CHẠM & BỊ DỘI NGƯỢC (DROP)
      spawnShieldDeflection(p.x, p.y);
      particles.splice(i, 1);
      continue;
    }

    // Đã chạm đích của chặng hiện tại
    if (p.progress >= 1) {
      // Nếu là gói tin MitM vừa tới Node Hacker (chặng 1) -> Bẻ góc chuyển tiếp sang Server (chặng 2)
      if (p.mitmRelay && p.leg === 1) {
        p.leg = 2;
        p.progress = 0;
        p.startX = p.targetX;
        p.startY = p.targetY;
        p.targetX = p.finalTargetX;
        p.targetY = p.finalTargetY;
        p.color = '#ff9900'; // Đổi sang màu cam cảnh báo gói tin đã bị Hacker đọc trộm!
        if (Math.random() > 0.55) {
          floatingLabels.push({
            x: p.startX - 55,
            y: p.startY - 18,
            text: '🕵️ SNIFFED CREDENTIALS!',
            alpha: 1,
            color: '#ff9900',
          });
        }
        continue;
      }

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

function spawnShieldDeflection(x, y, customColor = '#00f0ff', customText = '🛡️ BLOCKED [L3]') {
  // Tạo tia lửa dội ngược
  for (let i = 0; i < 8; i++) {
    shieldImpactSparks.push({
      x,
      y,
      vx: (Math.random() - 0.5) * 7,
      vy: (Math.random() * 4 + 1),
      color: customColor,
      alpha: 1,
      size: Math.random() * 2.5 + 1.5,
    });
  }

  // Thêm nhãn chữ nổi
  if (Math.random() > 0.35) {
    floatingLabels.push({
      x: x - 35,
      y: y - 10,
      text: customText,
      alpha: 1,
      color: customColor,
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
    <td><span class="method-badge method-${escapeHtml(log.method)}">${escapeHtml(log.method)}</span></td>
    <td title="${escapeHtml(log.endpoint)}"><strong>${escapeHtml(log.endpoint)}</strong></td>
    <td><span class="status-badge ${statusClass}">${escapeHtml(log.status_code)}</span></td>
    <td>${escapeHtml(log.response_time)} ms</td>
    <td><code>${escapeHtml(log.client_ip)}</code></td>
    <td><span class="tag-badge tag-${escapeHtml(tag)}">${escapeHtml(tag)}</span></td>
    <td>${escapeHtml(log.defense_action || 'unknown')}</td>
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
  document.getElementById('btn-demo-arp').addEventListener('click', () => simulateTraffic('arp-spoof'));
  document.getElementById('btn-demo-syn').addEventListener('click', () => simulateTraffic('syn-flood'));
  document.getElementById('btn-demo-rst').addEventListener('click', () => simulateTraffic('rst-inject'));
  document.getElementById('btn-demo-clean-arp').addEventListener('click', () => restoreCleanArp());
  document.getElementById('btn-demo-sqli').addEventListener('click', () => simulateTraffic('sqli'));
  document.getElementById('btn-demo-dos').addEventListener('click', () => simulateTraffic('dos'));
}

async function restoreCleanArp() {
  try {
    await fetch('/api/telemetry/network', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'reset_arp' }),
    });
  } catch {
    updateNetworkStateUI({
      ...state.networkState,
      mitm_active: false,
      arp_table: state.networkState.arp_table.map((e) => ({ ...e, mac: e.expected_mac || e.mac, spoofed: false })),
    });
  }
}

async function toggleDefense() {
  const button = document.getElementById('btn-toggle-defense');
  button.disabled = true;
  try {
    const unknown = typeof state.defenseL3Active !== 'boolean';
    const res = await fetch(unknown ? '/api/defense/status' : '/api/defense/toggle', unknown ? {} : {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !state.defenseL3Active }),
    });
    const data = await res.json();
    if (!res.ok || typeof data.defense_l3_app !== 'boolean') throw new Error(data.message || 'Target chưa xác nhận trạng thái.');
    updateDefenseUI(data.defense_l3_app);
  } catch (error) {
    updateDefenseUI(null);
    document.getElementById('defense-error').textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

function renderAttackEvents() {
  const container = document.getElementById('attack-events');
  container.replaceChildren();
  if (!state.attackEvents.length) {
    container.textContent = 'Chưa nhận sự kiện Attacker. Chạy kịch bản từ Attacker Lab để xem dữ liệu thật.';
    return;
  }
  for (const event of state.attackEvents.slice(-50).reverse()) {
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    const step = event.payload.state || event.payload.stage || event.payload.type || event.event_type;
    summary.textContent = `${event.timestamp} | ${event.scenario} | ${step} | run ${event.run_id}`;
    const evidence = document.createElement('pre');
    evidence.textContent = JSON.stringify(event, null, 2);
    details.append(summary, evidence);
    container.append(details);
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
      endpoint: '/api/auth/login',
      status_code: 200,
      response_time: Math.floor(Math.random() * 15) + 10,
      client_ip: '172.20.0.10',
      payload_summary: {
        body_preview: { username: 'engineer_user', password: 'pass123' },
        token_preview: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlbmdpbmVlcl91c2VyIn0.signature',
      },
      attack_tag: 'NORMAL',
      is_suspicious: false,
    };
  } else if (type === 'arp-spoof') {
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'ARP',
      endpoint: '/L2/arp-cache-poison (Gratuitous ARP Reply)',
      status_code: 200,
      response_time: 1,
      client_ip: '172.20.0.66',
      payload_summary: {
        spoofed_ip: '172.20.0.20',
        spoofed_mac: '02:42:ac:14:00:42',
        body_preview: { username: 'engineer_user', password: 'pass123' },
        token_preview: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlbmdpbmVlcl91c2VyIn0.mitm_captured',
        detected_patterns: ['ARP_CACHE_POISONING', 'MITM_HTTP_SNIFF'],
      },
      attack_tag: 'ARP_SPOOF',
      is_suspicious: true,
      defense_action: 'monitored',
    };
  } else if (type === 'syn-flood') {
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'TCP',
      endpoint: '/L4/tcp-syn-flood (Flags: SYN, Port: 8000, Rate: 150 pps)',
      status_code: 503,
      response_time: 420,
      client_ip: '172.20.0.66',
      payload_summary: {
        pps: 150,
        backlog_queue: 'SYN_RECV_OVERFLOW',
        detected_patterns: ['HALF_OPEN_SYN_FLOOD'],
      },
      attack_tag: 'SYN_FLOOD',
      is_suspicious: true,
      defense_action: 'monitored',
    };
  } else if (type === 'rst-inject') {
    const seqNum = Math.floor(200000000 + Math.random() * 700000000);
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'TCP',
      endpoint: `/L4/tcp-rst-injection (Flags: RST, SEQ=${seqNum})`,
      status_code: 499,
      response_time: 2,
      client_ip: '172.20.0.66',
      payload_summary: {
        seq_num: seqNum,
        victim_ip: '172.20.0.10',
        target_ip: '172.20.0.20',
        detected_patterns: ['FORGED_TCP_RST_PACKET'],
      },
      attack_tag: 'RST_INJECTION',
      is_suspicious: true,
      defense_action: 'monitored',
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
    logPayload.metadata = { source: 'demo', synthetic: true };
    logPayload.endpoint = '[DEMO] ' + logPayload.endpoint;
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
  return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
