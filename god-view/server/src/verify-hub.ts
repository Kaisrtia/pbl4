import { app, server } from './server';

async function testGodView() {
  const baseUrl = 'http://127.0.0.1:4000';

  try {
    console.log('\n--- 1. Testing GET /api/health ---');
    const healthRes = await fetch(`${baseUrl}/api/health`);
    console.log('Health Status:', healthRes.status, await healthRes.json());

    console.log('\n--- 2. Testing GET / (Serve Client index.html) ---');
    const htmlRes = await fetch(`${baseUrl}/`);
    const htmlText = await htmlRes.text();
    console.log('HTML Status:', htmlRes.status, 'Contains Title:', htmlText.includes('PBL4 - GOD-VIEW SIEM'));

    console.log('\n--- 3. Testing POST /api/telemetry (Ingest Log) ---');
    const postRes = await fetch(`${baseUrl}/api/telemetry`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        timestamp: new Date().toISOString(),
        method: 'POST',
        endpoint: '/api/login',
        status_code: 200,
        response_time: 12,
        client_ip: '172.20.0.66',
        payload_summary: { username: "admin' --" },
        attack_tag: 'SQL_INJECTION',
        is_suspicious: true,
      }),
    });
    console.log('Post Status:', postRes.status, await postRes.json());

    console.log('\n--- 4. Testing GET /api/telemetry/history ---');
    const historyRes = await fetch(`${baseUrl}/api/telemetry/history`);
    const historyData: any = await historyRes.json();
    console.log('History Status:', historyRes.status, 'Count:', historyData.count, 'First Tag:', historyData.history[0]?.attack_tag);

    console.log('\n--- 5. Testing POST /api/defense/toggle ---');
    const toggleRes = await fetch(`${baseUrl}/api/defense/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    console.log('Toggle Status:', toggleRes.status, await toggleRes.json());

    console.log('\n--- 6. Testing DELETE /api/telemetry/clear ---');
    const clearRes = await fetch(`${baseUrl}/api/telemetry/clear`, { method: 'DELETE' });
    console.log('Clear Status:', clearRes.status, await clearRes.json());

    console.log('\n>>> ALL GOD-VIEW HUB TESTS COMPLETED SUCCESSFULLY! <<<');
  } catch (err) {
    console.error('Test error:', err);
  } finally {
    server.close(() => {
      console.log('God-View test server closed cleanly.');
    });
  }
}

// Chờ 1 giây để server khởi động rồi chạy test
setTimeout(testGodView, 1000);
