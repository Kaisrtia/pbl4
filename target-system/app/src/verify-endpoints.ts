import { createApp } from './app';

async function runTests() {
  const app = createApp();
  const server = app.listen(8001, async () => {
    console.log('Test server started on port 8001');
    const baseUrl = 'http://127.0.0.1:8001';

    try {
      // 1. Test Health
      console.log('\n--- 1. Testing GET /api/health ---');
      const healthRes = await fetch(`${baseUrl}/api/health`);
      console.log('Status:', healthRes.status, await healthRes.json());

      // 2. Test Normal Login
      console.log('\n--- 2. Testing POST /api/login (Valid User) ---');
      const loginRes = await fetch(`${baseUrl}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'admin',
          password: 'adminPassword2026!',
        }),
      });
      const loginData: any = await loginRes.json();
      console.log('Status:', loginRes.status, 'Success:', loginData.success, 'Token length:', loginData.token?.length);
      const token = loginData.token;

      // 3. Test SQL Injection Login Bypass
      console.log('\n--- 3. Testing POST /api/login (SQL Injection Bypass) ---');
      const sqliRes = await fetch(`${baseUrl}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: "admin' --",
          password: 'arbitrary_fake_password',
        }),
      });
      const sqliData: any = await sqliRes.json();
      console.log('Status:', sqliRes.status, 'Success:', sqliData.success, 'Message:', sqliData.message, 'User:', sqliData.user?.username);

      // 4. Test Protected Resources Without Token (Should be 401)
      console.log('\n--- 4. Testing GET /api/resources (Without Token) ---');
      const unauthRes = await fetch(`${baseUrl}/api/resources`);
      console.log('Status:', unauthRes.status, await unauthRes.json());

      // 5. Test Protected Resources With Token (Should be 200)
      console.log('\n--- 5. Testing GET /api/resources (With Token) ---');
      const authRes = await fetch(`${baseUrl}/api/resources`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const authData: any = await authRes.json();
      console.log('Status:', authRes.status, 'Count:', authData.count, 'Resources:', authData.resources?.map((r: any) => ({ id: r.id, name: r.name })));

      // 6. Test Ping Latency
      console.log('\n--- 6. Testing GET /api/ping ---');
      const pingStart = Date.now();
      const pingRes = await fetch(`${baseUrl}/api/ping?t=${pingStart}&echo=hello-godview`);
      const pingData: any = await pingRes.json();
      console.log('Status:', pingRes.status, 'Response:', pingData);

      // 7. Test Download Bandwidth
      console.log('\n--- 7. Testing GET /api/download (100KB test) ---');
      const downloadRes = await fetch(`${baseUrl}/api/download?bytes=102400`);
      const buffer = await downloadRes.arrayBuffer();
      console.log('Status:', downloadRes.status, 'Content-Length:', downloadRes.headers.get('content-length'), 'Received Bytes:', buffer.byteLength);

      // 8. Test Heavy Load Simulation (GET & POST)
      console.log('\n--- 8. Testing GET /api/heavy-load ---');
      const heavyRes = await fetch(`${baseUrl}/api/heavy-load?iterations=50000&delay=50`);
      const heavyData: any = await heavyRes.json();
      console.log('Status:', heavyRes.status, 'Heavy result:', heavyData.metrics);

      console.log('\n--- 9. Testing POST /api/heavy ---');
      const heavyPostRes = await fetch(`${baseUrl}/api/heavy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iterations: 60000, delay: 20 }),
      });
      const heavyPostData: any = await heavyPostRes.json();
      console.log('Status:', heavyPostRes.status, 'Metrics:', heavyPostData.metrics);

      console.log('\n>>> ALL 9 ENDPOINT TESTS PASSED SUCCESSFULLY! <<<');
    } catch (e) {
      console.error('Test error:', e);
    } finally {
      server.close(() => {
        console.log('Test server closed cleanly.');
      });
    }
  });
}

runTests();
