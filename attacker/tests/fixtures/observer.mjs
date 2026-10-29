// Test-only telemetry collector / independent legitimate client; not God-View UI.
import http from 'node:http';
import fs from 'node:fs';
const events = [], probes = [];
if (process.env.ROLE === 'client') {
  setInterval(async () => {
    const start = performance.now();
    try {
      const response = await fetch('http://172.29.44.20:8000/health', { signal: AbortSignal.timeout(1000) });
      await response.arrayBuffer();
      probes.push({ timestamp: new Date().toISOString(), ok: response.ok, latency_ms: performance.now() - start });
    } catch { probes.push({ timestamp: new Date().toISOString(), ok: false }); }
    if (probes.length > 100) probes.shift();
    fs.writeFileSync('/tmp/probes.json', JSON.stringify(probes));
  }, 500);
} else {
  http.createServer(async (req, res) => {
    if (req.method === 'POST' && req.url === '/api/events/attack') {
      let body = ''; for await (const chunk of req) body += chunk;
      try {
        const event = JSON.parse(body);
        if (!event.event_id || !event.run_id || event.schema_version !== '1.0') throw new Error();
        if (!events.some(e => e.event_id === event.event_id)) events.push(event);
        res.writeHead(200).end('{}');
      } catch { res.writeHead(400).end('{}'); }
    } else res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(events));
  }).listen(8080, '0.0.0.0');
}
