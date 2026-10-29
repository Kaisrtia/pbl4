let input = '';
for await (const chunk of process.stdin) input += chunk;
const config = JSON.parse(input);
const mode = process.argv[2];
const emit = event => process.stdout.write(JSON.stringify({ run_id: config.run_id, ...event }) + '\n');
emit({ type: 'ready' });
if (mode === 'fail') { emit({ type: 'error', message: 'deliberate failure' }); process.exitCode = 1; }
else if (mode === 'malformed') process.stdout.write('not json\n');
else if (mode === 'fragmented') {
  const line = JSON.stringify({ run_id: config.run_id, type: 'result', result: { outcome: 'OBSERVED', summary: 'actual fixture result', measurements: { count: 0 }, cleanup_pending: false } }) + '\n';
  process.stdout.write(line.slice(0, 14));
  setTimeout(() => process.stdout.write(line.slice(14)), 30);
} else if (mode === 'hang') {
  process.on('SIGTERM', () => {});
  setInterval(() => {}, 1000);
} else {
  const timer = setInterval(() => {}, 1000);
  process.on('SIGTERM', () => {
    clearInterval(timer);
    setTimeout(() => emit({ type: 'result', result: { outcome: 'INCONCLUSIVE', summary: 'cancelled', measurements: {}, cleanup_pending: false } }), 50);
  });
}
