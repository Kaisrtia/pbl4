const $ = id => document.getElementById(id);
let selected = null, definitions = [], connected = false, busy = false, active = null, requested = null;
async function api(path, method = 'GET', body) {
  const response = await fetch('/api/v1/' + path, { method,
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + $('token').value },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(5000),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
function notice(error) { $('notice').textContent = error instanceof Error ? error.message : error; }
function renderParameters() {
  const definition = definitions.find(s => s.id === $('scenario').value);
  $('description').textContent = definition?.description || '';
  $('parameters').replaceChildren();
  for (const [name, value] of Object.entries(definition?.defaults || {})) {
    const label = document.createElement('label'); label.textContent = name;
    const input = document.createElement('input'); input.type = 'number'; input.step = '1'; input.min = '1'; input.value = value;
    input.dataset.parameter = name; label.append(input); $('parameters').append(label);
  }
}
function buttons() {
  $('start').disabled = !connected || busy || Boolean(active);
  $('stop').disabled = !connected || !active || active.state === 'STOPPING';
}
async function refresh() {
  const [runs, config] = await Promise.all([api('runs'), api('config')]);
  connected = true; $('connection').textContent = 'Đã kết nối · Real workers';
  active = runs.find(r => ['STARTING', 'RUNNING', 'STOPPING'].includes(r.state));
  $('target').textContent = `Attacker ${config.attacker_ip} → Target ${config.target_ip} · SSH ${config.ssh_port} · HTTP ${config.http_port} | Telemetry đang chờ: ${config.telemetry.pending}${config.telemetry.delivery_error ? ' · God-View chưa nhận: ' + config.telemetry.delivery_error : ''}`;
  $('runs').replaceChildren();
  for (const run of runs) {
    const button = document.createElement('button');
    button.textContent = `${run.scenario} · ${run.state} · ${run.started_at} · ${run.run_id.slice(0, 8)}`;
    button.onclick = () => { selected = run.run_id; void update(); };
    $('runs').append(button);
  }
  selected ||= runs[0]?.run_id;
  const run = runs.find(r => r.run_id === selected);
  if (run) {
    if (run.run_id === requested && ['COMPLETED', 'FAILED', 'STOPPED'].includes(run.state)) {
      notice(`Lần chạy ${run.scenario}: ${run.state}.${run.cleanup_pending ? ' Cần kiểm tra dọn dẹp phía Target.' : ''}`);
      requested = null;
    }
    $('run-id').textContent = run.run_id;
    $('state').textContent = run.state;
    $('result').textContent = JSON.stringify({ state: run.state, error: run.error, cleanup_pending: run.cleanup_pending, result: run.result || null }, null, 2);
    $('events').textContent = (await api('events?run_id=' + encodeURIComponent(run.run_id))).map(e => `${e.timestamp} ${JSON.stringify(e.payload)}`).join('\n');
  }
  buttons();
}
async function update() {
  try { await refresh(); }
  catch (error) { connected = false; $('connection').textContent = 'Mất kết nối · Dữ liệu dưới đây có thể đã cũ'; notice(error); buttons(); }
}
$('connect').onclick = async () => {
  try { definitions = await api('scenarios'); renderParameters(); notice(''); await update(); }
  catch (error) { notice(error); }
};
$('scenario').onchange = renderParameters;
$('preflight').onclick = async () => {
  try { notice(JSON.stringify(await api('preflight'), null, 2)); } catch (error) { notice(error); }
};
$('start').onclick = async () => {
  busy = true; buttons();
  try {
    const parameters = {};
    document.querySelectorAll('[data-parameter]').forEach(input => { parameters[input.dataset.parameter] = Number(input.value); });
    const run = await api('runs', 'POST', { scenario: $('scenario').value, parameters });
    selected = run.run_id; requested = run.run_id; notice('Đã nhận yêu cầu; đang chờ worker.'); await update();
  } catch (error) { notice(error); }
  finally { busy = false; buttons(); }
};
$('stop').onclick = async () => {
  if (!active) return;
  try { await api(`runs/${active.run_id}/stop`, 'POST', {}); notice('Đã gửi yêu cầu dừng; chờ xác nhận kết thúc và dọn dẹp.'); await update(); }
  catch (error) { notice(error); }
};
async function poll() { if (connected) await update(); setTimeout(poll, 1200); }
void poll();
