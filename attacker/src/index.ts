import { loadConfig, loadEnvFiles } from './config.js';
import { startServer } from './server.js';
loadEnvFiles();
const config = loadConfig();
const app = await startServer(config);
console.log(`Attacker controller: http://${config.host}:${config.port} (real workers, one active run)`);
let closing = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  if (closing) return;
  closing = true;
  void app.close().then(() => process.exit(0));
});
