import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createRequire } from 'module';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(__dirname, '../api/package.json'));

const { AdminWebsocket } = await import(join(__dirname, '../api/node_modules/@holochain/client/lib/index.js'));

const ADMIN_PORT = parseInt(process.env.ADMIN_PORT || '44121');
const APP_PORT = parseInt(process.env.APP_PORT || '44122');
const APP_ID = process.env.APP_ID || 'toric';

const adminWs = await AdminWebsocket.connect({
  url: new URL(`ws://localhost:${ADMIN_PORT}`),
  wsClientOptions: { origin: 'http://localhost' },
});

const appInfo = await adminWs.listApps({ status_filter: 'enabled' });
const existing = appInfo.find(a => a.installed_app_id === APP_ID);
if (existing) {
  console.log('Happ already installed');
  await adminWs.client.close();
  process.exit(0);
}

const happPath = join(__dirname, '../toric.happ');
const issued = await adminWs.issueAppAuthenticationToken({ installed_app_id: APP_ID });
await adminWs.installApp({
  installed_app_id: APP_ID,
  agent_key: await adminWs.generateAgentPubKey(),
  membrane_proofs: {},
  source: { type: 'path', value: happPath },
});
await adminWs.enableApp({ installed_app_id: APP_ID });
await adminWs.attachAppInterface({ port: APP_PORT, allowed_origins: '*', installed_app_id: APP_ID });
console.log('Happ installed');
await adminWs.client.close();
