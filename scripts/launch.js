const { spawn } = require('child_process');

const nAgents = parseInt(process.env.AGENTS || '2');
const uiPort = process.env.UI_PORT || '?';
const happPath = 'workdir/toric.happ';

const conductors = [];
let apisLaunched = false;

const spin = spawn('hc-spin', [
  '-n', nAgents.toString(),
  '--ui-port', uiPort,
  happPath
]);

spin.stdout.on('data', (data) => {
  const text = data.toString();
  process.stdout.write(text);

  for (const line of text.split('\n')) {
    const match = line.match(/Conductor launched #!(\d+) ({.*})/);
    if (match) {
      try {
        const info = JSON.parse(match[2]);
        conductors.push({ index: parseInt(match[1]), ...info });
        if (conductors.length === nAgents && !apisLaunched) {
          apisLaunched = true;
          setTimeout(launchApis, 2000);
        }
      } catch(e) {}
    }
  }
});

spin.stderr.on('data', d => process.stderr.write(d));
spin.on('exit', code => process.exit(code || 0));

function launchApis() {
    // Re-print the UI URL clearly at the bottom
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`UI: http://localhost:${uiPort}/`);
  conductors.forEach((c, i) => {
    const apiPort = 3000 + i;
    const api = spawn('node', ['api/index.js'], {
      env: {
        ...process.env,
        ADMIN_PORT: c.admin_port.toString(),
        APP_PORT: c.app_ports[0].toString(),
        API_PORT: apiPort.toString(),
      },
    });
    api.stdout.on('data', d => process.stdout.write(`[api-${i}] ${d}`));
    api.stderr.on('data', d => process.stderr.write(`[api-${i}] ${d}`));
    console.log(`Agent ${i}: http://localhost:${uiPort}/?api=${apiPort}  (API: http://localhost:${apiPort}/v1)`);
  });
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
}