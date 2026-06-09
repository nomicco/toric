const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '../node_modules/@holochain/hc-spin/dist/main/index.js');
let f = fs.readFileSync(file, 'utf8');

// Patch 1 — use mem network instead of webrtc
f = f.replace(
  'generateArgs.push("--bootstrap", bootStrapUrl, "webrtc", signalUrl)',
  'generateArgs.push("--bootstrap", bootStrapUrl, "mem")'
);

// Patch 2 — skip kitsune2-bootstrap-srv, resolve immediately
f = f.replace(
  /async function startLocalServices\(\) \{[\s\S]*?^\}/m,
  'async function startLocalServices() { return ["http://localhost:0", "ws://localhost:0"]; }'
);

fs.writeFileSync(file, f);
console.log('hc-spin patches applied');