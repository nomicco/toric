import { AppWebsocket, AdminWebsocket } from "@holochain/client";
import express from "express";

const app = express();
app.use(express.json());

const ADMIN_PORT = parseInt(process.env.ADMIN_PORT || "44121");
const APP_PORT = parseInt(process.env.APP_PORT || "37351");
const API_PORT = parseInt(process.env.API_PORT || "3000");
const APP_ID = process.env.APP_ID || "poi";

let appWs = null;
let cellId = null;

async function connect() {
  try {
    const adminWs = await AdminWebsocket.connect({
      url: new URL(`ws://localhost:${ADMIN_PORT}`),
      wsClientOptions: { origin: "http://localhost" },
    });

    // Get registry cell ID
    const appInfo = await adminWs.listApps({ status_filter: "enabled" });
    const poiApp = appInfo.find(a => a.installed_app_id === APP_ID);
    if (!poiApp) throw new Error(`App ${APP_ID} not found or not running`);

    const registryCell = poiApp.cell_info["registry"][0].value;
    cellId = registryCell.cell_id;

    // Authorize signing credentials for this cell
    await adminWs.authorizeSigningCredentials(cellId);

    const issued = await adminWs.issueAppAuthenticationToken({
      installed_app_id: APP_ID,
    });

    appWs = await AppWebsocket.connect({
      url: new URL(`ws://localhost:${APP_PORT}`),
      token: issued.token,
      wsClientOptions: { origin: "http://localhost" },
    });

    console.log(`Connected to Holochain conductor`);
    await adminWs.client.close();
  } catch (e) {
    console.error("Failed to connect:", e.message);
    setTimeout(connect, 3000);
  }
}

async function registryCall(fnName, payload) {
  if (!appWs) throw new Error("Not connected to conductor");
  return appWs.callZome({
    cell_id: cellId,
    zome_name: "registry",
    fn_name: fnName,
    payload,
    provenance: cellId[1],
  });
}

app.get("/", (req, res) => {
  res.json({
    name: "POI Network API",
    version: "1.0.0",
    status: appWs ? "connected" : "connecting",
    endpoints: [
      "GET  /manifest/:hash",
      "GET  /manifest/:hash/attestations",
      "GET  /manifest/:hash/warrants",
      "GET  /agent/:pubkey/manifests",
      "GET  /agent/:pubkey/reputation",
      "POST /manifest",
      "POST /attestation",
      "POST /warrant",
    ],
  });
});

app.get("/manifest/:hash", async (req, res) => {
  try {
    const record = await registryCall("get_manifest", Buffer.from(req.params.hash, "base64url"));
    if (!record) return res.status(404).json({ error: "Manifest not found" });
    res.json(formatRecord(record));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/manifest/:hash/attestations", async (req, res) => {
  try {
    const records = await registryCall("get_manifest_attestations", Buffer.from(req.params.hash, "base64url"));
    res.json(records.map(formatRecord));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/manifest/:hash/warrants", async (req, res) => {
  try {
    const records = await registryCall("get_manifest_warrants", Buffer.from(req.params.hash, "base64url"));
    res.json(records.map(formatRecord));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/agent/:pubkey/manifests", async (req, res) => {
  try {
    const records = await registryCall("get_agent_manifests", req.params.pubkey);
    res.json(records.map(formatRecord));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/agent/:pubkey/reputation", async (req, res) => {
  try {
    const score = await registryCall("compute_reputation_score", {
      agent: req.params.pubkey,
    });
    res.json({ ...score, agent: toBase64(score.agent) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/manifest", async (req, res) => {
  try {
    const { blob } = req.body;
    if (!blob) return res.status(400).json({ error: "blob required" });
    const hash = await registryCall("create_manifest", { blob });
    res.status(201).json({ hash: toBase64(hash) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/attestation", async (req, res) => {
  try {
    const { manifest_hash, blob } = req.body;
    if (!manifest_hash || !blob)
      return res.status(400).json({ error: "manifest_hash and blob required" });
    const hash = await registryCall("create_attestation", { manifest_hash, blob });
    res.status(201).json({ hash: toBase64(hash) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/warrant", async (req, res) => {
  try {
    const { manifest_hash, blob } = req.body;
    if (!manifest_hash || !blob)
      return res.status(400).json({ error: "manifest_hash and blob required" });
    const hash = await registryCall("create_warrant", { manifest_hash, blob });
    res.status(201).json({ hash: toBase64(hash) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function toBase64(buf) {
  if (!buf) return null;
  if (buf.type === "Buffer") return Buffer.from(buf.data).toString("base64url");
  if (buf instanceof Uint8Array) return Buffer.from(buf).toString("base64url");
  return buf;
}

function formatRecord(record) {
  if (!record) return null;
  return {
    hash: toBase64(record.signed_action?.hashed?.hash),
    author: toBase64(record.signed_action?.hashed?.content?.author),
    timestamp: record.signed_action?.hashed?.content?.timestamp,
    entry: (() => { try { const e = record.entry?.Present?.entry; if (!e) return null; const buf = e.type === "Buffer" ? Buffer.from(e.data) : Buffer.from(e); const msgpack = buf; const jsonStart = msgpack.indexOf(123); return jsonStart >= 0 ? JSON.parse(msgpack.slice(jsonStart).toString()) : buf.toString(); } catch(e) { return null; } })(),
  };
}

connect();

app.listen(API_PORT, () => {
  console.log(`POI API running on http://localhost:${API_PORT}`);
});
