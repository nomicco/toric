import { AppWebsocket, AdminWebsocket } from "@holochain/client";
import express from "express";
import cors from "cors";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const app = express();
app.use(express.json());
app.use(cors());
app.use((req, res, next) => {
  res.removeHeader('Content-Security-Policy');
  res.removeHeader('X-Content-Type-Options');
  next();
});
const __dirname = dirname(fileURLToPath(import.meta.url));
app.use(express.static(join(__dirname, "../frontend")));

// All API routes under /v1/
const v1 = express.Router();
app.use('/v1', v1);

const quorumQueue = [];
let quorumProcessing = false;

async function processQuorumQueue() {
  if (quorumProcessing) return;
  quorumProcessing = true;
  while (quorumQueue.length > 0) {
    const { request_hash, resolve } = quorumQueue.shift();
    try {
      const appInfo = await appWs.appInfo();
      const rawReg = appInfo.cell_info["registry"][0].value.cell_id[0];
      const registryDnaHash = rawReg.type === "Buffer" ? Buffer.from(rawReg.data) : Buffer.from(rawReg);
      const rawMC = appInfo.cell_info["mutual_credit"][0].value.cell_id[0];
      const mutualCreditDnaHash = rawMC.type === "Buffer" ? Buffer.from(rawMC.data) : Buffer.from(rawMC);
      const qResult = await coordinationCall("check_quorum", {
        request_hash: Buffer.from(request_hash, "base64url"),
        registry_dna_hash: registryDnaHash,
        mutual_credit_dna_hash: mutualCreditDnaHash,
      });
      resolve(qResult);
    } catch(e) {
      resolve({ error: e.message });
    }
  }
  quorumProcessing = false;
}

function queueQuorumCheck(request_hash) {
  return new Promise(resolve => {
    quorumQueue.push({ request_hash, resolve });
    processQuorumQueue();
  });
}

const ADMIN_PORT = parseInt(process.env.ADMIN_PORT || "44121");
const APP_PORT   = parseInt(process.env.APP_PORT   || "44122");
const API_PORT   = parseInt(process.env.API_PORT   || "3000");
const APP_ID     = process.env.APP_ID || "toric";

let appWs  = null;
let cellId = null;

async function connect() {
  try {
    const adminWs = await AdminWebsocket.connect({
      url: new URL(`ws://localhost:${ADMIN_PORT}`),
      wsClientOptions: { origin: "http://localhost" },
    });

    const appInfo = await adminWs.listApps({ status_filter: "enabled" });
    const poiApp = appInfo.find(a => a.installed_app_id === APP_ID);
    if (!poiApp) throw new Error(`App ${APP_ID} not found or not running`);

    const registryCell = poiApp.cell_info["registry"][0].value;
    cellId = registryCell.cell_id;

    const allCells = [];
    for (const role of Object.values(poiApp.cell_info)) {
      for (const cell of role) {
        if (cell.value && cell.value.cell_id) {
          allCells.push(cell.value.cell_id);
        }
      }
    }
    for (const cid of allCells) {
      await adminWs.authorizeSigningCredentials(cid);
    }

    const issued = await adminWs.issueAppAuthenticationToken({
      installed_app_id: APP_ID,
    });

    appWs = await AppWebsocket.connect({
      url: new URL(`ws://localhost:${APP_PORT}`),
      token: issued.token,
      wsClientOptions: { origin: "http://localhost" },
    });

    appWs.on("signal", (signal) => {
      broadcastSignal(signal);
    });

    console.log(`Connected to Holochain conductor`);
    await adminWs.client.close();
  } catch (e) {
    console.error("Failed to connect:", e.message);
    setTimeout(connect, 3000);
  }
}

function toBase64(buf) {
  if (!buf) return null;
  if (buf.type === "Buffer") return Buffer.from(buf.data).toString("base64url");
  if (buf instanceof Uint8Array) return Buffer.from(buf).toString("base64url");
  return buf;
}

function formatRecord(record) {
  if (!record) return null;
  return {
    hash:      toBase64(record.signed_action?.hashed?.hash),
    author:    toBase64(record.signed_action?.hashed?.content?.author),
    timestamp: record.signed_action?.hashed?.content?.timestamp,
    entry: (() => {
      try {
        const e = record.entry?.Present?.entry;
        if (!e) return null;
        const buf = e.type === "Buffer" ? Buffer.from(e.data) : Buffer.from(e);
        const jsonStart = buf.indexOf(123);
        return jsonStart >= 0 ? JSON.parse(buf.slice(jsonStart).toString()) : buf.toString();
      } catch(e) { return null; }
    })(),
  };
}

async function registryCall(fnName, payload) {
  if (!appWs) throw new Error("Not connected to conductor");
  return appWs.callZome({
    cell_id:    cellId,
    zome_name:  "registry",
    fn_name:    fnName,
    payload,
    provenance: cellId[1],
  });
}

async function coordinationCall(fnName, payload) {
  if (!appWs) throw new Error("Not connected to conductor");
  const appInfo = await appWs.appInfo();
  const cell = appInfo.cell_info["coordination"][0].value;
  return appWs.callZome({
    cell_id:    cell.cell_id,
    zome_name:  "coordination",
    fn_name:    fnName,
    payload,
    provenance: cell.cell_id[1],
  });
}

async function identityCall(fnName, payload) {
  if (!appWs) throw new Error("Not connected to conductor");
  const appInfo = await appWs.appInfo();
  const cell = appInfo.cell_info["identity"][0].value;
  return appWs.callZome({
    cell_id:    cell.cell_id,
    zome_name:  "identity",
    fn_name:    fnName,
    payload,
    provenance: cell.cell_id[1],
  });
}

async function mutualCreditCall(fnName, payload) {
  if (!appWs) throw new Error("Not connected to conductor");
  const appInfo = await appWs.appInfo();
  const cell = appInfo.cell_info["mutual_credit"][0].value;
  return appWs.callZome({
    cell_id:    cell.cell_id,
    zome_name:  "mutual_credit",
    fn_name:    fnName,
    payload,
    provenance: cell.cell_id[1],
  });
}

async function getDnaHashes() {
  const appInfo = await appWs.appInfo();
  const rawReg  = appInfo.cell_info["registry"][0].value.cell_id[0];
  const rawMC   = appInfo.cell_info["mutual_credit"][0].value.cell_id[0];
  const rawCoord = appInfo.cell_info["coordination"][0].value.cell_id[0];
  return {
    registryDnaHash:     rawReg.type  === "Buffer" ? Buffer.from(rawReg.data)   : Buffer.from(rawReg),
    mutualCreditDnaHash: rawMC.type   === "Buffer" ? Buffer.from(rawMC.data)    : Buffer.from(rawMC),
    coordDnaHash:        rawCoord.type === "Buffer" ? Buffer.from(rawCoord.data) : Buffer.from(rawCoord),
  };
}

// ─────────────────────────────────────────────
// Unversioned — health + SSE
// ─────────────────────────────────────────────

app.get("/", (req, res) => {
  res.json({ name: "Toric Network API", version: "1.0.0", status: appWs ? "connected" : "connecting" });
});

const sseClients = new Set();

app.get("/signals", (req, res) => {
  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.flushHeaders();
  sseClients.add(res);
  const keepalive = setInterval(() => res.write(': keepalive\n\n'), 15000);
  req.on("close", () => {
    clearInterval(keepalive);
    sseClients.delete(res);
  });
});

function broadcastSignal(signal) {
  const data = JSON.stringify(signal);
  for (const client of sseClients) {
    client.write(`data: ${data}\n\n`);
  }
}

// ─────────────────────────────────────────────
// v1 — Status
// ─────────────────────────────────────────────

v1.get("/status", (req, res) => {
  res.json({ name: "Toric Network API", version: "1.0.0", status: appWs ? "connected" : "connecting" });
});

// ─────────────────────────────────────────────
// v1 — Agent
// ─────────────────────────────────────────────

v1.get("/agent/me", async (req, res) => {
  try {
    const info = await appWs.appInfo();
    const cell = info.cell_info["registry"][0].value;
    res.json({ agent: toBase64(cell.cell_id[1]) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/agent/:pubkey/manifests", async (req, res) => {
  try {
    const records = await registryCall("get_agent_manifests", Buffer.from(req.params.pubkey, "base64url"));
    res.json(records.map(formatRecord));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/agent/:pubkey/reputation", async (req, res) => {
  try {
    const score = await registryCall("compute_reputation_score", {
      agent: Buffer.from(req.params.pubkey, "base64url"),
    });
    res.json({ ...score, agent: toBase64(score.agent) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/agent/:pubkey/attestations", async (req, res) => {
  try {
    const records = await registryCall("get_agent_attestations", {
      agent: Buffer.from(req.params.pubkey, "base64url"),
    });
    res.json((records || []).map(formatRecord));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// v1 — Manifests
// ─────────────────────────────────────────────

v1.post("/manifest", async (req, res) => {
  try {
    const { blob } = req.body;
    if (!blob) return res.status(400).json({ error: "blob required" });
    if (blob.upstream_manifest_hashes && blob.upstream_manifest_hashes.length > 0) {
      blob.upstream_manifest_hashes = blob.upstream_manifest_hashes.map(h =>
        typeof h === 'string' ? Buffer.from(h, 'base64url') : h
      );
    }
    const hash = await registryCall("create_manifest", { blob });
    res.status(201).json({ hash: toBase64(hash) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/manifest/:hash", async (req, res) => {
  try {
    const record = await registryCall("get_manifest", Buffer.from(req.params.hash, "base64url"));
    if (!record) return res.status(404).json({ error: "Manifest not found" });
    res.json(formatRecord(record));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/manifest/:hash/attestations", async (req, res) => {
  try {
    const records = await registryCall("get_manifest_attestations", Buffer.from(req.params.hash, "base64url"));
    res.json(records.map(formatRecord));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/manifest/:hash/warrants", async (req, res) => {
  try {
    const records = await registryCall("get_manifest_warrants", Buffer.from(req.params.hash, "base64url"));
    res.json(records.map(formatRecord));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/manifest/:hash/trust-score", async (req, res) => {
  try {
    const result = await registryCall("compute_trust_score", {
      manifest_hash: Buffer.from(req.params.hash, "base64url"),
    });
    res.json({ ...result, manifest_hash: toBase64(result.manifest_hash) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/manifest/:hash/upstreams", async (req, res) => {
  try {
    const hashes = await registryCall("get_upstreams", {
      manifest_hash: Buffer.from(req.params.hash, "base64url"),
    });
    res.json((hashes || []).map(toBase64));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/manifest/:hash/derivatives", async (req, res) => {
  try {
    const hashes = await registryCall("get_derivatives", {
      manifest_hash: Buffer.from(req.params.hash, "base64url"),
    });
    res.json((hashes || []).map(toBase64));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/manifest/:hash/validators", async (req, res) => {
  try {
    const links = await registryCall("get_manifest_validators", {
      manifest_hash: Buffer.from(req.params.hash, "base64url"),
    });
    res.json((links || []).map(toBase64));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/manifest/:hash/validation-history", async (req, res) => {
  try {
    const hashes = await coordinationCall("get_manifest_requests", {
      manifest_hash: Buffer.from(req.params.hash, "base64url"),
    });
    res.json((hashes || []).map(toBase64));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/manifest/:hash/evidence", async (req, res) => {
  try {
    const records = await coordinationCall("get_manifest_evidence", {
      manifest_hash: Buffer.from(req.params.hash, "base64url"),
    });
    res.json((records || []).map(formatRecord));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// v1 — Content convergence
// ─────────────────────────────────────────────

v1.get("/content/:hash/manifests", async (req, res) => {
  try {
    const hashes = await registryCall("get_by_content_hash", {
      content_hash: req.params.hash,
    });
    res.json((hashes || []).map(toBase64));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/manifests", async (req, res) => {
  try {
    const hashes = await registryCall("get_all_manifests", null);
    if (!hashes || hashes.length === 0) return res.json([]);

    // Fetch manifests and trust scores in parallel, return sorted by score
    const results = await Promise.all(
      (hashes || []).map(async (h) => {
        const hash = toBase64(h);
        try {
          const [manifest, trustScore] = await Promise.all([
            registryCall("get_manifest", h),
            registryCall("compute_trust_score", { manifest_hash: h }).catch(() => null),
          ]);
          return {
            hash,
            entry: formatRecord(manifest)?.entry || null,
            author: toBase64(manifest?.signed_action?.hashed?.content?.author),
            score: trustScore?.score ?? 0,
            attestation_count: trustScore?.attestation_count ?? 0,
            passes: trustScore?.passes ?? false,
          };
        } catch(e) { return null; }
      })
    );

    const filtered = results
      .filter(Boolean)
      .sort((a, b) => b.score - a.score);

    res.json(filtered);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// v1 — Attestations & Warrants
// ─────────────────────────────────────────────

v1.post("/attestation", async (req, res) => {
  try {
    const { manifest_hash, blob } = req.body;
    if (!manifest_hash || !blob) return res.status(400).json({ error: "manifest_hash and blob required" });
    const hash = await registryCall("create_attestation", {
      manifest_hash: Buffer.from(manifest_hash, "base64url"),
      blob: Buffer.from(JSON.stringify(blob)),
    });
    res.status(201).json({ hash: toBase64(hash) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

function computeSeverity(evidenceType, expected, actual) {
  switch (evidenceType) {
    case "hash_mismatch":
      return expected === actual ? 0 : 1_000_000;
    case "performance_delta": {
      const exp = parseFloat(expected);
      const act = parseFloat(actual);
      if (isNaN(exp) || isNaN(act) || exp === 0) return 0;
      return Math.min(1_000_000, Math.round(Math.abs(exp - act) / exp * 1_000_000));
    }
    case "connector_output": {
      const total   = parseInt(expected);
      const present = parseInt(actual);
      if (isNaN(total) || total === 0) return 0;
      return Math.min(1_000_000, Math.round((total - present) / total * 1_000_000));
    }
    case "probe_result": {
      const total  = parseInt(expected);
      const passed = parseInt(actual);
      if (isNaN(total) || total === 0) return 0;
      return Math.min(1_000_000, Math.round((total - passed) / total * 1_000_000));
    }
    default:
      return 0;
  }
}

v1.post("/evidence", async (req, res) => {
  try {
    const { manifest_hash, evidence_type, expected, actual, metadata } = req.body;
    if (!manifest_hash || !evidence_type || !expected || !actual)
      return res.status(400).json({ error: "manifest_hash, evidence_type, expected, actual required" });
    const computed_severity = computeSeverity(evidence_type, expected, actual);
    const metaBytes = Buffer.from(JSON.stringify(metadata || {}));
    const result = await coordinationCall("record_evidence", {
      manifest_hash: Buffer.from(manifest_hash, "base64url"),
      evidence_type,
      expected,
      actual,
      computed_severity,
      metadata_blob: metaBytes,
    });
    res.json({ hash: toBase64(result), computed_severity });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.post("/warrant", async (req, res) => {
  try {
    const { manifest_hash, blob } = req.body;
    if (!manifest_hash || !blob) return res.status(400).json({ error: "manifest_hash and blob required" });
    const hash = await registryCall("create_warrant", { manifest_hash, blob });
    res.status(201).json({ hash: toBase64(hash) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.post("/warrant/:hash/confirm", async (req, res) => {
  try {
    const { manifest_hash } = req.body;
    if (!manifest_hash) return res.status(400).json({ error: "manifest_hash required" });
    const result = await registryCall("confirm_warrant", {
      warrant_hash:  Buffer.from(req.params.hash, "base64url"),
      manifest_hash: Buffer.from(manifest_hash, "base64url"),
    });
    res.json({ hash: toBase64(result) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// v1 — Network
// ─────────────────────────────────────────────

v1.get("/network/state", async (req, res) => {
  try {
    const state = await mutualCreditCall("get_network_state", null);
    res.json(state || { attestation_count: 0, next_fibonacci_threshold: 21, credit_supply: 987, cycle: 0, phase: 0 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/dna-hashes", async (req, res) => {
  try {
    const { registryDnaHash, mutualCreditDnaHash, coordDnaHash } = await getDnaHashes();
    const appInfo = await appWs.appInfo();
    const rawId = appInfo.cell_info["identity"]?.[0]?.value?.cell_id?.[0];
    const identityDnaHash = rawId
      ? (rawId.type === "Buffer" ? Buffer.from(rawId.data) : Buffer.from(rawId))
      : null;
    res.json({
      registry:      toBase64(registryDnaHash),
      mutual_credit: toBase64(mutualCreditDnaHash),
      coordination:  toBase64(coordDnaHash),
      identity:      toBase64(identityDnaHash),
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// v1 — Validation
// ─────────────────────────────────────────────

v1.get("/validation/pending", async (req, res) => {
  try {
    const requests = await coordinationCall("get_all_pending_requests", null);
    res.json(requests || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/validation/pending/:pubkey", async (req, res) => {
  try {
    const requests = await coordinationCall("get_pending_requests", Buffer.from(req.params.pubkey, "base64url"));
    res.json(requests || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.post("/validation/request", async (req, res) => {
  try {
    const { manifest_hash } = req.body;
    if (!manifest_hash) return res.status(400).json({ error: "manifest_hash required" });
    const hash = await coordinationCall("request_validation", {
      manifest_hash: Buffer.from(manifest_hash, "base64url"),
      metadata_blob: new Uint8Array(0),
    });
    res.status(201).json({ hash: toBase64(hash) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.post("/validation/evaluate", async (req, res) => {
  try {
    const { request_hash, passed, score, details } = req.body;
    if (!request_hash) return res.status(400).json({ error: "request_hash required" });
    const hash = await coordinationCall("submit_evaluation", {
      request_hash: Buffer.from(request_hash, "base64url"),
      passed: passed || false,
      score:  score  || 0.0,
      details: details || "",
    });
    console.log("evaluation submitted:", toBase64(hash).slice(0, 20) + "...");
    await new Promise(r => setTimeout(r, 2000));
    try {
      const { registryDnaHash, mutualCreditDnaHash } = await getDnaHashes();
      const qResult = await coordinationCall("check_quorum", {
        request_hash:         Buffer.from(request_hash, "base64url"),
        registry_dna_hash:    registryDnaHash,
        mutual_credit_dna_hash: mutualCreditDnaHash,
      });
      console.log("quorum check:", qResult.reached ? "REACHED ✓" : "not yet",
        "(" + qResult.evaluation_count + " evals, weight " + qResult.combined_weight?.toFixed(3) + ")");
    } catch(e) { console.log("quorum check error:", e.message); }
    res.status(201).json({ hash: toBase64(hash) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.post("/validation/commit", async (req, res) => {
  try {
    const { request_hash, commitment_hash } = req.body;
    if (!request_hash || !commitment_hash)
      return res.status(400).json({ error: "request_hash and commitment_hash required" });
    const hash = await coordinationCall("commit_evaluation", {
      request_hash:    Buffer.from(request_hash, "base64url"),
      commitment_hash: Array.from(Buffer.from(commitment_hash, "hex")),
    });
    res.status(201).json({ hash: toBase64(hash) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.post("/validation/reveal", async (req, res) => {
  try {
    const { request_hash, passed, score, details, salt } = req.body;
    if (!request_hash || !salt)
      return res.status(400).json({ error: "request_hash and salt required" });
    const { registryDnaHash, mutualCreditDnaHash } = await getDnaHashes();
    const hash = await coordinationCall("reveal_evaluation", {
      request_hash: Buffer.from(request_hash, "base64url"),
      passed: passed || false,
      score:  score  || 0.0,
      details: details || null,
      salt,
      registry_dna_hash: registryDnaHash,
    });
    await new Promise(r => setTimeout(r, 2000));
    try {
      const qResult = await coordinationCall("check_quorum", {
        request_hash:           Buffer.from(request_hash, "base64url"),
        registry_dna_hash:      registryDnaHash,
        mutual_credit_dna_hash: mutualCreditDnaHash,
      });
      console.log("quorum check:", qResult.reached ? "REACHED ✓" : "not yet",
        "(" + qResult.evaluation_count + " evals, weight " + qResult.combined_weight?.toFixed(3) + ")");
    } catch(e) { console.log("quorum check error:", e.message); }
    res.status(201).json({ hash: toBase64(hash) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.post("/validation/reveal-window", async (req, res) => {
  try {
    const { registryDnaHash, mutualCreditDnaHash } = await getDnaHashes();
    const result = await coordinationCall("check_reveal_window", {
      request_hash:           Buffer.from(req.body.request_hash, "base64url"),
      registry_dna_hash:      registryDnaHash,
      mutual_credit_dna_hash: mutualCreditDnaHash,
    });
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.post("/validation/quorum", async (req, res) => {
  try {
    const { registryDnaHash, mutualCreditDnaHash } = await getDnaHashes();
    const result = await coordinationCall("check_quorum", {
      request_hash:           Buffer.from(req.body.request_hash, "base64url"),
      registry_dna_hash:      registryDnaHash,
      mutual_credit_dna_hash: mutualCreditDnaHash,
    });
    res.json(result);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// v1 — Debug
// ─────────────────────────────────────────────

v1.post("/debug/attest/:hash", async (req, res) => {
  try {
    const hash = await registryCall("create_quorum_attestation",
      Buffer.from(req.params.hash, "base64url"));
    res.json({ attestation_hash: toBase64(hash) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// v1 — Identity
// ─────────────────────────────────────────────

v1.post("/agent/register", async (req, res) => {
  try {
    const { agent_type, capabilities, software_hash, version, metadata } = req.body;
    if (!agent_type || !capabilities || !software_hash || !version)
      return res.status(400).json({ error: "agent_type, capabilities, software_hash, version required" });
    const hash = await identityCall("register_agent", {
      agent_type,
      capabilities,
      software_hash,
      version,
      metadata: metadata || null,
    });
    res.status(201).json({ hash: toBase64(hash) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/agent/:pubkey/manifest", async (req, res) => {
  try {
    const record = await identityCall("get_agent_manifest",
      Buffer.from(req.params.pubkey, "base64url"));
    res.json(record ? formatRecord(record) : null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

v1.get("/agents", async (req, res) => {
  try {
    const { capability } = req.query;
    const agents = capability
      ? await identityCall("get_agents_by_capability", { capability })
      : await identityCall("get_all_agents", null);
    res.json((agents || []).map(toBase64));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────

connect();

app.listen(API_PORT, () => {
  console.log(`Toric API v1 running on http://localhost:${API_PORT}`);
  console.log(`Open UI at: http://localhost:UI_PORT/?api=${API_PORT}`);
  console.log(`  replace UI_PORT with the port hc-spin printed`);
});