#!/usr/bin/env node
// POI — Bittensor Connector
// Reads on-chain model commitments from a Bittensor subnet,
// fetches the committed HuggingFace models, and registers
// manifests in POI with full provenance chain.
//
// Usage: python3 bt-connector.py <netuid> | node bt-connector.js
// Or:    node bt-connector.js --netuid 37 [--dry-run] [--limit 10]
//
// Requires: python3 with bittensor SDK installed
// The Python bridge script outputs JSON to stdout.

import { execSync } from "child_process";
import { writeFileSync, unlinkSync } from "fs";
import crypto from "crypto";

const POI_API = process.env.POI_API || "http://localhost:3000/v1";
const HF_TOKEN  = process.env.HF_TOKEN || null;
const DRY_RUN   = process.argv.includes("--dry-run");
const NETUID    = (() => {
  const i = process.argv.indexOf("--netuid");
  return i >= 0 ? parseInt(process.argv[i + 1]) : 37;
})();
const LIMIT = (() => {
  const i = process.argv.indexOf("--limit");
  return i >= 0 ? parseInt(process.argv[i + 1]) : 50;
})();

console.log(`\nPOI Bittensor Connector`);
console.log(`Subnet  : ${NETUID}`);
console.log(`POI API : ${POI_API}`);
console.log(`Mode    : ${DRY_RUN ? "DRY RUN" : "LIVE"}`);
console.log(`Limit   : ${LIMIT} miners\n`);

// ─────────────────────────────────────────────
// Python bridge — reads metagraph + commitments
// ─────────────────────────────────────────────

function queryBittensor(netuid, limit) {
  const script = `
import json
import bittensor as bt

sub = bt.Subtensor('finney')
mg = sub.metagraph(${netuid})
commits = sub.get_all_commitments(netuid=${netuid})

results = []
for hotkey, commitment in commits.items():
    try:
        uid = mg.hotkeys.index(hotkey) if hotkey in mg.hotkeys else -1
        emission = float(mg.emission[uid]) if uid >= 0 else 0.0
        results.append({
            'hotkey': hotkey,
            'uid': uid,
            'emission': emission,
            'commitment': commitment,
        })
    except Exception as e:
        pass

results.sort(key=lambda x: x['emission'], reverse=True)
print(json.dumps(results[:${limit}]))
`;

  const tmpFile = `/tmp/bt_query_${Date.now()}.py`;
  writeFileSync(tmpFile, script);
  try {
    const out = execSync(`python3 ${tmpFile}`, { timeout: 30000 }).toString().trim();
    unlinkSync(tmpFile);
    return JSON.parse(out);
  } catch (e) {
    unlinkSync(tmpFile);
    throw e;
  }
}

// ─────────────────────────────────────────────
// Parse SN37 commitment format:
// namespace:model_name:git_hash:signature:version
// ─────────────────────────────────────────────

function parseCommitment(commitment) {
  const parts = commitment.split(":");
  if (parts.length < 3) return null;

  // Format: namespace:model_name:git_hash:signature:version
  // But model_name might contain colons, so take first two as namespace/model
  const namespace = parts[0];
  const modelName = parts[1];
  const gitHash   = parts[2];

  if (!namespace || !modelName) return null;

  return {
    hf_model_id: `${namespace}/${modelName}`,
    git_hash: gitHash,
  };
}

// ─────────────────────────────────────────────
// HuggingFace helpers
// ─────────────────────────────────────────────

async function hfGet(path) {
  const headers = { "Accept": "application/json" };
  if (HF_TOKEN) headers["Authorization"] = `Bearer ${HF_TOKEN}`;
  const res = await fetch(`https://huggingface.co/api/${path}`, { headers });
  if (!res.ok) throw new Error(`HF ${path} → ${res.status}`);
  return res.json();
}

function buildContentHash(siblings) {
  const weightExts = /\.(safetensors|bin|pt|gguf|ggml|pth|h5|ot)$/i;
  const weightFiles = siblings
    .filter(f => weightExts.test(f.rfilename) && f.lfs?.sha256)
    .sort((a, b) => a.rfilename.localeCompare(b.rfilename));

  if (weightFiles.length === 0) {
    const fallback = siblings
      .sort((a, b) => a.rfilename.localeCompare(b.rfilename))
      .map(f => `${f.rfilename}:${f.size || 0}`)
      .join("\n");
    return crypto.createHash("sha256").update(fallback).digest("hex");
  }

  return crypto.createHash("sha256")
    .update(weightFiles.map(f => f.lfs.sha256).join("\n"))
    .digest("hex");
}

function detectArchitecture(info, modelId) {
  const tags = (info.tags || []).map(t => t.toLowerCase());
  const id   = modelId.toLowerCase();
  for (const arch of ["llama", "mistral", "falcon", "gpt2", "gpt-j", "phi",
                       "gemma", "qwen", "mamba", "bloom", "opt", "t5", "bert"]) {
    if (tags.some(t => t.includes(arch)) || id.includes(arch)) return arch;
  }
  return "unknown";
}

function estimateParams(info, modelId) {
  if (info.safetensors?.total) return info.safetensors.total;
  const match = modelId.match(/(\d+(?:\.\d+)?)\s*([bBmM])/);
  if (match) {
    const n = parseFloat(match[1]);
    const unit = match[2].toLowerCase();
    return Math.round(n * (unit === "b" ? 1e9 : 1e6));
  }
  return 0;
}

// ─────────────────────────────────────────────
// POI API helpers
// ─────────────────────────────────────────────

async function poiPost(path, body) {
  const res = await fetch(`${POI_API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(`POI ${path} → ${res.status}: ${JSON.stringify(json)}`);
  return json;
}

// ─────────────────────────────────────────────
// Process one miner
// ─────────────────────────────────────────────

async function processMiner(miner) {
  const { hotkey, uid, emission, commitment } = miner;
  console.log(`\n  hotkey: ${hotkey.slice(0, 20)}... uid=${uid} emission=${emission.toFixed(4)}`);
  console.log(`  commitment: ${commitment.slice(0, 60)}...`);

  const parsed = parseCommitment(commitment);
  if (!parsed) {
    console.log(`  skipping — cannot parse commitment`);
    return null;
  }

  console.log(`  HF model: ${parsed.hf_model_id}`);

  // Fetch model info from HuggingFace
  let info;
  try {
    info = await hfGet(`models/${parsed.hf_model_id}`);
  } catch (e) {
    console.log(`  skipping — HF fetch failed: ${e.message}`);
    return null;
  }

  const contentHash = buildContentHash(info.siblings || []);
  console.log(`  content hash: ${contentHash.slice(0, 16)}...`);

  const blob = {
    blob_type: "ai_model",
    content_hash: contentHash,
    architecture: detectArchitecture(info, parsed.hf_model_id),
    parameter_count: estimateParams(info, parsed.hf_model_id),
    upstream_manifest_hashes: [],
    connector_source: "bittensor",
    version: parsed.git_hash || info.sha || null,
    description: info.cardData?.model_description || null,
    license: info.cardData?.license ||
      (info.tags || []).find(t => t.startsWith("license:"))?.replace("license:", "") || null,
    artifact_timestamp: info.lastModified
      ? Math.floor(new Date(info.lastModified).getTime() / 1000) : null,
    fine_tuned_from: info.cardData?.base_model || null,
    training_data_description: info.cardData?.datasets
      ? JSON.stringify(info.cardData.datasets) : null,
    quantization: null,
    context_length: null,
    tags: [
      `hf_id:${parsed.hf_model_id}`,
      `bt_hotkey:${hotkey}`,
      `bt_netuid:${NETUID}`,
      `bt_uid:${uid}`,
      ...(info.tags || []).slice(0, 6),
    ],
  };

  if (DRY_RUN) {
    console.log(`  [DRY RUN] would register:`, JSON.stringify(blob, null, 4));
    return null;
  }

  try {
    const { hash } = await poiPost("/manifest", { blob });
    console.log(`  ✓ manifest: ${hash}`);

    const { hash: reqHash } = await poiPost("/validation/request", {
      manifest_hash: hash,
      metadata: {
        bittensor_hotkey: hotkey,
        bittensor_netuid: NETUID,
        bittensor_uid: uid,
        hf_model_id: parsed.hf_model_id,
      },
    });
    console.log(`  ✓ validation requested: ${reqHash}`);
    return { hotkey, hf_model_id: parsed.hf_model_id, manifest_hash: hash };
  } catch (e) {
    console.log(`  error: ${e.message}`);
    return null;
  }
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

async function main() {
  console.log(`Querying Bittensor SN${NETUID} metagraph...`);

  try {
    await poiPost("/agent/register", {
      agent_type: "connector",
      capabilities: ["connect:bittensor"],
      software_hash: "bt-connector-v1",
      version: "1.0.0",
    });
  } catch(e) { /* non-fatal */ }

  let miners;
  try {
    miners = queryBittensor(NETUID, LIMIT);
  } catch (e) {
    console.error("Failed to query Bittensor:", e.message);
    process.exit(1);
  }

  console.log(`Found ${miners.length} miners with commitments`);

  const results = [];
  for (const miner of miners) {
    const result = await processMiner(miner);
    if (result) results.push(result);
    // Small delay to avoid rate limiting
    await new Promise(r => setTimeout(r, 500));
  }

  console.log(`\n✓ Done. Registered ${results.length} models.`);
  if (results.length > 0) {
    console.log(`\nRegistered models:`);
    for (const r of results) {
      console.log(`  ${r.hf_model_id} → ${r.manifest_hash}`);
    }
  }
}

const WATCH = process.argv.includes("--watch");
const WATCH_INTERVAL = parseInt(
  process.argv[process.argv.indexOf("--interval") + 1] || "1800"
) * 1000;

if (WATCH) {
  console.log(`\nWatch mode — polling every ${WATCH_INTERVAL / 1000}s`);
  const seen = new Set();

  async function poll() {
    try {
      const miners = queryBittensor(NETUID, LIMIT);
      let newCount = 0;
      for (const miner of miners) {
        const key = `${miner.hotkey}:${miner.commitment}`;
        if (!seen.has(key)) {
          seen.add(key);
          newCount++;
          await processMiner(miner);
        }
      }
      console.log(`[${new Date().toISOString()}] Checked ${miners.length} miners, ${newCount} new`);
    } catch(e) {
      console.error(`Poll error: ${e.message}`);
    }
    setTimeout(poll, WATCH_INTERVAL);
  }

  poll();
} else {
  main().catch(e => {
  console.error("Error:", e.message);
  process.exit(1);
});
}
