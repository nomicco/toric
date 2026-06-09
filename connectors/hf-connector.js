#!/usr/bin/env node
// POI — HuggingFace Connector
// Usage: node hf-connector.js <model_id> [--dry-run]
// Example: node hf-connector.js meta-llama/Llama-3.1-8B
// Example: node hf-connector.js mistralai/Mistral-7B-v0.1 --dry-run

import crypto from "crypto";

const POI_API = process.env.POI_API || "http://localhost:3000/v1";
const HF_API  = "https://huggingface.co/api";
const HF_TOKEN = process.env.HF_TOKEN || null; // optional — needed for gated models

const modelFlagIdx = process.argv.indexOf("--model");
const modelId = modelFlagIdx !== -1
  ? process.argv[modelFlagIdx + 1]
  : process.argv[2];
const dryRun = process.argv.includes("--dry-run");

if (!modelId || modelId.startsWith("--")) {
  console.error("Usage: node hf-connector.js <owner/model> [--dry-run]");
  console.error("   or: node hf-connector.js --model <owner/model> [--dry-run]");
  process.exit(1);
}

// ─────────────────────────────────────────────
// Fetch helpers
// ─────────────────────────────────────────────

async function hfGet(path) {
  const headers = { "Accept": "application/json" };
  if (HF_TOKEN) headers["Authorization"] = `Bearer ${HF_TOKEN}`;
  const res = await fetch(`${HF_API}/${path}`);
  if (!res.ok) throw new Error(`HF API ${path} → ${res.status} ${res.statusText}`);
  return res.json();
}

async function poiPost(path, body) {
  const res = await fetch(`${POI_API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(`POI API ${path} → ${res.status}: ${JSON.stringify(json)}`);
  return json;
}

// ─────────────────────────────────────────────
// Build a deterministic content_hash from the
// model's file list (sha256 of sorted sha256s).
// No download needed — HF provides file SHAs.
// ─────────────────────────────────────────────

function buildContentHash(siblings) {
  // siblings: [{ rfilename, size, lfs: { sha256 } }]
  const weightExts = /\.(safetensors|bin|pt|gguf|ggml|pth|h5|ot)$/i;
  const weightFiles = siblings
    .filter(f => weightExts.test(f.rfilename) && f.lfs?.sha256)
    .sort((a, b) => a.rfilename.localeCompare(b.rfilename));

  if (weightFiles.length === 0) {
    // Fall back: hash all file names + sizes
    const fallback = siblings
      .sort((a, b) => a.rfilename.localeCompare(b.rfilename))
      .map(f => `${f.rfilename}:${f.size || 0}`)
      .join("\n");
    return crypto.createHash("sha256").update(fallback).digest("hex");
  }

  const combined = weightFiles.map(f => f.lfs.sha256).join("\n");
  return crypto.createHash("sha256").update(combined).digest("hex");
}

// ─────────────────────────────────────────────
// Detect architecture from model card tags
// ─────────────────────────────────────────────

function detectArchitecture(modelInfo) {
  const tags = (modelInfo.tags || []).map(t => t.toLowerCase());
  const id   = modelId.toLowerCase();

  for (const arch of ["llama", "mistral", "falcon", "gpt2", "gpt-j", "gpt-neox",
                       "bloom", "opt", "t5", "bart", "bert", "roberta", "phi",
                       "gemma", "qwen", "mamba", "rwkv", "stablelm", "codellama"]) {
    if (tags.some(t => t.includes(arch)) || id.includes(arch)) return arch;
  }
  return modelInfo.modelId?.split("/")[1]?.split("-")[0]?.toLowerCase() || "unknown";
}

// ─────────────────────────────────────────────
// Estimate parameter count from model card or name
// ─────────────────────────────────────────────

function estimateParams(modelInfo) {
  // Check safetensors metadata if present
  if (modelInfo.safetensors?.total) return modelInfo.safetensors.total;

  // Parse from model name: "7B" → 7_000_000_000
  const match = modelId.match(/(\d+(?:\.\d+)?)\s*([bBmM])/);
  if (match) {
    const n = parseFloat(match[1]);
    const unit = match[2].toLowerCase();
    return Math.round(n * (unit === "b" ? 1e9 : 1e6));
  }
  return 0;
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

async function main() {
  console.log(`\nPOI HuggingFace Connector`);
  console.log(`Model  : ${modelId}`);
  console.log(`POI API: ${POI_API}`);
  if (dryRun) console.log(`Mode   : DRY RUN — will not write to DHT\n`);
  else console.log(`Mode   : LIVE — will register to DHT\n`);

  // 1. Fetch model card
  console.log("Fetching model card...");
  const info = await hfGet(`models/${modelId}`);

  // 2. Build content hash from file list
  console.log(`Found ${info.siblings?.length || 0} files`);
  const contentHash = buildContentHash(info.siblings || []);
  console.log(`Content hash: ${contentHash}`);

  // 3. Build the manifest blob
  const blob = {
    blob_type: "ai_model",
    content_hash: contentHash,
    architecture: detectArchitecture(info),
    parameter_count: estimateParams(info),
    upstream_manifest_hashes: [],
    connector_source: "huggingface",
    version: info.sha || null,
    description: info.cardData?.model_description || null,
    license: info.cardData?.license || (info.tags || []).find(t => t.startsWith("license:"))?.replace("license:", "") || null,
    artifact_timestamp: info.lastModified ? Math.floor(new Date(info.lastModified).getTime() / 1000) : null,
    fine_tuned_from: info.cardData?.base_model || null,
    training_data_description: info.cardData?.datasets ? JSON.stringify(info.cardData.datasets) : null,
    quantization: (info.tags || []).find(t => ["gguf","ggml","awq","gptq","int8","fp16","fp32"].includes(t)) || null,
    context_length: null,
    tags: [`hf_id:${modelId}`, ...(info.tags || []).slice(0, 9)],
  };

  console.log("\nManifest blob:");
  console.log(JSON.stringify(blob, null, 2));

  if (dryRun) {
    console.log("\nDry run complete. No DHT write.");
    return;
  }

  // 4. Register manifest
  console.log("\nRegistering manifest...");
  const { hash } = await poiPost("/manifest", { blob });
  console.log(`✓ Manifest registered: ${hash}`);

// Register connector identity (idempotent)
  try {
    await poiPost("/agent/register", {
      agent_type: "connector",
      capabilities: ["connect:huggingface"],
      software_hash: "hf-connector-v1",
      version: "1.0.0",
    });
  } catch(e) { /* non-fatal */ }

  // 5. Request validation
  console.log("Requesting validation...");
  const { hash: requestHash } = await poiPost("/validation/request", {
    manifest_hash: hash,
    metadata: {
      model_id: modelId,
      source: "huggingface",
    },
  });
  console.log(`✓ Validation requested: ${requestHash}`);

  console.log(`\nDone. Verify at: curl ${POI_API}/manifest/${hash}`);
}

const WATCH = process.argv.includes("--watch");
const WATCH_INTERVAL = parseInt(
  process.argv[process.argv.indexOf("--interval") + 1] || "3600"
) * 1000;

if (WATCH) {
  console.log(`\nWatch mode — polling every ${WATCH_INTERVAL / 1000}s`);
  const seen = new Set();

  async function poll() {
    try {
      const info = await hfGet(`models/${modelId}`);
      const key = `${modelId}:${info.sha}`;
      if (!seen.has(key)) {
        seen.add(key);
        console.log(`\n[${new Date().toISOString()}] New version detected: ${info.sha}`);
        await main();
      } else {
        console.log(`[${new Date().toISOString()}] No change — ${info.sha}`);
      }
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