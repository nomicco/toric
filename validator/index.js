#!/usr/bin/env node
// Toric Validator Client v2
// Adds HuggingFace-aware hash verification.
// Auto-files warrants on hash mismatch — no manual path for tampered_weights.
// Usage: TORIC_AGENT=uhCAk... node index.js
// Dry run: DRY_RUN=true TORIC_AGENT=uhCAk... node index.js

import fetch from 'node-fetch';
import crypto from 'crypto';

const BASE_URL = process.env.TORIC_API || process.env.POI_API || 'http://localhost:3000';
const API = BASE_URL + '/v1';
const AGENT   = process.env.TORIC_AGENT || process.env.POI_AGENT || '';
const DRY_RUN = process.env.DRY_RUN === 'true';
const HF_TOKEN = process.env.HF_TOKEN || null;

// ─────────────────────────────────────────────
// Geometry constants
// All timing derived from TAU_MS — base network tick.
// Conservative WAN estimate. Becomes a GeometryParam in Phase 5.5.
// ─────────────────────────────────────────────
const TAU_MS    = 10_000;
const PHI       = 1.6180339887498948;
const PHI_SQ    = 2.6180339887498948;
const PHI_CU    = 4.2360679774997896;
const PHI_4     = 6.8541019662496847;
const INV_PHI   = 0.6180339887498948;
const MIN_VALIDATORS = 3; // F(4) — mirrors Rust constant

const POLL_INTERVAL_MS        = TAU_MS * PHI;           // fallback poll: ~16.18s
const RECONNECT_DELAY_MS      = Math.round(TAU_MS / PHI_SQ);  // ~3820ms
const POST_SUBMIT_WAIT_MS     = Math.round(TAU_MS / PHI_CU);  // ~2361ms
const REVEAL_POLL_INTERVAL_MS = Math.round(TAU_MS / PHI_SQ);  // ~3820ms
const INTER_REQUEST_DELAY_MS  = Math.round(TAU_MS / PHI_4);   // ~1459ms
const REVEAL_DEADLINE_MS      = PHI_4 * TAU_MS * MIN_VALIDATORS; // mirrors Rust
const REVEAL_POLL_ATTEMPTS    = Math.ceil(REVEAL_DEADLINE_MS / REVEAL_POLL_INTERVAL_MS);

console.log('Toric Validator Client v2');
console.log('API:', API);
console.log('Agent:', AGENT || '(not set)');
console.log('Poll interval:', POLL_INTERVAL + 'ms');
console.log('Dry run:', DRY_RUN);
console.log('HF token:', HF_TOKEN ? 'set' : 'not set (public models only)');
console.log('');

function toBase64url(hash) {
  if (!hash) return 'unknown';
  if (typeof hash === 'string') return hash.slice(0, 20) + '...';
  if (hash.type === 'Buffer') return Buffer.from(hash.data).toString('base64url').slice(0, 20) + '...';
  return 'unknown';
}

// ─────────────────────────────────────────────
// HuggingFace helpers
// ─────────────────────────────────────────────

async function hfGet(path) {
  const headers = { 'Accept': 'application/json' };
  if (HF_TOKEN) headers['Authorization'] = `Bearer ${HF_TOKEN}`;
  const res = await fetch(`https://huggingface.co/api/${path}`, { headers });
  if (!res.ok) throw new Error(`HF API ${path} → ${res.status} ${res.statusText}`);
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
      .join('\n');
    return crypto.createHash('sha256').update(fallback).digest('hex');
  }

  const combined = weightFiles.map(f => f.lfs.sha256).join('\n');
  return crypto.createHash('sha256').update(combined).digest('hex');
}

function extractHfModelId(entry) {
  const tags = entry.tags || [];
  const tag = tags.find(t => t && t.startsWith('hf_id:'));
  return tag ? tag.slice(6) : null;
}

// ─────────────────────────────────────────────
// Auto-warrant — fires when hash mismatch detected
// Evidence recorded first, severity computed by backend
// ─────────────────────────────────────────────

async function fileHashMismatchWarrant(manifestHash, registeredHash, computedHash) {
  if (DRY_RUN) {
    console.log('  [DRY RUN] would file TamperedWeights warrant');
    console.log('    registered:', registeredHash);
    console.log('    computed:  ', computedHash);
    return;
  }

  try {
    // Step 1 — record evidence (severity computed by backend: always 1_000_000 for hash mismatch)
    const evidenceRes = await fetch(`${API}/evidence`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        manifest_hash: manifestHash,
        evidence_type: 'hash_mismatch',
        expected: registeredHash,
        actual: computedHash,
        metadata: { validator: AGENT, detected_at: new Date().toISOString() },
      }),
    });
    const evidenceData = await evidenceRes.json();

    if (!evidenceData.hash) {
      console.log('  warrant evidence error:', evidenceData.error);
      return;
    }

    console.log('  evidence recorded:', evidenceData.hash.slice(0, 20) + '...');
    console.log('  computed severity:', evidenceData.computed_severity);

    // Step 2 — file warrant pointing at evidence
    const warrantRes = await fetch(`${API}/warrant`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        manifest_hash: manifestHash,
        blob: {
          blob_type: 'tampered_weights',
          evidence_hash: evidenceData.hash,
          expected_hash: registeredHash,
          found_hash: computedHash,
          computed_severity: evidenceData.computed_severity,
          description: `Hash mismatch detected by validator ${AGENT.slice(0, 20)}...`,
        },
      }),
    });
    const warrantData = await warrantRes.json();

    if (warrantData.hash) {
      console.log('  ⚠ warrant filed:', warrantData.hash.slice(0, 20) + '...');
    } else {
      console.log('  warrant error:', warrantData.error);
    }
  } catch(e) {
    console.log('  error filing warrant:', e.message);
  }
}

// ─────────────────────────────────────────────
// Verify a manifest
// Returns { passed, score, details, mismatch }
// mismatch: { registered, computed } — set only on hash mismatch
// ─────────────────────────────────────────────

async function verifyManifest(manifest) {
  let entry = manifest.entry || {};
  const registeredHash = entry.content_hash;

  console.log('  registered hash:', registeredHash);

  if (!registeredHash) {
    return { passed: false, score: 0.0, details: 'No content_hash registered — cannot verify' };
  }

  const connectorSource = entry.connector_source;

  // Bittensor models that committed to HuggingFace — verify via HF
  if (connectorSource === 'bittensor') {
    const modelId = extractHfModelId(entry);
    if (modelId) {
      entry = { ...entry, connector_source: 'huggingface' };
    }
  }

  // ── HuggingFace path ──────────────────────
  if (connectorSource === 'huggingface' || entry.connector_source === 'huggingface') {
    const modelId = extractHfModelId(entry);

    if (!modelId) {
      console.log('  HF manifest but no hf_id tag — falling back to unverifiable');
      return {
        passed: true,
        score: 0.5,
        details: 'HuggingFace manifest — model ID not in tags, hash verification skipped',
      };
    }

    console.log('  HuggingFace model:', modelId);
    console.log('  fetching file list from HF API...');

    try {
      const info = await hfGet(`models/${modelId}`);
      const computedHash = buildContentHash(info.siblings || []);

      console.log('  computed hash: ', computedHash);
      const matches = computedHash === registeredHash;
      console.log('  match:', matches ? 'YES ✓' : 'NO ✗');

      if (matches) {
        const weightCount = (info.siblings || [])
          .filter(f => /\.(safetensors|bin|pt|gguf|ggml|pth|h5|ot)$/i.test(f.rfilename) && f.lfs?.sha256)
          .length;
        return {
          passed: true,
          score: 1.0,
          details: `HF hash verified: ${weightCount} weight files matched. Hash: ${computedHash}`,
        };
      } else {
        // Hash mismatch — return with mismatch data for auto-warrant
        return {
          passed: false,
          score: 0.0,
          details: `HF hash mismatch. Registered: ${registeredHash} | Recomputed: ${computedHash}`,
          mismatch: { registered: registeredHash, computed: computedHash },
        };
      }
    } catch (e) {
      console.log('  HF API error:', e.message);
      return {
        passed: false,
        score: 0.0,
        details: `HF verification failed: ${e.message}`,
      };
    }
  }

  // ── Generic fallback ──
  console.log('  no verification path for connector_source:', connectorSource || 'none');
  return {
    passed: true,
    score: 0.5,
    details: `No verification method for connector_source="${connectorSource || 'none'}". Hash on record: ${registeredHash}`,
  };
}

// ─────────────────────────────────────────────
// Parse request entry — extract manifest hash
// ─────────────────────────────────────────────

function extractManifestHash(request) {
  const entryBuf = request.entry?.Present?.entry;
  if (!entryBuf || entryBuf.type !== 'Buffer') return null;

  const data = Buffer.from(entryBuf.data);
  const keyMarker = Buffer.from([
    0xad,
    0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68,
  ]);
  const keyIdx = data.indexOf(keyMarker);
  if (keyIdx === -1) return null;

  const hashStart = keyIdx + keyMarker.length + 2;
  const hashBytes = data.slice(hashStart, hashStart + 39);
  return hashBytes.toString('base64url');
}

function extractRequestHash(request) {
  const hashBuf = request.signed_action?.hashed?.hash;
  if (!hashBuf || hashBuf.type !== 'Buffer') return null;
  return Buffer.from(hashBuf.data).toString('base64url');
}

async function processRequest(request, agent) {
  const requestHash = extractRequestHash(request);
  if (!requestHash) { console.log('  skipping — cannot parse request hash'); return; }

  console.log('  processing:', requestHash.slice(0, 30) + '...');

  // Skip if quorum already reached
  try {
    const qRes = await fetch(`${API}/validation/quorum`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request_hash: requestHash }),
    });
    const qData = await qRes.json();
    if (qData.reached) {
      console.log('  quorum already reached — skipping');
      return;
    }
  } catch(e) { /* proceed if check fails */ }

  const manifestHash = extractManifestHash(request);
  if (!manifestHash) { console.log('  skipping — cannot parse manifest hash'); return; }

  console.log('  manifest hash:', manifestHash.slice(0, 30) + '...');

  let manifest;
  try {
    const res = await fetch(`${API}/manifest/${manifestHash}`);
    if (!res.ok) { console.log('  manifest not found'); return; }
    manifest = await res.json();
  } catch(e) {
    console.log('  error fetching manifest:', e.message);
    return;
  }

  const entry = manifest.entry || {};
  console.log('  connector_source:', entry.connector_source || 'none');

  const result = await verifyManifest(manifest);
  console.log('  verdict:', result.passed ? 'PASS ✓' : 'FAIL ✗');
  console.log('  score:', result.score);

  // Auto-file warrant on hash mismatch — no manual path for this type
  if (result.mismatch) {
    console.log('  hash mismatch detected — filing warrant automatically...');
    await fileHashMismatchWarrant(
      manifestHash,
      result.mismatch.registered,
      result.mismatch.computed
    );
  }

  if (DRY_RUN) {
    console.log('  [DRY RUN] skipping submission');
    return;
  }

  // Phase 1 — commit
  const salt = crypto.randomBytes(32).toString('hex');
  // Score normalized to 6 decimal places — matches Rust's {:.6} format.
  // Prevents f64 string representation divergence between JS and Rust.
  const preimage = `${result.passed}:${result.score.toFixed(6)}:${result.details || ''}:${salt}`;
  const commitmentHash = crypto.createHash('sha256').update(preimage).digest('hex');

  console.log('  committing...');
  try {
    const commitRes = await fetch(`${API}/validation/commit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        request_hash: requestHash,
        commitment_hash: commitmentHash,
      }),
    });
    const commitData = await commitRes.json();
    if (!commitData.hash) {
      console.log('  commit error:', commitData.error);
      return;
    }
    console.log('  committed:', commitData.hash.slice(0, 20) + '...');
  } catch(e) {
    console.log('  error committing:', e.message);
    return;
  }

  // Wait for reveal window — poll until φ⁴ threshold crossed
  console.log('  waiting for reveal window...');
  // Poll until reveal window opens or deadline expires.
  // Poll interval: τ/φ² — frequent enough to catch the window without hammering.
  // Attempts: ceil(REVEAL_DEADLINE / poll_interval) — deadline-derived, not arbitrary.
  let windowOpen = false;
  for (let i = 0; i < REVEAL_POLL_ATTEMPTS; i++) {
    await new Promise(r => setTimeout(r, REVEAL_POLL_INTERVAL_MS));
    try {
      const windowRes = await fetch(`${API}/validation/reveal-window`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_hash: requestHash }),
      });
      const windowData = await windowRes.json();
      console.log(`  reveal window: ${windowData.reveal_window_open ? 'OPEN' : 'waiting'} (weight ${windowData.commitment_weight?.toFixed(3)}, threshold ${windowData.phi_4_threshold?.toFixed(3)}) [${i + 1}/${REVEAL_POLL_ATTEMPTS}]`);
      if (windowData.reveal_window_open) {
        windowOpen = true;
        break;
      }
    } catch(e) { /* continue polling */ }
  }

  if (!windowOpen) {
    console.log(`  reveal window did not open within deadline (${(REVEAL_DEADLINE_MS/1000).toFixed(1)}s) — recording timeout evidence`);

    // Record reveal timeout as ValidationEvidence.
    // Makes the commit-without-reveal visible on the DHT permanently.
    // Feeds into total_commits/total_reveals ratio in ReputationCache.
    // The geometry compounds the cost over time without additional enforcement.
    if (!DRY_RUN) {
      try {
        const evidenceRes = await fetch(`${API}/evidence`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            manifest_hash: manifestHash,
            evidence_type: 'reveal_timeout',
            expected: String(MIN_VALIDATORS),
            actual: '0',
            metadata: {
              validator: AGENT,
              request_hash: requestHash,
              deadline_ms: REVEAL_DEADLINE_MS,
              detected_at: new Date().toISOString(),
            },
          }),
        });
        const evidenceData = await evidenceRes.json();
        if (evidenceData.hash) {
          console.log(`  timeout evidence recorded: ${evidenceData.hash.slice(0, 20)}...`);
          console.log(`  computed severity: ${evidenceData.computed_severity}`);
        } else {
          console.log(`  evidence error: ${evidenceData.error}`);
        }
      } catch(e) {
        console.log(`  error recording timeout evidence: ${e.message}`);
      }
    } else {
      console.log(`  [DRY RUN] would record reveal_timeout evidence`);
    }

    return;
  }

  // Phase 2 — reveal
  console.log('  revealing...');
  let revealSucceeded = false;
  try {
    const revealRes = await fetch(`${API}/validation/reveal`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        request_hash: requestHash,
        passed: result.passed,
        score: result.score,
        details: result.details,
        salt,
      }),
    });
    const revealData = await revealRes.json();
    if (revealData.hash) {
      console.log('  revealed:', revealData.hash.slice(0, 20) + '...');
      revealSucceeded = true;
    } else {
      console.log('  reveal error:', revealData.error);
    }
  } catch(e) {
    console.log('  error revealing:', e.message);
  }

  if (!revealSucceeded) return;

  // Wait for quorum to propagate before pulling credit update
  await new Promise(r => setTimeout(r, POST_SUBMIT_WAIT_MS));

  // Check if quorum reached — pull model, not push
  let quorumReached = false;
  let agreedWithConsensus = false;
  try {
    const qRes = await fetch(`${API}/validation/quorum`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request_hash: requestHash }),
    });
    const qData = await qRes.json();
    quorumReached = qData.reached || false;
    console.log('  quorum:', quorumReached ? 'REACHED ✓' : 'not yet',
      `(${qData.evaluation_count} evals, weight ${qData.combined_weight?.toFixed(3)})`);

    // Determine if this validator agreed with consensus
    // Consensus passed if quorum reached — quorum requires passing_weight >= threshold
    agreedWithConsensus = result.passed === quorumReached;
  } catch(e) {
    console.log('  quorum check error:', e.message);
  }

  if (!quorumReached || DRY_RUN) return;

  // Pull credit limit update for this validator
  // Each validator pulls their own — no cross-machine push needed
  try {
    const agentRes = await fetch(`${API}/agent/me`);
    const agentData = await agentRes.json();
    const myPubkey = agentData.agent;

    const creditRes = await fetch(`${API}/agent/${myPubkey}/credit-update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const creditData = await creditRes.json();
    if (creditData.hash) {
      console.log('  credit limit updated:', creditData.hash.slice(0, 20) + '...');
    } else {
      console.log('  credit update skipped:', creditData.error || 'no change');
    }
  } catch(e) {
    console.log('  credit update error:', e.message);
  }

  // Record convergence signal for this validator
  // Each validator records their own — no cross-machine push needed
  try {
    const agentRes = await fetch(`${API}/agent/me`);
    const agentData = await agentRes.json();
    const myPubkey = agentData.agent;

    const convRes = await fetch(`${API}/agent/${myPubkey}/convergence`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agreed: agreedWithConsensus,
        request_hash: requestHash,
      }),
    });
    const convData = await convRes.json();
    if (convData.hash) {
      console.log('  convergence recorded:', agreedWithConsensus ? 'agreed ✓' : 'dissented');
    }
  } catch(e) {
    console.log('  convergence error:', e.message);
  }
}

// ─────────────────────────────────────────────
// Main validation loop
// ─────────────────────────────────────────────

async function runValidationCycle(agent) {
  console.log('[' + new Date().toISOString() + '] checking for pending requests...');
  try {
    const res = await fetch(`${API}/validation/pending`);
    const raw = await res.json();
    const requests = Array.isArray(raw) ? raw : [];

    if (requests.length === 0) {
      console.log('  no pending requests');
      return;
    }

    console.log('  found', requests.length, 'pending request(s)');
    for (const request of requests) {
      await processRequest(request, agent);
      await new Promise(r => setTimeout(r, INTER_REQUEST_DELAY_MS));
    }
  } catch (e) {
    console.log('  error:', e.message);
  }
}

async function start() {
  if (!AGENT) {
    console.error('TORIC_AGENT environment variable required.');
    process.exit(1);
  }

  console.log('Starting validator for agent:', AGENT);
  console.log('');

// Register agent identity on startup
  try {
    const softwareHash = crypto.createHash('sha256')
      .update(process.version + 'toric-validator-v2')
      .digest('hex');
    const regRes = await fetch(`${API}/agent/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agent_type: 'validator',
        capabilities: ['validate:hash'],
        software_hash: softwareHash,
        version: '2.0.0',
        metadata: { started_at: new Date().toISOString() },
      }),
    });
    const regData = await regRes.json();
    if (regData.hash) console.log('Agent registered:', regData.hash.slice(0, 20) + '...');
    else console.log('Agent registration:', regData.error || 'already registered');
  } catch(e) {
    console.log('Agent registration failed (non-fatal):', e.message);
  }

  // Run initial poll
  await runValidationCycle(AGENT);

  // Subscribe to signals for real-time notification
  subscribeToSignals(AGENT);

  // Fallback poll every 5 minutes — signals handle liveness
  // Fallback poll: τ×φ — one network tick plus golden ratio buffer.
  // Signals handle liveness. This catches anything signals miss.
  setInterval(() => runValidationCycle(AGENT), POLL_INTERVAL_MS);
}

async function subscribeToSignals(agent) {
  async function connect() {
    try {
      const res = await fetch(`${BASE_URL}/signals`);
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      console.log('Signal stream connected');
      let buffer = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const signal = JSON.parse(line.slice(6));
            const payload = signal?.value?.payload || signal;
            if (payload?.type === 'ValidationRequested') {
              console.log('[signal] ValidationRequested:', toBase64url(payload.request_hash));
              await new Promise(r => setTimeout(r, POST_SUBMIT_WAIT_MS));
              await runValidationCycle(agent);
            }
          } catch(e) {}
        }
      }
    } catch(e) {
      console.log('Signal stream disconnected — reconnecting in 5s...');
    }
    setTimeout(connect, RECONNECT_DELAY_MS);
  }
  connect();
}

start();