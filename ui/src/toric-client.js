
// ui/src/toric-client.js — dual-mode transport for the Toric UI.
// Kangaroo/launcher mode: __HC_LAUNCHER_ENV__ present -> direct zome calls.
// Browser mode (dev.sh + Express API): fetch fallback, unchanged behavior.

import { AppWebsocket, encodeHashToBase64, decodeHashFromBase64 } from '@holochain/client';

const LAUNCHER = typeof window !== 'undefined' && !!window.__HC_LAUNCHER_ENV__;
const API_PORT = new URL(location.href).searchParams.get('api') || '3000';
const BASE = `http://localhost:${API_PORT}/v1`;

let appWs = null;
let connecting = null;

async function ensureConnected() {
  if (appWs) return appWs;
  if (!connecting) {
    connecting = AppWebsocket.connect()
      .then(ws => { appWs = ws; connecting = null; return ws; })
      .catch(e => { connecting = null; throw e; });
  }
  return connecting;
}

const b64 = (bytes) => (bytes ? encodeHashToBase64(bytes) : null);
const unb64 = (s) => decodeHashFromBase64(s);
const enc = new TextEncoder();
const dec = new TextDecoder();

async function cell(role) {
  const ws = await ensureConnected();
  const info = await ws.appInfo();
  const c = info.cell_info[role]?.[0]?.value;
  if (!c) throw new Error(`cell for role '${role}' not found`);
  return c.cell_id;
}

async function zome(role, zome_name, fn_name, payload = null) {
  const ws = await ensureConnected();
  const cell_id = await cell(role);
  return ws.callZome({ cell_id, zome_name, fn_name, payload, provenance: cell_id[1] });
}

const registry     = (fn, p) => zome('ledger', 'registry', fn, p);
const mutualCredit = (fn, p) => zome('ledger', 'mutual_credit', fn, p);

function formatRecord(record) {
  if (!record) return null;
  let entry = null;
  try {
    const e = record.entry?.Present?.entry;
    if (e) {
      const buf = e instanceof Uint8Array ? e : new Uint8Array(e.data ?? e);
      const i = buf.indexOf(0x7b);
      entry = i >= 0 ? JSON.parse(dec.decode(buf.slice(i))) : dec.decode(buf);
    }
  } catch (_) { /* entry stays null */ }
  return {
    hash: b64(record.signed_action?.hashed?.hash),
    author: b64(record.signed_action?.hashed?.content?.author),
    timestamp: record.signed_action?.hashed?.content?.timestamp,
    entry,
  };
}

async function route(path, opts) {
  const body = opts?.body ? JSON.parse(opts.body) : null;

  if (path === '/status') {
    try { await ensureConnected(); return { status: 'connected' }; }
    catch { return { status: 'connecting' }; }
  }

  if (path === '/agent/me') {
    const cid = await cell('ledger');
    return { agent: b64(cid[1]) };
  }

  if (path === '/network/state') {
    const st = await mutualCredit('get_network_state', null);
    return st || { attestation_count: 0, next_fibonacci_threshold: 21, credit_supply: 987, cycle: 0, phase: 0 };
  }

  if (path === '/economy/snapshot') return mutualCredit('economic_snapshot', null);

  if (path.startsWith('/economy/balance/')) {
    const key = decodeURIComponent(path.slice('/economy/balance/'.length));
    return mutualCredit('get_balance', { agent: unb64(key) });
  }

  if (path === '/network/closure')    return (await registry('get_latest_closure', null)) || null;
  if (path === '/network/reputation') return registry('get_network_reputation', null);

  if (path === '/manifests') {
    const hashes = await registry('get_all_manifests', null);
    if (!hashes?.length) return [];
    const rows = await Promise.all(hashes.map(async (h) => {
      try {
        const [manifest, ts] = await Promise.all([
          registry('get_manifest', h),
          registry('compute_trust_score', { manifest_hash: h }).catch(() => null),
        ]);
        return {
          hash: b64(h),
          entry: formatRecord(manifest)?.entry || null,
          author: b64(manifest?.signed_action?.hashed?.content?.author),
          score: ts?.score ?? 0,
          attestation_count: ts?.attestation_count ?? 0,
          passes: ts?.passes ?? false,
        };
      } catch { return null; }
    }));
    return rows.filter(Boolean).sort((a, b) => b.score - a.score);
  }

  if (path === '/manifest' && opts?.method === 'POST') {
    const blob = body.blob;
    if (blob?.upstream_manifest_hashes?.length) {
      blob.upstream_manifest_hashes = blob.upstream_manifest_hashes.map(
        (h) => (typeof h === 'string' ? unb64(h) : h),
      );
    }
    const hash = await registry('create_manifest', { blob });
    return { hash: b64(hash) };
  }

  if (path === '/attestation' && opts?.method === 'POST') {
    const hash = await registry('create_attestation', {
      manifest_hash: unb64(body.manifest_hash),
      blob: enc.encode(JSON.stringify(body.blob)),
    });
    return { hash: b64(hash) };
  }

  if (path === '/agents') {
    // Discovery evidence: every agent the DHT has scored records for.
    const scored = await registry('get_scored_agents', null);
    return (scored || []).map(a => ({ agent: b64(a.agent), score: a.score ?? 0 }));
  }

  if (path.startsWith('/manifest/') && path.endsWith('/relational')) {
    const hash = decodeURIComponent(path.slice('/manifest/'.length, -'/relational'.length));
    const r = await registry('compute_relational_score', unb64(hash));
    return {
      manifest_hash: hash,
      absolute_millionths: r.absolute_millionths,
      relational_millionths: r.relational_millionths,
      residual_millionths: r.residual_millionths,
      component_size: r.component_size,
      edge_count: r.edge_count,
    };
  }

  if (path.startsWith('/manifest/') && path.endsWith('/standing')) {
    const hash = decodeURIComponent(path.slice('/manifest/'.length, -'/standing'.length));
    const s = await registry('get_comparative_standing', unb64(hash));
    return { manifest_hash: hash, net_millionths: s.net_millionths, comparisons: s.comparisons };
  }

  if (path === '/attest/compare' && opts?.method === 'POST') {
    const hash = await registry('create_comparative_attestation', {
      winner_hash: unb64(body.winner_hash),
      loser_hash: unb64(body.loser_hash),
      margin_millionths: body.margin_millionths ?? 200000,
      query_context: body.query_context || 'ui',
      cited_cycle: (body.cited_cycle || []).map(unb64),
    });
    return { hash: b64(hash) };
  }

  if (path === '/query' && opts?.method === 'POST') {
    const r = await registry('query_completion', {
      pinned_manifest: unb64(body.pinned_manifest),
      assertions: (body.assertions || []).map(a => ({
        better: unb64(a.better), worse: unb64(a.worse),
        margin_millionths: a.margin_millionths ?? 200000,
      })),
    });
    return {
      verdict: r.verdict,
      completions: r.completions.map(([h, v]) => ({ manifest: b64(h), position_millionths: v })),
      residual_with_millionths: r.residual_with,
      residual_without_millionths: r.residual_without,
      component_size: r.component_size, edge_count: r.edge_count,
    };
  }

  if (path === '/roster/declare' && opts?.method === 'POST') {
    const hash = await mutualCredit('declare_signer_roster', null);
    return { hash: b64(hash) };
  }

  if (path === '/dna-hashes') {
    const ws = await ensureConnected();
    const info = await ws.appInfo();
    const dna = (role) => {
      const raw = info.cell_info[role]?.[0]?.value?.cell_id?.[0];
      return raw ? b64(raw instanceof Uint8Array ? raw : new Uint8Array(raw.data ?? raw)) : null;
    };
    return { ledger: dna('ledger'), coordination: dna('coordination'), identity: dna('identity') };
  }

  throw new Error(`toric-client: unmapped path ${path} — add it to route()`);
}

export async function j(path, opts) {
  if (!LAUNCHER) {
    const r = await fetch(BASE + path, opts);
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
    return r.json();
  }
  try {
    return await route(path, opts);
  } catch (e) {
    throw new Error(e?.message || String(e));
  }
}
