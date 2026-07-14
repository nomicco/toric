// toric-ingest — the membrane door for external content.
//
// Design rule: ingestion PROPOSES, it never VOUCHES. No attestation
// call exists anywhere in this file — the connector structurally
// cannot rate its own imports. A registered-by-ingestion manifest
// starts at zero attestations, identical to a hand-registered one.
//
// Fields recorded: content_hash (sha256 of exact bytes — same hash
// dimension native manifests use), source_url + fetched_at (a claim
// about ONE fetch, not the URL forever), ingested_by (a connector
// that repeatedly imports bad content is itself attestable),
// source_type (open vocabulary — new sources need no code change).
//
// Deliberately absent: attestation, trust scores, crawling (it
// fetches one locator you hand it — watch-mode connectors are Phase 6
// and call this as their primitive), invented metadata.

import crypto from "crypto";

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// Fetch-then-decide, never fetch-then-auto-publish: returns the blob
// for the caller to inspect or reject before touching the network.
async function fetchForIngestion(sourceUrl, opts = {}) {
  const {
    sourceType = "url",
    ingestedBy = "unknown",
    maxBytes = 50 * 1024 * 1024,
    fetchImpl = fetch,
  } = opts;

  const res = await fetchImpl(sourceUrl);
  if (!res.ok) {
    throw new Error(`Ingestion fetch failed: ${res.status} ${res.statusText} for ${sourceUrl}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > maxBytes) {
    throw new Error(`Ingestion refused: ${buf.length} bytes exceeds cap of ${maxBytes} for ${sourceUrl}`);
  }
  const contentHash = sha256Hex(buf);

  return {
    blob: {
      blob_type: "ingested_content",
      name: sourceUrl.split("/").pop() || sourceUrl,
      source_url: sourceUrl,
      source_type: sourceType,
      content_hash: `sha256:${contentHash}`,
      content_type: res.headers.get("content-type") || "application/octet-stream",
      byte_length: buf.length,
      ingested_by: ingestedBy,
      fetched_at: new Date().toISOString(),
      // Native fields left absent, not faked: no capabilities or
      // upstream claims until an explicit separate step adds them.
    },
    rawBytes: buf,
    contentHash: `sha256:${contentHash}`,
  };
}

async function ingest(sourceUrl, registerFn, opts = {}) {
  const { blob, contentHash } = await fetchForIngestion(sourceUrl, opts);
  const manifestHash = await registerFn(blob);
  return { manifestHash, contentHash, blob };
}

// Per-item isolation: one bad URL must not abort the rest.
async function ingestBatch(sourceUrls, registerFn, opts = {}) {
  return Promise.all(
    sourceUrls.map(async (url) => {
      try {
        const result = await ingest(url, registerFn, opts);
        return { url, ok: true, ...result };
      } catch (e) {
        return { url, ok: false, error: e.message };
      }
    })
  );
}

export { fetchForIngestion, ingest, ingestBatch };
