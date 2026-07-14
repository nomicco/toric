// toric-search — the relevance and language axes over the existing
// authority axis.
//
// RELEVANCE: field-aware BM25 (Okapi), not neural embeddings. Toric's
// corpus is structured metadata, which lexical retrieval handles
// honestly: deterministic, zero trained parameters, every score
// decomposable to term contributions. The embedding upgrade, when a
// model source exists, slots in behind search() without changing the
// interface: it adds a second relevance signal, it does not replace
// this one.
//
// COMBINATION: final score = relevance × authority. Authority is the
// existing trust score — this module never recomputes trust.
//
// ABSTENTION: the margin rule. If the top result does not separate
// from the runner-up by MARGIN, the engine says so instead of
// pretending confidence. Default φ⁻⁷ — evidence-strength, not
// authority: epistemology, GeometryParams-revisable, not forced.
//
// LANGUAGE: structural query parsing (field:value terms, quoted
// phrases, bare terms); answers render from templates with every
// claim carrying its source hash. The render layer has no authority
// to add content.

const INV_PHI = 0.6180339887498949;
const MARGIN_DEFAULT = Math.pow(INV_PHI, 7); // ≈ 0.034442 — revisable epistemology

// BM25 standard parameters — engineering conventions, explicitly NOT
// φ-derived: relevance tuning is epistemology.
const BM25_K1 = 1.2;
const BM25_B = 0.75;

// Field weights: φ-ladder, because the ordering is forced (a name IS
// more identifying than a description).
const FIELD_WEIGHTS = {
  name: 1.0, // φ⁰
  capabilities: INV_PHI, // φ⁻¹
  blob: INV_PHI * INV_PHI, // φ⁻²
  author: INV_PHI * INV_PHI * INV_PHI, // φ⁻³
};

function tokenize(text) {
  if (!text) return [];
  return String(text)
    .toLowerCase()
    .split(/[^a-z0-9_.:-]+/)
    .filter((t) => t.length > 1);
}

function extractFields(doc) {
  const entry = doc.entry || {};
  let blobText = "";
  try {
    blobText = [entry.description, entry.architecture, entry.version,
      Array.isArray(entry.tags) ? entry.tags.join(" ") : entry.tags]
      .filter(Boolean).join(" ");
  } catch (_) { /* opaque entry — skip, never guess */ }
  return {
    name: entry.name || entry.model_name || entry.blob_type || "",
    capabilities: Array.isArray(entry.capabilities)
      ? entry.capabilities.join(" ")
      : entry.capabilities || "",
    blob: blobText,
    author: doc.author || "",
  };
}

class SearchIndex {
  constructor() {
    this.docs = [];
    this.df = new Map();
    this.avgLen = {};
  }

  build(documents) {
    this.docs = documents.map((doc) => {
      const raw = extractFields(doc);
      const fields = {};
      for (const f of Object.keys(FIELD_WEIGHTS)) fields[f] = tokenize(raw[f]);
      return { hash: doc.hash, fields, doc };
    });
    this.df.clear();
    const totals = {};
    for (const f of Object.keys(FIELD_WEIGHTS)) totals[f] = 0;
    for (const d of this.docs) {
      const seen = new Set();
      for (const f of Object.keys(FIELD_WEIGHTS)) {
        totals[f] += d.fields[f].length;
        for (const t of d.fields[f]) seen.add(t);
      }
      for (const t of seen) this.df.set(t, (this.df.get(t) || 0) + 1);
    }
    for (const f of Object.keys(FIELD_WEIGHTS))
      this.avgLen[f] = this.docs.length ? totals[f] / this.docs.length : 0;
    return this;
  }

  idf(term) {
    const n = this.docs.length;
    const df = this.df.get(term) || 0;
    return Math.log(1 + (n - df + 0.5) / (df + 0.5));
  }

  relevance(d, terms, fieldFilters) {
    let score = 0;
    for (const { term, field } of terms) {
      const idf = this.idf(term);
      if (idf === 0) continue;
      const searchFields = field ? [field] : Object.keys(FIELD_WEIGHTS);
      for (const f of searchFields) {
        if (!(f in FIELD_WEIGHTS)) continue;
        const tokens = d.fields[f];
        const tf = tokens.filter((t) => t === term).length;
        if (tf === 0) continue;
        const norm =
          tf + BM25_K1 * (1 - BM25_B + (BM25_B * tokens.length) / (this.avgLen[f] || 1));
        score += FIELD_WEIGHTS[f] * idf * ((tf * (BM25_K1 + 1)) / norm);
      }
    }
    for (const { field, value } of fieldFilters) {
      const tokens = d.fields[field] || [];
      if (!tokens.includes(value)) return 0;
    }
    return score;
  }
}

// Query grammar: bare terms, "quoted phrases", field:value hard
// filters, passes:true trust gate. Structural, not statistical.
function parseQuery(q) {
  const terms = [];
  const fieldFilters = [];
  let requirePasses = false;
  const re = /"([^"]+)"|(\w+):([\w.:-]+)|([^\s"]+)/g;
  let m;
  while ((m = re.exec(q || "")) !== null) {
    if (m[1]) {
      for (const t of tokenize(m[1])) terms.push({ term: t, required: true });
    } else if (m[2] && m[3]) {
      const field = m[2].toLowerCase();
      if (field === "passes" && m[3] === "true") requirePasses = true;
      else if (field in FIELD_WEIGHTS)
        fieldFilters.push({ field, value: m[3].toLowerCase() });
      else for (const t of tokenize(m[3])) terms.push({ term: t });
    } else if (m[4]) {
      for (const t of tokenize(m[4])) terms.push({ term: t });
    }
  }
  return { terms, fieldFilters, requirePasses };
}

function search(index, query, opts = {}) {
  const { terms, fieldFilters, requirePasses } = parseQuery(query);
  const margin = opts.margin ?? MARGIN_DEFAULT;
  const limit = opts.limit ?? 10;

  const scored = [];
  for (const d of index.docs) {
    if (requirePasses && !d.doc.passes) continue;
    const rel = index.relevance(d, terms, fieldFilters);
    if (rel <= 0) continue;
    // Search = relevance × authority. Authority floored at ε so
    // zero-trust content stays FINDABLE (ranked last) — search is
    // not admission.
    const authority = Math.max(d.doc.score ?? 0, 1e-6);
    scored.push({ ...d.doc, relevance: rel, combined: rel * authority });
  }
  scored.sort((a, b) => b.combined - a.combined);
  const results = scored.slice(0, limit);

  let confident = true;
  let marginObserved = null;
  if (results.length >= 2 && results[0].combined > 0) {
    marginObserved = (results[0].combined - results[1].combined) / results[0].combined;
    confident = marginObserved >= margin;
  } else if (results.length === 0) {
    confident = false;
  }

  return { results, confident, margin_observed: marginObserved, margin_required: margin, total_matched: scored.length };
}

function render(searchResult, query) {
  const { results, confident, total_matched } = searchResult;
  if (results.length === 0) {
    return `No registered content matches "${query}". The network can only search what agents have registered and attested.`;
  }
  const lines = [];
  const top = results[0];
  const name = top.entry?.name || top.entry?.model_name || top.hash.slice(0, 12);
  if (confident) {
    lines.push(
      `Best match for "${query}": ${name} — trust ${top.score.toFixed(4)}${top.passes ? " (passes φ⁻¹)" : " (below pass line)"}, ${top.attestation_count} attestation${top.attestation_count === 1 ? "" : "s"}. [${top.hash}]`
    );
  } else {
    lines.push(
      `${total_matched} matches for "${query}", but the top results do not separate cleanly — ranking below is by relevance × trust, without a single-best claim:`
    );
  }
  for (const r of results.slice(confident ? 1 : 0, 5)) {
    const rname = r.entry?.name || r.entry?.model_name || r.hash.slice(0, 12);
    lines.push(`  • ${rname} — trust ${r.score.toFixed(4)}, relevance ${r.relevance.toFixed(2)} [${r.hash}]`);
  }
  return lines.join("\n");
}

export { SearchIndex, search, render, parseQuery, MARGIN_DEFAULT };
