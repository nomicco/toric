# Toric — Migration & Feature Log

## 2026-07-14: PhiFixed Migration, Comparative Attestations, Relational Field, Witness Engine

This session completed the migration from f64-based consensus logic to exact
ℤ[φ] integer arithmetic and added the full comparative-attestation surface.

---

### What Changed

#### 1. PhiFixed Geometry (`dnas/shared/geometry/src/lib.rs`)

The geometry crate was rewritten to carry the exact-integer tier alongside the
existing f64 paths. No f64 code was removed — the migration is earned on
evidence, not forced.

**New exports:**
- `PhiFixed` — fixed-point type in millionths (i64), with `to_f64()` for
  backward-compatible consumers
- `zphi_sign(a, b)` — exact sign of `a + bφ` without float conversion
- `zphi_floor(a, b)` — exact floor of `a + bφ` as i64
- `default_credit_limit_exact(reputation_millionths)` — integer credit limit
- `mass_seal_threshold_exact(mass)` — integer φ⁻¹ threshold
- `reputation_recursion_exact(scores)` — exact reputation recursion
- `drift_exceeds_threshold_exact(sum_abs, s_ref)` — integer drift gate
- `SOVEREIGNTY_LEASE_ROUNDS` — F(7) = 13
- `PROBE_HOLONOMY = 8`, `PROBE_8_PASS_LINE = INV_PHI_CU`

**60 tests pass**, including 10 new test modules for the exact arithmetic.

#### 2. Registry Coordinator (`dnas/registry/zomes/coordinator/registry/src/lib.rs`)

**Reputation recursion:** `compute_reputation_score` now calls
`toric_geometry::reputation_recursion_exact` instead of an inline f64 loop.

**Drift gate:** `close_round` uses `drift_exceeds_threshold_exact(sum_abs,
s_ref)` with integer masses and `STALENESS_CEILING_ROUNDS` instead of float
`manifest_write_due`.

**Comparative attestations (new):**
- `ComparativeBlob` — JSON-encoded blob with `kind: "comparative"`,
  `winner_hash`, `loser_hash`, `margin_millionths`, `query_context`,
  `cited_cycle`
- `create_comparative_attestation` — creates a staked difference between two
  manifests, with cycle-flatness check (φ⁻⁴ negligibility floor)
- `get_comparative_standing` — reputation-weighted net preference mass
- `encode_comparative_blob` / `decode_comparative_blob` — JSON serialization
  helpers

**Relational trust field (new):**
- `RelationalScore` — absolute (gauge anchor) + solved field position +
  residual (local holonomy) + component size + edge count
- `compute_relational_score` — weighted Jacobi relaxation solver:
  - Pins lexicographic-first node at its absolute score (query-independent)
  - 21 iterations, integer division, BTreeMap ordering (deterministic)
  - Component bounded at F(9) = 34 manifests
  - Residual: pre-mean absolute mass denominator (contradictions don't vanish
    by symmetry)

**Witness Engine — COMPLETE step (new):**
- `QueryAssertion` — `{better, worse, margin_millionths}`
- `QueryCompletionInput` — `{pinned_manifest, assertions}`
- `QueryCompletion` — `{verdict, completions, residual_with, residual_without,
  component_size, edge_count}`
- `query_completion` — routes by residual:
  - `entailed` — record + assertions agree
  - `asker_conflict` — removing assertions flattens it
  - `record_dispute` — residual persists without assertions
- `solve_with_assertions` — mirrors `compute_relational_score`'s solver exactly
  (same BFS, same Jacobi, same frame rule) so residuals are commensurable

**Probe 8 — holonomy audit:** Added to `check_closure`. Samples up to F(8) = 21
recent manifests, direction-normalizes edges, measures contradiction mass as
fraction of total preference mass.

#### 3. API (`api/index.js`)

New endpoints:
- `POST /v1/attest/compare` — create comparative attestation
- `GET /v1/manifest/:hash/standing` — reputation-weighted net preference
- `GET /v1/manifest/:hash/relational` — solved field position + local holonomy
- `POST /v1/query` — Witness Engine COMPLETE step (entailed / asker_conflict /
  record_dispute)
- `GET /v1/search` — BM25 relevance × authority, margin-rule confidence
- `POST /v1/ingest` — membrane door for external content
- `POST /v1/ingest/batch` — per-item isolation

#### 4. Search & Ingest Modules

**`api/toric-search.js`:**
- Field-aware BM25 (Okapi) with φ-ladder field weights
- Query grammar: bare terms, quoted phrases, field:value filters, `passes:true`
- Combination: `relevance × authority` (trust score)
- Margin rule: φ⁻⁷ abstention threshold
- Cited rendering with source hashes

**`api/toric-ingest.js`:**
- Fetch-then-decide (never auto-publish)
- SHA-256 content hashing, size caps
- `blob_type: "ingested_content"` — no attestation, no trust assigned
- Per-item batch isolation

#### 5. Tryorama Tests (`tests/src/registry/registry/registry.test.ts`)

5 new tests:
- Comparative attestation round-trip (opposite-signed standing)
- Self-comparison rejection
- Cited cycle: flat accepted, contradiction unwritable
- Relational field: winner above, loser below, flat residual, isolated degrades
- Dispute: opposing edges from second agent → nonzero residual

#### 6. Desktop App (`toric-desktop/`)

- **Progenitor** set in `dna.yaml` (gates first roster declaration)
- **Relay URL** self-hosted on Pi (`192.168.1.169:3340`, plain HTTP `--dev`)
- **GPU fix** — `app.disableHardwareAcceleration()` prevents ANGLE cascade
- **ICE noise** — removed debug `console.log` in `cli.ts`
- **Click-to-copy** agent key in UI (full key shown, `execCommand` copy)
- **Preload bridge** — `__TORIC_CLIPBOARD__` via IPC (available for future use)

#### 7. Geometry Lib Constants

- `STALENESS_CEILING_ROUNDS = 21` (F(8))
- `SOVEREIGNTY_LEASE_ROUNDS = 13` (F(7))
- `PROBE_HOLONOMY = 8`
- `PROBE_8_PASS_LINE = INV_PHI_CU`

---

### Key Design Decisions

1. **Migration is earned, not forced.** f64 paths remain; exact paths run
   alongside. The old system works until the new one is proven.

2. **Frame rule.** The relational solver pins the lexicographic-first node in
   the component at its absolute score — deterministic, query-independent. The
   queried manifest is free to take its solved position.

3. **Pre-mean denominator.** Residual uses `Σw·|m|` (pre-mean absolute mass)
   so perfectly contradicted pairs report maximal dispute instead of dividing
   by zero.

4. **Negligibility floor.** φ⁻⁴ (≈ 0.146) is the consistency band for cycle
   checks and query verdicts. Deviations below this are structurally
   undetectable — the authority structure's resolution limit.

5. **Ingest proposes, never vouches.** No attestation call exists in the
   ingest module. Imported content starts at zero trust.

6. **Zero external dependencies.** Pi serves bootstrap, signal, and iroh relay.
   Changing any URL after deployment partitions the network.

---

### Queue State

**Completed:**
- [x] PhiFixed geometry (Tier 2)
- [x] Comparative attestations
- [x] Holonomy probe (Probe 8)
- [x] Relational trust field (field-solve)
- [x] Tryorama fixtures
- [x] Progenitor + relay URL + GPU fix
- [x] Click-to-copy agent key
- [x] Search & ingest modules
- [x] Witness Engine COMPLETE step

**Next:**
- [ ] Multi-node smoke on real hardware (2 desktops + Pi)
- [ ] Render layer over `/v1/query` output
- [ ] Contribution provenance (Phase 7/8 revenue flywheel)
- [ ] Tryorama tests for query_completion
