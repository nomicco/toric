use hdk::prelude::*;
use registry_integrity::{
    EntryTypes,
    LinkTypes,
    Manifest,
    Attestation,
    Warrant as RegistryWarrant,
};
use toric_geometry::{
    PHI, PHI_SQ, INV_PHI, INV_PHI_SQ, INV_PHI_CU, INV_PHI_4,
    derive_targets, DeviationSignal, ClosureStatus, normalized_deviation,
    drift_since, drift_exceeds_threshold_exact, STALENESS_CEILING_ROUNDS,
    ceiling_deviation, expected_supply,
    PROBE_SUPPLY_POSITION, PROBE_ROSTER_CONFORMANCE, PROBE_FROZEN_FRACTION,
};

pub mod blobs;
use blobs::*;

// Max upstream recursion depth derived from negligibility threshold.
// At depth 4, φ⁻⁴ = INV_PHI_4 = 0.1459 — contribution is below the
// threshold where it meaningfully affects the blended score.
// Depth 3 is the last level worth computing.
const MAX_UPSTREAM_DEPTH: u32 = 3;

#[hdk_extern]
pub fn init(_: ()) -> ExternResult<InitCallbackResult> {
    let mut fns: HashSet<(ZomeName, FunctionName)> = HashSet::new();
    fns.insert((zome_info()?.name, FunctionName::from("create_quorum_attestation")));
    fns.insert((zome_info()?.name, FunctionName::from("compute_reputation_score")));
    fns.insert((zome_info()?.name, FunctionName::from("compute_trust_score")));
    fns.insert((zome_info()?.name, FunctionName::from("confirm_warrant")));
    fns.insert((zome_info()?.name, FunctionName::from("record_convergence")));
    fns.insert((zome_info()?.name, FunctionName::from("get_network_reputation")));
    fns.insert((zome_info()?.name, FunctionName::from("get_scored_agents")));
    fns.insert((zome_info()?.name, FunctionName::from("increment_commit_count")));
    fns.insert((zome_info()?.name, FunctionName::from("increment_reveal_count")));
    fns.insert((zome_info()?.name, FunctionName::from("apply_reveal_penalty")));
    create_cap_grant(CapGrantEntry {
        tag: "bridge".into(),
        access: CapAccess::Unrestricted,
        functions: GrantedFunctions::Listed(fns),
    })?;
    Ok(InitCallbackResult::Pass)
}

// ─────────────────────────────────────────────
// Input / output types
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateManifestInput {
    pub blob: ManifestBlob,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateAttestationInput {
    pub manifest_hash: ActionHash,
    pub blob: SerializedBytes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateWarrantInput {
    pub manifest_hash: ActionHash,
    pub blob: WarrantBlob,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReputationInput {
    pub agent: AgentPubKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReputationScore {
    pub agent: AgentPubKey,
    pub score: f64,
    pub score_delta: f64,
    pub attestation_count: u32,
    pub warrant_count: u32,
    pub total_commits: u32,
    pub total_reveals: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TrustScoreInput {
    pub manifest_hash: ActionHash,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TrustScoreResult {
    pub manifest_hash: ActionHash,
    pub score: f64,
    pub passes: bool,
    pub attestation_count: u32,
    pub weighted_attestation_count: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkReputationResult {
    pub honest_rep_fraction: f64,
    pub total_reputation: f64,
    pub honest_reputation: f64,
    pub average_reputation: f64,
    pub agent_count: u32,
    pub warranted_agent_count: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LineageInput {
    pub manifest_hash: ActionHash,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ContentHashInput {
    pub content_hash: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IncrementInput {
    pub agent: AgentPubKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RevealPenaltyInput {
    pub agent: AgentPubKey,
    pub penalty: f64,
    pub request_hash: ActionHash,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConvergenceInput {
    pub agent: AgentPubKey,
    pub agreed: bool,
    pub request_hash: ActionHash,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConfirmWarrantInput {
    pub warrant_hash: ActionHash,
    pub manifest_hash: ActionHash,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QuorumAttestationInput {
    pub manifest_hash: ActionHash,
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

fn fetch_links(base: impl Into<AnyLinkableHash>, link_type: LinkTypes) -> ExternResult<Vec<Link>> {
    let query = LinkQuery::new(base.into(), link_type.try_into_filter()?);
    get_links(query, GetStrategy::Network)
}

fn links_to_records(links: Vec<Link>) -> ExternResult<Vec<Record>> {
    let mut records = Vec::new();
    for link in links {
        if let Some(action_hash) = link.target.into_action_hash() {
            if let Some(record) = get(action_hash, GetOptions::default())? {
                records.push(record);
            }
        }
    }
    Ok(records)
}

fn blob_content_hash(blob: &ManifestBlob) -> String {
    match blob {
        ManifestBlob::AiModel(b)           => b.content_hash.clone(),
        ManifestBlob::Dataset(b)           => b.content_hash.clone(),
        ManifestBlob::TrainingRun(b)       => b.content_hash.clone(),
        ManifestBlob::InferenceEndpoint(b) => b.content_hash.clone(),
        ManifestBlob::Connector(b)         => b.content_hash.clone(),
        ManifestBlob::Generic(b)           => b.content_hash.clone(),
    }
}

fn blob_upstream_hashes(blob: &ManifestBlob) -> Vec<ActionHash> {
    match blob {
        ManifestBlob::AiModel(b)           => b.upstream_manifest_hashes.clone(),
        ManifestBlob::Dataset(b)           => b.upstream_manifest_hashes.clone(),
        ManifestBlob::TrainingRun(b)       => b.upstream_manifest_hashes.clone(),
        ManifestBlob::InferenceEndpoint(b) => b.upstream_manifest_hashes.clone(),
        ManifestBlob::Connector(b)         => b.upstream_manifest_hashes.clone(),
        ManifestBlob::Generic(b)           => b.upstream_manifest_hashes.clone(),
    }
}

// ─────────────────────────────────────────────
// Reputation cache
// ─────────────────────────────────────────────

fn get_cached_reputation(agent: &AgentPubKey) -> ExternResult<Option<ReputationScore>> {
    use registry_integrity::ReputationCache;

    let links = fetch_links(agent.clone(), LinkTypes::AgentToReputationCache)?;
    let cache_link = match links.last() {
        Some(l) => l.clone(),
        None => return Ok(None),
    };
    let cache_hash = match cache_link.target.into_action_hash() {
        Some(h) => h,
        None => return Ok(None),
    };
    let record = match get(cache_hash, GetOptions::default())? {
        Some(r) => r,
        None => return Ok(None),
    };
    let cache = match record.entry().as_option() {
        Some(e) => match ReputationCache::try_from(e) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        },
        None => return Ok(None),
    };

    let manifest_links = fetch_links(agent.clone(), LinkTypes::AgentToManifest)?;
    for link in manifest_links {
        if let Some(manifest_hash) = link.target.into_action_hash() {
            let att_links = fetch_links(manifest_hash.clone(), LinkTypes::ManifestToAttestation)?;
            for att_link in &att_links {
                if att_link.author != *agent && att_link.timestamp > cache.computed_at {
                    return Ok(None);
                }
            }
            let war_links = fetch_links(manifest_hash, LinkTypes::ManifestToWarrant)?;
            for war_link in &war_links {
                if war_link.timestamp > cache.computed_at {
                    return Ok(None);
                }
            }
        }
    }

    Ok(Some(ReputationScore {
        agent: cache.agent,
        score: cache.score as f64 / 1_000_000.0,
        score_delta: cache.score_delta as f64 / 1_000_000.0,
        attestation_count: cache.attestation_count,
        warrant_count: cache.warrant_count,
        total_commits: cache.total_commits,
        total_reveals: cache.total_reveals,
    }))
}

/// The agent's latest ReputationCache, by hash — the citation target
/// for sealed CreditLimits (merge dividend). Roster members verify a
/// proposed CreditLimit's basis against THEIR view via this function;
/// mc integrity then pins the seal to the cited record with must_get.
#[derive(Serialize, Deserialize, Debug)]
pub struct ReputationBasis {
    pub cache_hash: ActionHash,
    pub score_ppm: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReputationBasisInput {
    pub agent: AgentPubKey,
}

#[hdk_extern]
pub fn get_reputation_basis(input: ReputationBasisInput) -> ExternResult<Option<ReputationBasis>> {
    let links = fetch_links(input.agent, LinkTypes::AgentToReputationCache)?;
    let Some(link) = links.last() else { return Ok(None) };
    let Some(hash) = link.target.clone().into_action_hash() else { return Ok(None) };
    let Some(record) = get(hash.clone(), GetOptions::default())? else { return Ok(None) };
    let Some(entry) = record.entry().as_option() else { return Ok(None) };
    let Ok(cache) = registry_integrity::ReputationCache::try_from(entry) else { return Ok(None) };
    Ok(Some(ReputationBasis { cache_hash: hash, score_ppm: cache.score }))
}

fn write_reputation_cache(result: &ReputationScore) -> ExternResult<()> {
    use registry_integrity::ReputationCache;

    let cache = ReputationCache {
        agent: result.agent.clone(),
        score: (result.score * 1_000_000.0) as u32,
        score_delta: (result.score_delta * 1_000_000.0) as i32,
        computed_at: sys_time()?,
        attestation_count: result.attestation_count,
        warrant_count: result.warrant_count,
        total_commits: result.total_commits,
        total_reveals: result.total_reveals,
    };
    let action_hash = create_entry(EntryTypes::ReputationCache(cache))?;
    create_link(result.agent.clone(), action_hash, LinkTypes::AgentToReputationCache, ())?;
    Ok(())
}

// ─────────────────────────────────────────────
// Trust score cache
// ─────────────────────────────────────────────

fn get_cached_trust_score(manifest_hash: &ActionHash) -> ExternResult<Option<TrustScoreResult>> {
    use registry_integrity::TrustScoreCache;

    let links = fetch_links(manifest_hash.clone(), LinkTypes::ManifestToTrustScoreCache)?;
    let cache_link = match links.last() {
        Some(l) => l.clone(),
        None => return Ok(None),
    };
    let cache_hash = match cache_link.target.into_action_hash() {
        Some(h) => h,
        None => return Ok(None),
    };
    let record = match get(cache_hash, GetOptions::default())? {
        Some(r) => r,
        None => return Ok(None),
    };
    let cache = match record.entry().as_option() {
        Some(e) => match TrustScoreCache::try_from(e) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        },
        None => return Ok(None),
    };

    let att_links = fetch_links(manifest_hash.clone(), LinkTypes::ManifestToAttestation)?;
    for link in &att_links {
        if link.timestamp > cache.computed_at {
            return Ok(None);
        }
    }
    let conf_links = fetch_links(manifest_hash.clone(), LinkTypes::ManifestToWarrantConfirmation)?;
    for link in &conf_links {
        if link.timestamp > cache.computed_at {
            return Ok(None);
        }
    }

    Ok(Some(TrustScoreResult {
        manifest_hash: manifest_hash.clone(),
        score: cache.score as f64 / 1_000_000.0,
        passes: cache.score as f64 / 1_000_000.0 >= INV_PHI,
        attestation_count: cache.attestation_count,
        weighted_attestation_count: 0.0,
    }))
}

fn write_trust_score_cache(manifest_hash: &ActionHash, result: &TrustScoreResult) -> ExternResult<()> {
    use registry_integrity::TrustScoreCache;

    let cache = TrustScoreCache {
        manifest_hash: manifest_hash.clone(),
        score: (result.score * 1_000_000.0) as u32,
        computed_at: sys_time()?,
        attestation_count: result.attestation_count,
    };
    let action_hash = create_entry(EntryTypes::TrustScoreCache(cache))?;
    create_link(manifest_hash.clone(), action_hash, LinkTypes::ManifestToTrustScoreCache, ())?;
    Ok(())
}

// ─────────────────────────────────────────────
// Create Manifest
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn create_manifest(input: CreateManifestInput) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;

    let content_hash = blob_content_hash(&input.blob);
    let path = Path::from(format!("content.{}", content_hash));
    let typed_path = path.typed(LinkTypes::ContentHashToManifest)?;
    if typed_path.exists()? {
        let existing_links = fetch_links(typed_path.path_entry_hash()?, LinkTypes::ContentHashToManifest)?;
        for link in &existing_links {
            if link.author == agent {
                if let Some(existing_hash) = link.target.clone().into_action_hash() {
                    return Ok(existing_hash);
                }
            }
        }
    }

    let metadata_blob = encode_manifest_blob(&input.blob)?;
    let manifest = Manifest { metadata_blob };
    let action_hash = create_entry(EntryTypes::Manifest(manifest))?;

    create_link(agent, action_hash.clone(), LinkTypes::AgentToManifest, ())?;

    let global_path = Path::from("manifests.all");
    let global_typed = global_path.typed(LinkTypes::GlobalManifestAnchor)?;
    global_typed.ensure()?;
    create_link(global_typed.path_entry_hash()?, action_hash.clone(), LinkTypes::GlobalManifestAnchor, ())?;

    let typed_path = Path::from(format!("content.{}", content_hash))
        .typed(LinkTypes::ContentHashToManifest)?;
    typed_path.ensure()?;
    create_link(typed_path.path_entry_hash()?, action_hash.clone(), LinkTypes::ContentHashToManifest, ())?;

    for upstream in blob_upstream_hashes(&input.blob) {
        create_link(action_hash.clone(), upstream.clone(), LinkTypes::ManifestToUpstream, ())?;
        create_link(upstream, action_hash.clone(), LinkTypes::UpstreamToDerivative, ())?;
    }

    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Lineage queries
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn get_upstreams(input: LineageInput) -> ExternResult<Vec<ActionHash>> {
    let links = fetch_links(input.manifest_hash, LinkTypes::ManifestToUpstream)?;
    Ok(links.into_iter().filter_map(|l| l.target.into_action_hash()).collect())
}

#[hdk_extern]
pub fn get_derivatives(input: LineageInput) -> ExternResult<Vec<ActionHash>> {
    let links = fetch_links(input.manifest_hash, LinkTypes::UpstreamToDerivative)?;
    Ok(links.into_iter().filter_map(|l| l.target.into_action_hash()).collect())
}

#[hdk_extern]
pub fn get_by_content_hash(input: ContentHashInput) -> ExternResult<Vec<ActionHash>> {
    let path = Path::from(format!("content.{}", input.content_hash));
    let links = fetch_links(path.path_entry_hash()?, LinkTypes::ContentHashToManifest)?;
    Ok(links.into_iter().filter_map(|l| l.target.into_action_hash()).collect())
}

// ─────────────────────────────────────────────
// Create Attestation
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn create_attestation(input: CreateAttestationInput) -> ExternResult<ActionHash> {
    let metadata_blob = input.blob;
    let attestation = Attestation {
        manifest_hash: input.manifest_hash.clone(),
        metadata_blob,
    };
    let action_hash = create_entry(EntryTypes::Attestation(attestation))?;
    let agent = agent_info()?.agent_initial_pubkey;
    create_link(input.manifest_hash.clone(), action_hash.clone(), LinkTypes::ManifestToAttestation, ())?;
    create_link(agent, action_hash.clone(), LinkTypes::AgentToAttestation, ())?;
    create_link(input.manifest_hash, agent_info()?.agent_initial_pubkey, LinkTypes::ManifestToValidator, ())?;
    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Comparative attestations — the relational primitive
//
// A comparative attestation is a claim of DIFFERENCE, not of absolute
// standing: "winner over loser, in this query context, by this margin."
// Same Attestation entry type, new blob shape — semantic meaning lives
// in the coordinator (the codebase's oldest convention), so this is
// NOT a DNA fork: old absolute attestations are untouched and remain
// valid.
//
// The checkpoint discipline: a comparative attestation may cite prior
// comparative edges forming a path from loser back to winner. If it
// does, this coordinator verifies the cycle sum — the cited path's
// margins plus this edge's margin must be consistent (flat) or the
// attestation is rejected as self-contradicting the very record it
// acknowledges. Deterministic, hash-anchored (gets by ActionHash),
// exact (ℤ[φ] millionths — no floats in the check).
//
// What this deliberately does NOT do: enforce global consistency (a
// global check cannot exist at write time on a DHT — that lives in
// closure probes), or replace absolute attestations (the relational
// form runs alongside and earns the migration on evidence).
// ─────────────────────────────────────────────

/// Blob shape for kind = "comparative". Margin in MILLIONTHS (exact
/// integer — the same scale discipline as roster masses).
#[derive(Serialize, Deserialize, Debug, Clone, SerializedBytes)]
pub struct ComparativeBlob {
    pub kind: String, // "comparative"
    pub winner_hash: ActionHash,
    pub loser_hash: ActionHash,
    /// Signed preference strength, millionths. Positive = winner over
    /// loser. The delta this edge asserts on the difference graph.
    pub margin_millionths: i64,
    /// Free-text frame: what question this preference answers.
    pub query_context: String,
    /// Optional cited cycle: prior comparative attestation hashes
    /// forming a path loser → ... → winner. If present, the cycle sum
    /// (their margins + this margin) must be flat within tolerance.
    #[serde(default)]
    pub cited_cycle: Vec<ActionHash>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateComparativeInput {
    pub winner_hash: ActionHash,
    pub loser_hash: ActionHash,
    pub margin_millionths: i64,
    pub query_context: String,
    #[serde(default)]
    pub cited_cycle: Vec<ActionHash>,
}

/// Cycle-flatness tolerance: φ⁻⁴ of the largest |margin| on the cycle
/// (the negligibility floor — deviations below the resolution of the
/// authority structure don't fire). Exact test via zphi_sign:
/// residual ≤ max·φ⁻⁴ ⟺ zphi_sign(5·max − residual... expanded below.
fn cycle_is_flat(residual_abs: i128, max_abs: i128) -> bool {
    // residual ≤ max·φ⁻⁴, φ⁻⁴ = 5 − 3φ:
    // max·(5 − 3φ) − residual ≥ 0 ⟺ zphi_sign(5·max − residual, −3·max) ≥ 0
    toric_geometry::zphi_sign(5 * max_abs - residual_abs, -3 * max_abs) >= 0
}

fn encode_comparative_blob(blob: &ComparativeBlob) -> ExternResult<SerializedBytes> {
    let bytes = serde_json::to_vec(blob).map_err(|e| {
        wasm_error!(WasmErrorInner::Guest(format!("Failed to serialize comparative blob: {}", e)))
    })?;
    Ok(SerializedBytes::from(UnsafeBytes::from(bytes)))
}

fn decode_comparative_blob(bytes: &SerializedBytes) -> ExternResult<ComparativeBlob> {
    let raw: Vec<u8> = UnsafeBytes::from(bytes.clone()).into();
    serde_json::from_slice(&raw).map_err(|e| {
        wasm_error!(WasmErrorInner::Guest(format!("Failed to deserialize comparative blob: {}", e)))
    })
}

#[hdk_extern]
pub fn create_comparative_attestation(
    input: CreateComparativeInput,
) -> ExternResult<ActionHash> {
    if input.winner_hash == input.loser_hash {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Comparative attestation cannot compare an artifact to itself".into()
        )));
    }
    // Both endpoints must exist — differences are between real things.
    for h in [&input.winner_hash, &input.loser_hash] {
        if get(h.clone(), GetOptions::default())?.is_none() {
            return Err(wasm_error!(WasmErrorInner::Guest(
                "Comparative attestation references a manifest not found on the DHT".into()
            )));
        }
    }
    // Checkpoint discipline: verify the cited cycle sums flat.
    if !input.cited_cycle.is_empty() {
        let mut cycle_sum: i128 = input.margin_millionths as i128;
        let mut max_abs: i128 = (input.margin_millionths as i128).abs();
        for cited in &input.cited_cycle {
            let record = get(cited.clone(), GetOptions::default())?.ok_or_else(|| {
                wasm_error!(WasmErrorInner::Guest("Cited cycle edge not found".into()))
            })?;
            let Some(entry) = record.entry().as_option() else {
                return Err(wasm_error!(WasmErrorInner::Guest("Cited edge has no entry".into())));
            };
            let att = Attestation::try_from(entry.clone()).map_err(|_| {
                wasm_error!(WasmErrorInner::Guest("Cited edge is not an attestation".into()))
            })?;
            let blob = decode_comparative_blob(&att.metadata_blob).map_err(|_| {
                wasm_error!(WasmErrorInner::Guest(
                    "Cited edge is not a comparative attestation".into()
                ))
            })?;
            // Path runs loser → winner, so cited margins ACCUMULATE
            // against this edge: flat cycle ⇒ sum ≈ 0.
            cycle_sum -= blob.margin_millionths as i128;
            max_abs = max_abs.max((blob.margin_millionths as i128).abs());
        }
        if !cycle_is_flat(cycle_sum.abs(), max_abs) {
            return Err(wasm_error!(WasmErrorInner::Guest(format!(
                "Comparative attestation contradicts its cited cycle: residual {} millionths exceeds φ⁻⁴ of max margin {} — the fired loop names the dispute",
                cycle_sum, max_abs
            ))));
        }
    }
    let blob = ComparativeBlob {
        kind: "comparative".into(),
        winner_hash: input.winner_hash.clone(),
        loser_hash: input.loser_hash.clone(),
        margin_millionths: input.margin_millionths,
        query_context: input.query_context,
        cited_cycle: input.cited_cycle,
    };
    let attestation = Attestation {
        manifest_hash: input.winner_hash.clone(),
        metadata_blob: encode_comparative_blob(&blob)?,
    };
    let action_hash = create_entry(EntryTypes::Attestation(attestation))?;
    let agent = agent_info()?.agent_initial_pubkey;
    // Winner side uses the existing link topology; loser side gets its
    // own link so preference flows are traversable from both ends.
    create_link(input.winner_hash.clone(), action_hash.clone(), LinkTypes::ManifestToAttestation, ())?;
    create_link(input.loser_hash, action_hash.clone(), LinkTypes::ManifestToAttestation, ())?;
    create_link(agent, action_hash.clone(), LinkTypes::AgentToAttestation, ())?;
    Ok(action_hash)
}

/// Aggregate comparative standing for a manifest: attester-reputation-
/// weighted net preference mass, exact millionths. The Bradley–Terry
/// slot: σ(r_w − r_l) becomes a staked, reputation-weighted sign.
#[hdk_extern]
pub fn get_comparative_standing(manifest_hash: ActionHash) -> ExternResult<ComparativeStanding> {
    let links = fetch_links(manifest_hash.clone(), LinkTypes::ManifestToAttestation)?;
    let mut net_millionths: i128 = 0;
    let mut comparisons: u32 = 0;
    for link in links {
        let Some(hash) = link.target.into_action_hash() else { continue };
        let Some(record) = get(hash, GetOptions::default())? else { continue };
        let Some(entry) = record.entry().as_option() else { continue };
        let Ok(att) = Attestation::try_from(entry.clone()) else { continue };
        let Ok(blob) = decode_comparative_blob(&att.metadata_blob) else {
            continue; // absolute attestation — not ours, skip silently
        };
        if blob.kind != "comparative" { continue; }
        let attester = record.action().author().clone();
        let rep = get_cached_reputation_millionths(&attester)?;
        let signed = if blob.winner_hash == manifest_hash {
            blob.margin_millionths as i128
        } else if blob.loser_hash == manifest_hash {
            -(blob.margin_millionths as i128)
        } else {
            continue;
        };
        // reputation-weighted, both in millionths ⇒ rescale once
        net_millionths += (signed * rep as i128) / 1_000_000;
        comparisons += 1;
    }
    Ok(ComparativeStanding { manifest_hash, net_millionths: net_millionths as i64, comparisons })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ComparativeStanding {
    pub manifest_hash: ActionHash,
    pub net_millionths: i64,
    pub comparisons: u32,
}

/// Attester reputation as exact millionths, from the existing
/// ReputationCache (score is already u32 millionths there); default
/// φ⁻² for uncached agents — same floor the recursion starts from.
fn get_cached_reputation_millionths(agent: &AgentPubKey) -> ExternResult<u64> {
    use registry_integrity::ReputationCache;
    let links = fetch_links(agent.clone(), LinkTypes::AgentToReputationCache)?;
    let Some(link) = links.into_iter().max_by_key(|l| l.timestamp.as_micros()) else {
        return Ok(381_966); // φ⁻² in millionths
    };
    let Some(hash) = link.target.into_action_hash() else { return Ok(381_966) };
    let Some(record) = get(hash, GetOptions::default())? else { return Ok(381_966) };
    let Some(entry) = record.entry().as_option() else { return Ok(381_966) };
    let Ok(cache) = ReputationCache::try_from(entry.clone()) else { return Ok(381_966) };
    Ok(cache.score as u64)
}

// ─────────────────────────────────────────────
// Relational trust field — score as position in the solved field
//
// The migration's substantive half: an artifact's standing is no
// longer only a stored property; it is its position in the field
// solved from the web of staked differences around it. The absolute
// trust score becomes the GAUGE ANCHOR (the frame), comparative edges
// the deltas. Runs alongside compute_trust_score — the migration is
// earned on evidence, not forced.
//
// Solver: weighted Jacobi relaxation, integer millionths throughout,
// deterministic (BTreeMap ordering, fixed iteration count F(8)=21,
// integer division). Component bounded at F(9)=34 manifests. Residual
// reported: per-edge inconsistency mass / total margin mass — the
// local holonomy, doubling as the confidence of the solve.
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub struct RelationalScore {
    pub manifest_hash: ActionHash,
    /// The gauge anchor: existing absolute trust score, millionths.
    pub absolute_millionths: i64,
    /// Solved field position, millionths (= absolute + relational delta).
    pub relational_millionths: i64,
    /// Local holonomy of the solved component: residual mass / margin
    /// mass, millionths. 0 = perfectly flat; higher = live dispute.
    pub residual_millionths: i64,
    pub component_size: u32,
    pub edge_count: u32,
}

#[hdk_extern]
pub fn compute_relational_score(manifest_hash: ActionHash) -> ExternResult<RelationalScore> {
    use std::collections::BTreeMap;
    let anchor_key = manifest_hash.get_raw_39().to_vec();

    // 1. BFS the comparative component around the anchor, cap F(9)=34.
    //    Edge aggregation: parallel edges collapse to a reputation-
    //    weighted mean margin (direction-normalized on sorted keys).
    let mut visited: BTreeMap<Vec<u8>, ActionHash> = BTreeMap::new();
    let mut frontier = vec![manifest_hash.clone()];
    visited.insert(anchor_key.clone(), manifest_hash.clone());
    let mut acc: BTreeMap<(Vec<u8>, Vec<u8>), (i128, i128, i128)> = BTreeMap::new(); // Σw·m, Σw, Σw·|m|
    while let Some(current) = frontier.pop() {
        if visited.len() >= 34 { break; }
        for alink in fetch_links(current.clone(), LinkTypes::ManifestToAttestation)? {
            let Some(ahash) = alink.target.into_action_hash() else { continue };
            let Some(record) = get(ahash, GetOptions::default())? else { continue };
            let Some(entry) = record.entry().as_option() else { continue };
            let Ok(att) = Attestation::try_from(entry.clone()) else { continue };
            let Ok(blob) = decode_comparative_blob(&att.metadata_blob) else { continue };
            if blob.kind != "comparative" { continue; }
            let w = get_cached_reputation_millionths(record.action().author())? as i128;
            let (wk, lk) = (blob.winner_hash.get_raw_39().to_vec(), blob.loser_hash.get_raw_39().to_vec());
            let (key, signed_m) = if wk <= lk {
                ((wk.clone(), lk.clone()), blob.margin_millionths as i128)
            } else {
                ((lk.clone(), wk.clone()), -(blob.margin_millionths as i128))
            };
            let e = acc.entry(key).or_insert((0, 0, 0));
            e.0 += w * signed_m;
            e.1 += w;
            e.2 += w * signed_m.abs();
            for (k, h) in [(wk, blob.winner_hash.clone()), (lk, blob.loser_hash.clone())] {
                if !visited.contains_key(&k) && visited.len() < 34 {
                    visited.insert(k, h.clone());
                    frontier.push(h);
                }
            }
        }
    }
    // Weighted-mean margins: x_a − x_b = m̄ for key (a, b).
    // Third component: pre-mean absolute mass Σw·|m| for the residual denominator.
    let edges: Vec<((Vec<u8>, Vec<u8>), i128, i128, i128)> = acc
        .into_iter()
        .filter(|(_, (_, sw, _))| *sw > 0)
        .map(|(k, (swm, sw, sam))| (k, swm / sw, sw, sam))
        .collect();

    // 2. Gauge frame: pin the component's lexicographically-first node
    //    at ITS absolute score — deterministic and query-independent,
    //    so the same component yields the same field from any entry
    //    point. The queried node is free to take its solved position.
    let frame_key = visited.keys().next().cloned().unwrap_or(anchor_key.clone());
    let frame_hash = visited.get(&frame_key).cloned().unwrap_or(manifest_hash.clone());
    let frame = compute_trust_score(TrustScoreInput { manifest_hash: frame_hash })?;
    let frame_val: i128 = (frame.score * 1_000_000.0) as i128;
    let absolute = compute_trust_score(TrustScoreInput { manifest_hash: manifest_hash.clone() })?;
    let anchor_val: i128 = (absolute.score * 1_000_000.0) as i128;

    // 3. Weighted Jacobi relaxation, 21 iterations, integers only.
    let mut x: BTreeMap<Vec<u8>, i128> = visited.keys().map(|k| (k.clone(), frame_val)).collect();
    for _ in 0..21 {
        let mut next = x.clone();
        for (node, val) in next.iter_mut() {
            if *node == frame_key { continue; } // the pin
            let (mut num, mut den): (i128, i128) = (0, 0);
            for ((a, b), m, w, _sam) in &edges {
                if a == node {
                    if let Some(xb) = x.get(b) { num += w * (xb + m); den += w; }
                } else if b == node {
                    if let Some(xa) = x.get(a) { num += w * (xa - m); den += w; }
                }
            }
            if den > 0 { *val = num / den; }
        }
        x = next;
    }

    // 4. Residual: Σ|x_a − x_b − m̄|·w / Σw·|m| — local holonomy.
    //    Denominator is pre-mean absolute mass so perfectly contradicted
    //    pairs (m̄ = 0) still report maximal residual, not zero.
    let (mut res_mass, mut tot_mass): (i128, i128) = (0, 0);
    for ((a, b), m, w, sam) in &edges {
        let (Some(xa), Some(xb)) = (x.get(a), x.get(b)) else { continue };
        res_mass += (xa - xb - m).abs() * w;
        tot_mass += sam;
    }
    let residual = if tot_mass > 0 { (res_mass * 1_000_000 / tot_mass).min(1_000_000) } else { 0 };

    Ok(RelationalScore {
        manifest_hash: manifest_hash.clone(),
        absolute_millionths: anchor_val as i64,
        relational_millionths: x.get(&anchor_key).copied().unwrap_or(anchor_val)
            .clamp(0, 1_000_000) as i64,
        residual_millionths: residual as i64,
        component_size: visited.len() as u32,
        edge_count: edges.len() as u32,
    })
}

// ─────────────────────────────────────────────
// query_completion — the Witness Engine's COMPLETE step
//
// A query = ONE gauge pin (the frame: a manifest the asker stands on)
// plus optional assertions (margins the asker claims). Solve the field;
// route by residual:
//   entailed      — record + assertions agree: emit solved positions
//                   with the edge list as the citation trail
//   asker_conflict — removing the assertions flattens it: the asker
//                   contradicts the record; the conflict IS the answer
//   record_dispute — residual persists without assertions: the network
//                   itself is in dispute here; abstain, name the mass
// Margin: φ⁻⁴ of solved-field mass (the negligibility floor, same line
// the cycle check uses). Abstention is a measured quantity, not a mood.
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryAssertion {
    pub better: ActionHash,
    pub worse: ActionHash,
    pub margin_millionths: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryCompletionInput {
    pub pinned_manifest: ActionHash,
    #[serde(default)]
    pub assertions: Vec<QueryAssertion>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryCompletion {
    pub verdict: String, // "entailed" | "asker_conflict" | "record_dispute"
    /// Solved positions, millionths — the completion itself.
    pub completions: Vec<(ActionHash, i64)>,
    /// Residual with assertions injected / without them, millionths.
    pub residual_with: i64,
    pub residual_without: i64,
    pub component_size: u32,
    pub edge_count: u32,
}

#[hdk_extern]
pub fn query_completion(input: QueryCompletionInput) -> ExternResult<QueryCompletion> {
    // Both solves anchor on the same frame — the pinned manifest's
    // component and absolute score (the gauge law: one frame per query).
    let base = compute_relational_score(input.pinned_manifest.clone())?;
    let residual_without = base.residual_millionths;

    // Second solve with the asker's assertions injected as maximal-
    // weight temporary edges (1e6: the asker fully stakes their frame).
    let with = solve_with_assertions(&input.pinned_manifest, &input.assertions)?;
    let residual_with = with.1;

    // φ⁻⁴ line in millionths: 1e6·(5 − 3φ) — exact via zphi on the
    // comparison, but the classification bands are on millionths.
    const MARGIN_MILLIONTHS: i64 = 145_898; // ⌊1e6·φ⁻⁴⌋; band edge, display-exactness not consensus

    let verdict = if residual_with <= MARGIN_MILLIONTHS {
        "entailed"
    } else if residual_without <= MARGIN_MILLIONTHS {
        "asker_conflict"
    } else {
        "record_dispute"
    };

    Ok(QueryCompletion {
        verdict: verdict.into(),
        completions: with.0,
        residual_with,
        residual_without,
        component_size: base.component_size,
        edge_count: base.edge_count + input.assertions.len() as u32,
    })
}

/// The field solve with assertion edges injected. Mirrors
/// compute_relational_score's solver exactly (same BFS bound, same 21
/// Jacobi iterations, same integer arithmetic, same frame rule) so the
/// two residuals are commensurable.
fn solve_with_assertions(
    pinned: &ActionHash,
    assertions: &[QueryAssertion],
) -> ExternResult<(Vec<(ActionHash, i64)>, i64)> {
    use std::collections::BTreeMap;
    // BFS identical to compute_relational_score, seeded with the pin
    // AND every assertion endpoint (assertions may reach off-component).
    let mut visited: BTreeMap<Vec<u8>, ActionHash> = BTreeMap::new();
    let mut frontier = vec![pinned.clone()];
    visited.insert(pinned.get_raw_39().to_vec(), pinned.clone());
    for a in assertions {
        for h in [&a.better, &a.worse] {
            let k = h.get_raw_39().to_vec();
            if !visited.contains_key(&k) {
                visited.insert(k, h.clone());
                frontier.push(h.clone());
            }
        }
    }
    let mut acc: BTreeMap<(Vec<u8>, Vec<u8>), (i128, i128, i128)> = BTreeMap::new();
    while let Some(current) = frontier.pop() {
        if visited.len() >= 34 { break; }
        for alink in fetch_links(current.clone(), LinkTypes::ManifestToAttestation)? {
            let Some(ahash) = alink.target.into_action_hash() else { continue };
            let Some(record) = get(ahash, GetOptions::default())? else { continue };
            let Some(entry) = record.entry().as_option() else { continue };
            let Ok(att) = Attestation::try_from(entry.clone()) else { continue };
            let Ok(blob) = decode_comparative_blob(&att.metadata_blob) else { continue };
            if blob.kind != "comparative" { continue; }
            let w = get_cached_reputation_millionths(record.action().author())? as i128;
            let (wk, lk) = (blob.winner_hash.get_raw_39().to_vec(), blob.loser_hash.get_raw_39().to_vec());
            let (key, signed_m) = if wk <= lk {
                ((wk.clone(), lk.clone()), blob.margin_millionths as i128)
            } else {
                ((lk.clone(), wk.clone()), -(blob.margin_millionths as i128))
            };
            let e = acc.entry(key).or_insert((0, 0, 0));
            e.0 += w * signed_m;
            e.1 += w;
            e.2 += w * signed_m.abs();
            for (k, h) in [(wk, blob.winner_hash.clone()), (lk, blob.loser_hash.clone())] {
                if !visited.contains_key(&k) && visited.len() < 34 {
                    visited.insert(k, h.clone());
                    frontier.push(h);
                }
            }
        }
    }
    // Inject assertions as full-stake edges.
    for a in assertions {
        let (wk, lk) = (a.better.get_raw_39().to_vec(), a.worse.get_raw_39().to_vec());
        let (key, signed_m) = if wk <= lk {
            ((wk, lk), a.margin_millionths as i128)
        } else {
            ((lk, wk), -(a.margin_millionths as i128))
        };
        let w: i128 = 1_000_000;
        let e = acc.entry(key).or_insert((0, 0, 0));
        e.0 += w * signed_m;
        e.1 += w;
        e.2 += w * (signed_m).abs();
    }
    let edges: Vec<((Vec<u8>, Vec<u8>), i128, i128, i128)> = acc
        .into_iter()
        .filter(|(_, (_, sw, _))| *sw > 0)
        .map(|(k, (swm, sw, sam))| (k, swm / sw, sw, sam))
        .collect();

    let frame_key = visited.keys().next().cloned().unwrap_or_default();
    let frame_hash = visited.get(&frame_key).cloned().unwrap_or(pinned.clone());
    let frame = compute_trust_score(TrustScoreInput { manifest_hash: frame_hash })?;
    let frame_val: i128 = (frame.score * 1_000_000.0) as i128;

    let mut x: BTreeMap<Vec<u8>, i128> = visited.keys().map(|k| (k.clone(), frame_val)).collect();
    for _ in 0..21 {
        let mut next = x.clone();
        for (node, val) in next.iter_mut() {
            if *node == frame_key { continue; }
            let (mut num, mut den): (i128, i128) = (0, 0);
            for ((a, b), m, w, _) in &edges {
                if a == node {
                    if let Some(xb) = x.get(b) { num += w * (xb + m); den += w; }
                } else if b == node {
                    if let Some(xa) = x.get(a) { num += w * (xa - m); den += w; }
                }
            }
            if den > 0 { *val = num / den; }
        }
        x = next;
    }

    let (mut res_mass, mut tot_mass): (i128, i128) = (0, 0);
    for ((a, b), m, w, sam) in &edges {
        let (Some(xa), Some(xb)) = (x.get(a), x.get(b)) else { continue };
        res_mass += (xa - xb - m).abs() * w;
        tot_mass += sam;
    }
    let residual = if tot_mass > 0 { (res_mass * 1_000_000 / tot_mass).min(1_000_000) as i64 } else { 0 };

    let completions = visited
        .iter()
        .filter_map(|(k, h)| x.get(k).map(|v| (h.clone(), (*v).clamp(0, 1_000_000) as i64)))
        .collect();
    Ok((completions, residual))
}

// ─────────────────────────────────────────────
// Create Warrant
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn create_warrant(input: CreateWarrantInput) -> ExternResult<ActionHash> {
    let _evidence_hash = warrant_evidence_hash(&input.blob);
    let metadata_blob = encode_warrant_blob(&input.blob)?;
    let warrant = RegistryWarrant {
        manifest_hash: input.manifest_hash.clone(),
        metadata_blob,
    };
    let action_hash = create_entry(EntryTypes::Warrant(warrant))?;
    create_link(input.manifest_hash, action_hash.clone(), LinkTypes::ManifestToWarrant, ())?;
    Ok(action_hash)
}

#[hdk_extern]
pub fn record_convergence(input: ConvergenceInput) -> ExternResult<ActionHash> {
    use registry_integrity::ConvergenceSignal;
    let signal = ConvergenceSignal {
        agent: input.agent.clone(),
        agreed: input.agreed,
        request_hash: input.request_hash,
    };
    let action_hash = create_entry(EntryTypes::ConvergenceSignal(signal))?;
    create_link(input.agent, action_hash.clone(), LinkTypes::AgentToConvergenceSignal, ())?;
    Ok(action_hash)
}

#[hdk_extern]
pub fn confirm_warrant(input: ConfirmWarrantInput) -> ExternResult<ActionHash> {
    use registry_integrity::WarrantConfirmation;

    let record = get(input.warrant_hash.clone(), GetOptions::default())?
        .ok_or(wasm_error!(WasmErrorInner::Guest("Warrant not found".to_string())))?;
    let warrant = record.entry().as_option()
        .ok_or(wasm_error!(WasmErrorInner::Guest("Warrant entry missing".to_string())))
        .and_then(|e| registry_integrity::Warrant::try_from(e)
            .map_err(|_| wasm_error!(WasmErrorInner::Guest("Failed to decode warrant".to_string()))))?;

    let raw: Vec<u8> = UnsafeBytes::from(warrant.metadata_blob).into();
    let json_start = raw.iter().position(|&b| b == b'{').unwrap_or(0);
    let computed_severity = serde_json::from_slice::<serde_json::Value>(&raw[json_start..])
        .ok()
        .and_then(|j| j["computed_severity"].as_u64())
        .unwrap_or(0) as u32;

    let confirmation = WarrantConfirmation {
        warrant_hash: input.warrant_hash,
        manifest_hash: input.manifest_hash.clone(),
        confirmed_severity: computed_severity,
        confirmed_at: sys_time()?,
    };
    let action_hash = create_entry(EntryTypes::WarrantConfirmation(confirmation))?;
    create_link(input.manifest_hash, action_hash.clone(), LinkTypes::ManifestToWarrantConfirmation, ())?;
    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Get functions
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn get_manifest(action_hash: ActionHash) -> ExternResult<Option<Record>> {
    get(action_hash, GetOptions::default())
}

#[hdk_extern]
pub fn get_agent_manifests(agent: AgentPubKey) -> ExternResult<Vec<Record>> {
    links_to_records(fetch_links(agent, LinkTypes::AgentToManifest)?)
}

#[hdk_extern]
pub fn get_manifest_attestations(manifest_hash: ActionHash) -> ExternResult<Vec<Record>> {
    links_to_records(fetch_links(manifest_hash, LinkTypes::ManifestToAttestation)?)
}

#[hdk_extern]
pub fn get_manifest_warrants(manifest_hash: ActionHash) -> ExternResult<Vec<Record>> {
    links_to_records(fetch_links(manifest_hash, LinkTypes::ManifestToWarrant)?)
}

#[hdk_extern]
pub fn get_manifest_validators(input: LineageInput) -> ExternResult<Vec<AgentPubKey>> {
    let links = fetch_links(input.manifest_hash, LinkTypes::ManifestToValidator)?;
    Ok(links.into_iter().filter_map(|l| AgentPubKey::try_from(l.target).ok()).collect())
}

#[hdk_extern]
pub fn get_all_manifests(_: ()) -> ExternResult<Vec<ActionHash>> {
    let path = Path::from("manifests.all");
    let typed = path.typed(LinkTypes::GlobalManifestAnchor)?;
    let links = fetch_links(typed.path_entry_hash()?, LinkTypes::GlobalManifestAnchor)?;
    Ok(links.into_iter().filter_map(|l| l.target.into_action_hash()).collect())
}

#[hdk_extern]
pub fn get_agent_attestations(agent: AgentPubKey) -> ExternResult<Vec<Record>> {
    links_to_records(fetch_links(agent, LinkTypes::AgentToAttestation)?)
}

// ─────────────────────────────────────────────
// Bridge-callable functions
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn submit_attestation(input: CreateAttestationInput) -> ExternResult<ActionHash> {
    create_attestation(input)
}

#[hdk_extern]
pub fn create_quorum_attestation(input: QuorumAttestationInput) -> ExternResult<ActionHash> {
    let blob = AttestationBlob::Generic(GenericAttestation {
        validation_method_hash: None,
        attestation_type: "quorum_consensus".to_string(),
        passed: true,
        score: Some(1.0),
        details: Some("Quorum reached via reputation-weighted consensus".to_string()),
        evaluated_at: None,
    });
    create_attestation(CreateAttestationInput {
        manifest_hash: input.manifest_hash,
        blob: encode_attestation_blob(&blob)?,
    })
}

// ─────────────────────────────────────────────
// Commit / reveal counters
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn apply_reveal_penalty(input: RevealPenaltyInput) -> ExternResult<()> {
    use registry_integrity::ReputationCache;

    let links = fetch_links(input.agent.clone(), LinkTypes::AgentToReputationCache)?;
    let (prev_commits, prev_reveals, prev_score, prev_delta, prev_att, prev_warr) =
        if let Some(link) = links.last() {
            if let Some(hash) = link.target.clone().into_action_hash() {
                if let Some(record) = get(hash, GetOptions::default())? {
                    if let Some(entry) = record.entry().as_option() {
                        if let Ok(cache) = ReputationCache::try_from(entry) {
                            (cache.total_commits, cache.total_reveals,
                             cache.score, cache.score_delta,
                             cache.attestation_count, cache.warrant_count)
                        } else { (0, 0, 0, 0, 0, 0) }
                    } else { (0, 0, 0, 0, 0, 0) }
                } else { (0, 0, 0, 0, 0, 0) }
            } else { (0, 0, 0, 0, 0, 0) }
        } else { (0, 0, 0, 0, 0, 0) };

    let current_score = prev_score as f64 / 1_000_000.0;
    let penalized_score = (current_score - input.penalty).max(f64::EPSILON);

    let cache = ReputationCache {
        agent: input.agent.clone(),
        score: (penalized_score * 1_000_000.0) as u32,
        score_delta: prev_delta,
        computed_at: sys_time()?,
        attestation_count: prev_att,
        warrant_count: prev_warr,
        total_commits: prev_commits,
        total_reveals: prev_reveals,
    };
    let action_hash = create_entry(EntryTypes::ReputationCache(cache))?;
    create_link(input.agent, action_hash, LinkTypes::AgentToReputationCache, ())?;
    Ok(())
}

#[hdk_extern]
pub fn increment_commit_count(input: IncrementInput) -> ExternResult<()> {
    use registry_integrity::ReputationCache;

    let links = fetch_links(input.agent.clone(), LinkTypes::AgentToReputationCache)?;
    let (prev_commits, prev_reveals, prev_score, prev_delta, prev_att, prev_warr) =
        if let Some(link) = links.last() {
            if let Some(hash) = link.target.clone().into_action_hash() {
                if let Some(record) = get(hash, GetOptions::default())? {
                    if let Some(entry) = record.entry().as_option() {
                        if let Ok(cache) = ReputationCache::try_from(entry) {
                            (cache.total_commits, cache.total_reveals,
                             cache.score, cache.score_delta,
                             cache.attestation_count, cache.warrant_count)
                        } else { (0, 0, 0, 0, 0, 0) }
                    } else { (0, 0, 0, 0, 0, 0) }
                } else { (0, 0, 0, 0, 0, 0) }
            } else { (0, 0, 0, 0, 0, 0) }
        } else { (0, 0, 0, 0, 0, 0) };

    let cache = ReputationCache {
        agent: input.agent.clone(),
        score: prev_score,
        score_delta: prev_delta,
        computed_at: sys_time()?,
        attestation_count: prev_att,
        warrant_count: prev_warr,
        total_commits: prev_commits + 1,
        total_reveals: prev_reveals,
    };
    let action_hash = create_entry(EntryTypes::ReputationCache(cache))?;
    create_link(input.agent, action_hash, LinkTypes::AgentToReputationCache, ())?;
    Ok(())
}

#[hdk_extern]
pub fn increment_reveal_count(input: IncrementInput) -> ExternResult<()> {
    use registry_integrity::ReputationCache;

    let links = fetch_links(input.agent.clone(), LinkTypes::AgentToReputationCache)?;
    let (prev_commits, prev_reveals, prev_score, prev_delta, prev_att, prev_warr) =
        if let Some(link) = links.last() {
            if let Some(hash) = link.target.clone().into_action_hash() {
                if let Some(record) = get(hash, GetOptions::default())? {
                    if let Some(entry) = record.entry().as_option() {
                        if let Ok(cache) = ReputationCache::try_from(entry) {
                            (cache.total_commits, cache.total_reveals,
                             cache.score, cache.score_delta,
                             cache.attestation_count, cache.warrant_count)
                        } else { (0, 0, 0, 0, 0, 0) }
                    } else { (0, 0, 0, 0, 0, 0) }
                } else { (0, 0, 0, 0, 0, 0) }
            } else { (0, 0, 0, 0, 0, 0) }
        } else { (0, 0, 0, 0, 0, 0) };

    let cache = ReputationCache {
        agent: input.agent.clone(),
        score: prev_score,
        score_delta: prev_delta,
        computed_at: sys_time()?,
        attestation_count: prev_att,
        warrant_count: prev_warr,
        total_commits: prev_commits,
        total_reveals: prev_reveals + 1,
    };
    let action_hash = create_entry(EntryTypes::ReputationCache(cache))?;
    create_link(input.agent, action_hash, LinkTypes::AgentToReputationCache, ())?;
    Ok(())
}

// ─────────────────────────────────────────────
// Compute reputation score
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn compute_reputation_score(input: ReputationInput) -> ExternResult<ReputationScore> {
    if let Some(cached) = get_cached_reputation(&input.agent)? {
        return Ok(cached);
    }

    let agent_manifests = fetch_links(input.agent.clone(), LinkTypes::AgentToManifest)?;
    let mut actions: Vec<(Timestamp, bool)> = Vec::new();
    let mut total_attestations: u32 = 0;
    let mut total_warrants: u32 = 0;

    for link in agent_manifests {
        if let Some(manifest_hash) = link.target.into_action_hash() {
            let attestation_links = fetch_links(manifest_hash.clone(), LinkTypes::ManifestToAttestation)?;
            for att_link in &attestation_links {
                if att_link.author != input.agent {
                    actions.push((att_link.timestamp, true));
                    total_attestations += 1;
                }
            }
            let warrant_links = fetch_links(manifest_hash.clone(), LinkTypes::ManifestToWarrant)?;
            for war_link in &warrant_links {
                actions.push((war_link.timestamp, false));
                total_warrants += 1;
            }
        }
    }

    let score = if actions.is_empty() {
        INV_PHI_SQ
    } else {
        actions.sort_by_key(|(ts, _)| ts.as_micros());
        // Tier 2 exact: identical law, integer fixed-point ℚ(φ) —
        // bit-identical on every platform. f64 only at the boundary.
        let events: Vec<bool> = actions.iter().map(|(_, a)| *a).collect();
        toric_geometry::reputation_recursion_exact(&events)
            .to_f64()
            .max(f64::EPSILON)
    };

    let convergence_links = fetch_links(input.agent.clone(), LinkTypes::AgentToConvergenceSignal).unwrap_or_default();
    let adjusted_score = if convergence_links.is_empty() {
        score
    } else {
        let mut s = score;
        for link in &convergence_links {
            if let Some(hash) = link.target.clone().into_action_hash() {
                if let Ok(Some(record)) = get(hash, GetOptions::default()) {
                    if let Some(entry) = record.entry().as_option() {
                        if let Ok(sig) = registry_integrity::ConvergenceSignal::try_from(entry) {
                            if sig.agreed {
                                s += (1.0 - s) * INV_PHI_4;
                            } else {
                                s -= s * INV_PHI_4 * PHI;
                            }
                        }
                    }
                }
            }
        }
        s.max(f64::EPSILON)
    };

    let previous_score = get_cached_reputation(&input.agent)
        .ok().flatten().map(|c| c.score).unwrap_or(INV_PHI_SQ);
    let score_delta = adjusted_score - previous_score;

    let result = ReputationScore {
        agent: input.agent,
        score: adjusted_score,
        score_delta,
        attestation_count: total_attestations,
        warrant_count: total_warrants,
        total_commits: 0,
        total_reveals: 0,
    };
    write_reputation_cache(&result).ok();
    Ok(result)
}

// ─────────────────────────────────────────────
// Network reputation
// ─────────────────────────────────────────────

// Canonical network-agent enumeration: every agent that has authored a
// manifest, discovered by walking GlobalManifestAnchor. Single source of
// truth for "who is on the network" — get_network_reputation and
// check_closure both call this so they cannot diverge on the population
// they measure over. Do not enumerate agents any other way.
fn collect_network_agents() -> ExternResult<std::collections::HashSet<AgentPubKey>> {
    let path = Path::from("manifests.all");
    let typed = path.typed(LinkTypes::GlobalManifestAnchor)?;
    let all_manifest_links = match typed.exists()? {
        true => fetch_links(typed.path_entry_hash()?, LinkTypes::GlobalManifestAnchor)?,
        false => vec![],
    };

    let mut seen_agents: std::collections::HashSet<AgentPubKey> = std::collections::HashSet::new();
    for link in &all_manifest_links {
        seen_agents.insert(link.author.clone());
    }
    Ok(seen_agents)
}

/// (agent, score) pairs over the canonical population — the input to
/// the sovereignty roster function. Bridge-callable by mutual_credit
/// (roster derivation) and by every roster member's independent
/// verification in sign_network_state.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScoredAgent {
    pub agent: AgentPubKey,
    pub score: f64,
}

#[hdk_extern]
pub fn get_scored_agents(_: ()) -> ExternResult<Vec<ScoredAgent>> {
    let mut out: Vec<ScoredAgent> = Vec::new();
    for agent in collect_network_agents()? {
        let rep = match get_cached_reputation(&agent)? {
            Some(cached) => cached,
            None => match compute_reputation_score(ReputationInput { agent: agent.clone() }) {
                Ok(r) => r,
                Err(_) => continue,
            },
        };
        out.push(ScoredAgent { agent, score: rep.score });
    }
    Ok(out)
}

pub fn get_network_reputation(_: ()) -> ExternResult<NetworkReputationResult> {
    let seen_agents = collect_network_agents()?;

    if seen_agents.is_empty() {
        return Ok(NetworkReputationResult {
            honest_rep_fraction: 1.0,
            total_reputation: 0.0,
            honest_reputation: 0.0,
            average_reputation: INV_PHI_SQ,
            agent_count: 0,
            warranted_agent_count: 0,
        });
    }

    let mut total_reputation: f64 = 0.0;
    let mut honest_reputation: f64 = 0.0;
    let mut warranted_agent_count: u32 = 0;
    let mut agent_scores: Vec<f64> = Vec::new();

    for agent in &seen_agents {
        let rep = match get_cached_reputation(agent)? {
            Some(cached) => cached,
            None => match compute_reputation_score(ReputationInput { agent: agent.clone() }) {
                Ok(r) => r,
                Err(_) => continue,
            },
        };
        total_reputation += rep.score;
        agent_scores.push(rep.score);
    }

    let network_average = if agent_scores.is_empty() {
        INV_PHI_SQ
    } else {
        total_reputation / agent_scores.len() as f64
    };

    let honest_threshold = (network_average / PHI).max(INV_PHI_SQ / PHI);

    for score in &agent_scores {
        if *score >= honest_threshold {
            honest_reputation += score;
        } else {
            warranted_agent_count += 1;
        }
    }

    let honest_rep_fraction = if total_reputation <= 0.0 {
        1.0
    } else {
        (honest_reputation / total_reputation).clamp(0.0, 1.0)
    };

    let average_reputation = if seen_agents.is_empty() {
        INV_PHI_SQ
    } else {
        total_reputation / seen_agents.len() as f64
    };

    Ok(NetworkReputationResult {
        honest_rep_fraction,
        total_reputation,
        honest_reputation,
        average_reputation,
        agent_count: seen_agents.len() as u32,
        warranted_agent_count,
    })
}

// ─────────────────────────────────────────────
// Trust score computation
// ─────────────────────────────────────────────

fn compute_direct_score(manifest_hash: &ActionHash) -> ExternResult<(f64, f64, u32)> {
    let attestation_links = fetch_links(manifest_hash.clone(), LinkTypes::ManifestToAttestation)?;
    if attestation_links.is_empty() {
        return Ok((0.0, 0.0, 0));
    }

    let mut sorted_links = attestation_links.clone();
    sorted_links.sort_by_key(|l| l.timestamp.as_micros());

    let n_total = sorted_links.len() as f64;
    let denominator = PHI * (1.0 - PHI.powf(-n_total));
    let mut score: f64 = 0.0;
    let mut weighted_count: f64 = 0.0;

    for (i, link) in sorted_links.iter().enumerate() {
        let n = (i + 1) as f64;
        let base_weight = PHI.powf(-n) / denominator;
        let attestor_rep = match compute_reputation_score(ReputationInput { agent: link.author.clone() }) {
            Ok(r) => r.score,
            Err(_) => INV_PHI_SQ,
        };
        let contribution = base_weight * attestor_rep;

        if let Some(att_hash) = link.target.clone().into_action_hash() {
            if let Some(record) = get(att_hash, GetOptions::default())? {
                if let Some(entry) = record.entry().as_option() {
                    if let Ok(attestation) = registry_integrity::Attestation::try_from(entry) {
                        let raw: Vec<u8> = UnsafeBytes::from(attestation.metadata_blob.clone()).into();
                        let json_start = raw.iter().position(|&b| b == b'{').unwrap_or(0);
                        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&raw[json_start..]) {
                            // Multi-dimensional scoring — reads four dimensions if present
                            // Falls back to legacy passed/score for older attestations
                            let dimensional_score = {
                                let hash_score = json["hash_score"].as_f64();
                                let provenance_score = json["provenance_score"].as_f64();
                                let static_score = json["static_score"].as_f64();
                                let probe_score = json["probe_score"].as_f64();

                                if let Some(h) = hash_score {
                                    let mut total_weight = INV_PHI;
                                    let mut blended = h * INV_PHI;
                                    if let Some(p) = provenance_score {
                                        blended += p * INV_PHI_SQ;
                                        total_weight += INV_PHI_SQ;
                                    }
                                    if let Some(s) = static_score {
                                        blended += s * INV_PHI_CU;
                                        total_weight += INV_PHI_CU;
                                    }
                                    if let Some(pr) = probe_score {
                                        blended += pr * INV_PHI_4;
                                        total_weight += INV_PHI_4;
                                    }
                                    blended / total_weight
                                } else {
                                    let passed = json["passed"].as_bool().unwrap_or(true);
                                    json["score"].as_f64().unwrap_or(if passed { 1.0 } else { 0.0 })
                                }
                            };

                            // INV_PHI (φ⁻¹ = 0.618) is the geometric pass threshold —
                            // consistent with the trust score pass threshold.
                            // Below φ⁻¹: attestation contributes negatively, amplified by φ.
                            if dimensional_score >= INV_PHI {
                                score += contribution * dimensional_score;
                            } else {
                                score -= contribution * (1.0 - dimensional_score) * PHI;
                            }
                            weighted_count += contribution;
                        } else {
                            score += contribution;
                            weighted_count += contribution;
                        }
                    }
                }
            }
        }
    }

    Ok((score, weighted_count, sorted_links.len() as u32))
}

fn compute_upstream_score(manifest_hash: &ActionHash, depth: u32) -> f64 {
    if depth == 0 { return 0.0; }

    let upstream_links = match fetch_links(manifest_hash.clone(), LinkTypes::ManifestToUpstream) {
        Ok(l) => l,
        Err(_) => return 0.0,
    };
    if upstream_links.is_empty() { return 0.0; }

    let mut upstream_scores: Vec<f64> = Vec::new();
    for link in &upstream_links {
        if let Some(upstream_hash) = link.target.clone().into_action_hash() {
            let score = if let Ok(Some(cached)) = get_cached_trust_score(&upstream_hash) {
                cached.score
            } else {
                match compute_direct_score(&upstream_hash) {
                    Ok((s, _, _)) => s.clamp(0.0, 1.0),
                    Err(_) => 0.0,
                }
            };
            let recursive = compute_upstream_score(&upstream_hash, depth - 1);
            upstream_scores.push(score * INV_PHI + recursive * (1.0 - INV_PHI));
        }
    }

    if upstream_scores.is_empty() { return 0.0; }
    upstream_scores.iter().sum::<f64>() / upstream_scores.len() as f64
}

fn compute_warrant_penalty(manifest_hash: &ActionHash) -> f64 {
    let confirmation_links = match fetch_links(manifest_hash.clone(), LinkTypes::ManifestToWarrantConfirmation) {
        Ok(l) => l,
        Err(_) => return 0.0,
    };
    if confirmation_links.is_empty() { return 0.0; }

    let mut total_penalty: f64 = 0.0;
    for link in &confirmation_links {
        if let Some(conf_hash) = link.target.clone().into_action_hash() {
            if let Ok(Some(record)) = get(conf_hash, GetOptions::default()) {
                if let Some(entry) = record.entry().as_option() {
                    if let Ok(confirmation) = registry_integrity::WarrantConfirmation::try_from(entry) {
                        let severity = confirmation.confirmed_severity as f64 / 1_000_000.0;
                        total_penalty += PHI * severity;
                    }
                }
            }
        }
    }
    total_penalty
}

fn recompute_trust_score_uncached(manifest_hash: &ActionHash) -> ExternResult<TrustScoreResult> {
    // Blob type check — trust score only for scoreable artifact types
    let manifest_record = get(manifest_hash.clone(), GetOptions::default())?;
    let blob_type_valid = manifest_record
        .as_ref()
        .and_then(|r| r.entry().as_option())
        .and_then(|e| registry_integrity::Manifest::try_from(e).ok())
        .and_then(|m| {
            let raw: Vec<u8> = UnsafeBytes::from(m.metadata_blob).into();
            let json_start = raw.iter().position(|&b| b == b'{')?;
            let json: serde_json::Value = serde_json::from_slice(&raw[json_start..]).ok()?;
            json["blob_type"].as_str().map(|t| matches!(t,
                "ai_model" | "dataset" | "training_run" | "inference_endpoint"
            ))
        })
        .unwrap_or(false);

    if !blob_type_valid {
        return Ok(TrustScoreResult {
            manifest_hash: manifest_hash.clone(),
            score: 0.0,
            passes: false,
            attestation_count: 0,
            weighted_attestation_count: 0.0,
        });
    }

    let (direct_score, weighted_count, attestation_count) = compute_direct_score(manifest_hash)?;
    let upstream_score = compute_upstream_score(manifest_hash, MAX_UPSTREAM_DEPTH);

    let convergence_score = {
        let manifest_record = get(manifest_hash.clone(), GetOptions::default())?;
        let content_hash_opt = manifest_record
            .and_then(|r| r.entry().as_option().cloned())
            .and_then(|e| registry_integrity::Manifest::try_from(&e).ok())
            .and_then(|m| {
                let raw: Vec<u8> = UnsafeBytes::from(m.metadata_blob).into();
                let json_start = raw.iter().position(|&b| b == b'{')?;
                let json: serde_json::Value = serde_json::from_slice(&raw[json_start..]).ok()?;
                json["content_hash"].as_str().map(|s| s.to_string())
            });

        if let Some(content_hash) = content_hash_opt {
            let path = Path::from(format!("content.{}", content_hash));
            let typed_path = path.typed(LinkTypes::ContentHashToManifest)?;
            let convergence_links = fetch_links(typed_path.path_entry_hash()?, LinkTypes::ContentHashToManifest)?;
            let unique_agents: std::collections::HashSet<_> = convergence_links.iter().map(|l| l.author.clone()).collect();
            let n_raw = unique_agents.len() as f64;
            let total_agents = match get_network_reputation(()) {
                Ok(net) if net.agent_count > 0 => net.agent_count as f64,
                _ => n_raw,
            };
            let n_weighted = (n_raw / total_agents) * PHI_SQ;
            1.0 - INV_PHI.powf(n_weighted)
        } else {
            0.0
        }
    };

    let total_weight = INV_PHI + INV_PHI_SQ + INV_PHI_CU;
    let blended = if upstream_score > 0.0 || convergence_score > 0.0 {
        (direct_score * INV_PHI + upstream_score * INV_PHI_SQ + convergence_score * INV_PHI_CU) / total_weight
    } else {
        direct_score
    };

    let warrant_penalty = compute_warrant_penalty(manifest_hash);
    let final_score = (blended - warrant_penalty).clamp(0.0, 1.0);

    Ok(TrustScoreResult {
        manifest_hash: manifest_hash.clone(),
        score: final_score,
        passes: final_score >= INV_PHI,
        attestation_count,
        weighted_attestation_count: weighted_count,
    })
}

#[hdk_extern]
pub fn compute_trust_score(input: TrustScoreInput) -> ExternResult<TrustScoreResult> {
    if let Ok(Some(cached)) = get_cached_trust_score(&input.manifest_hash) {
        return Ok(cached);
    }

    let result = recompute_trust_score_uncached(&input.manifest_hash)?;
    write_trust_score_cache(&input.manifest_hash, &result).ok();
    Ok(result)
}

// ─────────────────────────────────────────────
// Closure detection
// ─────────────────────────────────────────────

fn fetch_latest_geometry_params() -> ExternResult<Option<(ActionHash, registry_integrity::GeometryParams)>> {
    use registry_integrity::GeometryParams;

    let path = Path::from("geometry.params");
    let typed = path.typed(LinkTypes::GeometryParamsAnchor)?;
    let links = fetch_links(typed.path_entry_hash()?, LinkTypes::GeometryParamsAnchor)?;
    if let Some(link) = links.last() {
        if let Some(hash) = link.target.clone().into_action_hash() {
            if let Some(record) = get(hash.clone(), GetOptions::default())? {
                if let Some(entry) = record.entry().as_option() {
                    if let Ok(gp) = GeometryParams::try_from(entry) {
                        return Ok(Some((hash, gp)));
                    }
                }
            }
        }
    }
    Ok(None)
}

/// Run the three active closure probes against live DHT state:
///
///   - Probe 2: quorum weight measured-vs-target (latest round)
///   - Probe 3: reveal discipline measured-vs-target (network-wide)
///   - Probe 4: trust score recompute-vs-stored  (given manifest)
///
/// Each probe emits a DeviationSignal; the caller (NetworkRoundManifest
/// author) serializes the returned ClosureStatus into the round entry.
///
/// Returns empty signals (not an error) when GeometryParams are absent —
/// the network has no target to check against. Callers must interpret
/// `worst_deviation() == None` as "investigate, not healthy."
fn fetch_economic_snapshot() -> Option<EconomicSnapshot> {
    match call(
        CallTargetCell::Local,
        ZomeName::from("mutual_credit"),
        FunctionName::from("economic_snapshot"),
        None,
        (),
    ) {
        Ok(ZomeCallResponse::Ok(bytes)) => bytes.decode().ok(),
        _ => None,
    }
}

fn check_closure(
    manifest_hash: &ActionHash,
    combined_weight: f64,
) -> ExternResult<ClosureStatus> {
    let (gp_hash, gp) = match fetch_latest_geometry_params()? {
        Some(pair) => pair,
        None => return Ok(ClosureStatus { passed: true, signals: vec![] }),
    };
    let targets = derive_targets(gp.tau_us);
    let gp_hash_bytes: Vec<u8> = gp_hash.get_raw_32().to_vec();

    let mut signals: Vec<DeviationSignal> = Vec::new();

    // ── Probe 3: reveal discipline (network reveal rate vs φ⁻¹ target) ──
    // Network-wide aggregation over the canonical agent set. Uses
    // collect_network_agents (the same enumeration get_network_reputation
    // uses) so the two cannot diverge on what "the network" is. actual =
    // Σreveals / Σcommits across all agents; expected = reveal_rate_target
    // (φ⁻¹), the same pass line used everywhere else in the system.
    //
    // No-data handling: when sum_commits == 0 the probe is OMITTED, not
    // pushed as a synthetic healthy 0.0. "No measurement was possible" must
    // stay structurally distinct from "measured and healthy" all the way up
    // to worst_deviation — collapsing them would manufacture confidence the
    // system doesn't have, the same failure as a cache-compared-to-itself
    // audit. An empty network simply contributes no probe-3 signal this
    // round; probes 2 and 4 stand on their own.
    {
        let mut sum_commits: u64 = 0;
        let mut sum_reveals: u64 = 0;
        for a in collect_network_agents()? {
            if let Ok(r) = compute_reputation_score(ReputationInput { agent: a }) {
                sum_commits += r.total_commits as u64;
                sum_reveals += r.total_reveals as u64;
            }
        }
        if sum_commits > 0 {
            let actual_reveal_rate = sum_reveals as f64 / sum_commits as f64;
            signals.push(DeviationSignal {
                probe_id: 3,
                deviation_magnitude: normalized_deviation(
                    targets.reveal_rate_target,
                    actual_reveal_rate,
                ),
                expected: targets.reveal_rate_target,
                actual: actual_reveal_rate,
                geometry_params_hash: gp_hash_bytes.clone(),
                manifest_hash: None,
            });
        }
    }

    // ── Probe 2: quorum weight vs target ──────────────────────────
    // actual = this round's combined_weight, passed in from check_quorum
    // (the value it already computed for its own resolution decision) —
    // measures the round being closed, not a lagged prior round.
    // expected = total_reputation × quorum_weight_multiplier (φ⁻¹ ideal).
    {
        let net_rep = match get_network_reputation(()) {
            Ok(r) => r,
            Err(_) => NetworkReputationResult {
                honest_rep_fraction: 1.0,
                total_reputation: 0.0,
                honest_reputation: 0.0,
                average_reputation: INV_PHI_SQ,
                agent_count: 0,
                warranted_agent_count: 0,
            },
        };
        let expected_qw = net_rep.total_reputation * targets.quorum_weight_multiplier;
        signals.push(DeviationSignal {
            probe_id: 2,
            deviation_magnitude: normalized_deviation(expected_qw, combined_weight),
            expected: expected_qw,
            actual: combined_weight,
            geometry_params_hash: gp_hash_bytes.clone(),
            manifest_hash: None,
        });
    }

    // ── Probe 4: trust score drift ────────────────────────────────
    let ts_cached = get_cached_trust_score(manifest_hash)?;
    let ts_recomputed = match recompute_trust_score_uncached(manifest_hash) {
        Ok(r) => r,
        Err(_) => TrustScoreResult {
            manifest_hash: manifest_hash.clone(),
            score: 0.0,
            passes: false,
            attestation_count: 0,
            weighted_attestation_count: 0.0,
        },
    };
    let expected_ts = ts_cached.map(|c| c.score).unwrap_or(0.0);
    let actual_ts = ts_recomputed.score;
    signals.push(DeviationSignal {
        probe_id: 4,
        deviation_magnitude: normalized_deviation(expected_ts, actual_ts),
        expected: expected_ts,
        actual: actual_ts,
        geometry_params_hash: gp_hash_bytes.clone(),
        manifest_hash: Some(manifest_hash.get_raw_32().to_vec()),
    });

    // ── Probes 5–7: economic domain ───────────────────────────────
    // Measured by the mutual_credit sibling zome, pulled locally.
    // None ⇒ omitted, not synthesized healthy — same no-data discipline
    // as probe 3.
    let economic = fetch_economic_snapshot();
    if let Some(econ) = economic.as_ref() {
        // Probe 5: supply position. Live supply vs genesis folded
        // through ⌊supply × φ⌋ per crossing — the per-step law integrity
        // enforces, replayed from origin. Any mismatch means a step
        // escaped validation (or a fork is being read).
        let expected = expected_supply(econ.cycle) as f64;
        signals.push(DeviationSignal {
            probe_id: PROBE_SUPPLY_POSITION,
            deviation_magnitude: normalized_deviation(expected, econ.credit_supply as f64),
            expected,
            actual: econ.credit_supply as f64,
            geometry_params_hash: gp_hash_bytes.clone(),
            manifest_hash: None,
        });

        // Probe 6: roster conformance. Jaccard distance between the
        // sealed roster and the reputation-derived one — the
        // sovereignty probe. Nonzero means governance has drifted from
        // the function that legitimizes it; a persistently nonzero
        // value under an unchanged roster is entrenchment, observable.
        // Omitted before sovereignty is declared (no roster to audit).
        if !econ.sealed_roster.is_empty() {
            signals.push(DeviationSignal {
                probe_id: PROBE_ROSTER_CONFORMANCE,
                deviation_magnitude: econ.roster_divergence,
                expected: 0.0,
                actual: econ.roster_divergence,
                geometry_params_hash: gp_hash_bytes.clone(),
                manifest_hash: None,
            });
        }

        // Probe 7: frozen MASS fraction vs the negligibility ceiling
        // φ⁻⁴. Mass-shaped, not count-shaped — counting frozen agents
        // instead of frozen credit capacity is the head/mass confusion
        // (item 2's disease) at the observation layer: sybils are cheap
        // in heads, expensive in mass. Falls back to the count basis
        // only for pre-mass snapshots (total_mass 0). Omitted when
        // there is nothing to measure.
        if econ.account_count > 0 {
            let frozen_fraction = if econ.total_credit_mass > 0 {
                econ.frozen_credit_mass as f64 / econ.total_credit_mass as f64
            } else {
                econ.frozen_count as f64 / econ.account_count as f64
            };
            signals.push(DeviationSignal {
                probe_id: PROBE_FROZEN_FRACTION,
                deviation_magnitude: ceiling_deviation(INV_PHI_4, frozen_fraction),
                expected: INV_PHI_4,
                actual: frozen_fraction,
                geometry_params_hash: gp_hash_bytes.clone(),
                manifest_hash: None,
            });
        }
    }

    // Probe 8 — holonomy audit. Sample recent manifests' comparative
    // edges; measure contradiction mass on 2-cycles (A>B and B>A whose
    // margins fail to cancel — the smallest fired loop) as a fraction
    // of total preference mass. Localizing: fired pairs name the exact
    // manifests in dispute. Mass-shaped (margin millionths), expected
    // 0. Omitted when no comparative edges exist — the network never
    // reports synthetic health. Bounded at F(8)=21 manifests (the era
    // quantum), most recent first.
    {
        let path = Path::from("manifests.all");
        let typed = path.typed(LinkTypes::GlobalManifestAnchor)?;
        let mut mlinks = fetch_links(typed.path_entry_hash()?, LinkTypes::GlobalManifestAnchor)?;
        mlinks.sort_by_key(|l| std::cmp::Reverse(l.timestamp.as_micros()));
        let mut edges: std::collections::BTreeMap<(Vec<u8>, Vec<u8>), i128> =
            std::collections::BTreeMap::new();
        let mut total_margin_mass: i128 = 0;
        for mlink in mlinks.into_iter().take(21) {
            let Some(mhash) = mlink.target.into_action_hash() else { continue };
            for alink in fetch_links(mhash.clone(), LinkTypes::ManifestToAttestation)? {
                let Some(ahash) = alink.target.into_action_hash() else { continue };
                let Some(record) = get(ahash, GetOptions::default())? else { continue };
                let Some(entry) = record.entry().as_option() else { continue };
                let Ok(att) = Attestation::try_from(entry.clone()) else { continue };
                let Ok(blob) = decode_comparative_blob(&att.metadata_blob) else { continue };
                if blob.kind != "comparative" { continue; }
                let key = (
                    blob.winner_hash.get_raw_39().to_vec(),
                    blob.loser_hash.get_raw_39().to_vec(),
                );
                // Direction-normalized: A→B stored positive, B→A folds
                // in negated. A flat pair sums to zero; residue = dispute.
                let (key, signed) = if key.0 <= key.1 {
                    (key, blob.margin_millionths as i128)
                } else {
                    ((key.1, key.0), -(blob.margin_millionths as i128))
                };
                *edges.entry(key).or_insert(0) += signed;
                total_margin_mass += (blob.margin_millionths as i128).abs();
            }
        }
        if total_margin_mass > 0 {
            let residual_mass: i128 = edges.values().map(|v| v.abs()).sum::<i128>()
                .min(total_margin_mass);
            let holonomy = residual_mass as f64 / total_margin_mass as f64;
            signals.push(DeviationSignal {
                probe_id: toric_geometry::PROBE_HOLONOMY,
                deviation_magnitude: holonomy,
                expected: 0.0,
                actual: holonomy,
                geometry_params_hash: gp_hash_bytes.clone(),
                manifest_hash: None,
            });
        }
    }

    // Per-probe pass lines (probe-boundary audit): probes normalized
    // against φ-targets keep the φ⁻¹ relative line — composition puts
    // their absolute trigger a rung below the target automatically.
    // Probe 6 (raw Jaccard, expected 0, nothing to compose) carries its
    // depth in the line itself: φ⁻³, one level below its φ⁻² boundary.
    let passed = signals
        .iter()
        .all(|s| s.deviation_magnitude < toric_geometry::probe_pass_line(s.probe_id));
    Ok(ClosureStatus { passed, signals })
}

fn unimplemented_metric_blob() -> ExternResult<SerializedBytes> {
    let bytes = serde_json::to_vec(&serde_json::json!({}))
        .map_err(|e| wasm_error!(WasmErrorInner::Guest(format!("metric stub encode: {e}"))))?;
    Ok(SerializedBytes::from(UnsafeBytes::from(bytes)))
}

/// The trust distribution as (raw agent bytes, score) pairs — the wire
/// form the drift accumulator compares across snapshots.
fn current_trust_distribution() -> ExternResult<Vec<(Vec<u8>, f64)>> {
    let mut out = Vec::new();
    for entry in get_scored_agents(())? {
        out.push((entry.agent.get_raw_39().to_vec(), entry.score));
    }
    Ok(out)
}

fn latest_manifest() -> ExternResult<Option<(ActionHash, registry_integrity::NetworkStateManifest)>> {
    let nsm_path = Path::from("network.state");
    let nsm_typed = nsm_path.typed(LinkTypes::NetworkStateManifestAnchor)?;
    if !nsm_typed.exists()? {
        return Ok(None);
    }
    let nsm_anchor = nsm_typed.path_entry_hash()?;
    let links = fetch_links(nsm_anchor, LinkTypes::NetworkStateManifestAnchor)?;
    let Some(hash) = links.last().and_then(|l| l.target.clone().into_action_hash()) else {
        return Ok(None);
    };
    let Some(record) = get(hash.clone(), GetOptions::default())? else {
        return Ok(None);
    };
    let Some(entry) = record.entry().as_option() else {
        return Ok(None);
    };
    match registry_integrity::NetworkStateManifest::try_from(entry) {
        Ok(m) => Ok(Some((hash, m))),
        Err(_) => Ok(None),
    }
}

/// Attestation count of the mutual_credit NetworkState a manifest (or
/// this round) points at — the sequence coordinate for the staleness
/// ceiling. Same DHT since the merge: a plain get.
fn state_round(network_state_hash: &ActionHash) -> ExternResult<Option<u64>> {
    #[derive(serde::Deserialize, Debug)]
    struct StateCount {
        attestation_count: u64,
    }
    let Some(record) = get(network_state_hash.clone(), GetOptions::default())? else {
        return Ok(None);
    };
    let Some(entry) = record.entry().as_option() else {
        return Ok(None);
    };
    let bytes = match entry {
        Entry::App(app) => app.clone().into_sb(),
        _ => return Ok(None),
    };
    let decoded: Result<StateCount, _> = holochain_serialized_bytes::decode(bytes.bytes());
    Ok(decoded.ok().map(|s| s.attestation_count))
}

fn write_network_state_manifest(
    network_state_hash: ActionHash,
    closure_status: ClosureStatus,
    trust_distribution: Vec<(Vec<u8>, f64)>,
    previous_manifest_hash: Option<ActionHash>,
) -> ExternResult<ActionHash> {
    use registry_integrity::NetworkStateManifest;

    let geometry_params_hash = fetch_latest_geometry_params()?.map(|(h, _)| h);

    let nsm_path = Path::from("network.state");
    let nsm_typed = nsm_path.typed(LinkTypes::NetworkStateManifestAnchor)?;
    let nsm_anchor = nsm_typed.path_entry_hash()?;

    let closure_bytes = serde_json::to_vec(&closure_status)
        .map_err(|e| wasm_error!(WasmErrorInner::Guest(format!("closure_status encode: {e}"))))?;
    let closure_status_sb = SerializedBytes::from(UnsafeBytes::from(closure_bytes));

    let dist_bytes = serde_json::to_vec(&trust_distribution)
        .map_err(|e| wasm_error!(WasmErrorInner::Guest(format!("distribution encode: {e}"))))?;
    let population_bytes = serde_json::to_vec(&serde_json::json!({
        "agent_count": trust_distribution.len(),
    }))
    .map_err(|e| wasm_error!(WasmErrorInner::Guest(format!("population encode: {e}"))))?;

    let manifest = NetworkStateManifest {
        network_state_hash,
        trust_score_distribution: SerializedBytes::from(UnsafeBytes::from(dist_bytes)),
        agent_population: SerializedBytes::from(UnsafeBytes::from(population_bytes)),
        credit_flow_patterns: unimplemented_metric_blob()?,
        disagreement_signal_density: 0,
        geometry_params_hash,
        closure_status: closure_status_sb,
        previous_manifest_hash,
    };

    let action_hash = create_entry(EntryTypes::NetworkStateManifest(manifest))?;
    create_link(
        nsm_anchor,
        action_hash.clone(),
        LinkTypes::NetworkStateManifestAnchor,
        (),
    )?;
    Ok(action_hash)
}

/// Latest self-observation, for consumers (UI, MCP) that want to see
/// what the network sees of itself: the most recent NetworkStateManifest's
/// closure status, decoded.
#[derive(Serialize, Deserialize, Debug)]
pub struct LatestClosure {
    pub manifest_hash: ActionHash,
    pub closure: ClosureStatus,
}

#[hdk_extern]
pub fn get_latest_closure(_: ()) -> ExternResult<Option<LatestClosure>> {
    let nsm_path = Path::from("network.state");
    let nsm_typed = nsm_path.typed(LinkTypes::NetworkStateManifestAnchor)?;
    if !nsm_typed.exists()? {
        return Ok(None);
    }
    let nsm_anchor = nsm_typed.path_entry_hash()?;
    let links = fetch_links(nsm_anchor, LinkTypes::NetworkStateManifestAnchor)?;
    let Some(hash) = links.last().and_then(|l| l.target.clone().into_action_hash()) else {
        return Ok(None);
    };
    let Some(record) = get(hash.clone(), GetOptions::default())? else {
        return Ok(None);
    };
    let Some(entry) = record.entry().as_option() else {
        return Ok(None);
    };
    let manifest = registry_integrity::NetworkStateManifest::try_from(entry)
        .map_err(|e| wasm_error!(WasmErrorInner::Guest(format!("decode: {:?}", e))))?;
    let closure: ClosureStatus = serde_json::from_slice(manifest.closure_status.bytes())
        .map_err(|e| wasm_error!(WasmErrorInner::Guest(format!("closure decode: {}", e))))?;
    Ok(Some(LatestClosure { manifest_hash: hash, closure }))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CloseRoundInput {
    pub manifest_hash: ActionHash,
    pub network_state_hash: ActionHash,
    pub combined_weight: f64,
}

/// Mirror of mutual_credit's EconomicSnapshot — field-identical wire
/// shape. Fetched by check_closure via local sibling-zome call: registry
/// owns what closing means and now pulls the measurement itself; a
/// failed call omits probes 5–7 this round ("no measurement" stays
/// distinct from "measured healthy").
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EconomicSnapshot {
    pub cycle: u64,
    pub credit_supply: i64,
    pub sealed_roster: Vec<AgentPubKey>,
    pub roster_divergence: f64,
    pub account_count: u32,
    pub frozen_count: u32,
    /// Σ|credit limit| over frozen accounts — probe 7's mass numerator.
    #[serde(default)]
    pub frozen_credit_mass: u64,
    /// Σ|credit limit| over all accounts — probe 7's mass denominator.
    #[serde(default)]
    pub total_credit_mass: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CloseRoundResult {
    pub network_state_manifest_hash: ActionHash,
    pub passed: bool,
    /// False when the drift gate held and the standing manifest was
    /// reused — "the last mirror still resembles us."
    #[serde(default)]
    pub manifest_written: bool,
}

// Single bridge entry point for closing a resolved round. Coordination's
// job ends at "this round resolved"; registry owns everything about what
// closing means, including the order: run check_closure first, then write
// the NetworkStateManifest carrying that closure result. Coordination does
// not call check_closure and write_network_state_manifest separately —
// that would put registry's internal sequencing under coordination's
// control across the bridge.
#[hdk_extern]
pub fn close_round(input: CloseRoundInput) -> ExternResult<CloseRoundResult> {
    // Closure runs unconditionally: it is cheap, deterministic, and the
    // immune signal must exist every round regardless of whether the
    // snapshot refreshes.
    let closure_status = check_closure(&input.manifest_hash, input.combined_weight)?;
    let passed = closure_status.passed;

    // The drift gate. The network has no clock, but it has a mirror:
    // it re-records itself when accumulated trust movement since the
    // last NetworkStateManifest crosses φ⁻² (one rung of the φ-ladder),
    // when the staleness ceiling in rounds is hit (so the threshold
    // cannot be surfed), or when no snapshot exists at all. Between
    // writes, the last manifest stands as the current state.
    let current_dist = current_trust_distribution()?;
    let prior = latest_manifest()?;
    let (due, prior_hash) = match &prior {
        None => (true, None),
        Some((prior_hash, manifest)) => {
            let prev_dist: Vec<(Vec<u8>, f64)> =
                serde_json::from_slice(manifest.trust_score_distribution.bytes())
                    .unwrap_or_default();
            let drift = drift_since(&prev_dist, &current_dist);
            // Exact boundary decision: Σ|Δ| and S_ref as MASS_SCALE integers,
            // threshold via integer sign test — no f64 at the gate.
            let sum_abs: u64 = prev_dist.iter().zip(current_dist.iter())
                .map(|((_, p), (_, c))| ((p - c).abs() * 1_000_000.0) as u64).sum();
            let s_ref: u64 = prev_dist.iter().map(|(_, s)| (s * 1_000_000.0) as u64).sum();
            let rounds_since = match (
                state_round(&manifest.network_state_hash)?,
                state_round(&input.network_state_hash)?,
            ) {
                (Some(then), Some(now)) => now.saturating_sub(then),
                // Sequence coordinates unavailable: fail toward
                // freshness, never toward staleness.
                _ => u64::MAX,
            };
            // prior exists on this branch — due on drift or staleness only
            let write_due = drift_exceeds_threshold_exact(sum_abs, s_ref)
                || rounds_since >= STALENESS_CEILING_ROUNDS;
            let _ = drift; // retained for the manifest's reported magnitude only
            (
                write_due,
                Some(prior_hash.clone()),
            )
        }
    };

    let (network_state_manifest_hash, manifest_written) = if due {
        (
            write_network_state_manifest(
                input.network_state_hash,
                closure_status,
                current_dist,
                prior_hash,
            )?,
            true,
        )
    } else {
        // The standing snapshot remains the network's self-image.
        (prior_hash.expect("not-due implies a prior manifest"), false)
    };

    Ok(CloseRoundResult {
        network_state_manifest_hash,
        passed,
        manifest_written,
    })
}

// ─────────────────────────────────────────────
// Signals
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Signal {
    ManifestCreated { action_hash: ActionHash },
    AttestationCreated { action_hash: ActionHash },
    WarrantCreated { action_hash: ActionHash },
}

#[hdk_extern(infallible)]
pub fn post_commit(committed_actions: Vec<SignedActionHashed>) {
    for action in committed_actions {
        if let Err(err) = signal_action(action) {
            error!("Error signaling new action: {:?}", err);
        }
    }
}

fn signal_action(action: SignedActionHashed) -> ExternResult<()> {
    if let Action::Create(create) = action.action() {
        match &create.entry_type {
            EntryType::App(app_entry) => {
                let hash = action.action_address().clone();
                let signal = match app_entry.entry_index.index() {
                    0 => Some(Signal::ManifestCreated { action_hash: hash }),
                    1 => Some(Signal::AttestationCreated { action_hash: hash }),
                    2 => Some(Signal::WarrantCreated { action_hash: hash }),
                    _ => None,
                };
                if let Some(s) = signal {
                    emit_signal(s)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}