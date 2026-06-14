use hdk::prelude::*;
use registry_integrity::{
    EntryTypes,
    LinkTypes,
    Manifest,
    Attestation,
    Warrant as RegistryWarrant,
};

pub mod blobs;
use blobs::*;

const PHI: f64     = 1.6180339887498948;
const PHI_SQ: f64  = 2.6180339887498948;
const INV_PHI: f64  = 0.6180339887498948;
const INV_PHI_SQ: f64 = 0.3819660112501051;
const INV_PHI_CU: f64 = 0.2360679774997896;
const INV_PHI_4: f64  = 0.14589803375031546;

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
        let n_total = actions.len() as f64;
        let denominator = PHI * (1.0 - PHI.powf(-n_total));
        let mut rep: f64 = INV_PHI_SQ;
        for (i, (_, is_attestation)) in actions.iter().enumerate() {
            let n = (i + 1) as f64;
            let base_weight = PHI.powf(-n) / denominator;
            if *is_attestation {
                rep += (1.0 - rep) * base_weight;
            } else {
                rep -= rep * base_weight * PHI;
            }
        }
        rep.max(f64::EPSILON)
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

#[hdk_extern]
pub fn get_network_reputation(_: ()) -> ExternResult<NetworkReputationResult> {
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

#[hdk_extern]
pub fn compute_trust_score(input: TrustScoreInput) -> ExternResult<TrustScoreResult> {
    if let Ok(Some(cached)) = get_cached_trust_score(&input.manifest_hash) {
        return Ok(cached);
    }

    // Blob type check — trust score only for scoreable artifact types
    let manifest_record = get(input.manifest_hash.clone(), GetOptions::default())?;
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
            manifest_hash: input.manifest_hash,
            score: 0.0,
            passes: false,
            attestation_count: 0,
            weighted_attestation_count: 0.0,
        });
    }

    let (direct_score, weighted_count, attestation_count) = compute_direct_score(&input.manifest_hash)?;
    let upstream_score = compute_upstream_score(&input.manifest_hash, MAX_UPSTREAM_DEPTH);

    let convergence_score = {
        let manifest_record = get(input.manifest_hash.clone(), GetOptions::default())?;
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

    let warrant_penalty = compute_warrant_penalty(&input.manifest_hash);
    let final_score = (blended - warrant_penalty).clamp(0.0, 1.0);

    let result = TrustScoreResult {
        manifest_hash: input.manifest_hash.clone(),
        score: final_score,
        passes: final_score >= INV_PHI,
        attestation_count,
        weighted_attestation_count: weighted_count,
    };
    write_trust_score_cache(&input.manifest_hash, &result).ok();
    Ok(result)
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