use hdi::prelude::*;

// ─────────────────────────────────────────────
// Entry Types
// Three generic entry types. All semantic meaning
// lives in the coordinator — blobs are opaque here.
// ─────────────────────────────────────────────

#[hdk_entry_helper]
#[derive(Clone)]
pub struct Manifest {
    pub metadata_blob: SerializedBytes,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct Attestation {
    pub manifest_hash: ActionHash,
    pub metadata_blob: SerializedBytes,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct Warrant {
    pub manifest_hash: ActionHash,
    pub metadata_blob: SerializedBytes,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct ReputationCache {
    pub agent: AgentPubKey,
    pub score: u32,
    pub score_delta: i32,
    pub computed_at: Timestamp,
    pub attestation_count: u32,
    pub warrant_count: u32,
    pub total_commits: u32,
    pub total_reveals: u32,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct TrustScoreCache {
    pub manifest_hash: ActionHash,
    pub score: u32,
    pub computed_at: Timestamp,
    pub attestation_count: u32,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct ConvergenceSignal {
    pub agent: AgentPubKey,
    pub agreed: bool,       // true = agreed with consensus, false = dissented
    pub request_hash: ActionHash,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct WarrantConfirmation {
    pub warrant_hash: ActionHash,
    pub manifest_hash: ActionHash,
    pub confirmed_severity: u32,   
    pub confirmed_at: Timestamp,
}

// Network-health snapshot owned by registry. Does NOT duplicate the
// mutual_credit-owned NetworkState (attestation_count, credit_supply,
// cycle, phase, next_fibonacci_threshold) — it references that entry by
// hash and stores only what registry itself measures. The mutual_credit
// slice is reached through network_state_hash, never copied here.
#[hdk_entry_helper]
#[derive(Clone)]
pub struct NetworkStateManifest {
    pub network_state_hash: ActionHash,
    pub trust_score_distribution: SerializedBytes,
    pub agent_population: SerializedBytes,
    pub credit_flow_patterns: SerializedBytes,
    pub disagreement_signal_density: u32,
    pub geometry_params_hash: Option<ActionHash>,
    pub closure_status: SerializedBytes,
    pub previous_manifest_hash: Option<ActionHash>,
}

// Only tau_us is stored. Every other constant (MIN_VALIDATORS,
// MAX_UPSTREAM_DEPTH, REVEAL_DEADLINE, admission multiplier) is derived
// from tau_us and φ at read time in the coordinator, not stored here.
#[hdk_entry_helper]
#[derive(Clone)]
pub struct GeometryParams {
    pub tau_us: u64,
}

// Derived, not declared. Stores only the GeometryParams hash it was
// derived against plus a derivation version. Targets are recomputed from
// that GeometryParams by the coordinator at read time — nothing forgeable
// is stored, because the integrity zome cannot read the DHT to validate
// stored target values. A wrong NetworkGoalManifest is one whose hash
// doesn't resolve, not one whose numbers disagree with the geometry.
#[hdk_entry_helper]
#[derive(Clone)]
pub struct NetworkGoalManifest {
    pub geometry_params_hash: ActionHash,
    pub derivation_version: u32,
}

// One entry per validation round. References everything the round
// produced by hash rather than embedding it. closure_status carries the
// serialized ClosureStatus (per-probe deviation magnitudes), not a bool.
// No round timestamp — sequencing comes from previous_round_hash and the
// action header.
#[hdk_entry_helper]
#[derive(Clone)]
pub struct NetworkRoundManifest {
    pub tau_us: u64,
    pub network_state_hash: ActionHash,
    pub network_goal_manifest_hash: ActionHash,
    pub geometry_params_hash: ActionHash,
    pub closure_status: SerializedBytes,
    pub active_probe_set_hash: Option<ActionHash>,
    pub quorum_participant_keys: Vec<AgentPubKey>,
    pub previous_round_hash: Option<ActionHash>,
}

// Committed at genesis, immutable. The network's function in four
// falsifiable clauses.
#[hdk_entry_helper]
#[derive(Clone)]
pub struct NetworkIdentity {
    pub attests_integrity_of: String,
    pub through_mechanism: String,
    pub weighted_by: String,
    pub producing: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
pub enum EntryTypes {
    Manifest(Manifest),
    Attestation(Attestation),
    Warrant(Warrant),
    ReputationCache(ReputationCache),
    TrustScoreCache(TrustScoreCache),
    WarrantConfirmation(WarrantConfirmation),
    ConvergenceSignal(ConvergenceSignal),
    NetworkStateManifest(NetworkStateManifest),
    GeometryParams(GeometryParams),
    NetworkGoalManifest(NetworkGoalManifest),
    NetworkRoundManifest(NetworkRoundManifest),
    NetworkIdentity(NetworkIdentity),
}

// ─────────────────────────────────────────────
// Link Types
// Append-only — delete always returns Invalid.
// ─────────────────────────────────────────────

#[hdk_link_types]
pub enum LinkTypes {
    AgentToManifest,
    ManifestToAttestation,
    ManifestToWarrant,
    AttestationToWarrant,
    AgentToReputationCache,
    ManifestToUpstream,
    UpstreamToDerivative,
    ContentHashToManifest,
    ManifestToValidationRequest,
    AgentToAttestation,
    ManifestToValidator,
    ManifestToTrustScoreCache,
    ManifestToWarrantConfirmation,
    AgentToConvergenceSignal,
    GlobalManifestAnchor,
    GeometryParamsAnchor,
    NetworkStateManifestAnchor,
    NetworkGoalManifestAnchor,
    NetworkRoundAnchor,
    NetworkIdentityAnchor,
}

// ─────────────────────────────────────────────
// Genesis + Agent Joining
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn genesis_self_check(
    _data: GenesisSelfCheckData,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

pub fn validate_agent_joining(
    _agent_pub_key: AgentPubKey,
    _membrane_proof: &Option<MembraneProof>,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

// ─────────────────────────────────────────────
// Entry Validators
// ─────────────────────────────────────────────

fn validate_create_manifest(
    _action: Create,
    _manifest: Manifest,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_attestation(
    _action: Create,
    attestation: Attestation,
) -> ExternResult<ValidateCallbackResult> {
    must_get_valid_record(attestation.manifest_hash)?;
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_warrant(
    _action: Create,
    warrant: Warrant,
) -> ExternResult<ValidateCallbackResult> {
    must_get_valid_record(warrant.manifest_hash)?;
    // Blob must be non-empty — deep evidence validation
    // happens in the coordinator where serde_json is available
    let raw: Vec<u8> = UnsafeBytes::from(warrant.metadata_blob).into();
    if raw.is_empty() {
        return Ok(ValidateCallbackResult::Invalid(
            "Warrant metadata blob cannot be empty".to_string()
        ));
    }
    Ok(ValidateCallbackResult::Valid)
}
fn validate_create_reputation_cache(
    _action: Create,
    cache: ReputationCache,
) -> ExternResult<ValidateCallbackResult> {
    // The score VALUE cannot be law-validated: it is a function of the
    // agent's complete attestation/warrant set, and completeness is not
    // provable in deterministic validation (link enumeration is
    // non-deterministic). That impossibility is why sealed CreditLimits
    // exist. Authorship cannot be pinned either — penalty and
    // commit/reveal counter updates are legitimately written by agents
    // OTHER than the subject, so `cache.agent == author` would break
    // real flows. What law CAN do: bound the representation, so a
    // forged cache can at most claim a perfect score (1.0 in ppm),
    // never u32::MAX — keeping every downstream arithmetic consumer
    // (credit_limit_for_reputation) in range by construction.
    const SCORE_PPM_DENOM: u32 = 1_000_000; // mirrors toric_geometry::SCORE_PPM_DENOM
    if cache.score > SCORE_PPM_DENOM {
        return Ok(ValidateCallbackResult::Invalid(format!(
            "ReputationCache.score {} exceeds the fixed-point range [0, {}]",
            cache.score, SCORE_PPM_DENOM
        )));
    }
    if cache.score_delta.unsigned_abs() > SCORE_PPM_DENOM {
        return Ok(ValidateCallbackResult::Invalid(
            "ReputationCache.score_delta outside the fixed-point range".into(),
        ));
    }
    if cache.total_reveals > cache.total_commits {
        return Ok(ValidateCallbackResult::Invalid(
            "ReputationCache cannot record more reveals than commits".into(),
        ));
    }
    Ok(ValidateCallbackResult::Valid)
}

// ─────────────────────────────────────────────
// Link Validators
// ─────────────────────────────────────────────

fn validate_create_link_agent_to_manifest(
    _action: CreateLink,
    base_address: AnyLinkableHash,
    target_address: AnyLinkableHash,
    _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> {
    AgentPubKey::try_from(base_address).map_err(|_| {
        wasm_error!(WasmErrorInner::Guest(
            "Base must be an AgentPubKey".to_string()
        ))
    })?;
    must_get_valid_record(
        ActionHash::try_from(target_address).map_err(|_| {
            wasm_error!(WasmErrorInner::Guest(
                "Target must be an ActionHash".to_string()
            ))
        })?,
    )?;
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_link_manifest_to_attestation(
    _action: CreateLink,
    base_address: AnyLinkableHash,
    _target_address: AnyLinkableHash,
    _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> {
    must_get_valid_record(
        ActionHash::try_from(base_address).map_err(|_| {
            wasm_error!(WasmErrorInner::Guest(
                "Base must be an ActionHash".to_string()
            ))
        })?,
    )?;
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_link_manifest_to_warrant(
    _action: CreateLink,
    base_address: AnyLinkableHash,
    target_address: AnyLinkableHash,
    _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> {
    must_get_valid_record(
        ActionHash::try_from(base_address).map_err(|_| {
            wasm_error!(WasmErrorInner::Guest(
                "Base must be an ActionHash".to_string()
            ))
        })?,
    )?;
    must_get_valid_record(
        ActionHash::try_from(target_address).map_err(|_| {
            wasm_error!(WasmErrorInner::Guest(
                "Target must be an ActionHash".to_string()
            ))
        })?,
    )?;
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_link_attestation_to_warrant(
    _action: CreateLink,
    base_address: AnyLinkableHash,
    target_address: AnyLinkableHash,
    _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> {
    must_get_valid_record(
        ActionHash::try_from(base_address).map_err(|_| {
            wasm_error!(WasmErrorInner::Guest(
                "Base must be an ActionHash".to_string()
            ))
        })?,
    )?;
    must_get_valid_record(
        ActionHash::try_from(target_address).map_err(|_| {
            wasm_error!(WasmErrorInner::Guest(
                "Target must be an ActionHash".to_string()
            ))
        })?,
    )?;
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_link_agent_to_reputation_cache(
    _action: CreateLink,
    _base_address: AnyLinkableHash,
    _target_address: AnyLinkableHash,
    _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

// ─────────────────────────────────────────────
// Validation Dispatcher
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    match op.flattened::<EntryTypes, LinkTypes>()? {

        FlatOp::StoreEntry(OpEntry::CreateEntry { app_entry, action }) => {
            match app_entry {
                EntryTypes::Manifest(manifest) =>
                    validate_create_manifest(action, manifest),
                EntryTypes::Attestation(attestation) =>
                    validate_create_attestation(action, attestation),
                EntryTypes::Warrant(warrant) =>
                    validate_create_warrant(action, warrant),
                EntryTypes::ReputationCache(cache) =>
                    validate_create_reputation_cache(action, cache),
                EntryTypes::TrustScoreCache(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::WarrantConfirmation(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::ConvergenceSignal(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::NetworkStateManifest(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::GeometryParams(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::NetworkGoalManifest(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::NetworkRoundManifest(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::NetworkIdentity(_) =>
                    Ok(ValidateCallbackResult::Valid),
            }
        }

        FlatOp::StoreEntry(OpEntry::UpdateEntry { .. }) => {
            Ok(ValidateCallbackResult::Invalid(
                "Registry entries are immutable — updates are not permitted".to_string(),
            ))
        }

        FlatOp::RegisterUpdate(_) => {
            Ok(ValidateCallbackResult::Invalid(
                "Registry entries are immutable — updates are not permitted".to_string(),
            ))
        }

        FlatOp::RegisterDelete(_) => {
            Ok(ValidateCallbackResult::Invalid(
                "Registry entries are immutable — deletes are not permitted".to_string(),
            ))
        }

        FlatOp::RegisterCreateLink {
            link_type,
            base_address,
            target_address,
            tag,
            action,
        } => match link_type {
            LinkTypes::AgentToManifest =>
                validate_create_link_agent_to_manifest(action, base_address, target_address, tag),
            LinkTypes::ManifestToAttestation =>
                validate_create_link_manifest_to_attestation(action, base_address, target_address, tag),
            LinkTypes::ManifestToWarrant =>
                validate_create_link_manifest_to_warrant(action, base_address, target_address, tag),
            LinkTypes::AttestationToWarrant =>
                validate_create_link_attestation_to_warrant(action, base_address, target_address, tag),
            LinkTypes::AgentToReputationCache =>
                validate_create_link_agent_to_reputation_cache(action, base_address, target_address, tag),
            LinkTypes::ManifestToUpstream |
            LinkTypes::UpstreamToDerivative |
            LinkTypes::ContentHashToManifest |
            LinkTypes::ManifestToValidationRequest |
            LinkTypes::AgentToAttestation |
            LinkTypes::ManifestToValidator |
            LinkTypes::ManifestToTrustScoreCache |
            LinkTypes::ManifestToWarrantConfirmation =>
                Ok(ValidateCallbackResult::Valid),
            LinkTypes::AgentToConvergenceSignal |
            LinkTypes::GlobalManifestAnchor |
            LinkTypes::GeometryParamsAnchor |
            LinkTypes::NetworkStateManifestAnchor |
            LinkTypes::NetworkGoalManifestAnchor |
            LinkTypes::NetworkRoundAnchor |
            LinkTypes::NetworkIdentityAnchor =>
                Ok(ValidateCallbackResult::Valid),
        },

        FlatOp::RegisterDeleteLink{ .. } => {
            Ok(ValidateCallbackResult::Invalid(
                "Registry links are permanent — deletes are not permitted".to_string(),
            ))
        }

        FlatOp::StoreRecord(OpRecord::CreateEntry { app_entry, action }) => {
            match app_entry {
                EntryTypes::Manifest(manifest) =>
                    validate_create_manifest(action, manifest),
                EntryTypes::Attestation(attestation) =>
                    validate_create_attestation(action, attestation),
                EntryTypes::Warrant(warrant) =>
                    validate_create_warrant(action, warrant),
                EntryTypes::ReputationCache(cache) =>
                    validate_create_reputation_cache(action, cache),
                EntryTypes::TrustScoreCache(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::WarrantConfirmation(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::ConvergenceSignal(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::NetworkStateManifest(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::GeometryParams(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::NetworkGoalManifest(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::NetworkRoundManifest(_) =>
                    Ok(ValidateCallbackResult::Valid),
                EntryTypes::NetworkIdentity(_) =>
                    Ok(ValidateCallbackResult::Valid),
            }
        }

        FlatOp::StoreRecord(OpRecord::UpdateEntry { .. }) => {
            Ok(ValidateCallbackResult::Invalid(
                "Registry entries are immutable — updates are not permitted".to_string(),
            ))
        }

        FlatOp::StoreRecord(OpRecord::DeleteEntry { .. }) => {
            Ok(ValidateCallbackResult::Invalid(
                "Registry entries are immutable — deletes are not permitted".to_string(),
            ))
        }

        FlatOp::StoreRecord(OpRecord::CreateLink {
            base_address,
            target_address,
            tag,
            link_type,
            action,
        }) => match link_type {
            LinkTypes::AgentToManifest =>
                validate_create_link_agent_to_manifest(action, base_address, target_address, tag),
            LinkTypes::ManifestToAttestation =>
                validate_create_link_manifest_to_attestation(action, base_address, target_address, tag),
            LinkTypes::ManifestToWarrant =>
                validate_create_link_manifest_to_warrant(action, base_address, target_address, tag),
            LinkTypes::AttestationToWarrant =>
                validate_create_link_attestation_to_warrant(action, base_address, target_address, tag),
            LinkTypes::AgentToReputationCache =>
                validate_create_link_agent_to_reputation_cache(action, base_address, target_address, tag),
            LinkTypes::ManifestToUpstream |
            LinkTypes::UpstreamToDerivative |
            LinkTypes::ContentHashToManifest |
            LinkTypes::ManifestToValidationRequest |
            LinkTypes::AgentToAttestation |
            LinkTypes::ManifestToValidator |
            LinkTypes::ManifestToTrustScoreCache |
            LinkTypes::ManifestToWarrantConfirmation =>
                Ok(ValidateCallbackResult::Valid),
            LinkTypes::AgentToConvergenceSignal |
            LinkTypes::GlobalManifestAnchor |
            LinkTypes::GeometryParamsAnchor |
            LinkTypes::NetworkStateManifestAnchor |
            LinkTypes::NetworkGoalManifestAnchor |
            LinkTypes::NetworkRoundAnchor |
            LinkTypes::NetworkIdentityAnchor =>
                Ok(ValidateCallbackResult::Valid),
        },

        FlatOp::StoreRecord(OpRecord::DeleteLink { .. }) => {
            Ok(ValidateCallbackResult::Invalid(
                "Registry links are permanent — deletes are not permitted".to_string(),
            ))
        }

        FlatOp::RegisterAgentActivity(OpActivity::CreateAgent { agent, action }) => {
            let previous_action = must_get_action(action.prev_action)?;
            match previous_action.action() {
                Action::AgentValidationPkg(AgentValidationPkg { membrane_proof, .. }) =>
                    validate_agent_joining(agent, membrane_proof),
                _ => Ok(ValidateCallbackResult::Invalid(
                    "The previous action for a `CreateAgent` action must be an `AgentValidationPkg`"
                        .to_string(),
                )),
            }
        }

        _ => Ok(ValidateCallbackResult::Valid),
    }
}