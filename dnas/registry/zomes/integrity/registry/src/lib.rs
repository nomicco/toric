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
    _cache: ReputationCache,
) -> ExternResult<ValidateCallbackResult> {
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
            LinkTypes::GlobalManifestAnchor =>
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
            LinkTypes::GlobalManifestAnchor =>
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