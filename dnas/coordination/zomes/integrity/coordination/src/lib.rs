use hdi::prelude::*;

#[hdk_entry_helper]
#[derive(Clone)]
pub struct ValidationRequest {
    pub manifest_hash: ActionHash,
    pub requester: AgentPubKey,
    pub validation_type: String,
    pub required_capabilities: Vec<String>,
    pub metadata_blob: SerializedBytes,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct EvaluationBundle {
    pub request_hash: ActionHash,
    pub evaluator: AgentPubKey,
    pub metadata_blob: SerializedBytes,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct EvaluationCommitment {
    pub request_hash: ActionHash,
    pub evaluator: AgentPubKey,
    pub commitment_hash: Vec<u8>,  
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct ValidationEvidence {
    pub manifest_hash: ActionHash,
    pub evidence_type: String,   
    pub expected: String,         
    pub actual: String,           
    pub computed_severity: u32,   
    pub metadata_blob: SerializedBytes, 
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct QuorumBundle {
    pub request_hash: ActionHash,
    pub evaluation_hashes: Vec<ActionHash>,
    pub reached_quorum: bool,
    pub metadata_blob: SerializedBytes,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
pub enum EntryTypes {
    ValidationRequest(ValidationRequest),
    EvaluationCommitment(EvaluationCommitment),
    EvaluationBundle(EvaluationBundle),
    QuorumBundle(QuorumBundle),
    ValidationEvidence(ValidationEvidence),
}

#[hdk_link_types]
pub enum LinkTypes {
    RequestToEvaluation,
    RequestToCommitment,
    RequestToQuorum,
    AgentToRequest,
    ManifestToRequest,
    ManifestToEvidence,
    GlobalValidationRequestAnchor,
}

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

fn validate_create_validation_request(
    _action: Create,
    _request: ValidationRequest,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_evaluation_commitment(
    _action: Create,
    commitment: EvaluationCommitment,
) -> ExternResult<ValidateCallbackResult> {
    must_get_valid_record(commitment.request_hash)?;
    if commitment.commitment_hash.len() != 32 {
        return Ok(ValidateCallbackResult::Invalid(
            "Commitment hash must be 32 bytes (sha256)".to_string()
        ));
    }
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_evaluation_bundle(
    _action: Create,
    bundle: EvaluationBundle,
) -> ExternResult<ValidateCallbackResult> {
    must_get_valid_record(bundle.request_hash)?;
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_quorum_bundle(
    _action: Create,
    bundle: QuorumBundle,
) -> ExternResult<ValidateCallbackResult> {
    must_get_valid_record(bundle.request_hash)?;
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_link_request_to_commitment(
    _action: CreateLink,
    _base_address: AnyLinkableHash,
    _target_address: AnyLinkableHash,
    _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_link_request_to_evaluation(
    _action: CreateLink,
    _base_address: AnyLinkableHash,
    _target_address: AnyLinkableHash,
    _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_link_request_to_quorum(
    _action: CreateLink,
    _base_address: AnyLinkableHash,
    _target_address: AnyLinkableHash,
    _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_validation_evidence(
    _action: Create,
    evidence: ValidationEvidence,
) -> ExternResult<ValidateCallbackResult> {
    // manifest_hash lives in registry DNA — can't must_get_valid_record cross-DNA
    // structural validation only here
    if evidence.evidence_type.is_empty() {
        return Ok(ValidateCallbackResult::Invalid(
            "ValidationEvidence requires a non-empty evidence_type".to_string()
        ));
    }
    if evidence.computed_severity > 1_000_000 {
        return Ok(ValidateCallbackResult::Invalid(
            "computed_severity must be 0-1_000_000".to_string()
        ));
    }
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_link_manifest_to_evidence(
    _action: CreateLink,
    _base_address: AnyLinkableHash,
    _target_address: AnyLinkableHash,
    _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_link_agent_to_request(
    _action: CreateLink,
    _base_address: AnyLinkableHash,
    _target_address: AnyLinkableHash,
    _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    match op.flattened::<EntryTypes, LinkTypes>()? {

        FlatOp::StoreEntry(OpEntry::CreateEntry { app_entry, action }) => {
            match app_entry {
                EntryTypes::ValidationRequest(request) =>
                    validate_create_validation_request(action, request),
                EntryTypes::EvaluationCommitment(commitment) =>
                    validate_create_evaluation_commitment(action, commitment),
                EntryTypes::EvaluationBundle(bundle) =>
                    validate_create_evaluation_bundle(action, bundle),
                EntryTypes::QuorumBundle(bundle) =>
                    validate_create_quorum_bundle(action, bundle),
                EntryTypes::ValidationEvidence(evidence) =>
                    validate_create_validation_evidence(action, evidence),
            }
        }

        FlatOp::StoreEntry(OpEntry::UpdateEntry { .. }) =>
            Ok(ValidateCallbackResult::Invalid(
                "Coordination entries are immutable".to_string(),
            )),

        FlatOp::RegisterUpdate(_) =>
            Ok(ValidateCallbackResult::Invalid(
                "Coordination entries are immutable".to_string(),
            )),

        FlatOp::RegisterDelete(_) =>
            Ok(ValidateCallbackResult::Invalid(
                "Coordination entries are immutable".to_string(),
            )),

        FlatOp::RegisterCreateLink {
            link_type,
            base_address,
            target_address,
            tag,
            action,
        } => match link_type {
            LinkTypes::RequestToEvaluation =>
                validate_create_link_request_to_evaluation(action, base_address, target_address, tag),
            LinkTypes::RequestToCommitment =>
                validate_create_link_request_to_commitment(action, base_address, target_address, tag),
            LinkTypes::RequestToQuorum =>
                validate_create_link_request_to_quorum(action, base_address, target_address, tag),
            LinkTypes::AgentToRequest =>
                validate_create_link_agent_to_request(action, base_address, target_address, tag),
            LinkTypes::ManifestToRequest =>
                Ok(ValidateCallbackResult::Valid),
            LinkTypes::ManifestToEvidence =>
                validate_create_link_manifest_to_evidence(action, base_address, target_address, tag),
            LinkTypes::GlobalValidationRequestAnchor =>
                Ok(ValidateCallbackResult::Valid),
        },

        FlatOp::RegisterDeleteLink { .. } =>
            Ok(ValidateCallbackResult::Invalid(
                "Coordination links are permanent".to_string(),
            )),

        FlatOp::StoreRecord(OpRecord::CreateEntry { app_entry, action }) => {
            match app_entry {
                EntryTypes::ValidationRequest(request) =>
                    validate_create_validation_request(action, request),
                EntryTypes::EvaluationCommitment(commitment) =>
                    validate_create_evaluation_commitment(action, commitment),
                EntryTypes::EvaluationBundle(bundle) =>
                    validate_create_evaluation_bundle(action, bundle),
                EntryTypes::QuorumBundle(bundle) =>
                    validate_create_quorum_bundle(action, bundle),
                EntryTypes::ValidationEvidence(evidence) =>
                    validate_create_validation_evidence(action, evidence),
            }
        }

        FlatOp::StoreRecord(OpRecord::UpdateEntry { .. }) =>
            Ok(ValidateCallbackResult::Invalid(
                "Coordination entries are immutable".to_string(),
            )),

        FlatOp::StoreRecord(OpRecord::DeleteEntry { .. }) =>
            Ok(ValidateCallbackResult::Invalid(
                "Coordination entries are immutable".to_string(),
            )),

        FlatOp::StoreRecord(OpRecord::CreateLink {
            base_address,
            target_address,
            tag,
            link_type,
            action,
        }) => match link_type {
            LinkTypes::RequestToEvaluation =>
                validate_create_link_request_to_evaluation(action, base_address, target_address, tag),
            LinkTypes::RequestToCommitment =>
                validate_create_link_request_to_commitment(action, base_address, target_address, tag),
            LinkTypes::RequestToQuorum =>
                validate_create_link_request_to_quorum(action, base_address, target_address, tag),
            LinkTypes::AgentToRequest =>
                validate_create_link_agent_to_request(action, base_address, target_address, tag),
            LinkTypes::ManifestToRequest =>
                Ok(ValidateCallbackResult::Valid),
            LinkTypes::ManifestToEvidence =>
                validate_create_link_manifest_to_evidence(action, base_address, target_address, tag),
            LinkTypes::GlobalValidationRequestAnchor =>
                Ok(ValidateCallbackResult::Valid),
        },

        FlatOp::StoreRecord(OpRecord::DeleteLink { .. }) =>
            Ok(ValidateCallbackResult::Invalid(
                "Coordination links are permanent".to_string(),
            )),

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