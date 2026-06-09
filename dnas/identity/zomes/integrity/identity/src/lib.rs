use hdi::prelude::*;

#[hdk_entry_helper]
#[derive(Clone)]
pub struct AgentManifest {
    pub agent: AgentPubKey,
    pub agent_type: String,
    pub capabilities: Vec<String>,
    pub software_hash: String,
    pub version: String,
    pub metadata_blob: SerializedBytes,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
pub enum EntryTypes {
    AgentManifest(AgentManifest),
}

#[hdk_link_types]
pub enum LinkTypes {
    AgentToAgentManifest,
    CapabilityToAgent,
    GlobalAgentAnchor,
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

fn validate_create_agent_manifest(
    action: Create,
    manifest: AgentManifest,
) -> ExternResult<ValidateCallbackResult> {
    if manifest.agent != action.author {
        return Ok(ValidateCallbackResult::Invalid(
            "Agent manifest author must match declared agent pubkey".to_string()
        ));
    }
    if manifest.agent_type.is_empty() {
        return Ok(ValidateCallbackResult::Invalid(
            "agent_type cannot be empty".to_string()
        ));
    }
    Ok(ValidateCallbackResult::Valid)
}

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    match op.flattened::<EntryTypes, LinkTypes>()? {

        FlatOp::StoreEntry(OpEntry::CreateEntry { app_entry, action }) => {
            match app_entry {
                EntryTypes::AgentManifest(manifest) =>
                    validate_create_agent_manifest(action, manifest),
            }
        }

        FlatOp::StoreEntry(OpEntry::UpdateEntry { .. }) =>
            Ok(ValidateCallbackResult::Invalid(
                "Identity entries are immutable".to_string()
            )),

        FlatOp::RegisterUpdate(_) =>
            Ok(ValidateCallbackResult::Invalid(
                "Identity entries are immutable".to_string()
            )),

        FlatOp::RegisterDelete(_) =>
            Ok(ValidateCallbackResult::Invalid(
                "Identity entries are immutable".to_string()
            )),

        FlatOp::RegisterCreateLink { link_type, .. } => match link_type {
            LinkTypes::AgentToAgentManifest => Ok(ValidateCallbackResult::Valid),
            LinkTypes::CapabilityToAgent    => Ok(ValidateCallbackResult::Valid),
            LinkTypes::GlobalAgentAnchor    => Ok(ValidateCallbackResult::Valid),
        },

        FlatOp::RegisterDeleteLink { .. } =>
            Ok(ValidateCallbackResult::Invalid(
                "Identity links are permanent".to_string()
            )),

        FlatOp::StoreRecord(OpRecord::CreateEntry { app_entry, action }) => {
            match app_entry {
                EntryTypes::AgentManifest(manifest) =>
                    validate_create_agent_manifest(action, manifest),
            }
        }

        FlatOp::StoreRecord(OpRecord::UpdateEntry { .. }) =>
            Ok(ValidateCallbackResult::Invalid(
                "Identity entries are immutable".to_string()
            )),

        FlatOp::StoreRecord(OpRecord::DeleteEntry { .. }) =>
            Ok(ValidateCallbackResult::Invalid(
                "Identity entries are immutable".to_string()
            )),

        FlatOp::StoreRecord(OpRecord::CreateLink { link_type, .. }) => match link_type {
            LinkTypes::AgentToAgentManifest => Ok(ValidateCallbackResult::Valid),
            LinkTypes::CapabilityToAgent    => Ok(ValidateCallbackResult::Valid),
            LinkTypes::GlobalAgentAnchor    => Ok(ValidateCallbackResult::Valid),
        },

        FlatOp::StoreRecord(OpRecord::DeleteLink { .. }) =>
            Ok(ValidateCallbackResult::Invalid(
                "Identity links are permanent".to_string()
            )),

        FlatOp::RegisterAgentActivity(OpActivity::CreateAgent { agent, action }) => {
            let previous_action = must_get_action(action.prev_action)?;
            match previous_action.action() {
                Action::AgentValidationPkg(AgentValidationPkg { membrane_proof, .. }) =>
                    validate_agent_joining(agent, membrane_proof),
                _ => Ok(ValidateCallbackResult::Invalid(
                    "Previous action must be AgentValidationPkg".to_string()
                )),
            }
        }

        _ => Ok(ValidateCallbackResult::Valid),
    }
}