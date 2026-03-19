use hdi::prelude::*;

#[hdk_entry_helper]
#[derive(Clone)]
pub struct Account {
    pub agent: AgentPubKey,
    pub credit_limit: i64,
    pub metadata_blob: SerializedBytes,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct Transaction {
    pub from_agent: AgentPubKey,
    pub to_agent: AgentPubKey,
    pub amount: i64,
    pub metadata_blob: SerializedBytes,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct CreditLimit {
    pub agent: AgentPubKey,
    pub limit: i64,
    pub reputation_score: u32,
    pub metadata_blob: SerializedBytes,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct NetworkState {
    pub attestation_count: u64,
    pub next_fibonacci_threshold: u64,
    pub credit_supply: i64,
    pub cycle: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
pub enum EntryTypes {
    Account(Account),
    Transaction(Transaction),
    CreditLimit(CreditLimit),
    NetworkState(NetworkState),
}

#[hdk_link_types]
pub enum LinkTypes {
    AgentToAccount,
    AgentToTransactions,
    AgentToCreditLimit,
    NetworkStateAnchor,
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

fn validate_create_account(
    _action: Create,
    _account: Account,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_transaction(
    _action: Create,
    transaction: Transaction,
) -> ExternResult<ValidateCallbackResult> {
    if transaction.amount <= 0 {
        return Ok(ValidateCallbackResult::Invalid(
            "Transaction amount must be positive".to_string(),
        ));
    }
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_credit_limit(
    _action: Create,
    _credit_limit: CreditLimit,
) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_network_state(
    _action: Create,
    state: NetworkState,
) -> ExternResult<ValidateCallbackResult> {
    if state.next_fibonacci_threshold == 0 {
        return Ok(ValidateCallbackResult::Invalid(
            "Fibonacci threshold cannot be zero".to_string(),
        ));
    }
    Ok(ValidateCallbackResult::Valid)
}

fn validate_create_link_agent_to_account(
    _action: CreateLink, _base: AnyLinkableHash, _target: AnyLinkableHash, _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> { Ok(ValidateCallbackResult::Valid) }

fn validate_create_link_agent_to_transactions(
    _action: CreateLink, _base: AnyLinkableHash, _target: AnyLinkableHash, _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> { Ok(ValidateCallbackResult::Valid) }

fn validate_create_link_agent_to_credit_limit(
    _action: CreateLink, _base: AnyLinkableHash, _target: AnyLinkableHash, _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> { Ok(ValidateCallbackResult::Valid) }

fn validate_create_link_network_state_anchor(
    _action: CreateLink, _base: AnyLinkableHash, _target: AnyLinkableHash, _tag: LinkTag,
) -> ExternResult<ValidateCallbackResult> { Ok(ValidateCallbackResult::Valid) }

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    match op.flattened::<EntryTypes, LinkTypes>()? {

        FlatOp::StoreEntry(OpEntry::CreateEntry { app_entry, action }) => {
            match app_entry {
                EntryTypes::Account(a) => validate_create_account(action, a),
                EntryTypes::Transaction(t) => validate_create_transaction(action, t),
                EntryTypes::CreditLimit(c) => validate_create_credit_limit(action, c),
                EntryTypes::NetworkState(s) => validate_create_network_state(action, s),
            }
        }

        FlatOp::StoreEntry(OpEntry::UpdateEntry { .. }) =>
            Ok(ValidateCallbackResult::Invalid("Mutual credit entries are immutable".to_string())),

        FlatOp::RegisterUpdate(_) =>
            Ok(ValidateCallbackResult::Invalid("Mutual credit entries are immutable".to_string())),

        FlatOp::RegisterDelete(_) =>
            Ok(ValidateCallbackResult::Invalid("Mutual credit entries are immutable".to_string())),

        FlatOp::RegisterCreateLink { link_type, base_address, target_address, tag, action } =>
            match link_type {
                LinkTypes::AgentToAccount =>
                    validate_create_link_agent_to_account(action, base_address, target_address, tag),
                LinkTypes::AgentToTransactions =>
                    validate_create_link_agent_to_transactions(action, base_address, target_address, tag),
                LinkTypes::AgentToCreditLimit =>
                    validate_create_link_agent_to_credit_limit(action, base_address, target_address, tag),
                LinkTypes::NetworkStateAnchor =>
                    validate_create_link_network_state_anchor(action, base_address, target_address, tag),
            },

        FlatOp::RegisterDeleteLink { .. } =>
            Ok(ValidateCallbackResult::Invalid("Mutual credit links are permanent".to_string())),

        FlatOp::StoreRecord(OpRecord::CreateEntry { app_entry, action }) => {
            match app_entry {
                EntryTypes::Account(a) => validate_create_account(action, a),
                EntryTypes::Transaction(t) => validate_create_transaction(action, t),
                EntryTypes::CreditLimit(c) => validate_create_credit_limit(action, c),
                EntryTypes::NetworkState(s) => validate_create_network_state(action, s),
            }
        }

        FlatOp::StoreRecord(OpRecord::UpdateEntry { .. }) =>
            Ok(ValidateCallbackResult::Invalid("Mutual credit entries are immutable".to_string())),

        FlatOp::StoreRecord(OpRecord::DeleteEntry { .. }) =>
            Ok(ValidateCallbackResult::Invalid("Mutual credit entries are immutable".to_string())),

        FlatOp::StoreRecord(OpRecord::CreateLink { base_address, target_address, tag, link_type, action }) =>
            match link_type {
                LinkTypes::AgentToAccount =>
                    validate_create_link_agent_to_account(action, base_address, target_address, tag),
                LinkTypes::AgentToTransactions =>
                    validate_create_link_agent_to_transactions(action, base_address, target_address, tag),
                LinkTypes::AgentToCreditLimit =>
                    validate_create_link_agent_to_credit_limit(action, base_address, target_address, tag),
                LinkTypes::NetworkStateAnchor =>
                    validate_create_link_network_state_anchor(action, base_address, target_address, tag),
            },

        FlatOp::StoreRecord(OpRecord::DeleteLink { .. }) =>
            Ok(ValidateCallbackResult::Invalid("Mutual credit links are permanent".to_string())),

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
