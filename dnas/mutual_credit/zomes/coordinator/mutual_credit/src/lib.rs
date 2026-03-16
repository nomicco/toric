use hdk::prelude::*;
use mutual_credit_integrity::*;

#[hdk_extern]
pub fn init(_: ()) -> ExternResult<InitCallbackResult> {
    Ok(InitCallbackResult::Pass)
}

// ─────────────────────────────────────────────
// Constants — EIP-1559 style calibration
// These get adjusted automatically based on
// network health metrics over time.
// ─────────────────────────────────────────────

const INITIAL_CREDIT_LIMIT: i64 = -100;
const MAX_CREDIT_LIMIT: i64 = -10000;
const DEPLETION_RATE: f64 = 0.01;       // 1% per period if inactive
const VALIDATION_REWARD: i64 = 10;      // credits earned per convergent validation
const DISPUTE_COST_BASE: i64 = 20;      // base cost to file a dispute

// ─────────────────────────────────────────────
// Input / Output types
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateAccountInput {
    pub metadata_blob: SerializedBytes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TransactInput {
    pub to_agent: AgentPubKey,
    pub amount: i64,
    pub metadata_blob: SerializedBytes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateCreditLimitInput {
    pub agent: AgentPubKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetBalanceInput {
    pub agent: AgentPubKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BalanceResult {
    pub agent: AgentPubKey,
    pub balance: i64,
    pub credit_limit: i64,
    pub is_frozen: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RewardValidatorInput {
    pub agent: AgentPubKey,
}

// ─────────────────────────────────────────────
// Helper — fetch links
// ─────────────────────────────────────────────

fn fetch_links(
    base: impl Into<AnyLinkableHash>,
    link_type: LinkTypes,
) -> ExternResult<Vec<Link>> {
    let query = LinkQuery::new(base.into(), link_type.try_into_filter()?);
    get_links(query, GetStrategy::Network)
}

// ─────────────────────────────────────────────
// Helper — get reputation score via bridge call
// ─────────────────────────────────────────────

fn get_reputation_score(agent: AgentPubKey, registry_cell_id: CellId) -> ExternResult<f64> {
    #[derive(Serialize, Deserialize, Debug)]
    struct ReputationInput {
        agent: AgentPubKey,
    }
    #[derive(Serialize, Deserialize, Debug)]
    struct ReputationScore {
        agent: AgentPubKey,
        score: f64,
        attestation_count: u32,
        warrant_count: u32,
    }

    let result = call(
        CallTargetCell::OtherCell(registry_cell_id),
        ZomeName::from("registry"),
        FunctionName::from("compute_reputation_score"),
        None,
        ReputationInput { agent },
    )?;

    match result {
        ZomeCallResponse::Ok(extern_io) => {
            let score: ReputationScore = extern_io.decode().map_err(|e| {
                wasm_error!(WasmErrorInner::Guest(format!(
                    "Failed to decode reputation score: {:?}", e
                )))
            })?;
            Ok(score.score)
        }
        _ => Ok(0.5),
    }
}

// ─────────────────────────────────────────────
// Helper — compute credit limit from reputation
// Higher reputation = higher credit capacity
// ─────────────────────────────────────────────

fn compute_credit_limit(reputation_score: f64) -> i64 {
    let range = (MAX_CREDIT_LIMIT - INITIAL_CREDIT_LIMIT).abs() as f64;
    let limit = INITIAL_CREDIT_LIMIT as f64 - (reputation_score * range);
    limit.max(MAX_CREDIT_LIMIT as f64) as i64
}

// ─────────────────────────────────────────────
// Helper — compute balance from transaction chain
// ─────────────────────────────────────────────

fn compute_balance(agent: &AgentPubKey) -> ExternResult<i64> {
    let links = fetch_links(agent.clone(), LinkTypes::AgentToTransactions)?;
    let mut balance: i64 = 0;

    for link in links {
        if let Some(action_hash) = link.target.into_action_hash() {
            if let Some(record) = get(action_hash, GetOptions::default())? {
                if let Some(entry) = record.entry().as_option() {
                    if let Ok(tx) = Transaction::try_from(entry) {
                        if tx.from_agent == *agent {
                            balance -= tx.amount;
                        } else if tx.to_agent == *agent {
                            balance += tx.amount;
                        }
                    }
                }
            }
        }
    }
    Ok(balance)
}

// ─────────────────────────────────────────────
// Create Account
// Called when a new agent joins the network
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn create_account(input: CreateAccountInput) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;
    let account = Account {
        agent: agent.clone(),
        credit_limit: INITIAL_CREDIT_LIMIT,
        metadata_blob: input.metadata_blob,
    };
    let action_hash = create_entry(EntryTypes::Account(account))?;
    create_link(agent, action_hash.clone(), LinkTypes::AgentToAccount, ())?;
    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Transact
// Move credits between agents
// Enforces credit limit before writing
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn transact(input: TransactInput) -> ExternResult<ActionHash> {
    let from_agent = agent_info()?.agent_initial_pubkey;

    if input.amount <= 0 {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Transaction amount must be positive".to_string()
        )));
    }

    // Check sender has enough capacity
    let balance = compute_balance(&from_agent)?;
    let credit_limit = get_current_credit_limit(&from_agent)?;

    if balance - input.amount < credit_limit {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Transaction would exceed credit limit — account frozen or insufficient capacity".to_string()
        )));
    }

    let tx = Transaction {
        from_agent: from_agent.clone(),
        to_agent: input.to_agent.clone(),
        amount: input.amount,
        metadata_blob: input.metadata_blob,
    };

    let action_hash = create_entry(EntryTypes::Transaction(tx))?;

    // Link to both agents for traversal
    create_link(
        from_agent,
        action_hash.clone(),
        LinkTypes::AgentToTransactions,
        (),
    )?;
    create_link(
        input.to_agent,
        action_hash.clone(),
        LinkTypes::AgentToTransactions,
        (),
    )?;

    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Get Balance
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn get_balance(input: GetBalanceInput) -> ExternResult<BalanceResult> {
    let balance = compute_balance(&input.agent)?;
    let credit_limit = get_current_credit_limit(&input.agent)?;
    let is_frozen = balance <= credit_limit;

    Ok(BalanceResult {
        agent: input.agent,
        balance,
        credit_limit,
        is_frozen,
    })
}

// ─────────────────────────────────────────────
// Get current credit limit for an agent
// ─────────────────────────────────────────────

fn get_current_credit_limit(agent: &AgentPubKey) -> ExternResult<i64> {
    let links = fetch_links(agent.clone(), LinkTypes::AgentToCreditLimit)?;

    // Get the most recent credit limit entry
    if let Some(link) = links.last() {
        if let Some(action_hash) = link.target.clone().into_action_hash() {
            if let Some(record) = get(action_hash, GetOptions::default())? {
                if let Some(entry) = record.entry().as_option() {
                    if let Ok(credit_limit) = CreditLimit::try_from(entry) {
                        return Ok(credit_limit.limit);
                    }
                }
            }
        }
    }

    Ok(INITIAL_CREDIT_LIMIT)
}

// ─────────────────────────────────────────────
// Update Credit Limit
// Called after reputation changes.
// Pulls latest reputation from Registry
// via bridge call and updates credit limit.
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn update_credit_limit(input: UpdateCreditLimitInput) -> ExternResult<ActionHash> {
    let dna_info = dna_info()?;
    let registry_cell_id = CellId::new(dna_info.hash, input.agent.clone());

    let reputation = get_reputation_score(
        input.agent.clone(),
        registry_cell_id,
    ).unwrap_or(0.0);

    let new_limit = compute_credit_limit(reputation);

    let metadata = {
        let json = serde_json::json!({
            "reputation_score": reputation,
            "computed_at": sys_time()?.as_millis(),
        });
        let bytes = serde_json::to_vec(&json).map_err(|e| {
            wasm_error!(WasmErrorInner::Guest(format!(
                "Failed to serialize credit limit metadata: {}", e
            )))
        })?;
        SerializedBytes::from(UnsafeBytes::from(bytes))
    };

    let credit_limit = CreditLimit {
        agent: input.agent.clone(),
        limit: new_limit,
        reputation_score: (reputation * 1000.0) as u32,
        metadata_blob: metadata,
    };

    let action_hash = create_entry(EntryTypes::CreditLimit(credit_limit))?;
    create_link(
        input.agent,
        action_hash.clone(),
        LinkTypes::AgentToCreditLimit,
        (),
    )?;
    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Reward Validator
// Called after a convergent validation.
// Issues credits to the validator.
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn reward_validator(input: RewardValidatorInput) -> ExternResult<ActionHash> {
    let from_agent = agent_info()?.agent_initial_pubkey;

    let metadata = {
        let json = serde_json::json!({
            "reward_type": "validation_convergence",
            "amount": VALIDATION_REWARD,
        });
        let bytes = serde_json::to_vec(&json).map_err(|e| {
            wasm_error!(WasmErrorInner::Guest(format!(
                "Failed to serialize reward metadata: {}", e
            )))
        })?;
        SerializedBytes::from(UnsafeBytes::from(bytes))
    };

    transact(TransactInput {
        to_agent: input.agent,
        amount: VALIDATION_REWARD,
        metadata_blob: metadata,
    })
}

// ─────────────────────────────────────────────
// Signals
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Signal {
    TransactionCreated { action_hash: ActionHash },
    CreditLimitUpdated { agent: AgentPubKey, new_limit: i64 },
    AccountFrozen { agent: AgentPubKey },
}

#[hdk_extern(infallible)]
pub fn post_commit(committed_actions: Vec<SignedActionHashed>) {
    for action in committed_actions {
        if let Err(err) = signal_action(action) {
            error!("Error signaling new action: {:?}", err);
        }
    }
}

fn signal_action(_action: SignedActionHashed) -> ExternResult<()> {
    Ok(())
}