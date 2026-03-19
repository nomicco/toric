use hdk::prelude::*;
use mutual_credit_integrity::*;

const PHI: f64 = 1.6180339887498948;
const PHI_SQ: f64 = 2.6180339887498948;
const INV_PHI: f64 = 0.6180339887498948;
const INV_PHI_SQ: f64 = 0.3819660112501051;
const GENESIS_CREDIT_SUPPLY: i64 = 1000;
const MIN_VALIDATORS: u32 = 3;

fn starting_reputation(network_avg: f64) -> f64 {
    (network_avg / PHI_SQ).max(0.01)
}

fn admission_allowance(honest_rep_fraction: f64) -> u32 {
    if honest_rep_fraction <= INV_PHI {
        return 0;
    }
    let margin = honest_rep_fraction - INV_PHI;
    ((margin * PHI * 10.0).floor() as u32).max(1)
}

fn expand_credit_supply(current: i64) -> i64 {
    (current as f64 * PHI).floor() as i64
}

fn base_reward_unit(credit_supply: i64, validator_count: u32) -> f64 {
    credit_supply as f64 / (validator_count as f64 * 10.0)
}

fn next_fibonacci(n: u64) -> u64 {
    let mut a: u64 = 1;
    let mut b: u64 = 1;
    loop {
        let c = a + b;
        if c > n { return c; }
        a = b;
        b = c;
    }
}

fn compute_network_avg_reputation(
    registry_cell_id: CellId,
    agents: Vec<AgentPubKey>,
) -> f64 {
    if agents.is_empty() { return 0.5; }
    let total: f64 = agents.iter().filter_map(|agent| {
        get_reputation_score(agent.clone(), registry_cell_id.clone()).ok()
    }).sum();
    total / agents.len() as f64
}

fn default_credit_limit() -> i64 {
    -((GENESIS_CREDIT_SUPPLY as f64 * INV_PHI_SQ) as i64)
}

fn validation_reward(credit_supply: i64, validator_count: u32) -> i64 {
    base_reward_unit(credit_supply, validator_count) as i64
}

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

fn fetch_links(
    base: impl Into<AnyLinkableHash>,
    link_type: LinkTypes,
) -> ExternResult<Vec<Link>> {
    let query = LinkQuery::new(base.into(), link_type.try_into_filter()?);
    get_links(query, GetStrategy::Network)
}

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

fn compute_credit_limit(reputation_score: f64) -> i64 {
    let limit = -((GENESIS_CREDIT_SUPPLY as f64 * INV_PHI_SQ
        + reputation_score * GENESIS_CREDIT_SUPPLY as f64 * PHI) as i64);
    limit.max(-10000)
}

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

fn get_current_credit_limit(agent: &AgentPubKey) -> ExternResult<i64> {
    let links = fetch_links(agent.clone(), LinkTypes::AgentToCreditLimit)?;

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

    Ok(default_credit_limit())
}

#[hdk_extern]
pub fn init(_: ()) -> ExternResult<InitCallbackResult> {
    Ok(InitCallbackResult::Pass)
}

#[hdk_extern]
pub fn create_account(input: CreateAccountInput) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;
    let account = Account {
        agent: agent.clone(),
        credit_limit: default_credit_limit(),
        metadata_blob: input.metadata_blob,
    };
    let action_hash = create_entry(EntryTypes::Account(account))?;
    create_link(agent, action_hash.clone(), LinkTypes::AgentToAccount, ())?;
    Ok(action_hash)
}

#[hdk_extern]
pub fn transact(input: TransactInput) -> ExternResult<ActionHash> {
    let from_agent = agent_info()?.agent_initial_pubkey;

    if input.amount <= 0 {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Transaction amount must be positive".to_string()
        )));
    }

    let balance = compute_balance(&from_agent)?;
    let credit_limit = get_current_credit_limit(&from_agent)?;

    if balance - input.amount < credit_limit {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Transaction would exceed credit limit".to_string()
        )));
    }

    let tx = Transaction {
        from_agent: from_agent.clone(),
        to_agent: input.to_agent.clone(),
        amount: input.amount,
        metadata_blob: input.metadata_blob,
    };

    let action_hash = create_entry(EntryTypes::Transaction(tx))?;
    create_link(from_agent, action_hash.clone(), LinkTypes::AgentToTransactions, ())?;
    create_link(input.to_agent, action_hash.clone(), LinkTypes::AgentToTransactions, ())?;
    Ok(action_hash)
}

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
    create_link(input.agent, action_hash.clone(), LinkTypes::AgentToCreditLimit, ())?;
    Ok(action_hash)
}

#[hdk_extern]
pub fn reward_validator(input: RewardValidatorInput) -> ExternResult<ActionHash> {
    let reward = validation_reward(GENESIS_CREDIT_SUPPLY, MIN_VALIDATORS);

    let metadata = {
        let json = serde_json::json!({
            "reward_type": "validation_convergence",
            "amount": reward,
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
        amount: reward,
        metadata_blob: metadata,
    })
}

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

// ─────────────────────────────────────────────
// Network State — anchor path for DHT lookup
// ─────────────────────────────────────────────

const NETWORK_STATE_ANCHOR: &str = "network_state";
const BOOTSTRAP_ATTESTATIONS: u64 = 21;

fn get_network_state_anchor() -> ExternResult<EntryHash> {
    let path = Path::from(NETWORK_STATE_ANCHOR);
    path.path_entry_hash()
}

fn get_current_network_state() -> ExternResult<Option<NetworkState>> {
    let anchor = get_network_state_anchor()?;
    let links = fetch_links(anchor, LinkTypes::NetworkStateAnchor)?;

    // Most recent state is last link
    if let Some(link) = links.last() {
        if let Some(hash) = link.target.clone().into_action_hash() {
            if let Some(record) = get(hash, GetOptions::default())? {
                if let Some(entry) = record.entry().as_option() {
                    if let Ok(state) = NetworkState::try_from(entry) {
                        return Ok(Some(state));
                    }
                }
            }
        }
    }
    Ok(None)
}

fn write_network_state(state: NetworkState) -> ExternResult<ActionHash> {
    let anchor = get_network_state_anchor()?;
    let action_hash = create_entry(EntryTypes::NetworkState(state))?;
    create_link(anchor, action_hash.clone(), LinkTypes::NetworkStateAnchor, ())?;
    Ok(action_hash)
}

// ─────────────────────────────────────────────
// on_attestation_created
// Called by Coordination DNA via bridge after
// every successful quorum. Increments attestation
// count and fires Fibonacci expansion if threshold
// is crossed.
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationNotification {
    pub attestation_hash: ActionHash,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FibonacciResult {
    pub attestation_count: u64,
    pub threshold_crossed: bool,
    pub new_credit_supply: Option<i64>,
    pub admission_allowance: Option<u32>,
    pub next_threshold: u64,
}

#[hdk_extern]
pub fn on_attestation_created(input: AttestationNotification) -> ExternResult<FibonacciResult> {
    // Get or initialize network state
    let current = get_current_network_state()?;

    let (attestation_count, credit_supply, cycle) = match current {
        Some(ref s) => (s.attestation_count + 1, s.credit_supply, s.cycle),
        None => (1, GENESIS_CREDIT_SUPPLY, 0),
    };

    let current_threshold = match current {
        Some(ref s) => s.next_fibonacci_threshold,
        None => BOOTSTRAP_ATTESTATIONS,
    };

    // Check if we crossed a Fibonacci threshold
    if attestation_count >= current_threshold {
        // Expand credit supply by φ
        let new_supply = expand_credit_supply(credit_supply);
        let next_threshold = next_fibonacci(attestation_count);

        // Write new network state
        let new_state = NetworkState {
            attestation_count,
            next_fibonacci_threshold: next_threshold,
            credit_supply: new_supply,
            cycle: cycle + 1,
        };
        write_network_state(new_state)?;

        // Compute admission allowance
        // In production this would query honest rep fraction from Registry
        // For now use a conservative default of 0.8
        let honest_rep_fraction = 0.8_f64;
        let allowance = admission_allowance(honest_rep_fraction);

        Ok(FibonacciResult {
            attestation_count,
            threshold_crossed: true,
            new_credit_supply: Some(new_supply),
            admission_allowance: Some(allowance),
            next_threshold,
        })
    } else {
        // No threshold crossed — just update count
        let next_threshold = current_threshold;
        let new_state = NetworkState {
            attestation_count,
            next_fibonacci_threshold: next_threshold,
            credit_supply,
            cycle,
        };
        write_network_state(new_state)?;

        Ok(FibonacciResult {
            attestation_count,
            threshold_crossed: false,
            new_credit_supply: None,
            admission_allowance: None,
            next_threshold,
        })
    }
}

// ─────────────────────────────────────────────
// get_network_state — readable by any agent
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn get_network_state(_: ()) -> ExternResult<Option<NetworkState>> {
    get_current_network_state()
}
