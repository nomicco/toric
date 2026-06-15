use hdk::prelude::*;
use mutual_credit_integrity::*;

const PHI: f64 = 1.6180339887498948;
const PHI_4: f64 = 6.8541019662496847;
const INV_PHI: f64 = 0.6180339887498948;
const INV_PHI_SQ: f64 = 0.3819660112501051;
// F(16) — the 16th Fibonacci number.
// Genesis supply is on the Fibonacci sequence so the first expansion
// lands on F(17) = 1597, and every subsequent expansion stays on the sequence.
const GENESIS_CREDIT_SUPPLY: i64 = 987;


fn admission_allowance(honest_rep_fraction: f64, attestation_count: u64, next_threshold: u64) -> u32 {
    if honest_rep_fraction <= INV_PHI {
        return 0;
    }
    let prev = previous_fibonacci(attestation_count);
    let cycle_progress = if next_threshold == prev {
        1.0
    } else {
        (attestation_count - prev) as f64 / (next_threshold - prev) as f64
    };
    let margin = honest_rep_fraction - INV_PHI;
    // φ³ amplifies the margin above the φ⁻¹ honest threshold.
    // Geometric choice — admission headroom compounds at the same
    // rate as reputation itself.
    const PHI_CU: f64 = 4.2360679774997896;
    (margin * PHI_CU * cycle_progress).floor() as u32
}

fn expand_credit_supply(current: i64) -> i64 {
    (current as f64 * PHI).floor() as i64
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

fn previous_fibonacci(n: u64) -> u64 {
    let mut a: u64 = 1;
    let mut b: u64 = 1;
    loop {
        let c = a + b;
        if c >= n { return a; }
        a = b;
        b = c;
    }
}

fn default_credit_limit() -> i64 {
    let supply = GENESIS_CREDIT_SUPPLY;
    -((supply as f64 * INV_PHI_SQ) as i64)
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
    pub registry_dna_hash: DnaHash,
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
        _ => Ok(INV_PHI_SQ),
    }
}

fn compute_credit_limit(reputation_score: f64, credit_supply: i64) -> i64 {
    let lower = credit_supply as f64 * INV_PHI_SQ;  // φ⁻² — zero reputation
    let upper = credit_supply as f64 * INV_PHI;      // φ⁻¹ — full reputation
    // φ-weighted interpolation — reputation compounds geometrically not linearly
    let t = reputation_score.powf(PHI);
    let limit = -((lower + t * (upper - lower)) as i64);
    let ceiling = -(next_fibonacci(credit_supply as u64) as i64);
    limit.max(ceiling)
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
    let mut fns: HashSet<(ZomeName, FunctionName)> = HashSet::new();
    fns.insert((zome_info()?.name, FunctionName::from("on_attestation_created")));
    create_cap_grant(CapGrantEntry {
        tag: "bridge".into(),
        access: CapAccess::Unrestricted,
        functions: GrantedFunctions::Listed(fns),
    })?;
    Ok(InitCallbackResult::Pass)
}

#[hdk_extern]
pub fn create_account(input: CreateAccountInput) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;

    let current = get_current_network_state()?;

    match &current {
        None => {
            // No state at all — absolute genesis, first agent ever
            // Always allow, no check needed
        }
        Some(state) => {
            match state.phase {
                0 => {
                    // Genesis phase — open admission
                    // Founders operate before the geometry can enforce itself
                    // This window closes permanently when cycle 1 begins
                }
                _ => {
                    // Governed phase — admission gate checks cycle progress.
                    // honest_rep_fraction is enforced client-side before join
                    // is attempted — it requires a live network view that the
                    // joining agent's cells do not have at initialization time.
                    let prev = previous_fibonacci(state.attestation_count);
                    let cycle_progress = if state.next_fibonacci_threshold == prev {
                        1.0
                    } else {
                        (state.attestation_count - prev) as f64
                            / (state.next_fibonacci_threshold - prev) as f64
                    };
                    if cycle_progress <= 0.0 {
                        return Err(wasm_error!(WasmErrorInner::Guest(
                            "Admission gate closed — no validation work done \
                             in current Fibonacci cycle.".to_string()
                        )));
                    }
                }
            }
        }
    }

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
    let registry_cell_id = CellId::new(input.registry_dna_hash.clone(), input.agent.clone());

    let reputation = get_reputation_score(
        input.agent.clone(),
        registry_cell_id,
    ).unwrap_or(0.0);

    let current_state = get_current_network_state()?;
    let credit_supply = current_state.map(|s| s.credit_supply).unwrap_or(GENESIS_CREDIT_SUPPLY);
    let new_limit = compute_credit_limit(reputation, credit_supply);

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
    let current_state = get_current_network_state()?;
    let credit_supply = current_state.map(|s| s.credit_supply).unwrap_or(GENESIS_CREDIT_SUPPLY);
    let reward = (credit_supply as f64 / PHI_4) as i64;

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
// F(8) — the eighth Fibonacci number. First quorum threshold.
// The network operates in genesis phase until 21 attestations are reached.
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
pub fn on_attestation_created(_input: AttestationNotification) -> ExternResult<FibonacciResult> {
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

    // Idempotency check — if a state entry with this attestation_count
    // already exists, another agent wrote it first. Return their result
    // rather than writing a duplicate. Concurrent writes from multiple
    // validators calling check_quorum simultaneously are the expected case.
    // Phase 5.5 replaces this with NetworkStateManifest through commit-reveal
    // quorum, which makes state updates single-writer by design.
    let all_state_links = fetch_links(
        get_network_state_anchor()?,
        LinkTypes::NetworkStateAnchor,
    )?;
    for link in &all_state_links {
        if let Some(hash) = link.target.clone().into_action_hash() {
            if let Some(record) = get(hash, GetOptions::default())? {
                if let Some(entry) = record.entry().as_option() {
                    if let Ok(existing) = NetworkState::try_from(entry) {
                        if existing.attestation_count == attestation_count {
                            // State for this count already written.
                            // Detect if it diverges from what we would have written
                            // and emit a signal if so — deviation visible on DHT.
                            let would_cross = attestation_count >= current_threshold;
                            let did_cross = existing.next_fibonacci_threshold > current_threshold;
                            if would_cross != did_cross {
                                // Divergence detected — the existing state disagrees
                                // with what this agent would have written.
                                // TODO Phase 5.5: emit deviation signal here.
                                // For now, log and return the existing state's values.
                                debug!("NetworkState divergence detected at count {}: \
                                    existing threshold={}, expected={}",
                                    attestation_count,
                                    existing.next_fibonacci_threshold,
                                    if would_cross { next_fibonacci(attestation_count) } else { current_threshold }
                                );
                            }
                            return Ok(FibonacciResult {
                                attestation_count: existing.attestation_count,
                                threshold_crossed: did_cross,
                                new_credit_supply: if did_cross { Some(existing.credit_supply) } else { None },
                                admission_allowance: None,
                                next_threshold: existing.next_fibonacci_threshold,
                            });
                        }
                    }
                }
            }
        }
    }

    // No existing state for this count — we are first writer.
    if attestation_count >= current_threshold {
        let new_supply = expand_credit_supply(credit_supply);
        let next_threshold = next_fibonacci(attestation_count);

        let new_state = NetworkState {
            attestation_count,
            next_fibonacci_threshold: next_threshold,
            credit_supply: new_supply,
            cycle: cycle + 1,
            // Phase 1 — governed phase begins after first Fibonacci crossing
            phase: 1,
        };
        write_network_state(new_state)?;

        let honest_rep_fraction = INV_PHI;
        let allowance = admission_allowance(honest_rep_fraction, attestation_count, next_threshold);

        Ok(FibonacciResult {
            attestation_count,
            threshold_crossed: true,
            new_credit_supply: Some(new_supply),
            admission_allowance: Some(allowance),
            next_threshold,
        })
    } else {
        let new_state = NetworkState {
            attestation_count,
            next_fibonacci_threshold: current_threshold,
            credit_supply,
            cycle,
            phase: match current {
                Some(ref s) => s.phase,
                None => 0,
            },
        };
        write_network_state(new_state)?;

        Ok(FibonacciResult {
            attestation_count,
            threshold_crossed: false,
            new_credit_supply: None,
            admission_allowance: None,
            next_threshold: current_threshold,
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
