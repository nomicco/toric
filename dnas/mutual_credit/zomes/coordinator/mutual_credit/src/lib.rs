use hdk::prelude::*;
use mutual_credit_integrity::*;
use toric_geometry::{
    PHI, PHI_4, PHI_CU, INV_PHI, INV_PHI_SQ,
    default_credit_limit, derive_roster, jaccard_distance, next_fibonacci,
    previous_fibonacci, GENESIS_CREDIT_SUPPLY,
};

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
    (margin * PHI_CU * cycle_progress).floor() as u32
}

fn expand_credit_supply(current: i64) -> i64 {
    (current as f64 * PHI).floor() as i64
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

fn get_reputation_score(agent: AgentPubKey) -> ExternResult<f64> {
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

    // Same cell now — registry is a sibling zome in the ledger DNA.
    // No cell id, no DNA hash, no bridge to misconfigure.
    let result = call(
        CallTargetCell::Local,
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

    // Dedupe by target — duplicate index links must not double-count.
    let mut seen_hashes: Vec<ActionHash> = Vec::new();
    for link in links {
        if let Some(action_hash) = link.target.into_action_hash() {
            if seen_hashes.contains(&action_hash) {
                continue;
            }
            seen_hashes.push(action_hash.clone());
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

    Ok(default_credit_limit(GENESIS_CREDIT_SUPPLY))
}

#[hdk_extern]
pub fn init(_: ()) -> ExternResult<InitCallbackResult> {
    let mut fns: HashSet<(ZomeName, FunctionName)> = HashSet::new();
    fns.insert((zome_info()?.name, FunctionName::from("on_attestation_created")));
    // Peer-callable consent functions: both only ever sign what matches
    // the callee's own independent evaluation, so unrestricted access
    // grants nothing beyond the ability to ask.
    fns.insert((zome_info()?.name, FunctionName::from("endorse_transaction")));
    fns.insert((zome_info()?.name, FunctionName::from("sign_network_state")));
    fns.insert((zome_info()?.name, FunctionName::from("economic_snapshot")));
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
        credit_limit: default_credit_limit(GENESIS_CREDIT_SUPPLY),
        metadata_blob: input.metadata_blob,
    };
    let action_hash = create_entry(EntryTypes::Account(account))?;
    create_link(agent, action_hash.clone(), LinkTypes::AgentToAccount, ())?;
    // Global enumeration path for the economic probes.
    let accounts_anchor = Path::from("accounts.all").path_entry_hash()?;
    create_link(accounts_anchor, action_hash.clone(), LinkTypes::AccountsAnchor, ())?;
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

    // Balance basis for integrity validation: latest CreditLimit on
    // our chain, else our Account creation. Validation re-walks the
    // chain and rejects a stale citation, so latest-link is safe here.
    let checkpoint = {
        let cl_links = fetch_links(from_agent.clone(), LinkTypes::AgentToCreditLimit)?;
        let acct_links = fetch_links(from_agent.clone(), LinkTypes::AgentToAccount)?;
        cl_links
            .last()
            .or(acct_links.last())
            .and_then(|l| l.target.clone().into_action_hash())
            .ok_or(wasm_error!(WasmErrorInner::Guest(
                "No CreditLimit or Account found to checkpoint against — create an account first"
                    .to_string()
            )))?
    };

    // Bilateral act: the recipient endorses this exact spend (including
    // the checkpoint) before it exists. Integrity rejects unendorsed
    // transactions, so an offline recipient means no transaction — the
    // correct semantics for a credit network: credit is a relationship,
    // both ends present.
    let endorsement_payload = TransactionPayload {
        domain: SEAL_DOMAIN_TRANSACTION.into(),
        dna_hash: dna_info()?.hash,
        from_agent: from_agent.clone(),
        to_agent: input.to_agent.clone(),
        amount: input.amount,
        checkpoint: checkpoint.clone(),
    };
    let response = call_remote(
        input.to_agent.clone(),
        zome_info()?.name,
        FunctionName::from("endorse_transaction"),
        None,
        &endorsement_payload,
    )?;
    let recipient_sig: Signature = match response {
        ZomeCallResponse::Ok(io) => io.decode().map_err(|e| {
            wasm_error!(WasmErrorInner::Guest(format!(
                "Failed to decode endorsement: {:?}", e
            )))
        })?,
        _ => {
            return Err(wasm_error!(WasmErrorInner::Guest(
                "Recipient declined or is unreachable — transactions are bilateral".to_string()
            )))
        }
    };

    let tx = Transaction {
        from_agent: from_agent.clone(),
        to_agent: input.to_agent.clone(),
        amount: input.amount,
        checkpoint: Some(checkpoint),
        recipient_sig: Some(recipient_sig),
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
    let reputation = get_reputation_score(input.agent.clone()).unwrap_or(0.0);

    let current_state = get_current_network_state()?;
    let credit_supply = current_state.map(|s| s.credit_supply).unwrap_or(GENESIS_CREDIT_SUPPLY);
    let new_limit = compute_credit_limit(reputation, credit_supply);

    let metadata = {
        let json = serde_json::json!({
            "reputation_score": reputation,
            // What the φ-interpolated limit WOULD be — recorded so the
            // sealed path (and operators) can compare attested vs
            // computed. Unvalidated metadata; the enforced limit below
            // is the fresh-account default until a seal carries better.
            "computed_limit": new_limit,
            "computed_at": sys_time()?.as_millis(),
        });
        let bytes = serde_json::to_vec(&json).map_err(|e| {
            wasm_error!(WasmErrorInner::Guest(format!(
                "Failed to serialize credit limit metadata: {}", e
            )))
        })?;
        SerializedBytes::from(UnsafeBytes::from(bytes))
    };

    // Unsealed path — integrity caps it at fresh-account terms: default
    // limit, zero attested balance, zero claimed reputation. Better
    // terms require the sealed path.
    let credit_limit = CreditLimit {
        agent: input.agent.clone(),
        limit: default_credit_limit(credit_supply),
        reputation_score: 0,
        attested_balance: 0,
        cycle: 0,
        seal: None,
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
    Ok(get_current_network_state_with_hash()?.map(|(s, _)| s))
}

/// Same read, but keeps the ActionHash — needed to set prev_state_hash
/// on successor states (integrity enforces the succession chain).
fn get_current_network_state_with_hash() -> ExternResult<Option<(NetworkState, ActionHash)>> {
    let anchor = get_network_state_anchor()?;
    let links = fetch_links(anchor, LinkTypes::NetworkStateAnchor)?;

    // Most recent state is last link
    if let Some(link) = links.last() {
        if let Some(hash) = link.target.clone().into_action_hash() {
            if let Some(record) = get(hash.clone(), GetOptions::default())? {
                if let Some(entry) = record.entry().as_option() {
                    if let Ok(state) = NetworkState::try_from(entry) {
                        return Ok(Some((state, hash)));
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
    // Action hash of the NetworkState entry authoritative for this
    // attestation_count — either the one we just wrote, or, in the
    // idempotency branch, the one another agent wrote first this round.
    // Coordination passes this into registry's write_network_state_manifest
    // so the manifest references the mutual_credit NetworkState by hash
    // rather than duplicating its fields. No #[serde(default)] needed:
    // FibonacciResult is a return value only, never stored or deserialized
    // from prior DHT data (verified — five occurrences, all in this file,
    // none an entry type).
    pub network_state_hash: ActionHash,
}

#[hdk_extern]
pub fn on_attestation_created(_input: AttestationNotification) -> ExternResult<FibonacciResult> {
    // Get or initialize network state
    let current = get_current_network_state_with_hash()?;

    let prev_state_hash = current.as_ref().map(|(_, h)| h.clone());
    let current = current.map(|(s, _)| s);

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
                let existing_state_hash = record.action_address().clone();
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
                                network_state_hash: existing_state_hash,
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
            // Roster stays empty until sovereignty is declared
            // (declare_signer_roster) — until then, unsealed succession
            // is the validated bootstrap path.
            authorized_signers: vec![],
            prev_state_hash: prev_state_hash.clone(),
            seal: None,
        };
        let state_hash = write_network_state(new_state)?;

        let honest_rep_fraction = INV_PHI;
        let allowance = admission_allowance(honest_rep_fraction, attestation_count, next_threshold);

        Ok(FibonacciResult {
            attestation_count,
            threshold_crossed: true,
            new_credit_supply: Some(new_supply),
            admission_allowance: Some(allowance),
            next_threshold,
            network_state_hash: state_hash,
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
            authorized_signers: vec![],
            prev_state_hash: prev_state_hash.clone(),
            seal: None,
        };
        let state_hash = write_network_state(new_state)?;

        Ok(FibonacciResult {
            attestation_count,
            threshold_crossed: false,
            new_credit_supply: None,
            admission_allowance: None,
            next_threshold: current_threshold,
            network_state_hash: state_hash,
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
// ─────────────────────────────────────────────
// Endorsement — the recipient's half of every transaction
// ─────────────────────────────────────────────

/// Called remotely by a sender. Sign iff the payload survives OUR view:
/// the cited checkpoint is the sender's latest basis and the spend fits
/// inside it. Signing a stale or overdrawn spend makes US warrant-liable
/// — this function is where counterparty liability gets teeth.
#[hdk_extern]
pub fn endorse_transaction(payload: TransactionPayload) -> ExternResult<Signature> {
    let me = agent_info()?.agent_initial_pubkey;
    if payload.to_agent != me {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Endorsement request is not addressed to this agent".to_string()
        )));
    }
    if payload.domain != SEAL_DOMAIN_TRANSACTION || payload.dna_hash != dna_info()?.hash {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Endorsement payload domain/network mismatch".to_string()
        )));
    }
    if payload.amount <= 0 {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Refusing to endorse a non-positive spend".to_string()
        )));
    }
    // Checkpoint currency check against OUR view of the sender's index.
    let cl_links = fetch_links(payload.from_agent.clone(), LinkTypes::AgentToCreditLimit)?;
    let acct_links = fetch_links(payload.from_agent.clone(), LinkTypes::AgentToAccount)?;
    let latest_basis = cl_links
        .last()
        .or(acct_links.last())
        .and_then(|l| l.target.clone().into_action_hash());
    match latest_basis {
        Some(hash) if hash == payload.checkpoint => {}
        Some(_) => {
            return Err(wasm_error!(WasmErrorInner::Guest(
                "Refusing to endorse: cited checkpoint is not the sender's latest basis"
                    .to_string()
            )))
        }
        None => {
            return Err(wasm_error!(WasmErrorInner::Guest(
                "Refusing to endorse: sender has no visible basis".to_string()
            )))
        }
    }
    // Solvency per our view — advisory (integrity re-derives the law),
    // but refusing here keeps our name off doomed spends.
    let balance = compute_balance(&payload.from_agent)?;
    let limit = get_current_credit_limit(&payload.from_agent)?;
    if balance - payload.amount < limit {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Refusing to endorse: spend exceeds sender's limit in this view".to_string()
        )));
    }
    sign(me, payload)
}

// ─────────────────────────────────────────────
// Sovereignty roster — derived, declared, rotated
// ─────────────────────────────────────────────



#[derive(Serialize, Deserialize, Debug, Clone)]
struct ScoredAgent {
    agent: AgentPubKey,
    score: f64,
}

/// Fetch (agent, score) pairs from the registry over the bridge and run
/// the pure roster function. Every roster member runs this same code
/// against their own registry view — determinism across honest signers
/// is the wasm module plus DHT convergence, and transient divergence
/// surfaces as a failed signature round, not a fork.
fn derive_roster_from_registry() -> ExternResult<Vec<AgentPubKey>> {
    let result = call(
        CallTargetCell::Local,
        ZomeName::from("registry"),
        FunctionName::from("get_scored_agents"),
        None,
        (),
    )?;
    let scored: Vec<ScoredAgent> = match result {
        ZomeCallResponse::Ok(io) => io.decode().map_err(|e| {
            wasm_error!(WasmErrorInner::Guest(format!(
                "Failed to decode scored agents: {:?}", e
            )))
        })?,
        _ => {
            return Err(wasm_error!(WasmErrorInner::Guest(
                "Registry bridge call for scored agents failed".to_string()
            )))
        }
    };
    let byte_scored: Vec<(Vec<u8>, f64)> = scored
        .iter()
        .map(|s| (s.agent.get_raw_39().to_vec(), s.score))
        .collect();
    let roster_bytes = derive_roster(&byte_scored);
    let mut roster = Vec::with_capacity(roster_bytes.len());
    for bytes in roster_bytes {
        roster.push(AgentPubKey::try_from_raw_39(bytes).map_err(|e| {
            wasm_error!(WasmErrorInner::Guest(format!("Bad agent key bytes: {:?}", e)))
        })?);
    }
    Ok(roster)
}

/// Bootstrap sovereignty declaration: writes a rotation state carrying
/// the reputation-derived roster. Integrity gates this to the progenitor
/// when DNA properties configure one.
#[hdk_extern]
pub fn declare_signer_roster(_: ()) -> ExternResult<ActionHash> {
    let Some((current, current_hash)) = get_current_network_state_with_hash()? else {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "No NetworkState exists — the network must metabolize before it can govern"
                .to_string()
        )));
    };
    if !current.authorized_signers.is_empty() {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Roster already declared — use rotate_roster".to_string()
        )));
    }
    let roster = derive_roster_from_registry()?;
    if roster.is_empty() {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Derived roster is empty — no reputation mass to govern with".to_string()
        )));
    }
    let state = NetworkState {
        authorized_signers: roster,
        prev_state_hash: Some(current_hash),
        seal: None, // first declaration — progenitor-gated in integrity
        ..current
    };
    write_network_state(state)
}

/// What a roster member is asked to sign for a successor state.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RosterRotationRequest {
    pub payload: NetworkStatePayload,
}

/// Called remotely during rotation. Sign iff the proposed successor is
/// byte-identical to what WE would derive: same economics as current
/// state, roster equal to our own reputation-derived computation. The
/// roster stays a function — a proposal that diverges from the function
/// collects no honest signatures, and a sealed divergence is probe-6
/// deviation plus warrant material against its signers.
#[hdk_extern]
pub fn sign_network_state(req: RosterRotationRequest) -> ExternResult<Signature> {
    let me = agent_info()?.agent_initial_pubkey;
    if req.payload.domain != SEAL_DOMAIN_NETWORK_STATE
        || req.payload.dna_hash != dna_info()?.hash
    {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Rotation payload domain/network mismatch".to_string()
        )));
    }
    let Some((current, current_hash)) = get_current_network_state_with_hash()? else {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "No current NetworkState in this view".to_string()
        )));
    };
    if req.payload.anchor_state_hash != current_hash
        || req.payload.prev_state_hash != current_hash
    {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Refusing to sign: proposal does not succeed the current state in this view"
                .to_string()
        )));
    }
    if req.payload.attestation_count != current.attestation_count
        || req.payload.next_fibonacci_threshold != current.next_fibonacci_threshold
        || req.payload.credit_supply != current.credit_supply
        || req.payload.cycle != current.cycle
        || req.payload.phase != current.phase
    {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Refusing to sign: rotation must carry economics unchanged".to_string()
        )));
    }
    let expected_roster = derive_roster_from_registry()?;
    if req.payload.authorized_signers != expected_roster {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Refusing to sign: proposed roster diverges from the reputation-derived roster"
                .to_string()
        )));
    }
    sign(me, req.payload)
}

/// Rotate sovereignty: derive the fresh roster, collect seals from the
/// CURRENT roster, write the rotation state. Callable by anyone — the
/// caller has no power here beyond assembling signatures that honest
/// signers only produce for the derived roster.
#[hdk_extern]
pub fn rotate_roster(_: ()) -> ExternResult<ActionHash> {
    let Some((current, current_hash)) = get_current_network_state_with_hash()? else {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "No NetworkState exists".to_string()
        )));
    };
    if current.authorized_signers.is_empty() {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "No roster declared — use declare_signer_roster".to_string()
        )));
    }
    let new_roster = derive_roster_from_registry()?;
    if new_roster == current.authorized_signers {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Derived roster matches the sealed roster — nothing to rotate".to_string()
        )));
    }
    let payload = NetworkStatePayload {
        domain: SEAL_DOMAIN_NETWORK_STATE.into(),
        dna_hash: dna_info()?.hash,
        anchor_state_hash: current_hash.clone(),
        prev_state_hash: current_hash.clone(),
        attestation_count: current.attestation_count,
        next_fibonacci_threshold: current.next_fibonacci_threshold,
        credit_supply: current.credit_supply,
        cycle: current.cycle,
        phase: current.phase,
        authorized_signers: new_roster.clone(),
    };
    let request = RosterRotationRequest { payload: payload.clone() };
    let mut signers: Vec<AgentPubKey> = Vec::new();
    let mut signatures: Vec<Signature> = Vec::new();
    for member in &current.authorized_signers {
        let response = call_remote(
            member.clone(),
            zome_info()?.name,
            FunctionName::from("sign_network_state"),
            None,
            &request,
        );
        if let Ok(ZomeCallResponse::Ok(io)) = response {
            if let Ok(sig) = io.decode::<Signature>() {
                signers.push(member.clone());
                signatures.push(sig);
            }
        }
        // Threshold check happens in integrity — collect what's live.
    }
    let state = NetworkState {
        attestation_count: current.attestation_count,
        next_fibonacci_threshold: current.next_fibonacci_threshold,
        credit_supply: current.credit_supply,
        cycle: current.cycle,
        phase: current.phase,
        authorized_signers: new_roster,
        prev_state_hash: Some(current_hash.clone()),
        seal: Some(QuorumSeal {
            anchor_state_hash: current_hash,
            signers,
            signatures,
        }),
    };
    write_network_state(state)
}

// ─────────────────────────────────────────────
// Economic snapshot — what closure sees of the economy
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EconomicSnapshot {
    pub cycle: u64,
    pub credit_supply: i64,
    pub sealed_roster: Vec<AgentPubKey>,
    /// Jaccard distance between the sealed roster and the reputation-
    /// derived roster, computed here where the registry bridge exists.
    pub roster_divergence: f64,
    pub account_count: u32,
    pub frozen_count: u32,
}

/// Everything the economic closure probes need, measured in one pass.
/// Coordination fetches this and hands it to registry's close_round —
/// registry keeps owning what closing means; this DNA only reports what
/// it is.
#[hdk_extern]
pub fn economic_snapshot(_: ()) -> ExternResult<EconomicSnapshot> {
    let current = get_current_network_state()?;
    let (cycle, credit_supply, sealed_roster) = match &current {
        Some(s) => (s.cycle, s.credit_supply, s.authorized_signers.clone()),
        None => (0, GENESIS_CREDIT_SUPPLY, vec![]),
    };

    let derived = derive_roster_from_registry().unwrap_or_default();
    let sealed_bytes: Vec<Vec<u8>> = sealed_roster
        .iter()
        .map(|a| a.get_raw_39().to_vec())
        .collect();
    let derived_bytes: Vec<Vec<u8>> = derived
        .iter()
        .map(|a| a.get_raw_39().to_vec())
        .collect();
    let roster_divergence = jaccard_distance(&sealed_bytes, &derived_bytes);

    // Frozen fraction over the global account population.
    let accounts_anchor = Path::from("accounts.all").path_entry_hash()?;
    let account_links = fetch_links(accounts_anchor, LinkTypes::AccountsAnchor)?;
    let mut seen: Vec<AgentPubKey> = Vec::new();
    let mut frozen_count: u32 = 0;
    for link in account_links {
        let Some(hash) = link.target.into_action_hash() else { continue };
        let Some(record) = get(hash, GetOptions::default())? else { continue };
        let Some(entry) = record.entry().as_option() else { continue };
        let Ok(account) = Account::try_from(entry) else { continue };
        if seen.contains(&account.agent) {
            continue;
        }
        seen.push(account.agent.clone());
        let balance = compute_balance(&account.agent)?;
        let limit = get_current_credit_limit(&account.agent)?;
        if balance <= limit {
            frozen_count += 1;
        }
    }

    Ok(EconomicSnapshot {
        cycle,
        credit_supply,
        sealed_roster,
        roster_divergence,
        account_count: seen.len() as u32,
        frozen_count,
    })
}