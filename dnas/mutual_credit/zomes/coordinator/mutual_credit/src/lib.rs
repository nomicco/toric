use hdk::prelude::*;
use mutual_credit_integrity::*;
use toric_geometry::{
    PHI, PHI_4, PHI_CU, INV_PHI_SQ,
    credit_limit_for_reputation, default_credit_limit, derive_roster_with_mass,
    jaccard_distance, next_fibonacci, previous_fibonacci,
    ADMISSION_GATE_FLOOR, GENESIS_CREDIT_SUPPLY, SCORE_PPM_DENOM,
};

fn admission_allowance(honest_rep_fraction: f64, attestation_count: u64, next_threshold: u64) -> u32 {
    // Gate floor 1 − φ⁻³ = φ⁻¹ + φ⁻⁴: the gate reacts at the pre-capture
    // ALARM line (dishonest ≥ φ⁻³), one partition level before the
    // quorum boundary (dishonest ≥ φ⁻²) where capture becomes possible.
    // The security margin is thereby forced to exactly φ⁻⁴ of total
    // reputation mass — the old floor of φ⁻¹ sat ON the boundary,
    // leaving zero margin (the audit's severest finding).
    if honest_rep_fraction <= ADMISSION_GATE_FLOOR {
        return 0;
    }
    let prev = previous_fibonacci(attestation_count);
    let cycle_progress = if next_threshold == prev {
        1.0
    } else {
        (attestation_count - prev) as f64 / (next_threshold - prev) as f64
    };
    let margin = honest_rep_fraction - ADMISSION_GATE_FLOOR;
    // φ³ amplifies the margin. Assigned-pending under the forcing rule
    // (growth quantities and positive powers are not yet derived) —
    // flagged in the Gap-7 doc, not silently kept.
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

/// Score [0,1] → fixed-point ppm, clamped. The old local f64 curve
/// (t = s^φ via powf) is deleted: the limit function now lives in
/// toric-geometry as `credit_limit_for_reputation`, integer-exact,
/// because integrity validates limit == that function — computing here
/// with any other arithmetic would be a self-inflicted fork.
fn score_to_ppm(score: f64) -> u32 {
    (score.clamp(0.0, 1.0) * SCORE_PPM_DENOM as f64) as u32
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
    fns.insert((zome_info()?.name, FunctionName::from("sign_credit_limit")));
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
    let new_limit = credit_limit_for_reputation(score_to_ppm(reputation), credit_supply);

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
        reputation_basis: None,
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
    // Lease clock and roster ride through attestation successions
    // untouched — integrity enforces exactly this.
    let (carried_roster, carried_declared_at) = match current {
        Some(ref s) => (s.authorized_signers.clone(), s.roster_declared_at),
        None => (vec![], 0),
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
            authorized_signers: carried_roster.clone(),
            prev_state_hash: prev_state_hash.clone(),
            roster_declared_at: carried_declared_at,
            seal: None,
        };
        let state_hash = write_network_state(new_state)?;

        // Real measurement, not a placeholder: the registry's
        // reputation view is a sibling zome since the merge. The old
        // hardcoded INV_PHI made margin ≡ 0 and the allowance vacuous —
        // the gate wasn't just marginless, it wasn't reading reality.
        // On bridge failure, fail CLOSED (allowance 0): no admission on
        // no data.
        let honest_rep_fraction = fetch_honest_rep_fraction().unwrap_or(0.0);
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
            authorized_signers: carried_roster.clone(),
            prev_state_hash: prev_state_hash.clone(),
            roster_declared_at: carried_declared_at,
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
// Sealed CreditLimit — the merge dividend flow
//
// The seal now carries strictly less than it used to: integrity
// recomputes the score→limit arithmetic (law) and pins the seal to the
// cited registry ReputationCache (binding). What the quorum still
// attests — the only things it CAN attest — are the two enumeration
// facts validation cannot reach: that the cited cache is the agent's
// LATEST (freshness) and that the attested balance matches the real
// net position. Each signer checks both against their own view; a
// divergent view yields a missing signature, not a fork.
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreditLimitSignRequest {
    pub payload: CreditLimitPayload,
}

/// Fetch the agent's latest ReputationCache citation from the registry
/// sibling zome. None on any failure — callers pick their fail
/// direction explicitly.
fn fetch_reputation_basis(agent: AgentPubKey) -> Option<(ActionHash, u32)> {
    #[derive(Serialize, Deserialize, Debug)]
    struct BasisInput {
        agent: AgentPubKey,
    }
    #[derive(Serialize, Deserialize, Debug)]
    struct Basis {
        cache_hash: ActionHash,
        score_ppm: u32,
    }
    let result = call(
        CallTargetCell::Local,
        ZomeName::from("registry"),
        FunctionName::from("get_reputation_basis"),
        None,
        BasisInput { agent },
    )
    .ok()?;
    match result {
        ZomeCallResponse::Ok(io) => io
            .decode::<Option<Basis>>()
            .ok()
            .flatten()
            .map(|b| (b.cache_hash, b.score_ppm)),
        _ => None,
    }
}

/// Called remotely by an agent refreshing their limit. Sign iff the
/// payload survives OUR view:
///  • the cited basis is the agent's LATEST ReputationCache we can see
///    (freshness — the enumeration fact validation cannot verify),
///  • the score matches that record,
///  • the limit is exactly the law function of that score (cheap local
///    recheck; integrity re-enforces it regardless),
///  • the attested balance matches our computed net position,
///  • anchor/cycle bind to the current state.
#[hdk_extern]
pub fn sign_credit_limit(req: CreditLimitSignRequest) -> ExternResult<Signature> {
    let me = agent_info()?.agent_initial_pubkey;
    let p = &req.payload;
    if p.domain != SEAL_DOMAIN_CREDIT_LIMIT || p.dna_hash != dna_info()?.hash {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "CreditLimit payload domain/network mismatch".to_string()
        )));
    }
    let Some((current, current_hash)) = get_current_network_state_with_hash()? else {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "No current NetworkState in this view".to_string()
        )));
    };
    if p.anchor_state_hash != current_hash || p.cycle != current.cycle {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Refusing to sign: payload does not anchor to the current state in this view"
                .to_string()
        )));
    }
    let Some((basis_hash, score_ppm)) = fetch_reputation_basis(p.agent.clone()) else {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Refusing to sign: no reputation basis visible for this agent".to_string()
        )));
    };
    match &p.reputation_basis {
        Some(cited) if *cited == basis_hash => {}
        Some(_) => {
            return Err(wasm_error!(WasmErrorInner::Guest(
                "Refusing to sign: cited basis is not the agent's latest ReputationCache in this view"
                    .to_string()
            )))
        }
        None => {
            return Err(wasm_error!(WasmErrorInner::Guest(
                "Refusing to sign: sealed CreditLimit payload must cite a reputation basis"
                    .to_string()
            )))
        }
    }
    if p.reputation_score != score_ppm {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Refusing to sign: payload score disagrees with the cited basis in this view"
                .to_string()
        )));
    }
    if p.limit != credit_limit_for_reputation(score_ppm, current.credit_supply) {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Refusing to sign: limit is not the law function of the score".to_string()
        )));
    }
    let balance = compute_balance(&p.agent)?;
    if p.attested_balance != balance {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Refusing to sign: attested balance disagrees with this view's net position"
                .to_string()
        )));
    }
    sign(me, req.payload)
}

/// Refresh the caller's own CreditLimit through the sealed path:
/// derive score and basis from the registry, compute the law limit,
/// collect roster signatures, commit. Self-pull preserved — only the
/// subject agent can commit their own limit (integrity enforces
/// cl.agent == author). Fails cleanly when no roster is declared:
/// during bootstrap the unsealed fresh-terms path is the only one.
#[hdk_extern]
pub fn refresh_credit_limit(_: ()) -> ExternResult<ActionHash> {
    let me = agent_info()?.agent_initial_pubkey;
    let Some((current, current_hash)) = get_current_network_state_with_hash()? else {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "No NetworkState exists — nothing to anchor a seal to".to_string()
        )));
    };
    if current.authorized_signers.is_empty() {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "No roster declared — sealed limits unavailable; unsealed fresh-account terms apply"
                .to_string()
        )));
    }
    let Some((basis_hash, score_ppm)) = fetch_reputation_basis(me.clone()) else {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "No reputation basis on record — earn standing before refreshing".to_string()
        )));
    };
    let limit = credit_limit_for_reputation(score_ppm, current.credit_supply);
    let attested_balance = compute_balance(&me)?;
    let payload = CreditLimitPayload {
        domain: SEAL_DOMAIN_CREDIT_LIMIT.into(),
        dna_hash: dna_info()?.hash,
        anchor_state_hash: current_hash.clone(),
        agent: me.clone(),
        limit,
        attested_balance,
        reputation_score: score_ppm,
        cycle: current.cycle,
        reputation_basis: Some(basis_hash.clone()),
    };
    let request = CreditLimitSignRequest { payload: payload.clone() };
    let mut signers: Vec<AgentPubKey> = Vec::new();
    let mut signatures: Vec<Signature> = Vec::new();
    for seat in &current.authorized_signers {
        let response = call_remote(
            seat.agent.clone(),
            zome_info()?.name,
            FunctionName::from("sign_credit_limit"),
            None,
            &request,
        );
        if let Ok(ZomeCallResponse::Ok(io)) = response {
            if let Ok(sig) = io.decode::<Signature>() {
                signers.push(seat.agent.clone());
                signatures.push(sig);
            }
        }
        // Mass threshold check happens in integrity — collect what's live.
    }
    let metadata = {
        let json = serde_json::json!({
            "sealed": true,
            "score_ppm": score_ppm,
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
        agent: me.clone(),
        limit,
        reputation_score: score_ppm,
        attested_balance,
        cycle: current.cycle,
        seal: Some(QuorumSeal {
            anchor_state_hash: current_hash,
            signers,
            signatures,
        }),
        reputation_basis: Some(basis_hash),
        metadata_blob: metadata,
    };
    let action_hash = create_entry(EntryTypes::CreditLimit(credit_limit))?;
    create_link(me, action_hash.clone(), LinkTypes::AgentToCreditLimit, ())?;
    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Sovereignty roster — derived, declared, rotated
// ─────────────────────────────────────────────



#[derive(Serialize, Deserialize, Debug, Clone)]
struct ScoredAgent {
    agent: AgentPubKey,
    score: f64,
}

/// Honest reputation fraction from the registry sibling zome. None on
/// any failure — callers decide their fail direction explicitly.
fn fetch_honest_rep_fraction() -> Option<f64> {
    #[derive(serde::Deserialize, Debug)]
    struct NetRep {
        honest_rep_fraction: f64,
    }
    let result = call(
        CallTargetCell::Local,
        ZomeName::from("registry"),
        FunctionName::from("get_network_reputation"),
        None,
        (),
    )
    .ok()?;
    match result {
        ZomeCallResponse::Ok(io) => io.decode::<NetRep>().ok().map(|r| r.honest_rep_fraction),
        _ => None,
    }
}

/// Fetch (agent, score) pairs from the registry over the bridge and run
/// the pure roster function. Every roster member runs this same code
/// against their own registry view — determinism across honest signers
/// is the wasm module plus DHT convergence, and transient divergence
/// surfaces as a failed signature round, not a fork.
/// Score-to-mass scale. Pure representation: every threshold is a ratio
/// over the same vector, so the scale cancels — it exists only to make
/// masses integers for consensus-critical arithmetic.
const MASS_SCALE: f64 = 1_000_000.0;

fn derive_roster_from_registry() -> ExternResult<Vec<RosterSeat>> {
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
    let byte_scored: Vec<(Vec<u8>, u64)> = scored
        .iter()
        .map(|s| {
            let mass = (s.score.max(0.0) * MASS_SCALE).round() as u64;
            (s.agent.get_raw_39().to_vec(), mass)
        })
        .collect();
    let seats_bytes = derive_roster_with_mass(&byte_scored);
    let mut roster = Vec::with_capacity(seats_bytes.len());
    for (bytes, mass) in seats_bytes {
        let agent = AgentPubKey::try_from_raw_39(bytes).map_err(|e| {
            wasm_error!(WasmErrorInner::Guest(format!("Bad agent key bytes: {:?}", e)))
        })?;
        roster.push(RosterSeat { agent, mass });
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
        roster_declared_at: current.attestation_count, // lease clock starts
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
        || req.payload.roster_declared_at != current.attestation_count
    {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Refusing to sign: rotation must carry economics unchanged and stamp the lease clock".to_string()
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
        roster_declared_at: current.attestation_count,
    };
    let request = RosterRotationRequest { payload: payload.clone() };
    let mut signers: Vec<AgentPubKey> = Vec::new();
    let mut signatures: Vec<Signature> = Vec::new();
    for seat in &current.authorized_signers {
        let member = &seat.agent;
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
        roster_declared_at: current.attestation_count,
        seal: Some(QuorumSeal {
            anchor_state_hash: current_hash,
            signers,
            signatures,
        }),
    };
    write_network_state(state)
}

/// Accession past a dead sovereign. When the sitting roster's lease has
/// expired (SOVEREIGNTY_LEASE_ROUNDS since roster_declared_at), the
/// freshly derived roster seals its own accession — signatures are
/// collected from the INCOMING roster, and integrity accepts the seal
/// against the new roster only under verified expiry. Callable by
/// anyone; like rotation, the caller only assembles signatures honest
/// signers produce solely for the derived roster. If the old roster is
/// actually alive, use rotate_roster — its seal is always the cheaper
/// and preferred path, and remains valid even past expiry.
#[hdk_extern]
pub fn accede_roster(_: ()) -> ExternResult<ActionHash> {
    let Some((current, current_hash)) = get_current_network_state_with_hash()? else {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "No NetworkState exists".to_string()
        )));
    };
    if current.authorized_signers.is_empty() {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "No roster declared — nothing to accede past; use declare_signer_roster".to_string()
        )));
    }
    if !toric_geometry::roster_expired(current.roster_declared_at, current.attestation_count) {
        return Err(wasm_error!(WasmErrorInner::Guest(format!(
            "Sitting roster's lease has not expired (declared at round {}, now {}, lease {}) — use rotate_roster",
            current.roster_declared_at,
            current.attestation_count,
            toric_geometry::SOVEREIGNTY_LEASE_ROUNDS
        ))));
    }
    let new_roster = derive_roster_from_registry()?;
    if new_roster.is_empty() {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Derived roster is empty — no reputation mass to accede with".to_string()
        )));
    }
    if new_roster == current.authorized_signers {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Derived roster equals the expired roster — accession requires a changed roster; if these agents are alive, rotate; if dead, sovereignty heals as reputation accrues to live agents"
                .to_string()
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
        roster_declared_at: current.attestation_count,
    };
    let request = RosterRotationRequest { payload: payload.clone() };
    let mut signers: Vec<AgentPubKey> = Vec::new();
    let mut signatures: Vec<Signature> = Vec::new();
    // Signatures from the INCOMING roster — the constitutional
    // difference between accession and rotation.
    for seat in &new_roster {
        let member = &seat.agent;
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
    }
    let state = NetworkState {
        attestation_count: current.attestation_count,
        next_fibonacci_threshold: current.next_fibonacci_threshold,
        credit_supply: current.credit_supply,
        cycle: current.cycle,
        phase: current.phase,
        authorized_signers: new_roster,
        prev_state_hash: Some(current_hash.clone()),
        roster_declared_at: current.attestation_count,
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
    /// Σ|credit limit| over frozen accounts. Probe 7 measures frozen
    /// MASS, not frozen heads — counts are sybil-cheap, mass is not.
    pub frozen_credit_mass: u64,
    /// Σ|credit limit| over all accounts.
    pub total_credit_mass: u64,
}

/// Everything the economic closure probes need, measured in one pass.
/// Coordination fetches this and hands it to registry's close_round —
/// registry keeps owning what closing means; this DNA only reports what
/// it is.
#[hdk_extern]
pub fn economic_snapshot(_: ()) -> ExternResult<EconomicSnapshot> {
    let current = get_current_network_state()?;
    let (cycle, credit_supply, sealed_seats) = match &current {
        Some(s) => (s.cycle, s.credit_supply, s.authorized_signers.clone()),
        None => (0, GENESIS_CREDIT_SUPPLY, vec![]),
    };
    let sealed_roster: Vec<AgentPubKey> =
        sealed_seats.iter().map(|seat| seat.agent.clone()).collect();

    let derived = derive_roster_from_registry().unwrap_or_default();
    // Probe 6 measures MEMBERSHIP conformance (keys); mass drift is the
    // drift accumulator's jurisdiction.
    let sealed_bytes: Vec<Vec<u8>> = sealed_seats
        .iter()
        .map(|seat| seat.agent.get_raw_39().to_vec())
        .collect();
    let derived_bytes: Vec<Vec<u8>> = derived
        .iter()
        .map(|seat| seat.agent.get_raw_39().to_vec())
        .collect();
    let roster_divergence = jaccard_distance(&sealed_bytes, &derived_bytes);

    // Frozen fraction over the global account population.
    let accounts_anchor = Path::from("accounts.all").path_entry_hash()?;
    let account_links = fetch_links(accounts_anchor, LinkTypes::AccountsAnchor)?;
    let mut seen: Vec<AgentPubKey> = Vec::new();
    let mut frozen_count: u32 = 0;
    let mut frozen_credit_mass: u64 = 0;
    let mut total_credit_mass: u64 = 0;
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
        let mass = limit.unsigned_abs();
        total_credit_mass = total_credit_mass.saturating_add(mass);
        if balance <= limit {
            frozen_count += 1;
            frozen_credit_mass = frozen_credit_mass.saturating_add(mass);
        }
    }

    Ok(EconomicSnapshot {
        cycle,
        credit_supply,
        sealed_roster,
        roster_divergence,
        account_count: seen.len() as u32,
        frozen_count,
        frozen_credit_mass,
        total_credit_mass,
    })
}