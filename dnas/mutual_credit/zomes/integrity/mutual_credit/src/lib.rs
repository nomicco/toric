//! Mutual Credit integrity zome — the economic membrane, enforced.
//!
//! Everything in this file is law: it runs on every peer that stores or
//! serves these entries, regardless of what coordinator the author ran.
//! The coordinator is convention; this is the network's identity.
//!
//! ## The QuorumSeal primitive
//!
//! Integrity validation cannot bridge to the registry DNA, so reputation
//! cannot be *recomputed* here. It is made portable instead: a quorum of
//! authorized signers — agents who CAN see the registry DHT through
//! their coordinators — countersign a payload, and validation verifies
//! the signatures with `verify_signature` (deterministic) against a
//! roster anchored in a `must_get`-able prior NetworkState in THIS DHT.
//! Trust crosses the membrane as signatures, never as claims.
//!
//! One primitive, three consumers:
//!   - CreditLimit      — reputation-derived limits become unforgeable
//!   - NetworkState     — governed-phase writes become single-writer in law
//!   - PaymentReceipt   — external value enters only as an attested fact
//!
//! ## Seal threshold: φ⁻¹ of the roster
//!
//! Deciding takes φ⁻² of reputation (quorum). Re-anchoring identity —
//! which is what every membrane crossing is — takes the complement:
//! 1 − φ⁻² = φ⁻¹. Computed integer-exact as ⌈n·610/987⌉ (F(15)/F(16))
//! so no float enters consensus arithmetic. No transcendental function
//! is ever evaluated in this zome: powf-derived quantities (the credit
//! limit value itself) arrive as *attested* numbers under signatures,
//! not as recomputations.
//!
//! ## What integrity can and cannot guarantee
//!
//! Guaranteed here: unforgeability (no seal, no privileged write),
//! arithmetic law (Fibonacci expansion, balance ≥ limit, sum-zero),
//! chain consistency (checkpoints, monotonic state succession).
//! NOT guaranteed here: freshness/canonicity — deterministic validation
//! cannot know the "latest" global state. An agent citing a stale-but-
//! valid anchor is caught by the warrant layer and by coordinators that
//! check currency, not by validation. The damage of every legacy/
//! unsealed path below is capped to fresh-account terms, so staleness
//! buys nothing beyond what a new agent gets for free.

use hdi::prelude::*;
use toric_geometry::{
    default_credit_limit, is_fibonacci, next_fibonacci, seal_threshold,
    GENESIS_CREDIT_SUPPLY,
};

// ─────────────────────────────────────────────
// Domain-separation tags — bound into every signed payload so a
// signature produced for one purpose can never validate another.
// Versioned: payload schema changes bump the tag.
// ─────────────────────────────────────────────

pub const SEAL_DOMAIN_CREDIT_LIMIT: &str = "toric.seal.credit_limit.v1";
pub const SEAL_DOMAIN_NETWORK_STATE: &str = "toric.seal.network_state.v1";
pub const SEAL_DOMAIN_PAYMENT_RECEIPT: &str = "toric.seal.payment_receipt.v1";
pub const SEAL_DOMAIN_TRANSACTION: &str = "toric.seal.transaction.v1";

// ─────────────────────────────────────────────
// The seal and its payloads
// ─────────────────────────────────────────────

/// Quorum countersignature carried by membrane-crossing entries.
///
/// `anchor_state_hash` names the prior NetworkState (in THIS DHT) whose
/// `authorized_signers` roster legitimizes the signers. Validation
/// `must_get`s it — deterministic, same-DHT, no bridge.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct QuorumSeal {
    pub anchor_state_hash: ActionHash,
    pub signers: Vec<AgentPubKey>,
    pub signatures: Vec<Signature>,
}

/// What roster members sign for a CreditLimit. Field order is the wire
/// format — never reorder without bumping the domain tag.
#[derive(Serialize, Deserialize, Clone, Debug, SerializedBytes)]
pub struct CreditLimitPayload {
    pub domain: String,
    pub dna_hash: DnaHash,
    pub anchor_state_hash: ActionHash,
    pub agent: AgentPubKey,
    pub limit: i64,
    pub attested_balance: i64,
    pub reputation_score: u32,
    pub cycle: u64,
}

/// What roster members sign for a governed NetworkState write.
#[derive(Serialize, Deserialize, Clone, Debug, SerializedBytes)]
pub struct NetworkStatePayload {
    pub domain: String,
    pub dna_hash: DnaHash,
    pub anchor_state_hash: ActionHash,
    pub prev_state_hash: ActionHash,
    pub attestation_count: u64,
    pub next_fibonacci_threshold: u64,
    pub credit_supply: i64,
    pub cycle: u64,
    pub phase: u8,
    pub authorized_signers: Vec<AgentPubKey>,
}

/// What roster members sign for a PaymentReceipt: the attested external
/// fact plus the provenance-derived distribution. The quorum — not this
/// zome — is what verified the external proof and computed the
/// distribution from registry provenance; the seal makes that
/// verification portable into this DHT.
#[derive(Serialize, Deserialize, Clone, Debug, SerializedBytes)]
pub struct PaymentReceiptPayload {
    pub domain: String,
    pub dna_hash: DnaHash,
    pub anchor_state_hash: ActionHash,
    pub artifact_manifest_hash: ActionHash,
    pub rail: String,
    pub external_proof: SerializedBytes,
    pub amount_external: i64,
    pub distribution: Vec<DistributionShare>,
}

/// What a recipient signs to endorse a spend. The endorsement is the
/// immune system's efferent limb: by signing, the recipient attests the
/// sender's cited checkpoint is current *to their view* — cosigning a
/// stale-anchored spend makes the recipient warrant-liable. Sanctions
/// stop requiring the cooperation of the sanctioned; they require only
/// that counterparties protect their own standing.
#[derive(Serialize, Deserialize, Clone, Debug, SerializedBytes)]
pub struct TransactionPayload {
    pub domain: String,
    pub dna_hash: DnaHash,
    pub from_agent: AgentPubKey,
    pub to_agent: AgentPubKey,
    pub amount: i64,
    pub checkpoint: ActionHash,
}

// ─────────────────────────────────────────────
// Entry types
// ─────────────────────────────────────────────

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
    /// The author's balance basis: action hash of their latest
    /// CreditLimit, or their Account creation if no limit exists yet.
    /// Validation walks the author's chain from this transaction back
    /// to the checkpoint and enforces the limit over the segment.
    /// `#[serde(default)]` for pre-hardening entries only; new creates
    /// without it are Invalid.
    #[serde(default)]
    pub checkpoint: Option<ActionHash>,
    /// Recipient's endorsement over TransactionPayload. Required on
    /// create — credit moves only as a bilateral act.
    #[serde(default)]
    pub recipient_sig: Option<Signature>,
    pub metadata_blob: SerializedBytes,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct CreditLimit {
    pub agent: AgentPubKey,
    pub limit: i64,
    pub reputation_score: u32,
    /// Net position attested by the sealing quorum at seal time. Acts as
    /// the balance checkpoint for subsequent transaction validation:
    /// spend-since-checkpoint is bounded by attested_balance − limit.
    #[serde(default)]
    pub attested_balance: i64,
    /// Must equal the anchor state's cycle when sealed — binds the seal
    /// to a network epoch.
    #[serde(default)]
    pub cycle: u64,
    /// None ⇒ legacy/bootstrap limit, valid only at fresh-account terms
    /// (see validate_create_credit_limit). Some ⇒ full seal check.
    #[serde(default)]
    pub seal: Option<QuorumSeal>,
    pub metadata_blob: SerializedBytes,
}

#[hdk_entry_helper]
#[derive(Clone)]
pub struct NetworkState {
    pub attestation_count: u64,
    pub next_fibonacci_threshold: u64,
    pub credit_supply: i64,
    pub cycle: u64,
    pub phase: u8,
    /// The sovereignty roster. Empty ⇒ sealing not yet active
    /// (bootstrap). Once non-empty, every successor state requires a
    /// seal by the *previous* roster — sovereignty is a chain.
    #[serde(default)]
    pub authorized_signers: Vec<AgentPubKey>,
    /// Succession pointer. None only at genesis (attestation_count ≤ 1).
    #[serde(default)]
    pub prev_state_hash: Option<ActionHash>,
    #[serde(default)]
    pub seal: Option<QuorumSeal>,
}

/// One share of a payment distribution. `weight` is the raw φ-weighted
/// provenance score, scaled to integer by the sealing quorum —
/// distribution is proportional, so no denominator constant exists to
/// tune. Settlement divides by the sum.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DistributionShare {
    pub agent: AgentPubKey,
    pub weight: u64,
}

/// External value entering the membrane as an attested fact. Never
/// touches credit balances: credit stays sum-zero and non-convertible.
/// The receipt is the network's computation of who is owed what share
/// of revenue for an artifact, sealed by quorum; settlement happens on
/// the external rail named in `rail`.
#[hdk_entry_helper]
#[derive(Clone)]
pub struct PaymentReceipt {
    /// Registry-DNA manifest of the artifact sold. Opaque here — this
    /// zome never dereferences it; the sealing quorum did.
    pub artifact_manifest_hash: ActionHash,
    pub rail: String,
    pub external_proof: SerializedBytes,
    pub amount_external: i64,
    pub distribution: Vec<DistributionShare>,
    /// Mandatory. There is no unsealed path for money.
    pub seal: QuorumSeal,
    pub metadata_blob: SerializedBytes,
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
    PaymentReceipt(PaymentReceipt),
}

#[hdk_link_types]
pub enum LinkTypes {
    AgentToAccount,
    AgentToTransactions,
    AgentToCreditLimit,
    NetworkStateAnchor,
    PaymentReceiptAnchor,
    /// Global enumeration path — every Account links from "accounts.all"
    /// so the economic probes can measure over the full population.
    AccountsAnchor,
}

// ─────────────────────────────────────────────
// Seal verification — the shared primitive
// ─────────────────────────────────────────────

/// Fetches and decodes the anchor NetworkState for a seal.
fn get_anchor_state(anchor: &ActionHash) -> ExternResult<Result<NetworkState, ValidateCallbackResult>> {
    let record = must_get_valid_record(anchor.clone())?;
    let entry = match record.entry().as_option() {
        Some(e) => e,
        None => {
            return Ok(Err(ValidateCallbackResult::Invalid(
                "Seal anchor record carries no entry".into(),
            )))
        }
    };
    match NetworkState::try_from(entry) {
        Ok(state) => Ok(Ok(state)),
        Err(_) => Ok(Err(ValidateCallbackResult::Invalid(
            "Seal anchor is not a NetworkState".into(),
        ))),
    }
}

/// Verifies a QuorumSeal against a roster: signer legitimacy, threshold,
/// and every signature over the given payload bytes. Deterministic —
/// `verify_signature` is pure crypto, the roster arrived via `must_get`.
fn verify_seal(
    seal: &QuorumSeal,
    roster: &[AgentPubKey],
    payload_bytes: Vec<u8>,
) -> ExternResult<ValidateCallbackResult> {
    if roster.is_empty() {
        return Ok(ValidateCallbackResult::Invalid(
            "Seal anchored to a state with an empty roster — sealing not active at that anchor"
                .into(),
        ));
    }
    if seal.signers.len() != seal.signatures.len() {
        return Ok(ValidateCallbackResult::Invalid(
            "Seal signer/signature count mismatch".into(),
        ));
    }
    // Dedup — a signer counts once toward threshold.
    let mut seen: Vec<&AgentPubKey> = Vec::with_capacity(seal.signers.len());
    for signer in &seal.signers {
        if seen.contains(&signer) {
            return Ok(ValidateCallbackResult::Invalid(
                "Duplicate signer in seal".into(),
            ));
        }
        if !roster.contains(signer) {
            return Ok(ValidateCallbackResult::Invalid(
                "Seal signer not in the anchor roster".into(),
            ));
        }
        seen.push(signer);
    }
    let required = seal_threshold(roster.len());
    if seal.signers.len() < required {
        return Ok(ValidateCallbackResult::Invalid(format!(
            "Seal has {} signatures; roster of {} requires {} (⌈n·φ⁻¹⌉)",
            seal.signers.len(),
            roster.len(),
            required
        )));
    }
    for (signer, signature) in seal.signers.iter().zip(seal.signatures.iter()) {
        if !verify_signature(signer.clone(), signature.clone(), payload_bytes.clone())? {
            return Ok(ValidateCallbackResult::Invalid(
                "Seal signature failed verification".into(),
            ));
        }
    }
    Ok(ValidateCallbackResult::Valid)
}

fn payload_bytes<T: TryInto<SerializedBytes, Error = SerializedBytesError>>(
    payload: T,
) -> ExternResult<Vec<u8>> {
    let sb: SerializedBytes = payload.try_into().map_err(|e| {
        wasm_error!(WasmErrorInner::Guest(format!(
            "Seal payload serialization failed: {:?}",
            e
        )))
    })?;
    Ok(sb.bytes().to_vec())
}

// ─────────────────────────────────────────────
// Genesis / membrane checks
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn genesis_self_check(_data: GenesisSelfCheckData) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

pub fn validate_agent_joining(
    _agent_pub_key: AgentPubKey,
    _membrane_proof: &Option<MembraneProof>,
) -> ExternResult<ValidateCallbackResult> {
    // Deliberately open: Toric's admission economics (allowance,
    // honest_rep_fraction) are enforced at Account creation and by the
    // credit geometry, not at DHT entry. A peer with no Account can
    // hold data but cannot move credit.
    Ok(ValidateCallbackResult::Valid)
}

// ─────────────────────────────────────────────
// Account
// ─────────────────────────────────────────────

fn validate_create_account(action: Create, account: Account) -> ExternResult<ValidateCallbackResult> {
    if account.agent != action.author {
        return Ok(ValidateCallbackResult::Invalid(
            "Account.agent must be the authoring agent".into(),
        ));
    }
    // Self-declared limits are capped at fresh-account terms. Better
    // limits exist only as sealed CreditLimit entries. Limits are
    // negative: ≥ means no more borrowing power than default.
    let floor = default_credit_limit(GENESIS_CREDIT_SUPPLY);
    if account.credit_limit < floor {
        return Ok(ValidateCallbackResult::Invalid(format!(
            "Account credit_limit {} exceeds the unsealed floor {} — reputation-derived limits require a sealed CreditLimit",
            account.credit_limit, floor
        )));
    }
    // One Account per agent, enforced on the author's own chain — a
    // deterministic full-chain walk. Runs once per agent lifetime.
    let activity = must_get_agent_activity(
        action.author.clone(),
        ChainFilter::new(action.prev_action.clone()),
    )?;
    for item in activity {
        if let Some((_, EntryTypes::Account(_))) = decode_app_entry(item.action.action())? {
            return Ok(ValidateCallbackResult::Invalid(
                "Agent already has an Account".into(),
            ));
        }
    }
    Ok(ValidateCallbackResult::Valid)
}

// ─────────────────────────────────────────────
// Transaction — author binding + chain-walk balance law
// ─────────────────────────────────────────────

/// Decodes an app entry of THIS zome from an action, if it is one.
/// Returns the entry hash alongside for callers that need identity.
fn decode_app_entry(action: &Action) -> ExternResult<Option<(EntryHash, EntryTypes)>> {
    let (entry_hash, entry_type) = match (action.entry_hash(), action.entry_type()) {
        (Some(h), Some(t)) => (h.clone(), t.clone()),
        _ => return Ok(None),
    };
    let EntryType::App(AppEntryDef {
        zome_index,
        entry_index,
        ..
    }) = entry_type
    else {
        return Ok(None);
    };
    let entry = must_get_entry(entry_hash.clone())?;
    let decoded = EntryTypes::deserialize_from_type(zome_index, entry_index, entry.as_content())?;
    Ok(decoded.map(|e| (entry_hash, e)))
}

fn validate_create_transaction(
    action: Create,
    tx: Transaction,
) -> ExternResult<ValidateCallbackResult> {
    if tx.amount <= 0 {
        return Ok(ValidateCallbackResult::Invalid(
            "Transaction amount must be positive".into(),
        ));
    }
    if tx.from_agent != action.author {
        return Ok(ValidateCallbackResult::Invalid(
            "Transaction.from_agent must be the authoring agent — no spending from other accounts"
                .into(),
        ));
    }
    if tx.to_agent == tx.from_agent {
        return Ok(ValidateCallbackResult::Invalid(
            "Self-payment is meaningless in a sum-zero ledger".into(),
        ));
    }
    let Some(checkpoint) = tx.checkpoint.clone() else {
        return Ok(ValidateCallbackResult::Invalid(
            "Transaction must carry a checkpoint (latest CreditLimit or Account creation)".into(),
        ));
    };

    // The checkpoint must be on the author's own chain and must be
    // either a CreditLimit (sealed balance basis) or the Account
    // creation (default basis).
    let cp_record = must_get_valid_record(checkpoint.clone())?;
    if cp_record.action().author() != &action.author {
        return Ok(ValidateCallbackResult::Invalid(
            "Checkpoint is not on the author's chain".into(),
        ));
    }
    let cp_entry = match cp_record.entry().as_option() {
        Some(e) => e,
        None => {
            return Ok(ValidateCallbackResult::Invalid(
                "Checkpoint record carries no entry".into(),
            ))
        }
    };
    let (limit, basis_balance) = if let Ok(cl) = CreditLimit::try_from(cp_entry) {
        if cl.agent != action.author {
            return Ok(ValidateCallbackResult::Invalid(
                "Checkpoint CreditLimit is for a different agent".into(),
            ));
        }
        (cl.limit, cl.attested_balance)
    } else if let Ok(acct) = Account::try_from(cp_entry) {
        if acct.agent != action.author {
            return Ok(ValidateCallbackResult::Invalid(
                "Checkpoint Account is for a different agent".into(),
            ));
        }
        (acct.credit_limit, 0)
    } else {
        return Ok(ValidateCallbackResult::Invalid(
            "Checkpoint must be a CreditLimit or Account entry".into(),
        ));
    };

    // Walk the author's chain from just before this transaction back to
    // the checkpoint (inclusive endpoint, skipped in the scan). Sum
    // outgoing spends; reject if a newer CreditLimit than the cited
    // checkpoint appears — the checkpoint must be the LATEST basis.
    let activity = must_get_agent_activity(
        action.author.clone(),
        ChainFilter::new(action.prev_action.clone()).until_hash(checkpoint.clone()),
    )?;
    let mut spent_since: i64 = 0;
    for item in activity {
        let act = item.action.action();
        let act_hash = item.action.as_hash();
        if *act_hash == checkpoint {
            continue; // the basis itself
        }
        match decode_app_entry(act)? {
            Some((_, EntryTypes::Transaction(prior))) => {
                // Author binding above guarantees every Transaction on
                // this chain is an outgoing spend by this author.
                spent_since = spent_since.checked_add(prior.amount).ok_or_else(|| {
                    wasm_error!(WasmErrorInner::Guest("Spend sum overflow".into()))
                })?;
            }
            Some((_, EntryTypes::CreditLimit(_))) => {
                return Ok(ValidateCallbackResult::Invalid(
                    "A newer CreditLimit exists after the cited checkpoint — transactions must cite their latest basis"
                        .into(),
                ));
            }
            _ => {}
        }
    }

    // The balance law. basis_balance is the quorum-attested (or zero)
    // net position at the checkpoint; limit is negative headroom.
    let post = basis_balance
        .checked_sub(spent_since)
        .and_then(|b| b.checked_sub(tx.amount))
        .ok_or_else(|| wasm_error!(WasmErrorInner::Guest("Balance underflow".into())))?;
    if post < limit {
        return Ok(ValidateCallbackResult::Invalid(format!(
            "Transaction would exceed credit limit: basis {} − spent {} − amount {} = {} < limit {}",
            basis_balance, spent_since, tx.amount, post, limit
        )));
    }

    // Countersignature: the recipient endorsed this exact spend,
    // including its checkpoint.
    let Some(recipient_sig) = tx.recipient_sig.clone() else {
        return Ok(ValidateCallbackResult::Invalid(
            "Transaction requires the recipient's endorsement signature".into(),
        ));
    };
    let payload = TransactionPayload {
        domain: SEAL_DOMAIN_TRANSACTION.into(),
        dna_hash: dna_info()?.hash,
        from_agent: tx.from_agent.clone(),
        to_agent: tx.to_agent.clone(),
        amount: tx.amount,
        checkpoint,
    };
    if !verify_signature(tx.to_agent.clone(), recipient_sig, payload_bytes(payload)?)? {
        return Ok(ValidateCallbackResult::Invalid(
            "Recipient endorsement signature failed verification".into(),
        ));
    }
    Ok(ValidateCallbackResult::Valid)
}

// ─────────────────────────────────────────────
// CreditLimit — reputation made portable
// ─────────────────────────────────────────────

fn validate_create_credit_limit(
    action: Create,
    cl: CreditLimit,
) -> ExternResult<ValidateCallbackResult> {
    // Self-pull pattern preserved: each agent commits their own limit.
    if cl.agent != action.author {
        return Ok(ValidateCallbackResult::Invalid(
            "CreditLimit.agent must be the authoring agent (self-pull)".into(),
        ));
    }
    match &cl.seal {
        None => {
            // Legacy/bootstrap path — damage-capped to fresh-account
            // terms: no better limit than default, no attested balance,
            // no claimed reputation. Grants nothing a new Account
            // doesn't already have.
            let floor = default_credit_limit(GENESIS_CREDIT_SUPPLY);
            if cl.limit < floor || cl.attested_balance != 0 || cl.reputation_score != 0 {
                return Ok(ValidateCallbackResult::Invalid(format!(
                    "Unsealed CreditLimit exceeds fresh-account terms (limit ≥ {}, attested_balance = 0, reputation = 0) — better terms require a quorum seal",
                    floor
                )));
            }
            Ok(ValidateCallbackResult::Valid)
        }
        Some(seal) => {
            let anchor = match get_anchor_state(&seal.anchor_state_hash)? {
                Ok(s) => s,
                Err(invalid) => return Ok(invalid),
            };
            if cl.cycle != anchor.cycle {
                return Ok(ValidateCallbackResult::Invalid(
                    "Sealed CreditLimit cycle must equal the anchor state's cycle".into(),
                ));
            }
            // The limit ceiling is arithmetic law even under seal: no
            // quorum may grant more than the next Fibonacci number of
            // headroom above the anchored supply.
            let ceiling = -(next_fibonacci(anchor.credit_supply.max(0) as u64) as i64);
            if cl.limit < ceiling {
                return Ok(ValidateCallbackResult::Invalid(format!(
                    "Sealed limit {} exceeds the Fibonacci ceiling {} for anchored supply {}",
                    cl.limit, ceiling, anchor.credit_supply
                )));
            }
            let payload = CreditLimitPayload {
                domain: SEAL_DOMAIN_CREDIT_LIMIT.into(),
                dna_hash: dna_info()?.hash,
                anchor_state_hash: seal.anchor_state_hash.clone(),
                agent: cl.agent.clone(),
                limit: cl.limit,
                attested_balance: cl.attested_balance,
                reputation_score: cl.reputation_score,
                cycle: cl.cycle,
            };
            verify_seal(seal, &anchor.authorized_signers, payload_bytes(payload)?)
        }
    }
}

// ─────────────────────────────────────────────
// NetworkState — succession as law
// ─────────────────────────────────────────────

/// DNA properties. `progenitor`, when set (production), is the only
/// agent who may declare the first non-empty roster. When unset (dev
/// sandboxes), the declaration is open — set it before launch.
#[derive(Serialize, Deserialize, Debug, SerializedBytes, Default)]
pub struct DnaProps {
    #[serde(default)]
    pub progenitor: Option<AgentPubKey>,
}

fn dna_progenitor() -> ExternResult<Option<AgentPubKey>> {
    let props = dna_info()?.modifiers.properties;
    Ok(DnaProps::try_from(props).ok().and_then(|p| p.progenitor))
}

fn validate_create_network_state(
    action: Create,
    state: NetworkState,
) -> ExternResult<ValidateCallbackResult> {
    if state.next_fibonacci_threshold == 0 {
        return Ok(ValidateCallbackResult::Invalid(
            "Fibonacci threshold cannot be zero".into(),
        ));
    }
    if !is_fibonacci(state.next_fibonacci_threshold) {
        return Ok(ValidateCallbackResult::Invalid(
            "next_fibonacci_threshold must be a Fibonacci number".into(),
        ));
    }
    if state.credit_supply < GENESIS_CREDIT_SUPPLY {
        return Ok(ValidateCallbackResult::Invalid(
            "credit_supply below genesis is impossible — supply only expands".into(),
        ));
    }

    let Some(prev_hash) = state.prev_state_hash.clone() else {
        // Genesis: exactly the shape on_attestation_created writes for
        // the first attestation, nothing more. Competing genesis chains
        // are distinguished by the anchor-link layer and quorum
        // (canonicity is a coordinator concern); what THIS rule
        // guarantees is that no genesis smuggles in supply, cycles,
        // phase, or a roster.
        if state.attestation_count > 1
            || state.cycle != 0
            || state.phase != 0
            || state.credit_supply != GENESIS_CREDIT_SUPPLY
            || !state.authorized_signers.is_empty()
            || state.seal.is_some()
        {
            return Ok(ValidateCallbackResult::Invalid(
                "Genesis NetworkState must be: count ≤ 1, cycle 0, phase 0, genesis supply, no roster, no seal"
                    .into(),
            ));
        }
        return Ok(ValidateCallbackResult::Valid);
    };

    // Succession: fetch the predecessor and enforce the arithmetic.
    let prev = match get_anchor_state(&prev_hash)? {
        Ok(s) => s,
        Err(invalid) => return Ok(invalid),
    };
    // Two succession forms:
    //   count + 1  — attestation succession (economics may cross)
    //   count + 0  — roster rotation (economics frozen, only the roster
    //                may change; sovereignty rotates without minting an
    //                attestation)
    if state.attestation_count == prev.attestation_count {
        if state.credit_supply != prev.credit_supply
            || state.next_fibonacci_threshold != prev.next_fibonacci_threshold
            || state.cycle != prev.cycle
            || state.phase != prev.phase
        {
            return Ok(ValidateCallbackResult::Invalid(
                "Rotation states must carry all economics unchanged — only the roster rotates"
                    .into(),
            ));
        }
        if state.authorized_signers == prev.authorized_signers {
            return Ok(ValidateCallbackResult::Invalid(
                "Rotation state changes nothing — a no-op succession is noise".into(),
            ));
        }
        return validate_roster_succession(action, state, prev, prev_hash);
    }
    if state.attestation_count != prev.attestation_count + 1 {
        return Ok(ValidateCallbackResult::Invalid(
            "NetworkState succession must increment attestation_count by exactly 1 (or 0 for rotation)".into(),
        ));
    }
    let crossed = prev.attestation_count + 1 >= prev.next_fibonacci_threshold;
    if crossed {
        // Fibonacci expansion is law: supply × φ (floor), threshold to
        // the next Fibonacci number, cycle increments. The φ product is
        // f64 mul + floor — IEEE-exact basic ops, identical in every
        // wasm module; no transcendental involved.
        let expected_supply = (prev.credit_supply as f64 * toric_geometry::PHI).floor() as i64;
        let expected_threshold = next_fibonacci(state.attestation_count);
        if state.credit_supply != expected_supply
            || state.next_fibonacci_threshold != expected_threshold
            || state.cycle != prev.cycle + 1
        {
            return Ok(ValidateCallbackResult::Invalid(format!(
                "Fibonacci crossing arithmetic violated: expected supply {}, threshold {}, cycle {}",
                expected_supply,
                expected_threshold,
                prev.cycle + 1
            )));
        }
        if state.phase < 1 || state.phase < prev.phase {
            return Ok(ValidateCallbackResult::Invalid(
                "Phase must be ≥ 1 after a crossing and never regress".into(),
            ));
        }
    } else {
        if state.credit_supply != prev.credit_supply
            || state.next_fibonacci_threshold != prev.next_fibonacci_threshold
            || state.cycle != prev.cycle
            || state.phase != prev.phase
        {
            return Ok(ValidateCallbackResult::Invalid(
                "Non-crossing NetworkState must carry supply, threshold, cycle, and phase unchanged"
                    .into(),
            ));
        }
    }

    validate_roster_succession(action, state, prev, prev_hash)
}

/// The sovereignty chain: empty-roster predecessors permit bootstrap
/// succession or the (progenitor-gated) first declaration; rostered
/// predecessors demand a seal by the PREVIOUS roster over the successor.
fn validate_roster_succession(
    action: Create,
    state: NetworkState,
    prev: NetworkState,
    prev_hash: ActionHash,
) -> ExternResult<ValidateCallbackResult> {
    if prev.authorized_signers.is_empty() {
        match (&state.seal, state.authorized_signers.is_empty()) {
            (None, true) => Ok(ValidateCallbackResult::Valid), // bootstrap continues
            (None, false) => {
                // First roster declaration — the single centralization
                // point, gated to the progenitor when one is configured.
                if let Some(progenitor) = dna_progenitor()? {
                    if action.author != progenitor {
                        return Ok(ValidateCallbackResult::Invalid(
                            "Only the progenitor may declare the first signer roster".into(),
                        ));
                    }
                }
                Ok(ValidateCallbackResult::Valid)
            }
            (Some(_), _) => Ok(ValidateCallbackResult::Invalid(
                "A seal against an empty roster is meaningless — declare the roster first".into(),
            )),
        }
    } else {
        // Governed: every successor is sealed by the PREVIOUS roster.
        let Some(seal) = &state.seal else {
            return Ok(ValidateCallbackResult::Invalid(
                "Governed NetworkState (predecessor has a roster) requires a quorum seal".into(),
            ));
        };
        if seal.anchor_state_hash != prev_hash {
            return Ok(ValidateCallbackResult::Invalid(
                "NetworkState seal must anchor to its own predecessor".into(),
            ));
        }
        let payload = NetworkStatePayload {
            domain: SEAL_DOMAIN_NETWORK_STATE.into(),
            dna_hash: dna_info()?.hash,
            anchor_state_hash: prev_hash.clone(),
            prev_state_hash: prev_hash,
            attestation_count: state.attestation_count,
            next_fibonacci_threshold: state.next_fibonacci_threshold,
            credit_supply: state.credit_supply,
            cycle: state.cycle,
            phase: state.phase,
            authorized_signers: state.authorized_signers.clone(),
        };
        verify_seal(seal, &prev.authorized_signers, payload_bytes(payload)?)
    }
}

// ─────────────────────────────────────────────
// PaymentReceipt — the membrane oracle
// ─────────────────────────────────────────────

fn validate_create_payment_receipt(
    _action: Create,
    receipt: PaymentReceipt,
) -> ExternResult<ValidateCallbackResult> {
    if receipt.amount_external <= 0 {
        return Ok(ValidateCallbackResult::Invalid(
            "PaymentReceipt amount must be positive".into(),
        ));
    }
    if receipt.rail.is_empty() {
        return Ok(ValidateCallbackResult::Invalid(
            "PaymentReceipt must name its settlement rail".into(),
        ));
    }
    if receipt.distribution.is_empty() {
        return Ok(ValidateCallbackResult::Invalid(
            "PaymentReceipt distribution cannot be empty".into(),
        ));
    }
    let mut sum: u128 = 0;
    let mut seen: Vec<&AgentPubKey> = Vec::with_capacity(receipt.distribution.len());
    for share in &receipt.distribution {
        if share.weight == 0 {
            return Ok(ValidateCallbackResult::Invalid(
                "Zero-weight distribution shares are noise — omit them".into(),
            ));
        }
        if seen.contains(&&share.agent) {
            return Ok(ValidateCallbackResult::Invalid(
                "Duplicate agent in distribution".into(),
            ));
        }
        seen.push(&share.agent);
        sum += share.weight as u128;
    }
    if sum > u64::MAX as u128 {
        return Ok(ValidateCallbackResult::Invalid(
            "Distribution weight sum overflows u64".into(),
        ));
    }

    let anchor = match get_anchor_state(&receipt.seal.anchor_state_hash)? {
        Ok(s) => s,
        Err(invalid) => return Ok(invalid),
    };
    // No money before sovereignty: receipts require an active roster —
    // verify_seal rejects empty rosters, which enforces exactly this.
    let payload = PaymentReceiptPayload {
        domain: SEAL_DOMAIN_PAYMENT_RECEIPT.into(),
        dna_hash: dna_info()?.hash,
        anchor_state_hash: receipt.seal.anchor_state_hash.clone(),
        artifact_manifest_hash: receipt.artifact_manifest_hash.clone(),
        rail: receipt.rail.clone(),
        external_proof: receipt.external_proof.clone(),
        amount_external: receipt.amount_external,
        distribution: receipt.distribution.clone(),
    };
    verify_seal(&receipt.seal, &anchor.authorized_signers, payload_bytes(payload)?)
}

// ─────────────────────────────────────────────
// Link validation — links carry balance-visible structure, so they
// are bound to entry authorship.
// ─────────────────────────────────────────────

fn link_target_action(target: &AnyLinkableHash) -> Option<ActionHash> {
    target.clone().into_action_hash()
}

fn validate_tx_link(
    action: CreateLink,
    base: AnyLinkableHash,
    target: AnyLinkableHash,
) -> ExternResult<ValidateCallbackResult> {
    let Some(target_hash) = link_target_action(&target) else {
        return Ok(ValidateCallbackResult::Invalid(
            "AgentToTransactions target must be an action hash".into(),
        ));
    };
    let record = must_get_valid_record(target_hash)?;
    // Only the transaction's author links it — prevents third parties
    // from decorating anyone's index.
    if record.action().author() != &action.author {
        return Ok(ValidateCallbackResult::Invalid(
            "Only the transaction author may create its index links".into(),
        ));
    }
    let entry = match record.entry().as_option() {
        Some(e) => e,
        None => {
            return Ok(ValidateCallbackResult::Invalid(
                "AgentToTransactions target carries no entry".into(),
            ))
        }
    };
    let Ok(tx) = Transaction::try_from(entry) else {
        return Ok(ValidateCallbackResult::Invalid(
            "AgentToTransactions target is not a Transaction".into(),
        ));
    };
    let base_agent: Option<AgentPubKey> = base.into_agent_pub_key();
    match base_agent {
        Some(agent) if agent == tx.from_agent || agent == tx.to_agent => {
            Ok(ValidateCallbackResult::Valid)
        }
        _ => Ok(ValidateCallbackResult::Invalid(
            "AgentToTransactions base must be the transaction's sender or recipient".into(),
        )),
    }
}

/// Shared rule for AgentToAccount / AgentToCreditLimit: the link author
/// authored the target, and the base is that same agent.
fn validate_self_index_link(
    action: CreateLink,
    base: AnyLinkableHash,
    target: AnyLinkableHash,
    kind: &str,
) -> ExternResult<ValidateCallbackResult> {
    let Some(target_hash) = link_target_action(&target) else {
        return Ok(ValidateCallbackResult::Invalid(format!(
            "{} target must be an action hash",
            kind
        )));
    };
    let record = must_get_valid_record(target_hash)?;
    if record.action().author() != &action.author {
        return Ok(ValidateCallbackResult::Invalid(format!(
            "Only the entry author may create {} links",
            kind
        )));
    }
    match base.into_agent_pub_key() {
        Some(agent) if agent == action.author => Ok(ValidateCallbackResult::Valid),
        _ => Ok(ValidateCallbackResult::Invalid(format!(
            "{} base must be the authoring agent",
            kind
        ))),
    }
}

fn validate_state_anchor_link(
    action: CreateLink,
    target: AnyLinkableHash,
) -> ExternResult<ValidateCallbackResult> {
    let Some(target_hash) = link_target_action(&target) else {
        return Ok(ValidateCallbackResult::Invalid(
            "NetworkStateAnchor target must be an action hash".into(),
        ));
    };
    let record = must_get_valid_record(target_hash)?;
    if record.action().author() != &action.author {
        return Ok(ValidateCallbackResult::Invalid(
            "Only the NetworkState author may anchor it".into(),
        ));
    }
    Ok(ValidateCallbackResult::Valid)
}

// ─────────────────────────────────────────────
// validate() — dispatch
// ─────────────────────────────────────────────

fn validate_entry_create(action: Create, app_entry: EntryTypes) -> ExternResult<ValidateCallbackResult> {
    match app_entry {
        EntryTypes::Account(a) => validate_create_account(action, a),
        EntryTypes::Transaction(t) => validate_create_transaction(action, t),
        EntryTypes::CreditLimit(c) => validate_create_credit_limit(action, c),
        EntryTypes::NetworkState(s) => validate_create_network_state(action, s),
        EntryTypes::PaymentReceipt(r) => validate_create_payment_receipt(action, r),
    }
}

fn validate_link_create(
    link_type: LinkTypes,
    action: CreateLink,
    base: AnyLinkableHash,
    target: AnyLinkableHash,
) -> ExternResult<ValidateCallbackResult> {
    match link_type {
        LinkTypes::AgentToAccount => validate_self_index_link(action, base, target, "AgentToAccount"),
        LinkTypes::AgentToTransactions => validate_tx_link(action, base, target),
        LinkTypes::AgentToCreditLimit => {
            validate_self_index_link(action, base, target, "AgentToCreditLimit")
        }
        LinkTypes::NetworkStateAnchor => validate_state_anchor_link(action, target),
        LinkTypes::PaymentReceiptAnchor => validate_state_anchor_link(action, target),
        LinkTypes::AccountsAnchor => validate_state_anchor_link(action, target),
    }
}

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    match op.flattened::<EntryTypes, LinkTypes>()? {
        FlatOp::StoreEntry(OpEntry::CreateEntry { app_entry, action }) => {
            validate_entry_create(action, app_entry)
        }
        FlatOp::StoreEntry(OpEntry::UpdateEntry { .. }) => Ok(ValidateCallbackResult::Invalid(
            "Mutual credit entries are immutable".to_string(),
        )),
        FlatOp::RegisterUpdate(_) => Ok(ValidateCallbackResult::Invalid(
            "Mutual credit entries are immutable".to_string(),
        )),
        FlatOp::RegisterDelete(_) => Ok(ValidateCallbackResult::Invalid(
            "Mutual credit entries are immutable".to_string(),
        )),
        FlatOp::RegisterCreateLink {
            link_type,
            base_address,
            target_address,
            action,
            ..
        } => validate_link_create(link_type, action, base_address, target_address),
        FlatOp::RegisterDeleteLink { .. } => Ok(ValidateCallbackResult::Invalid(
            "Mutual credit links are permanent".to_string(),
        )),
        FlatOp::StoreRecord(OpRecord::CreateEntry { app_entry, action }) => {
            validate_entry_create(action, app_entry)
        }
        FlatOp::StoreRecord(OpRecord::UpdateEntry { .. }) => Ok(ValidateCallbackResult::Invalid(
            "Mutual credit entries are immutable".to_string(),
        )),
        FlatOp::StoreRecord(OpRecord::DeleteEntry { .. }) => Ok(ValidateCallbackResult::Invalid(
            "Mutual credit entries are immutable".to_string(),
        )),
        FlatOp::StoreRecord(OpRecord::CreateLink {
            base_address,
            target_address,
            link_type,
            action,
            ..
        }) => validate_link_create(link_type, action, base_address, target_address),
        FlatOp::StoreRecord(OpRecord::DeleteLink { .. }) => Ok(ValidateCallbackResult::Invalid(
            "Mutual credit links are permanent".to_string(),
        )),
        FlatOp::RegisterAgentActivity(OpActivity::CreateAgent { agent, action }) => {
            let previous_action = must_get_action(action.prev_action)?;
            match previous_action.action() {
                Action::AgentValidationPkg(AgentValidationPkg { membrane_proof, .. }) => {
                    validate_agent_joining(agent, membrane_proof)
                }
                _ => Ok(ValidateCallbackResult::Invalid(
                    "The previous action for a `CreateAgent` action must be an `AgentValidationPkg`"
                        .to_string(),
                )),
            }
        }
        _ => Ok(ValidateCallbackResult::Valid),
    }
}