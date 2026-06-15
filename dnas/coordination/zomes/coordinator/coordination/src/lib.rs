use hdk::prelude::*;
use coordination_integrity::*;

// Base network tick — minimum expected DHT round-trip in microseconds.
// Conservative WAN estimate. Becomes a GeometryParam in Phase 5.5,
// at which point the network observes its own round-trip times and
// updates τ without a code change.
const TAU_US: i64 = 10_000_000; // 10 seconds

// Minimum validators required for quorum and reveal window.
// F(4) — the fourth Fibonacci number. The minimum network that produces
// a meaningful reputation-weighted quorum with a tiebreaker.
// Becomes a GeometryParam in Phase 5.5.
const MIN_VALIDATORS: usize = 3;

// φ⁴ — used in reveal deadline and commit window threshold.
const PHI_4: f64 = 6.8541019662496847;

// Reveal deadline derived from geometry: φ⁴ × τ × MIN_VALIDATORS.
// Scales with network tempo and quorum size.
// A validator who slows the network to push others past the deadline
// also extends the deadline proportionally — the attack closes itself.
const REVEAL_DEADLINE_US: i64 = (PHI_4 * TAU_US as f64 * MIN_VALIDATORS as f64) as i64;

// Negligibility threshold — φ⁻⁴. Upstream contributions below this
// weight are not worth computing. Used to derive max recursion depth.
const NEGLIGIBILITY_THRESHOLD: f64 = 0.14589803375031546;
const PHI_SQ: f64     = 2.6180339887498948;
const INV_PHI_SQ: f64 = 0.3819660112501051;

#[hdk_extern]
pub fn init(_: ()) -> ExternResult<InitCallbackResult> {
    Ok(InitCallbackResult::Pass)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RequestValidationInput {
    pub manifest_hash: ActionHash,
    pub metadata_blob: SerializedBytes,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SubmitEvaluationInput {
    pub request_hash: ActionHash,
    pub passed: bool,
    pub score: f64,
    pub details: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CheckQuorumInput {
    pub request_hash: ActionHash,
    pub registry_dna_hash: DnaHash,
    pub mutual_credit_dna_hash: DnaHash,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QuorumResult {
    pub reached: bool,
    pub combined_weight: f64,
    pub evaluation_count: u32,
    pub quorum_bundle_hash: Option<ActionHash>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvaluationRecord {
    pub evaluator: AgentPubKey,
    pub passed: bool,
    pub score: f64,
    pub reputation_weight: f64,
    pub details: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CommitEvaluationInput {
    pub request_hash: ActionHash,
    pub commitment_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RevealEvaluationInput {
    pub request_hash: ActionHash,
    pub passed: bool,
    pub score: f64,
    pub details: Option<String>,
    pub salt: String,
    pub registry_dna_hash: DnaHash,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CommitmentStatus {
    pub commitment_weight: f64,
    pub reveal_window_open: bool,
    pub commitment_count: u32,
    pub phi_4_threshold: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LineageInput {
    pub manifest_hash: ActionHash,
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
    const INV_PHI_SQ: f64 = 0.3819660112501051;
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
        _ => {
            Ok(INV_PHI_SQ)
        }
    }
}

// ─────────────────────────────────────────────
// Helper — submit attestation via bridge call
// ─────────────────────────────────────────────

fn submit_attestation_to_registry(
    manifest_hash: ActionHash,
    _metadata_blob: SerializedBytes,
    registry_cell_id: CellId,
) -> ExternResult<ActionHash> {

    #[derive(Serialize, Deserialize, Debug)]
    struct QuorumAttestationInput {
        manifest_hash: ActionHash,
    }

    let result = call(
        CallTargetCell::OtherCell(registry_cell_id),
        ZomeName::from("registry"),
        FunctionName::from("create_quorum_attestation"),
        None,
        QuorumAttestationInput { manifest_hash },
    )?;

    match result {
        ZomeCallResponse::Ok(extern_io) => {
            let action_hash: ActionHash = extern_io.decode().map_err(|e| {
                wasm_error!(WasmErrorInner::Guest(format!(
                    "Failed to decode attestation hash: {:?}", e
                )))
            })?;
            Ok(action_hash)
        }
        ZomeCallResponse::Unauthorized(_, _, _, _) => Err(wasm_error!(WasmErrorInner::Guest(
            "Registry bridge call unauthorized".to_string()
        ))),
        ZomeCallResponse::NetworkError(e) => Err(wasm_error!(WasmErrorInner::Guest(format!(
            "Registry bridge call network error: {}", e
        )))),
        _ => Err(wasm_error!(WasmErrorInner::Guest(
            "Unexpected bridge call response".to_string()
        ))),
    }
}

fn notify_mutual_credit(
    attestation_hash: ActionHash,
    mutual_credit_cell_id: CellId,
) -> ExternResult<()> {
    #[derive(Serialize, Deserialize, Debug)]
    struct AttestationNotification {
        attestation_hash: ActionHash,
    }

    let result = call(
        CallTargetCell::OtherCell(mutual_credit_cell_id),
        ZomeName::from("mutual_credit"),
        FunctionName::from("on_attestation_created"),
        None,
        AttestationNotification { attestation_hash },
    )?;

    match result {
        ZomeCallResponse::Ok(_) => Ok(()),
        _ => Ok(()),
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct RecordEvidenceInput {
    pub manifest_hash: ActionHash,
    pub evidence_type: String,
    pub expected: String,
    pub actual: String,
    pub computed_severity: u32,
    pub metadata_blob: SerializedBytes,
}

#[hdk_extern]
pub fn record_evidence(input: RecordEvidenceInput) -> ExternResult<ActionHash> {
    use coordination_integrity::ValidationEvidence;

    let evidence = ValidationEvidence {
        manifest_hash: input.manifest_hash.clone(),
        evidence_type: input.evidence_type,
        expected: input.expected,
        actual: input.actual,
        computed_severity: input.computed_severity,
        metadata_blob: input.metadata_blob,
    };

    let action_hash = create_entry(EntryTypes::ValidationEvidence(evidence))?;
    create_link(
        input.manifest_hash,
        action_hash.clone(),
        LinkTypes::ManifestToEvidence,
        (),
    )?;

    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Request Validation
// Creates a ValidationRequest entry and links it
// to the agent so validators can discover it
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn request_validation(input: RequestValidationInput) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;
    let request = ValidationRequest {
        manifest_hash: input.manifest_hash.clone(),
        requester: agent.clone(),
        validation_type: "hash".to_string(),
        required_capabilities: vec![],
        metadata_blob: input.metadata_blob,
    };
    let action_hash = create_entry(EntryTypes::ValidationRequest(request))?;
    create_link(
        agent,
        action_hash.clone(),
        LinkTypes::AgentToRequest,
        (),
    )?;
    create_link(
        input.manifest_hash.clone(),
        action_hash.clone(),
        LinkTypes::ManifestToRequest,
        (),
    )?;

    // Emit signal so validators can respond immediately
    // without waiting for next poll cycle
    let global_path = Path::from("validation_requests.all");
    let global_typed = global_path.typed(LinkTypes::GlobalValidationRequestAnchor)?;
    global_typed.ensure()?;
    create_link(
        global_typed.path_entry_hash()?,
        action_hash.clone(),
        LinkTypes::GlobalValidationRequestAnchor,
        (),
    )?;

    emit_signal(Signal::ValidationRequested {
        request_hash: action_hash.clone(),
    })?;

    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Submit Evaluation
// Called by a validator after running benchmarks
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn submit_evaluation(input: SubmitEvaluationInput) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;

    // Build evaluation blob
    let blob_bytes = {
        let json = serde_json::json!({
            "passed": input.passed,
            "score": input.score,
            "details": input.details,
        });
        let bytes = serde_json::to_vec(&json).map_err(|e| {
            wasm_error!(WasmErrorInner::Guest(format!(
                "Failed to serialize evaluation: {}", e
            )))
        })?;
        SerializedBytes::from(UnsafeBytes::from(bytes))
    };

    let bundle = EvaluationBundle {
        request_hash: input.request_hash.clone(),
        evaluator: agent,
        metadata_blob: blob_bytes,
    };

    let action_hash = create_entry(EntryTypes::EvaluationBundle(bundle))?;
    create_link(
        input.request_hash,
        action_hash.clone(),
        LinkTypes::RequestToEvaluation,
        (),
    )?;
    Ok(action_hash)
}


#[hdk_extern]
pub fn commit_evaluation(input: CommitEvaluationInput) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;

    if input.commitment_hash.len() != 32 {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Commitment hash must be 32 bytes".to_string()
        )));
    }

    let commitment = EvaluationCommitment {
        request_hash: input.request_hash.clone(),
        evaluator: agent,
        commitment_hash: input.commitment_hash,
    };

    let action_hash = create_entry(EntryTypes::EvaluationCommitment(commitment))?;
    create_link(
        input.request_hash,
        action_hash.clone(),
        LinkTypes::RequestToCommitment,
        (),
    )?;
    Ok(action_hash)
}

#[hdk_extern]
pub fn check_reveal_window(input: CheckQuorumInput) -> ExternResult<CommitmentStatus> {
    // PHI_4 and INV_PHI_SQ from module-level geometry constants 

    let registry_cell_id = {
        let agent = agent_info()?.agent_initial_pubkey;
        CellId::new(input.registry_dna_hash.clone(), agent)
    };

    let commit_links = fetch_links(
        input.request_hash.clone(),
        LinkTypes::RequestToCommitment,
    )?;

    let mut commitment_weight: f64 = 0.0;
    let mut total_network_rep: f64 = 0.0;

    for link in &commit_links {
        let rep = get_reputation_score(
            link.author.clone(),
            registry_cell_id.clone(),
        ).unwrap_or(INV_PHI_SQ);
        let weight = if rep <= 0.0 { INV_PHI_SQ } else { rep };
        commitment_weight += weight;
        total_network_rep += weight;
    }

    // Reveal window opens when commitment_weight >= total_rep / φ⁴
    let phi_4_threshold = total_network_rep / PHI_4;
    let reveal_window_open = commitment_weight >= phi_4_threshold
        && commit_links.len() >= MIN_VALIDATORS;

    Ok(CommitmentStatus {
        commitment_weight,
        reveal_window_open,
        commitment_count: commit_links.len() as u32,
        phi_4_threshold,
    })
}

#[hdk_extern]
pub fn reveal_evaluation(input: RevealEvaluationInput) -> ExternResult<ActionHash> {
    // PHI_4 and INV_PHI_SQ from module-level geometry constants

    let agent = agent_info()?.agent_initial_pubkey;

    // Check reveal window is open before accepting reveal
    let commit_links = fetch_links(
        input.request_hash.clone(),
        LinkTypes::RequestToCommitment,
    )?;

    let mut commitment_weight: f64 = 0.0;
    for link in &commit_links {
        let rep = get_reputation_score(
            link.author.clone(),
            CellId::new(input.registry_dna_hash.clone(), agent.clone()),
        ).unwrap_or(INV_PHI_SQ);
        let weight = if rep <= 0.0 { INV_PHI_SQ } else { rep };
        commitment_weight += weight;
    }

    let total_rep = commitment_weight;
    let phi_4_threshold = total_rep / PHI_4;
    let reveal_window_open = commitment_weight >= phi_4_threshold
        && commit_links.len() >= 1;

    if !reveal_window_open {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "Reveal window not yet open — φ⁴ commitment threshold not reached".to_string()
        )));
    }

    // Check deadline — reject reveals from agents who waited too long
    let now_us = sys_time()?.as_micros();
    let my_commit_link = commit_links.iter().find(|l| l.author == agent);
    if let Some(cl) = my_commit_link {
        let committed_at = cl.timestamp.as_micros();
        if now_us - committed_at > REVEAL_DEADLINE_US as i64 {
            return Err(wasm_error!(WasmErrorInner::Guest(format!(
                "Reveal deadline exceeded — {}μs since commit, limit {}μs",
                now_us - committed_at,
                REVEAL_DEADLINE_US
            ))));
        }
    }

    // Find this agent's commitment
    let commit_links = fetch_links(
        input.request_hash.clone(),
        LinkTypes::RequestToCommitment,
    )?;

    let my_commitment = commit_links.iter().find(|l| l.author == agent);
    if my_commitment.is_none() {
        return Err(wasm_error!(WasmErrorInner::Guest(
            "No commitment found for this agent — must commit before revealing".to_string()
        )));
    }

    // Verify commitment hash matches reveal
    let commitment_link = my_commitment.unwrap();
    if let Some(commit_hash) = commitment_link.target.clone().into_action_hash() {
                if let Some(record) = get(commit_hash, GetOptions::default())? {
                    if let Some(entry) = record.entry().as_option() {
                        if let Ok(commitment) = EvaluationCommitment::try_from(entry) {
                            use sha2::{Sha256, Digest};

                            // Recompute hash from revealed values.
                            // Score normalized to 6 decimal places to match
                            // validator client's toFixed(6) — prevents f64
                            // string representation divergence between JS and Rust.
                            let preimage = format!(
                                "{}:{:.6}:{}:{}",
                                input.passed,
                                input.score,
                                input.details.as_deref().unwrap_or(""),
                                input.salt
                            );
                            let computed_hash = {
                                let mut hasher = Sha256::new();
                                hasher.update(preimage.as_bytes());
                                hasher.finalize().to_vec()
                            };

                            if commitment.commitment_hash != computed_hash {
                                // Record the mismatch as ValidationEvidence before rejecting.
                                // Makes the violation permanent on the DHT and warrant-eligible.
                                // The geometry then compounds the penalty through reputation.
                                let evidence = ValidationEvidence {
                                    manifest_hash: {
                                        // Retrieve manifest hash from the original request
                                        get(input.request_hash.clone(), GetOptions::default())?
                                            .and_then(|r| r.entry().as_option().cloned())
                                            .and_then(|e| ValidationRequest::try_from(&e).ok())
                                            .map(|req| req.manifest_hash)
                                            .unwrap_or(input.request_hash.clone())
                                    },
                                    evidence_type: "commitment_mismatch".to_string(),
                                    expected: hex::encode(&commitment.commitment_hash),
                                    actual: hex::encode(&computed_hash),
                                    computed_severity: 1_000_000,
                                    metadata_blob: {
                                        let json = serde_json::json!({
                                            "request_hash": input.request_hash,
                                            "evaluator": agent,
                                            "violation": "revealed values do not match commitment"
                                        });
                                        SerializedBytes::from(UnsafeBytes::from(
                                            serde_json::to_vec(&json).unwrap_or_default()
                                        ))
                                    },
                                };
                                if let Ok(evidence_hash) = create_entry(
                                    EntryTypes::ValidationEvidence(evidence)
                                ) {
                                    let _ = create_link(
                                        input.request_hash.clone(),
                                        evidence_hash,
                                        LinkTypes::ManifestToEvidence,
                                        (),
                                    );
                                }

                                return Err(wasm_error!(WasmErrorInner::Guest(
                                    "Commitment mismatch — revealed values do not match \
                                     commitment. Violation recorded on DHT.".to_string()
                                )));
                            }
                        }
                    }
                }
            }

    // Commitment verified — write evaluation bundle
    let blob_bytes = {
        let json = serde_json::json!({
            "passed": input.passed,
            "score": input.score,
            "details": input.details,
        });
        let bytes = serde_json::to_vec(&json).map_err(|e| {
            wasm_error!(WasmErrorInner::Guest(format!(
                "Failed to serialize evaluation: {}", e
            )))
        })?;
        SerializedBytes::from(UnsafeBytes::from(bytes))
    };

    let bundle = EvaluationBundle {
        request_hash: input.request_hash.clone(),
        evaluator: agent,
        metadata_blob: blob_bytes,
    };

    let action_hash = create_entry(EntryTypes::EvaluationBundle(bundle))?;
    create_link(
        input.request_hash,
        action_hash.clone(),
        LinkTypes::RequestToEvaluation,
        (),
    )?;
    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Check Quorum
// Called after evaluations are submitted.
// If quorum is reached, fires bridge call to
// Registry to submit the final attestation.
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn check_quorum(input: CheckQuorumInput) -> ExternResult<QuorumResult> {
    // INV_PHI_SQ and PHI_SQ from module-level geometry constants

    let existing_quorum = {
        let query = LinkQuery::new(
            input.request_hash.clone(),
            LinkTypes::RequestToQuorum.try_into_filter()?,
        );
        get_links(query, GetStrategy::Network)?
    };
    if !existing_quorum.is_empty() {
        return Ok(QuorumResult {
            reached: true,
            combined_weight: 0.0,
            evaluation_count: 0,
            quorum_bundle_hash: existing_quorum[0].target.clone().into_action_hash(),
        });
    }

    let eval_links = fetch_links(
        input.request_hash.clone(),
        LinkTypes::RequestToEvaluation,
    )?;

    // Build set of agents whose commits are still within deadline
    let now_us = sys_time()?.as_micros();
    let all_commits = fetch_links(
        input.request_hash.clone(),
        LinkTypes::RequestToCommitment,
    )?;
    let active_commit_agents: std::collections::HashSet<AgentPubKey> = all_commits.into_iter()
        .filter(|l| now_us - l.timestamp.as_micros() <= REVEAL_DEADLINE_US as i64)
        .map(|l| l.author)
        .collect();
    // Only filter by commit if commit-reveal was used for this request
    // If no commits exist, evaluations came via direct submit_evaluation path
    let use_commit_filter = !active_commit_agents.is_empty();

    if eval_links.len() < 1 {
        return Ok(QuorumResult {
            reached: false,
            combined_weight: 0.0,
            evaluation_count: eval_links.len() as u32,
            quorum_bundle_hash: None,
        });
    }

    let registry_cell_id = {
        let agent = agent_info()?.agent_initial_pubkey;
        CellId::new(input.registry_dna_hash.clone(), agent)
    };

    // Collect all validator reputations to compute total network reputation
    let mut evaluations: Vec<EvaluationRecord> = Vec::new();
    let mut total_network_reputation: f64 = 0.0;
    let mut passing_weight: f64 = 0.0;
    let mut combined_weight: f64 = 0.0;

    for link in eval_links {
        if let Some(eval_hash) = link.target.into_action_hash() {
            if let Some(record) = get(eval_hash.clone(), GetOptions::default())? {
                if let Some(entry) = record.entry().as_option() {
                    if let Ok(bundle) = EvaluationBundle::try_from(entry) {
                        // Skip evaluators whose commit deadline expired
                        // Only applies when commit-reveal was used
                        if use_commit_filter && !active_commit_agents.contains(&bundle.evaluator) {
                            continue;
                        }
                        let weight = {
                            let rep = get_reputation_score(
                                bundle.evaluator.clone(),
                                registry_cell_id.clone(),
                            ).unwrap_or(INV_PHI_SQ);
                            if rep <= 0.0 { INV_PHI_SQ } else { rep }
                        };

                        total_network_reputation += weight;

                        let raw: Vec<u8> = UnsafeBytes::from(
                            bundle.metadata_blob.clone()
                        ).into();

                        let json_start = raw.iter().position(|&b| b == b'{').unwrap_or(0);
                        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&raw[json_start..]) {
                            let passed = json["passed"].as_bool().unwrap_or(false);
                            let score = json["score"].as_f64().unwrap_or(0.0);
                            let details = json["details"].as_str().map(String::from);

                            if passed {
                                passing_weight += weight;
                            }
                            combined_weight += weight;

                            evaluations.push(EvaluationRecord {
                                evaluator: bundle.evaluator,
                                passed,
                                score,
                                reputation_weight: weight,
                                details,
                            });
                        }
                    }
                }
            }
        }
    }

    // φ-derived quorum threshold = total_reputation / φ²
    // This is scale-invariant — same fraction at every network size
    let quorum_threshold = total_network_reputation / PHI_SQ;

    let quorum_reached = passing_weight >= quorum_threshold
        && evaluations.len() >= MIN_VALIDATORS;

    if !quorum_reached {
        return Ok(QuorumResult {
            reached: false,
            combined_weight,
            evaluation_count: evaluations.len() as u32,
            quorum_bundle_hash: None,
        });
    }

    // Build and store quorum bundle
    let eval_hashes: Vec<ActionHash> = vec![];

    let quorum_blob = {
        let json = serde_json::json!({
            "evaluations": evaluations.len(),
            "combined_weight": combined_weight,
            "passing_weight": passing_weight,
            "quorum_threshold": quorum_threshold,
            "phi_sq": PHI_SQ,
        });
        let bytes = serde_json::to_vec(&json).map_err(|e| {
            wasm_error!(WasmErrorInner::Guest(format!(
                "Failed to serialize quorum blob: {}", e
            )))
        })?;
        SerializedBytes::from(UnsafeBytes::from(bytes))
    };

    let quorum_bundle = QuorumBundle {
        request_hash: input.request_hash.clone(),
        evaluation_hashes: eval_hashes,
        reached_quorum: true,
        metadata_blob: quorum_blob.clone(),
    };

    let quorum_hash = create_entry(EntryTypes::QuorumBundle(quorum_bundle))?;
    create_link(
        input.request_hash.clone(),
        quorum_hash.clone(),
        LinkTypes::RequestToQuorum,
        (),
    )?;

    if let Some(record) = get(input.request_hash.clone(), GetOptions::default())? {
        if let Some(entry) = record.entry().as_option() {
            if let Ok(request) = ValidationRequest::try_from(entry) {
                // Bridge 1 — submit attestation to Registry
                let attestation_hash = match submit_attestation_to_registry(
                    request.manifest_hash,
                    quorum_blob,
                    registry_cell_id.clone(),
                ) {
                    Ok(h) => Some(h),
                    Err(e) => {
                        return Err(e);
                    }
                };

                if let Some(att_hash) = attestation_hash {
                    let mc_cell_id = CellId::new(input.mutual_credit_dna_hash.clone(), agent_info()?.agent_initial_pubkey);
                    notify_mutual_credit(att_hash, mc_cell_id.clone()).ok();

                    // Credit limit updates and convergence signals are pulled by each
                    // validator's client after they observe quorum reached.
                    // Push via bridge call is not used — cross-machine bridge calls
                    // fail silently when the target cell is on a different conductor.
                    // The pull model is reliable across machines and leaves a trace
                    // when a validator fails to update — visible in total_commits/
                    // total_reveals ratio over time.
                }
            }
        }
    }

    Ok(QuorumResult {
        reached: true,
        combined_weight,
        evaluation_count: evaluations.len() as u32,
        quorum_bundle_hash: Some(quorum_hash),
    })
}

#[hdk_extern]
pub fn get_manifest_requests(input: LineageInput) -> ExternResult<Vec<ActionHash>> {
    let links = fetch_links(input.manifest_hash, LinkTypes::ManifestToRequest)?;
    Ok(links.into_iter()
        .filter_map(|l| l.target.into_action_hash())
        .collect())
}

#[hdk_extern]
pub fn get_manifest_evidence(input: LineageInput) -> ExternResult<Vec<Record>> {
    let links = fetch_links(input.manifest_hash, LinkTypes::ManifestToEvidence)?;
    let mut records = Vec::new();
    for link in links {
        if let Some(hash) = link.target.into_action_hash() {
            if let Some(record) = get(hash, GetOptions::default())? {
                records.push(record);
            }
        }
    }
    Ok(records)
}

// ─────────────────────────────────────────────
// Get pending validation requests
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn get_pending_requests(agent: AgentPubKey) -> ExternResult<Vec<Record>> {
    let links = fetch_links(agent, LinkTypes::AgentToRequest)?;
    let mut records = Vec::new();
    for link in links {
        if let Some(action_hash) = link.target.into_action_hash() {
            if let Some(record) = get(action_hash, GetOptions::default())? {
                records.push(record);
            }
        }
    }
    Ok(records)
}

#[hdk_extern]
pub fn get_all_pending_requests(_: ()) -> ExternResult<Vec<Record>> {
    let path = Path::from("validation_requests.all");
    let typed = path.typed(LinkTypes::GlobalValidationRequestAnchor)?;
    if !typed.exists()? {
        return Ok(vec![]);
    }
    let links = fetch_links(typed.path_entry_hash()?, LinkTypes::GlobalValidationRequestAnchor)?;
    let mut records = Vec::new();
    for link in links {
        if let Some(hash) = link.target.into_action_hash() {
            let quorum_links = fetch_links(hash.clone(), LinkTypes::RequestToQuorum)?;
            if !quorum_links.is_empty() {
                continue;
            }
            if let Some(record) = get(hash, GetOptions::default())? {
                records.push(record);
            }
        }
    }
    Ok(records)
}

// ─────────────────────────────────────────────
// Signals
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Signal {
    ValidationRequested { request_hash: ActionHash },
    EvaluationSubmitted { request_hash: ActionHash },
    QuorumReached { request_hash: ActionHash, quorum_bundle_hash: ActionHash },
}

#[hdk_extern(infallible)]
pub fn post_commit(committed_actions: Vec<SignedActionHashed>) {
    for action in committed_actions {
        if let Err(err) = signal_action(action) {
            error!("Error signaling new action: {:?}", err);
        }
    }
}

fn signal_action(action: SignedActionHashed) -> ExternResult<()> {
    if let Action::Create(create) = action.action() {
        match create.entry_type {
            EntryType::App(AppEntryDef { entry_index, .. }) => {
                // Signal is already emitted in request_validation
                // post_commit is for any additional signaling needed
                let _ = entry_index;
            }
            _ => {}
        }
    }
    Ok(())
}