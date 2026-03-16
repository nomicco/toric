use hdk::prelude::*;
use coordination_integrity::*;

#[hdk_extern]
pub fn init(_: ()) -> ExternResult<InitCallbackResult> {
    Ok(InitCallbackResult::Pass)
}

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

const QUORUM_THRESHOLD: f64 = 1.5;  // combined reputation weight required
const MIN_VALIDATORS: u32 = 3;       // minimum number of validators regardless of weight

// ─────────────────────────────────────────────
// Input / Output types
// ─────────────────────────────────────────────

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
        _ => {
            // If bridge call fails default to 0.5 neutral score
            Ok(0.5)
        }
    }
}

// ─────────────────────────────────────────────
// Helper — submit attestation via bridge call
// ─────────────────────────────────────────────

fn submit_attestation_to_registry(
    manifest_hash: ActionHash,
    metadata_blob: SerializedBytes,
    registry_cell_id: CellId,
) -> ExternResult<ActionHash> {
    #[derive(Serialize, Deserialize, Debug)]
    struct CreateAttestationInput {
        manifest_hash: ActionHash,
        blob: serde_json::Value,
    }

    // Build the attestation blob as JSON
    let blob = serde_json::json!({
        "blob_type": "generic",
        "validation_method_hash": null,
        "attestation_type": "quorum_consensus",
        "passed": true,
        "details": "Quorum reached via reputation-weighted consensus"
    });

    #[derive(Serialize, Deserialize, Debug)]
    struct AttestationInput {
        manifest_hash: ActionHash,
        metadata_blob: SerializedBytes,
    }

    let result = call(
        CallTargetCell::OtherCell(registry_cell_id),
        ZomeName::from("registry"),
        FunctionName::from("submit_attestation"),
        None,
        AttestationInput {
            manifest_hash,
            metadata_blob,
        },
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

// ─────────────────────────────────────────────
// Request Validation
// Creates a ValidationRequest entry and links it
// to the agent so validators can discover it
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn request_validation(input: RequestValidationInput) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;
    let request = ValidationRequest {
        manifest_hash: input.manifest_hash,
        requester: agent.clone(),
        metadata_blob: input.metadata_blob,
    };
    let action_hash = create_entry(EntryTypes::ValidationRequest(request))?;
    create_link(
        agent,
        action_hash.clone(),
        LinkTypes::AgentToRequest,
        (),
    )?;
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

// ─────────────────────────────────────────────
// Check Quorum
// Called after evaluations are submitted.
// If quorum is reached, fires bridge call to
// Registry to submit the final attestation.
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn check_quorum(input: CheckQuorumInput) -> ExternResult<QuorumResult> {
    // Get all evaluations for this request
    let eval_links = fetch_links(
        input.request_hash.clone(),
        LinkTypes::RequestToEvaluation,
    )?;

    if eval_links.len() < MIN_VALIDATORS as usize {
        return Ok(QuorumResult {
            reached: false,
            combined_weight: 0.0,
            evaluation_count: eval_links.len() as u32,
            quorum_bundle_hash: None,
        });
    }

    // Get the registry cell id for bridge calls
    let registry_cell_id = {
        let agent = agent_info()?.agent_initial_pubkey;
        let dna_info = dna_info()?;
        // Registry DNA hash is stored in properties
        // For now we derive it from cell info
        // This will be refined when we have multi-cell calls working
        CellId::new(dna_info.hash, agent)
    };

    // Collect evaluations with reputation weights
    let mut evaluations: Vec<EvaluationRecord> = Vec::new();
    let mut combined_weight: f64 = 0.0;
    let mut passing_weight: f64 = 0.0;

    for link in eval_links {
        if let Some(eval_hash) = link.target.into_action_hash() {
            if let Some(record) = get(eval_hash, GetOptions::default())? {
                if let Some(entry) = record.entry().as_option() {
                    if let Ok(bundle) = EvaluationBundle::try_from(entry) {
                        // Get reputation weight for this evaluator
                        let weight = get_reputation_score(
                            bundle.evaluator.clone(),
                            registry_cell_id.clone(),
                        ).unwrap_or(0.5);

                        // Decode the evaluation blob
                        let raw: Vec<u8> = UnsafeBytes::from(
                            bundle.metadata_blob.clone()
                        ).into();

                        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&raw) {
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

    // Check if passing evaluations reach quorum threshold
    let quorum_reached = passing_weight >= QUORUM_THRESHOLD
        && evaluations.len() >= MIN_VALIDATORS as usize;

    if !quorum_reached {
        return Ok(QuorumResult {
            reached: false,
            combined_weight,
            evaluation_count: evaluations.len() as u32,
            quorum_bundle_hash: None,
        });
    }

    // Build quorum bundle
    let eval_hashes: Vec<ActionHash> = evaluations.iter()
        .filter_map(|_| None) // placeholder — will collect hashes properly
        .collect();

    let quorum_blob = {
        let json = serde_json::json!({
            "evaluations": evaluations.len(),
            "combined_weight": combined_weight,
            "passing_weight": passing_weight,
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

    // Get the manifest hash from the original request
    if let Some(record) = get(input.request_hash, GetOptions::default())? {
        if let Some(entry) = record.entry().as_option() {
            if let Ok(request) = ValidationRequest::try_from(entry) {
                // Fire bridge call to Registry
                submit_attestation_to_registry(
                    request.manifest_hash,
                    quorum_blob,
                    registry_cell_id,
                ).ok(); // best effort — quorum bundle is already written
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

fn signal_action(_action: SignedActionHashed) -> ExternResult<()> {
    Ok(())
}