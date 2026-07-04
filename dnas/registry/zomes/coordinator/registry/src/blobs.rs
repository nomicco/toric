use hdk::prelude::*;
use hdk::prelude::UnsafeBytes;

// ─────────────────────────────────────────────
// Blob type tags
// Every blob starts with a type field so the
// coordinator knows how to interpret it.
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "blob_type", rename_all = "snake_case")]
pub enum ManifestBlob {
    AiModel(AiModelManifest),
    Dataset(DatasetManifest),
    TrainingRun(TrainingRunManifest),
    InferenceEndpoint(InferenceEndpointManifest),
    Connector(ConnectorManifest),
    Generic(GenericManifest),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "blob_type", rename_all = "snake_case")]
pub enum AttestationBlob {
    ModelEvaluation(ModelEvaluationAttestation),
    DatasetAudit(DatasetAuditAttestation),
    ConnectorVerification(ConnectorVerificationAttestation),
    Generic(GenericAttestation),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "blob_type", rename_all = "snake_case")]
pub enum WarrantBlob {
    TamperedWeights(TamperedWeightsWarrant),
    MisrepresentedPerformance(MisrepresentedPerformanceWarrant),
    ConnectorMisbehavior(ConnectorMisbehaviorWarrant),
    FalseAttestation(FalseAttestationWarrant),
}

// ─────────────────────────────────────────────
// Manifest blobs
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AiModelManifest {
    // Required
    pub content_hash: String,       // hash of the actual model weights
    pub architecture: String,       // e.g. "llama", "mistral", "gpt2"
    pub parameter_count: u64,       // number of parameters

    // Provenance chain
    pub upstream_manifest_hashes: Vec<ActionHash>, // training run, dataset, etc.
    pub connector_source: Option<String>,           // "bittensor", "gensyn", "akash", "local"

    // Optional metadata
    pub version: Option<String>,
    pub description: Option<String>,
    pub license: Option<String>,
    pub artifact_timestamp: Option<u64>,
    pub fine_tuned_from: Option<String>,  // base model identifier
    pub training_data_description: Option<String>,
    pub quantization: Option<String>,     // e.g. "fp16", "int8", "gguf"
    pub context_length: Option<u64>,
    pub tags: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DatasetManifest {
    pub content_hash: String,
    pub dataset_type: String,       // e.g. "instruction", "pretraining", "rlhf"
    pub record_count: Option<u64>,
    pub connector_source: Option<String>,
    pub upstream_manifest_hashes: Vec<ActionHash>,
    pub description: Option<String>,
    pub license: Option<String>,
    pub artifact_timestamp: Option<u64>,
    pub tags: Option<Vec<String>>,

    // Discovery mechanism. A DatasetManifest with a domain is a probe: a
    // test that some population of agents fetches as active vocabulary.
    // Distinct from blob_type (artifact kind) — domain is test kind.
    //
    // #[serde(default)] on both: existing DatasetManifest entries predate
    // these fields and must still deserialize. Legacy entry → domain ""
    // (not a probe) and polarity None (not applicable) — both honest
    // "unset", neither a fabricated meaningful value.
    #[serde(default)]
    pub domain: String,

    // Consequence wiring, assigned once by the probe's filer, not derived:
    //   Some(true)  → positive result is a capability  (trust update)
    //   Some(false) → positive result is a violation   (warrant)
    //   None        → not a probe / polarity not applicable
    // Option<bool>, not bool: a defaulted bare bool would relabel every
    // legacy dataset as Some(false) = immune-layer violation-probe, which
    // is a manufactured measurement from no measurement. None keeps unset
    // structurally distinct from an explicit immune-layer false, so no
    // future reader can misread it and no cross-field gate is relied on.
    // polarity does NOT enter any φ computation — the geometry is identical
    // regardless of its value; it only selects which existing code path
    // fires on confirmation.
    #[serde(default)]
    pub polarity: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrainingRunManifest {
    pub content_hash: String,
    pub model_manifest_hash: Option<ActionHash>,
    pub dataset_manifest_hash: Option<ActionHash>,
    pub connector_source: Option<String>,    // "gensyn", "bittensor", "local"
    pub compute_hours: Option<f64>,
    pub hardware: Option<String>,
    pub framework: Option<String>,           // "pytorch", "jax", etc.
    pub hyperparameters: Option<String>,     // JSON string, kept flexible
    pub artifact_timestamp: Option<u64>,
    pub upstream_manifest_hashes: Vec<ActionHash>,
    pub tags: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InferenceEndpointManifest {
    pub content_hash: String,
    pub model_manifest_hash: ActionHash,
    pub connector_source: Option<String>,    // "akash", "local", "runpod"
    pub endpoint_type: Option<String>,       // "http", "websocket", "grpc"
    pub artifact_timestamp: Option<u64>,
    pub upstream_manifest_hashes: Vec<ActionHash>,
    pub tags: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectorManifest {
    // Minimum required fields every connector must fill
    pub source_network_id: String,
    pub connector_version: String,
    pub content_hash: String,
    pub operator_pubkey: String,

    // Optional
    pub supported_manifest_types: Option<Vec<String>>,
    pub documentation_url: Option<String>,
    pub upstream_manifest_hashes: Vec<ActionHash>,
    pub tags: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenericManifest {
    pub content_hash: String,
    pub manifest_type: String,
    pub upstream_manifest_hashes: Vec<ActionHash>,
    pub metadata: Option<String>,    // arbitrary JSON string
    pub artifact_timestamp: Option<u64>,
    pub tags: Option<Vec<String>>,
}

// ─────────────────────────────────────────────
// Attestation blobs
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModelEvaluationAttestation {
    pub validation_method_hash: Option<ActionHash>,
    pub benchmark_type: String,

    // Multi-dimensional score — Phase 5
    // Each dimension weighted at φ⁻ⁿ in compute_trust_score
    // Absent dimensions default to None — validator submits what they can verify
    pub hash_score: f64,                    // φ⁻¹ — did weights match registered hash
    pub provenance_score: Option<f64>,      // φ⁻² — upstream manifest chain quality
    pub static_score: Option<f64>,          // φ⁻³ — Garak static scan result
    pub probe_score: Option<f64>,           // φ⁻⁴ — behavioral probe set result

    // Legacy single-dimension fields — kept for backward compatibility
    // hash_score replaces score for model evaluations
    pub score: f64,
    pub passed: bool,
    pub confidence: Option<f64>,
    pub evaluation_details: Option<String>,
    pub evaluated_at: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DatasetAuditAttestation {
    pub validation_method_hash: Option<ActionHash>,
    pub audit_type: String,
    pub passed: bool,
    pub findings: Option<String>,
    pub evaluated_at: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectorVerificationAttestation {
    pub validation_method_hash: Option<ActionHash>,
    pub connector_manifest_hash: ActionHash,
    pub passed: bool,
    pub verified_schema_compliance: bool,
    pub verified_pipeline_compliance: bool,
    pub findings: Option<String>,
    pub evaluated_at: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenericAttestation {
    pub validation_method_hash: Option<ActionHash>,
    pub attestation_type: String,
    pub passed: bool,
    pub score: Option<f64>,
    pub details: Option<String>,
    pub evaluated_at: Option<u64>,
}
// ─────────────────────────────────────────────
// Warrant blobs
// Severity is always computed from the divergence
// measurement — never chosen by the filer.
// evidence_hash is required — points to the DHT
// entry containing the proof. Warrants without
// proof are rejected at the integrity layer.
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TamperedWeightsWarrant {
    // Binary — hash either matches or doesn't.
    // computed_severity always 1_000_000 (max, scaled).
    pub evidence_hash: ActionHash,   // validator's hash computation record
    pub expected_hash: String,
    pub found_hash: String,
    pub computed_severity: u32,      // always 1_000_000 — set by validator client
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MisrepresentedPerformanceWarrant {
    // computed_severity = |claimed - actual| / claimed × 1_000_000
    pub evidence_hash: ActionHash,   // benchmark output record
    pub claimed_score: f64,
    pub actual_score: f64,
    pub benchmark_type: String,
    pub computed_severity: u32,      // derived from delta, set by validator client
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectorMisbehaviorWarrant {
    // computed_severity = schema_deviation_fraction × 1_000_000
    pub evidence_hash: ActionHash,   // connector signed output record
    pub connector_manifest_hash: ActionHash,
    pub misbehavior_type: String,
    pub computed_severity: u32,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FalseAttestationWarrant {
    // computed_severity = reputation_weight of false attestor × 1_000_000
    pub evidence_hash: ActionHash,   // the disputed attestation hash
    pub disputed_attestation_hash: ActionHash,
    pub computed_severity: u32,
    pub description: Option<String>,
}

// ─────────────────────────────────────────────
// Serialization helpers
// ─────────────────────────────────────────────

pub fn encode_manifest_blob(blob: &ManifestBlob) -> ExternResult<SerializedBytes> {
    let bytes = serde_json::to_vec(blob).map_err(|e| {
        wasm_error!(WasmErrorInner::Guest(format!("Failed to serialize manifest blob: {}", e)))
    })?;
    Ok(SerializedBytes::from(UnsafeBytes::from(bytes)))
}

pub fn decode_manifest_blob(bytes: &SerializedBytes) -> ExternResult<ManifestBlob> {
    let raw: Vec<u8> = UnsafeBytes::from(bytes.clone()).into();
    serde_json::from_slice(&raw).map_err(|e| {
        wasm_error!(WasmErrorInner::Guest(format!("Failed to deserialize manifest blob: {}", e)))
    })
}

pub fn encode_attestation_blob(blob: &AttestationBlob) -> ExternResult<SerializedBytes> {
    let bytes = serde_json::to_vec(blob).map_err(|e| {
        wasm_error!(WasmErrorInner::Guest(format!("Failed to serialize attestation blob: {}", e)))
    })?;
    Ok(SerializedBytes::from(UnsafeBytes::from(bytes)))
}

pub fn decode_attestation_blob(bytes: &SerializedBytes) -> ExternResult<AttestationBlob> {
    let raw: Vec<u8> = UnsafeBytes::from(bytes.clone()).into();
    serde_json::from_slice(&raw).map_err(|e| {
        wasm_error!(WasmErrorInner::Guest(format!("Failed to deserialize attestation blob: {}", e)))
    })
}

pub fn encode_warrant_blob(blob: &WarrantBlob) -> ExternResult<SerializedBytes> {
    let bytes = serde_json::to_vec(blob).map_err(|e| {
        wasm_error!(WasmErrorInner::Guest(format!("Failed to serialize warrant blob: {}", e)))
    })?;
    Ok(SerializedBytes::from(UnsafeBytes::from(bytes)))
}

pub fn decode_warrant_blob(bytes: &SerializedBytes) -> ExternResult<WarrantBlob> {
    let raw: Vec<u8> = UnsafeBytes::from(bytes.clone()).into();
    serde_json::from_slice(&raw).map_err(|e| {
        wasm_error!(WasmErrorInner::Guest(format!("Failed to deserialize warrant blob: {}", e)))
    })
}

pub fn warrant_computed_severity(blob: &WarrantBlob) -> u32 {
    match blob {
        WarrantBlob::TamperedWeights(w)           => w.computed_severity,
        WarrantBlob::MisrepresentedPerformance(w) => w.computed_severity,
        WarrantBlob::ConnectorMisbehavior(w)      => w.computed_severity,
        WarrantBlob::FalseAttestation(w)          => w.computed_severity,
    }
}

pub fn warrant_evidence_hash(blob: &WarrantBlob) -> &ActionHash {
    match blob {
        WarrantBlob::TamperedWeights(w)           => &w.evidence_hash,
        WarrantBlob::MisrepresentedPerformance(w) => &w.evidence_hash,
        WarrantBlob::ConnectorMisbehavior(w)      => &w.evidence_hash,
        WarrantBlob::FalseAttestation(w)          => &w.evidence_hash,
    }
}