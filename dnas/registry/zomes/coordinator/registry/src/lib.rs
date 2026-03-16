use hdk::prelude::*;
use registry_integrity::{
    EntryTypes,
    LinkTypes,
    Manifest,
    Attestation,
    Warrant as RegistryWarrant,
};

pub mod blobs;
use blobs::*;

#[hdk_extern]
pub fn init(_: ()) -> ExternResult<InitCallbackResult> {
    Ok(InitCallbackResult::Pass)
}

// ─────────────────────────────────────────────
// Input types — typed blobs
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateManifestInput {
    pub blob: ManifestBlob,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateAttestationInput {
    pub manifest_hash: ActionHash,
    pub blob: AttestationBlob,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateWarrantInput {
    pub manifest_hash: ActionHash,
    pub blob: WarrantBlob,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReputationInput {
    pub agent: AgentPubKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReputationScore {
    pub agent: AgentPubKey,
    pub score: f64,
    pub attestation_count: u32,
    pub warrant_count: u32,
}

// ─────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────

fn fetch_links(base: impl Into<AnyLinkableHash>, link_type: LinkTypes) -> ExternResult<Vec<Link>> {
    let query = LinkQuery::new(
        base.into(),
        link_type.try_into_filter()?,
    );
    get_links(query, GetStrategy::Network)
}

fn links_to_records(links: Vec<Link>) -> ExternResult<Vec<Record>> {
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
// Create Manifest
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn create_manifest(input: CreateManifestInput) -> ExternResult<ActionHash> {
    let metadata_blob = encode_manifest_blob(&input.blob)?;
    let manifest = Manifest { metadata_blob };
    let action_hash = create_entry(EntryTypes::Manifest(manifest))?;
    let agent = agent_info()?.agent_initial_pubkey;
    create_link(agent, action_hash.clone(), LinkTypes::AgentToManifest, ())?;
    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Create Attestation
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn create_attestation(input: CreateAttestationInput) -> ExternResult<ActionHash> {
    let metadata_blob = encode_attestation_blob(&input.blob)?;
    let attestation = Attestation {
        manifest_hash: input.manifest_hash.clone(),
        metadata_blob,
    };
    let action_hash = create_entry(EntryTypes::Attestation(attestation))?;
    create_link(
        input.manifest_hash,
        action_hash.clone(),
        LinkTypes::ManifestToAttestation,
        (),
    )?;
    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Create Warrant
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn create_warrant(input: CreateWarrantInput) -> ExternResult<ActionHash> {
    let metadata_blob = encode_warrant_blob(&input.blob)?;
    let warrant = RegistryWarrant {
        manifest_hash: input.manifest_hash.clone(),
        metadata_blob,
    };
    let action_hash = create_entry(EntryTypes::Warrant(warrant))?;
    create_link(
        input.manifest_hash,
        action_hash.clone(),
        LinkTypes::ManifestToWarrant,
        (),
    )?;
    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Get Manifest
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn get_manifest(action_hash: ActionHash) -> ExternResult<Option<Record>> {
    get(action_hash, GetOptions::default())
}

#[hdk_extern]
pub fn get_agent_manifests(agent: AgentPubKey) -> ExternResult<Vec<Record>> {
    let links = fetch_links(agent, LinkTypes::AgentToManifest)?;
    links_to_records(links)
}

#[hdk_extern]
pub fn get_manifest_attestations(manifest_hash: ActionHash) -> ExternResult<Vec<Record>> {
    let links = fetch_links(manifest_hash, LinkTypes::ManifestToAttestation)?;
    links_to_records(links)
}

#[hdk_extern]
pub fn get_manifest_warrants(manifest_hash: ActionHash) -> ExternResult<Vec<Record>> {
    let links = fetch_links(manifest_hash, LinkTypes::ManifestToWarrant)?;
    links_to_records(links)
}

// ─────────────────────────────────────────────
// Bridge-callable functions
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn submit_attestation(input: CreateAttestationInput) -> ExternResult<ActionHash> {
    create_attestation(input)
}

#[hdk_extern]
pub fn compute_reputation_score(input: ReputationInput) -> ExternResult<ReputationScore> {
    let manifest_links = fetch_links(input.agent.clone(), LinkTypes::AgentToManifest)?;

    let mut total_attestations: u32 = 0;
    let mut total_warrants: u32 = 0;

    for link in manifest_links {
        if let Some(manifest_hash) = link.target.into_action_hash() {
            let attestation_links = fetch_links(
                manifest_hash.clone(),
                LinkTypes::ManifestToAttestation,
            )?;
            total_attestations += attestation_links.len() as u32;

            let warrant_links = fetch_links(
                manifest_hash,
                LinkTypes::ManifestToWarrant,
            )?;
            total_warrants += warrant_links.len() as u32;
        }
    }

    let score = if total_attestations == 0 && total_warrants == 0 {
        0.5
    } else {
        let total = (total_attestations + total_warrants) as f64;
        let attestation_ratio = total_attestations as f64 / total;
        let warrant_penalty = (total_warrants as f64 * 2.0) / total;
        (attestation_ratio - warrant_penalty).max(0.0).min(1.0)
    };

    Ok(ReputationScore {
        agent: input.agent,
        score,
        attestation_count: total_attestations,
        warrant_count: total_warrants,
    })
}

// ─────────────────────────────────────────────
// Signals
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Signal {
    ManifestCreated { action_hash: ActionHash },
    AttestationCreated { action_hash: ActionHash },
    WarrantCreated { action_hash: ActionHash },
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