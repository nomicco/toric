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
    const PHI: f64 = 1.6180339887498948;
    const PHI_SQ: f64 = 2.6180339887498948;
    const LEARNING_RATE: f64 = 0.1;

    let agent_manifests = fetch_links(input.agent.clone(), LinkTypes::AgentToManifest)?;

    let mut total_attestations: u32 = 0;
    let mut total_warrants: u32 = 0;

    for link in agent_manifests {
        if let Some(manifest_hash) = link.target.into_action_hash() {
            // Only count attestations from OTHER agents — exclude self-attestation
            let attestation_links = fetch_links(
                manifest_hash.clone(),
                LinkTypes::ManifestToAttestation,
            )?;

            for att_link in &attestation_links {
                // Author of the link creation = the attesting agent
                // This avoids a network fetch and works even if the
                // target record hasn't synced yet
                let attesting_agent = att_link.author.clone();
                if attesting_agent != input.agent {
                    total_attestations += 1;
                }
            }

            let warrant_links = fetch_links(
                manifest_hash,
                LinkTypes::ManifestToWarrant,
            )?;
            total_warrants += warrant_links.len() as u32;
        }
    }

    // φ-derived reputation from fixed point of closure recursion
    // Start at 0.5 neutral, converge toward fixed point based on
    // attestation/warrant history
    let score = if total_attestations == 0 && total_warrants == 0 {
        0.5 // neutral — no history yet
    } else {
        let total = (total_attestations + total_warrants) as f64;

        // Each attestation moves reputation (1/φ) of the distance toward 1.0
        // Each warrant moves reputation (1/φ) of the distance toward 0.0
        // This is the same update rule as the simulation
        let mut rep: f64 = 0.5;
        for _ in 0..total_attestations {
            let delta = (1.0 - rep) / PHI;
            rep = (rep + delta * LEARNING_RATE).clamp(0.01, 0.99);
        }
        for _ in 0..total_warrants {
            let delta = rep / PHI; // moves toward 0.0
            rep = (rep - delta * LEARNING_RATE * 2.0).clamp(0.01, 0.99);
        }
        rep
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