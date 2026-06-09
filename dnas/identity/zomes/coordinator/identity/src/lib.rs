use hdk::prelude::*;
use identity_integrity::*;

#[hdk_extern]
pub fn init(_: ()) -> ExternResult<InitCallbackResult> {
    Ok(InitCallbackResult::Pass)
}

fn fetch_links(
    base: impl Into<AnyLinkableHash>,
    link_type: LinkTypes,
) -> ExternResult<Vec<Link>> {
    let query = LinkQuery::new(base.into(), link_type.try_into_filter()?);
    get_links(query, GetStrategy::Network)
}

// ─────────────────────────────────────────────
// Register AgentManifest
// Idempotent — returns existing hash if already registered
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterAgentInput {
    pub agent_type: String,
    pub capabilities: Vec<String>,
    pub software_hash: String,
    pub version: String,
    pub metadata: Option<serde_json::Value>,
}

#[hdk_extern]
pub fn register_agent(input: RegisterAgentInput) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;

    // Idempotent — return existing if already registered
    let existing = fetch_links(agent.clone(), LinkTypes::AgentToAgentManifest)?;
    if let Some(link) = existing.last() {
        if let Some(hash) = link.target.clone().into_action_hash() {
            return Ok(hash);
        }
    }

    let metadata_bytes = {
        let json = input.metadata.unwrap_or(serde_json::Value::Object(Default::default()));
        let bytes = serde_json::to_vec(&json).map_err(|e| {
            wasm_error!(WasmErrorInner::Guest(format!("Failed to serialize metadata: {}", e)))
        })?;
        SerializedBytes::from(UnsafeBytes::from(bytes))
    };

    let manifest = AgentManifest {
        agent: agent.clone(),
        agent_type: input.agent_type,
        capabilities: input.capabilities.clone(),
        software_hash: input.software_hash,
        version: input.version,
        metadata_blob: metadata_bytes,
    };

    let action_hash = create_entry(EntryTypes::AgentManifest(manifest))?;

    // Link agent to their manifest
    create_link(
        agent.clone(),
        action_hash.clone(),
        LinkTypes::AgentToAgentManifest,
        (),
    )?;

    // Index by each capability
    for capability in &input.capabilities {
        let path = Path::from(format!("capability.{}", capability));
        let typed_path = path.typed(LinkTypes::CapabilityToAgent)?;
        typed_path.ensure()?;
        create_link(
            typed_path.path_entry_hash()?,
            agent.clone(),
            LinkTypes::CapabilityToAgent,
            (),
        )?;
    }

    // Global agent index
    let global_path = Path::from("agents.all");
    let global_typed = global_path.typed(LinkTypes::GlobalAgentAnchor)?;
    global_typed.ensure()?;
    create_link(
        global_typed.path_entry_hash()?,
        agent.clone(),
        LinkTypes::GlobalAgentAnchor,
        (),
    )?;


    Ok(action_hash)
}

// ─────────────────────────────────────────────
// Get agent manifest
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn get_agent_manifest(agent: AgentPubKey) -> ExternResult<Option<Record>> {
    let links = fetch_links(agent, LinkTypes::AgentToAgentManifest)?;
    match links.last() {
        Some(link) => {
            if let Some(hash) = link.target.clone().into_action_hash() {
                get(hash, GetOptions::default())
            } else {
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

// ─────────────────────────────────────────────
// Get agents by capability
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub struct CapabilityInput {
    pub capability: String,
}

#[hdk_extern]
pub fn get_agents_by_capability(input: CapabilityInput) -> ExternResult<Vec<AgentPubKey>> {
    let path = Path::from(format!("capability.{}", input.capability));
    let typed_path = path.typed(LinkTypes::CapabilityToAgent)?;
    let links = fetch_links(typed_path.path_entry_hash()?, LinkTypes::GlobalAgentAnchor)?;
    Ok(links.into_iter()
        .filter_map(|l| AgentPubKey::try_from(l.target).ok())
        .collect())
}

// ─────────────────────────────────────────────
// Get all registered agents
// ─────────────────────────────────────────────

#[hdk_extern]
pub fn get_all_agents(_: ()) -> ExternResult<Vec<AgentPubKey>> {
    // Query via the global capability anchor — any agent with any capability
    // For a truly global index we use a root path anchor
    let path = Path::from("agents.all");
    let typed_path = path.typed(LinkTypes::GlobalAgentAnchor)?;
    if !typed_path.exists()? {
        return Ok(vec![]);
    }
    let links = fetch_links(typed_path.path_entry_hash()?, LinkTypes::GlobalAgentAnchor)?;
    Ok(links.into_iter()
        .filter_map(|l| AgentPubKey::try_from(l.target).ok())
        .collect())
}