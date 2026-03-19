import { assert, test } from "vitest";
import { runScenario, Scenario } from "@holochain/tryorama";
import { ActionHash, Record, AppBundleSource } from "@holochain/client";
import { join } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const happPath = join(__dirname, "../../../../workdir/poi.happ");

async function createAiModelManifest(cell: any): Promise<ActionHash> {
  const blob = {
    blob_type: "ai_model",
    content_hash: "sha256:abc123testmodelhash",
    architecture: "llama",
    parameter_count: 7000000000,
    upstream_manifest_hashes: [],
    connector_source: "local",
    version: "1.0.0",
    description: "Test astrology AI model",
    tags: ["astrology", "test"],
  };
  return cell.callZome({ zome_name: "registry", fn_name: "create_manifest", payload: { blob } });
}

async function createAttestation(cell: any, manifestHash: ActionHash): Promise<ActionHash> {
  const blob = {
    blob_type: "model_evaluation",
    validation_method_hash: manifestHash,
    benchmark_type: "custom",
    score: 0.92,
    passed: true,
    confidence: 0.85,
    evaluation_details: JSON.stringify({ test: "astrology_accuracy" }),
  };
  return cell.callZome({ zome_name: "registry", fn_name: "create_attestation", payload: { manifest_hash: manifestHash, blob } });
}

async function createWarrant(cell: any, manifestHash: ActionHash): Promise<ActionHash> {
  const blob = {
    blob_type: "tampered_weights",
    severity: 8,
    evidence_hashes: [],
    expected_hash: "sha256:abc123testmodelhash",
    found_hash: "sha256:differenthash",
    description: "Model weights do not match registered hash",
  };
  return cell.callZome({ zome_name: "registry", fn_name: "create_warrant", payload: { manifest_hash: manifestHash, blob } });
}

test("create and retrieve a manifest", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const manifestHash: ActionHash = await createAiModelManifest(alice.namedCells.get("registry")!);
    assert.ok(manifestHash);
    const record: Record = await alice.namedCells.get("registry")!.callZome({ zome_name: "registry", fn_name: "get_manifest", payload: manifestHash });
    assert.ok(record);
    assert.deepEqual(record.signed_action.hashed.hash, manifestHash);
  }, true, { disableLocalServices: true });
});

test("manifest is append-only — update is rejected", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const manifestHash: ActionHash = await createAiModelManifest(alice.namedCells.get("registry")!);
    try {
      await alice.namedCells.get("registry")!.callZome({ zome_name: "registry", fn_name: "update_entry", payload: { original_action_hash: manifestHash, previous_action_hash: manifestHash, updated_entry: { metadata_blob: new Uint8Array() } } });
      assert.fail("Update should have been rejected");
    } catch (e) {
      assert.ok(e, "Update correctly rejected");
    }
  }, true, { disableLocalServices: true });
});

test("create attestation linked to manifest", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const manifestHash = await createAiModelManifest(alice.namedCells.get("registry")!);
    const attestationHash = await createAttestation(alice.namedCells.get("registry")!, manifestHash);
    assert.ok(attestationHash);
    const attestations: Record[] = await alice.namedCells.get("registry")!.callZome({ zome_name: "registry", fn_name: "get_manifest_attestations", payload: manifestHash });
    assert.equal(attestations.length, 1);
  }, true, { disableLocalServices: true });
});

test("create warrant linked to manifest", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const manifestHash = await createAiModelManifest(alice.namedCells.get("registry")!);
    const warrantHash = await createWarrant(alice.namedCells.get("registry")!, manifestHash);
    assert.ok(warrantHash);
    const warrants: Record[] = await alice.namedCells.get("registry")!.callZome({ zome_name: "registry", fn_name: "get_manifest_warrants", payload: manifestHash });
    assert.equal(warrants.length, 1);
  }, true, { disableLocalServices: true });
});

test("reputation score reflects attestations and warrants", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const bob = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const initialScore = await alice.namedCells.get("registry")!.callZome({ zome_name: "registry", fn_name: "compute_reputation_score", payload: { agent: alice.agentPubKey } });
    assert.equal(initialScore.score, 0.5);

    // Bob attests alice's manifests — self-attestation is excluded
    const manifest1 = await createAiModelManifest(alice.namedCells.get("registry")!);
    const manifest2 = await createAiModelManifest(alice.namedCells.get("registry")!);
    // Wait for manifests to propagate to bob's DHT before attesting
    await new Promise(r => setTimeout(r, 5000));
    await createAttestation(bob.namedCells.get("registry")!, manifest1);
    await createAttestation(bob.namedCells.get("registry")!, manifest2);
    await new Promise(r => setTimeout(r, 500));

    // Query from bob's cell — he has the links he just created
    const afterAttestations = await bob.namedCells.get("registry")!.callZome({
      zome_name: "registry",
      fn_name: "compute_reputation_score",
      payload: { agent: alice.agentPubKey },
    });
    // Alice warrants her own manifest — this still counts
    await createWarrant(alice.namedCells.get("registry")!, manifest1);
    await new Promise(r => setTimeout(r, 3000));  // was 500
    

    const afterWarrant = await bob.namedCells.get("registry")!.callZome({ zome_name: "registry", fn_name: "compute_reputation_score", payload: { agent: alice.agentPubKey } });
    assert.ok(afterWarrant.score < afterAttestations.score, "Score should decrease with warrants");
  }, true, { disableLocalServices: true });
});

test("two agents — manifests propagate across DHT", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const bob = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const manifestHash = await createAiModelManifest(alice.namedCells.get("registry")!);
    await new Promise(r => setTimeout(r, 3000));
    const record: Record = await bob.namedCells.get("registry")!.callZome({ zome_name: "registry", fn_name: "get_manifest", payload: manifestHash });
    assert.ok(record, "Bob can read Alice's manifest from DHT");
  }, true, { disableLocalServices: true });
});

test("get all manifests for an agent", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    await createAiModelManifest(alice.namedCells.get("registry")!);
    await createAiModelManifest(alice.namedCells.get("registry")!);
    await createAiModelManifest(alice.namedCells.get("registry")!);
    await new Promise(r => setTimeout(r, 500));
    const manifests: Record[] = await alice.namedCells.get("registry")!.callZome({ zome_name: "registry", fn_name: "get_agent_manifests", payload: alice.agentPubKey });
    assert.equal(manifests.length, 3);
  }, true, { disableLocalServices: true });
});
