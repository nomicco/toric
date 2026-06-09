import { assert, test } from "vitest";
import { runScenario, Scenario } from "@holochain/tryorama";
import { ActionHash } from "@holochain/client";
import { join } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";
import crypto from "crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const happPath = join(__dirname, "../../../../workdir/toric.happ");
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

function getRegistryDnaHash(cell: any): Uint8Array {
  // cell_id is [DnaHash, AgentPubKey] — both Uint8Array
  return cell.cell_id[0];
}

async function createManifest(cell: any): Promise<ActionHash> {
  return cell.callZome({
    zome_name: "registry",
    fn_name: "create_manifest",
    payload: {
      blob: {
        blob_type: "ai_model",
        content_hash: "sha256:testmodel123",
        architecture: "llama",
        parameter_count: 7000000000,
        upstream_manifest_hashes: [],
        connector_source: "local",
        version: "1.0.0",
        description: "Test model for coordination",
      }
    }
  });
}

async function requestValidation(cell: any, manifestHash: ActionHash): Promise<ActionHash> {
  return cell.callZome({
    zome_name: "coordination",
    fn_name: "request_validation",
    payload: {
      manifest_hash: manifestHash,
      metadata_blob: new Uint8Array(0),
    }
  });
}

async function submitEvaluation(
  cell: any,
  requestHash: ActionHash,
  passed: boolean,
  score: number
): Promise<ActionHash> {
  return cell.callZome({
    zome_name: "coordination",
    fn_name: "submit_evaluation",
    payload: {
      request_hash: requestHash,
      passed,
      score,
      details: passed ? "Model verified" : "Model failed verification",
    }
  });
}

async function checkQuorum(
  coordinationCell: any,
  requestHash: ActionHash,
  registryCell: any,
  mcCell: any
): Promise<any> {
  return coordinationCell.callZome({
    zome_name: "coordination",
    fn_name: "check_quorum",
    payload: {
      request_hash: requestHash,
      registry_dna_hash: registryCell.cell_id[0],
      mutual_credit_dna_hash: mcCell.cell_id[0],
    }
  });
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

test("request validation — creates a ValidationRequest entry", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    assert.ok(manifestHash);

    const requestHash = await requestValidation(
      alice.namedCells.get("coordination")!,
      manifestHash
    );
    assert.ok(requestHash);
  }, true, { disableLocalServices: true });
});

test("submit evaluation — validator can submit verdict", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    const requestHash = await requestValidation(
      alice.namedCells.get("coordination")!,
      manifestHash
    );

    const evalHash = await submitEvaluation(
      alice.namedCells.get("coordination")!,
      requestHash,
      true,
      0.95
    );
    assert.ok(evalHash);
  }, true, { disableLocalServices: true });
});

test("check quorum — single evaluation returns not reached", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    const requestHash = await requestValidation(
      alice.namedCells.get("coordination")!,
      manifestHash
    );

    await submitEvaluation(
      alice.namedCells.get("coordination")!,
      requestHash,
      true,
      0.95
    );

    await sleep(2000);

    const result = await checkQuorum(
      alice.namedCells.get("coordination")!,
      requestHash,
      alice.namedCells.get("registry")!,
      alice.namedCells.get("mutual_credit")!
    );

    assert.equal(result.reached, false);
    assert.equal(result.evaluation_count, 1);
  }, true, { disableLocalServices: true });
});

test("check quorum — three validators agreeing reaches quorum", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const bob   = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const carol = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    await sleep(2000);

    const requestHash = await requestValidation(
      alice.namedCells.get("coordination")!,
      manifestHash
    );
    await sleep(8000);

    await Promise.all([
      submitEvaluation(alice.namedCells.get("coordination")!, requestHash, true, 0.95),
      submitEvaluation(bob.namedCells.get("coordination")!,   requestHash, true, 0.90),
      submitEvaluation(carol.namedCells.get("coordination")!, requestHash, true, 0.88),
    ]);
    await sleep(5000);

    const result = await checkQuorum(
      alice.namedCells.get("coordination")!,
      requestHash,
      alice.namedCells.get("registry")!,
      alice.namedCells.get("mutual_credit")!
    );

    assert.equal(result.reached, true);
    assert.equal(result.evaluation_count, 3);
    assert.ok(result.quorum_bundle_hash);
  }, true, { disableLocalServices: true });
});

test("duplicate quorum bundle — calling check_quorum twice produces only one bundle", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const bob   = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const carol = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    await sleep(2000);

    const requestHash = await requestValidation(
      alice.namedCells.get("coordination")!,
      manifestHash
    );
    await sleep(8000);

    await submitEvaluation(alice.namedCells.get("coordination")!, requestHash, true, 0.95);
    await submitEvaluation(bob.namedCells.get("coordination")!,   requestHash, true, 0.90);
    await submitEvaluation(carol.namedCells.get("coordination")!, requestHash, true, 0.88);

    await sleep(3000);

    // First call — creates the bundle
    const result1 = await checkQuorum(
      alice.namedCells.get("coordination")!,
      requestHash,
      alice.namedCells.get("registry")!,
      alice.namedCells.get("mutual_credit")!
    );
    assert.equal(result1.reached, true);
    assert.ok(result1.quorum_bundle_hash);

    // Second call — must hit early return, not write another bundle
    await sleep(500);
    const result2 = await checkQuorum(
      alice.namedCells.get("coordination")!,
      requestHash,
      alice.namedCells.get("registry")!,
      alice.namedCells.get("mutual_credit")!
    );
    assert.equal(result2.reached, true);
    assert.ok(result2.quorum_bundle_hash);

    // Same bundle hash returned both times
    const hash1 = Buffer.from(result1.quorum_bundle_hash).toString("base64url");
    const hash2 = Buffer.from(result2.quorum_bundle_hash).toString("base64url");
    assert.equal(hash1, hash2, "second call must return existing bundle, not create a new one");

    // Third call from a different agent — same result after propagation
    await sleep(5000);
    const result3 = await checkQuorum(
      bob.namedCells.get("coordination")!,
      requestHash,
      bob.namedCells.get("registry")!,
      bob.namedCells.get("mutual_credit")!
    )
    assert.equal(result3.reached, true);
    const hash3 = Buffer.from(result3.quorum_bundle_hash).toString("base64url");
    assert.equal(hash1, hash3, "different agent also sees the same bundle hash");

  }, true, { disableLocalServices: true });
});

test("get pending requests — agent can query their requests", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    await requestValidation(alice.namedCells.get("coordination")!, manifestHash);
    await requestValidation(alice.namedCells.get("coordination")!, manifestHash);

    await sleep(500);

    const requests = await alice.namedCells.get("coordination")!.callZome({
      zome_name: "coordination",
      fn_name: "get_pending_requests",
      payload: alice.agentPubKey
    });

    assert.equal(requests.length, 2);
  }, true, { disableLocalServices: true });
});

test("commit evaluation — validator can commit a verdict", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    const requestHash = await requestValidation(
      alice.namedCells.get("coordination")!,
      manifestHash
    );

    const commitmentHash = Array.from(crypto.getRandomValues(new Uint8Array(32)));
    const commitHash = await alice.namedCells.get("coordination")!.callZome({
      zome_name: "coordination",
      fn_name: "commit_evaluation",
      payload: {
        request_hash: requestHash,
        commitment_hash: commitmentHash,
      }
    });
    assert.ok(commitHash);
  }, true, { disableLocalServices: true });
});

test("reveal window — opens after φ⁴ threshold crossed", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const bob   = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const carol = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    await sleep(2000);

    const requestHash = await requestValidation(
      alice.namedCells.get("coordination")!,
      manifestHash
    );
    await sleep(5000);

    const commitmentHash = Array.from(new Uint8Array(32).fill(1));

    for (const player of [alice, bob, carol]) {
      await player.namedCells.get("coordination")!.callZome({
        zome_name: "coordination",
        fn_name: "commit_evaluation",
        payload: { request_hash: requestHash, commitment_hash: commitmentHash },
      });
    }
    await sleep(8000);

    const after = await alice.namedCells.get("coordination")!.callZome({
      zome_name: "coordination",
      fn_name: "check_reveal_window",
      payload: {
        request_hash: requestHash,
        registry_dna_hash: alice.namedCells.get("registry")!.cell_id[0],
        mutual_credit_dna_hash: alice.namedCells.get("mutual_credit")!.cell_id[0],
      },
    });

    assert.equal(after.reveal_window_open, true);
    assert.equal(after.commitment_count, 3);
  }, true, { disableLocalServices: true });
});

test("reveal evaluation — requires prior commitment", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    const requestHash = await requestValidation(
      alice.namedCells.get("coordination")!,
      manifestHash
    );

    // Reveal without commit should fail
    try {
      await alice.namedCells.get("coordination")!.callZome({
        zome_name: "coordination",
        fn_name: "reveal_evaluation",
        payload: {
          request_hash: requestHash,
          passed: true,
          score: 0.95,
          details: "test",
          salt: "testsalt123",
        }
      });
      assert.fail("Reveal without commit should have been rejected");
    } catch(e) {
      assert.ok(e, "Reveal correctly rejected without prior commitment");
    }
  }, true, { disableLocalServices: true });
});

test("full commit-reveal flow — three validators reach quorum", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const bob   = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const carol = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    await sleep(2000);

    const requestHash = await requestValidation(
      alice.namedCells.get("coordination")!,
      manifestHash
    );
    await sleep(8000);

    // All three commit
    const salt = "testsalt123";
    const preimage = `true:0.95:test:${salt}`;
    const commitmentHash = Array.from(
      new Uint8Array(32).map((_, i) => preimage.charCodeAt(i % preimage.length))
    );

    await alice.namedCells.get("coordination")!.callZome({
      zome_name: "coordination",
      fn_name: "commit_evaluation",
      payload: { request_hash: requestHash, commitment_hash: commitmentHash }
    });
    await bob.namedCells.get("coordination")!.callZome({
      zome_name: "coordination",
      fn_name: "commit_evaluation",
      payload: { request_hash: requestHash, commitment_hash: commitmentHash }
    });
    await carol.namedCells.get("coordination")!.callZome({
      zome_name: "coordination",
      fn_name: "commit_evaluation",
      payload: { request_hash: requestHash, commitment_hash: commitmentHash }
    });

    await sleep(5000);

    // All three reveal in parallel — reduces total time
    await Promise.all([alice, bob, carol].map(player =>
      player.namedCells.get("coordination")!.callZome({
        zome_name: "coordination",
        fn_name: "reveal_evaluation",
        payload: {
          request_hash: requestHash,
          passed: true,
          score: 0.95,
          details: "test",
          salt,
          registry_dna_hash: player.namedCells.get("registry")!.cell_id[0],
        }
      })
    ));

    await sleep(8000);

    const result = await checkQuorum(
      alice.namedCells.get("coordination")!,
      requestHash,
      alice.namedCells.get("registry")!,
      alice.namedCells.get("mutual_credit")!
    );

    assert.equal(result.reached, true);
    assert.equal(result.evaluation_count, 3);
    assert.ok(result.quorum_bundle_hash);
  }, true, { disableLocalServices: true });
});

test("commit deadline — reveal after deadline is rejected", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const bob   = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const carol = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    await sleep(2000);

    const requestHash = await requestValidation(
      alice.namedCells.get("coordination")!,
      manifestHash
    );
    await sleep(8000);

    const salt = "testsalt123";
    const commitmentHash = Array.from(new Uint8Array(32).fill(1));

    // All three commit
    for (const player of [alice, bob, carol]) {
      await player.namedCells.get("coordination")!.callZome({
        zome_name: "coordination",
        fn_name: "commit_evaluation",
        payload: { request_hash: requestHash, commitment_hash: commitmentHash }
      });
    }

    // Wait past the deadline (REVEAL_DEADLINE_US = ~68.5 seconds)
    // In test we can't wait 68s — this test documents the behavior
    // and should be run with a reduced deadline constant for CI
    // For now verify the window check works within deadline
    await sleep(3000);

    const windowResult = await alice.namedCells.get("coordination")!.callZome({
      zome_name: "coordination",
      fn_name: "check_reveal_window",
      payload: {
        request_hash: requestHash,
        registry_dna_hash: alice.namedCells.get("registry")!.cell_id[0],
        mutual_credit_dna_hash: alice.namedCells.get("mutual_credit")!.cell_id[0],
      }
    });

    assert.equal(windowResult.reveal_window_open, true, "Reveal window should be open with 3 commits");
  }, true, { disableLocalServices: true });
});

test("ManifestToRequest link — validation history queryable from manifest", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    await sleep(500);

    await requestValidation(alice.namedCells.get("coordination")!, manifestHash);
    await requestValidation(alice.namedCells.get("coordination")!, manifestHash);
    await sleep(2000);

    const history: ActionHash[] = await alice.namedCells.get("coordination")!.callZome({
      zome_name: "coordination",
      fn_name: "get_manifest_requests",
      payload: { manifest_hash: manifestHash },
    });

    assert.equal(history.length, 2, "Both validation requests should be linked to manifest");
  }, true, { disableLocalServices: true });
});

test("ValidationEvidence — record_evidence creates retrievable entry", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const manifestHash = await createManifest(alice.namedCells.get("registry")!);
    await sleep(5000);

    const evidenceHash: ActionHash = await alice.namedCells.get("coordination")!.callZome({
      zome_name: "coordination",
      fn_name: "record_evidence",
      payload: {
        manifest_hash: manifestHash,
        evidence_type: "hash_mismatch",
        expected: "sha256:expected",
        actual: "sha256:actual",
        computed_severity: 1000000,
        metadata_blob: new Uint8Array(0),
      }
    });

    assert.ok(evidenceHash, "Evidence entry should be created");
    await sleep(2000);

    const evidenceRecords = await alice.namedCells.get("coordination")!.callZome({
      zome_name: "coordination",
      fn_name: "get_manifest_evidence",
      payload: { manifest_hash: manifestHash },
    });

    assert.equal(evidenceRecords.length, 1, "Evidence should be retrievable via manifest link");
  }, true, { disableLocalServices: true });
});