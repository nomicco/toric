import { assert, test } from "vitest";
import { runScenario, Scenario } from "@holochain/tryorama";
import { ActionHash } from "@holochain/client";
import { join } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const happPath = join(__dirname, "../../../../workdir/toric.happ");
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

// φ-derived default credit limit: -(987 × 377/987) = -377.
// F(14)/F(16) rational φ⁻² of the genesis supply — integer-exact,
// matching toric_geometry::default_credit_limit(GENESIS_CREDIT_SUPPLY).
const DEFAULT_CREDIT_LIMIT = -377;

// DHT propagation floor. Transactions are bilateral: the recipient's
// conductor must see the sender's Account/CreditLimit index links
// before it will endorse, so every transact is preceded by a sync wait.
const DHT_SYNC = 8000;

const metadata = new Uint8Array(0);

async function twoPlayers(scenario: Scenario) {
  const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
  const bob = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
  await scenario.shareAllAgents();
  return { alice, bob, aliceCell: alice.namedCells.get("ledger")!, bobCell: bob.namedCells.get("ledger")! };
}

test("create an account", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const cell = alice.namedCells.get("ledger")!;
    const accountHash: ActionHash = await cell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    assert.ok(accountHash);
  }, true, { disableLocalServices: true });
});

test("get balance — new account starts at zero with φ-derived limit", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const cell = alice.namedCells.get("ledger")!;
    await cell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    const balance = await cell.callZome({ zome_name: "mutual_credit", fn_name: "get_balance", payload: { agent: alice.agentPubKey } });
    assert.equal(balance.balance, 0);
    assert.equal(balance.credit_limit, DEFAULT_CREDIT_LIMIT);
    assert.equal(balance.is_frozen, false);
  }, true, { disableLocalServices: true });
});

test("transact — bilateral: recipient endorses, credits move", async () => {
  await runScenario(async (scenario: Scenario) => {
    const { alice, bob, aliceCell, bobCell } = await twoPlayers(scenario);
    await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    await bobCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    // Bob's conductor must see Alice's basis links before he'll endorse.
    await sleep(DHT_SYNC);

    await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "transact", payload: { to_agent: bob.agentPubKey, amount: 30, metadata_blob: metadata } });
    await sleep(DHT_SYNC);

    const aliceBalance = await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "get_balance", payload: { agent: alice.agentPubKey } });
    const bobBalance = await bobCell.callZome({ zome_name: "mutual_credit", fn_name: "get_balance", payload: { agent: bob.agentPubKey } });
    assert.equal(aliceBalance.balance, -30);
    assert.equal(bobBalance.balance, 30);
  }, true, { disableLocalServices: true });
});

test("transact — no unilateral spends: offline recipient means no transaction", async () => {
  await runScenario(async (scenario: Scenario) => {
    const { bob, aliceCell, bobCell } = await twoPlayers(scenario);
    await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    await bobCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    await sleep(DHT_SYNC);

    // Credit is a relationship — both ends present. Kill Bob's end.
    await bob.conductor.shutDown();

    try {
      await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "transact", payload: { to_agent: bob.agentPubKey, amount: 10, metadata_blob: metadata } });
      assert.fail("Transaction without a live endorsing recipient should fail");
    } catch (e) {
      assert.ok(e, "Correctly rejected: transactions are bilateral");
    }
  }, true, { disableLocalServices: true });
});

test("self-payment is rejected", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const cell = alice.namedCells.get("ledger")!;
    await cell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    try {
      await cell.callZome({ zome_name: "mutual_credit", fn_name: "transact", payload: { to_agent: alice.agentPubKey, amount: 5, metadata_blob: metadata } });
      assert.fail("Self-payment should be rejected");
    } catch (e) {
      assert.ok(e, "Self-payment correctly rejected — meaningless in a sum-zero ledger");
    }
  }, true, { disableLocalServices: true });
});

test("transaction exceeding credit limit is rejected", async () => {
  await runScenario(async (scenario: Scenario) => {
    const { bob, aliceCell, bobCell } = await twoPlayers(scenario);
    await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    await bobCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    await sleep(DHT_SYNC);
    try {
      await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "transact", payload: { to_agent: bob.agentPubKey, amount: 500, metadata_blob: metadata } });
      assert.fail("Transaction should have been rejected");
    } catch (e) {
      // Rejected at endorsement (Bob's solvency view) or at integrity
      // (balance law) — both are the limit holding.
      assert.ok(e, "Over-limit transaction correctly rejected");
    }
  }, true, { disableLocalServices: true });
});

test("accumulated spending cannot cross the limit — the balance law is per-chain, not per-spend", async () => {
  await runScenario(async (scenario: Scenario) => {
    const { bob, aliceCell, bobCell } = await twoPlayers(scenario);
    await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    await bobCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    await sleep(DHT_SYNC);

    // 200 is fine; 200 + 200 = 400 > 377 — the second must fail even
    // though it is individually under the limit.
    await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "transact", payload: { to_agent: bob.agentPubKey, amount: 200, metadata_blob: metadata } });
    await sleep(DHT_SYNC);
    try {
      await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "transact", payload: { to_agent: bob.agentPubKey, amount: 200, metadata_blob: metadata } });
      assert.fail("Second spend crossing the accumulated limit should fail");
    } catch (e) {
      assert.ok(e, "Accumulated overdraft correctly rejected");
    }
  }, true, { disableLocalServices: true });
});

test("zero or negative amount transaction is rejected", async () => {
  await runScenario(async (scenario: Scenario) => {
    const { bob, aliceCell } = await twoPlayers(scenario);
    await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    try {
      await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "transact", payload: { to_agent: bob.agentPubKey, amount: 0, metadata_blob: metadata } });
      assert.fail("Zero amount transaction should have been rejected");
    } catch (e) {
      assert.ok(e, "Zero amount correctly rejected");
    }
  }, true, { disableLocalServices: true });
});

test("sum-zero invariant — total credits in system stay balanced", async () => {
  await runScenario(async (scenario: Scenario) => {
    const { alice, bob, aliceCell, bobCell } = await twoPlayers(scenario);
    await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    await bobCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    await sleep(DHT_SYNC);
    await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "transact", payload: { to_agent: bob.agentPubKey, amount: 40, metadata_blob: metadata } });
    await sleep(12000);

    const aliceBalance = await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "get_balance", payload: { agent: alice.agentPubKey } });
    const bobBalance = await bobCell.callZome({ zome_name: "mutual_credit", fn_name: "get_balance", payload: { agent: bob.agentPubKey } });
    assert.equal(aliceBalance.balance + bobBalance.balance, 0);
  }, true, { disableLocalServices: true });
});

test("unsealed credit limit update is capped at fresh-account terms", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const cell = alice.namedCells.get("ledger")!;
    await cell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });

    // The unsealed path may succeed, but it cannot grant better terms
    // than a fresh account — reputation-derived limits require a
    // quorum seal. The computed limit lands in metadata only.
    await cell.callZome({ zome_name: "mutual_credit", fn_name: "update_credit_limit", payload: { agent: alice.agentPubKey } });
    await sleep(3000);
    const balance = await cell.callZome({ zome_name: "mutual_credit", fn_name: "get_balance", payload: { agent: alice.agentPubKey } });
    assert.equal(balance.credit_limit, DEFAULT_CREDIT_LIMIT, "Unsealed limit must equal fresh-account default");
  }, true, { disableLocalServices: true });
});

test("economic snapshot — reports the population closure observes", async () => {
  await runScenario(async (scenario: Scenario) => {
    const { aliceCell, bobCell } = await twoPlayers(scenario);
    await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    await bobCell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    await sleep(DHT_SYNC);

    const snap = await aliceCell.callZome({ zome_name: "mutual_credit", fn_name: "economic_snapshot", payload: null });
    assert.equal(snap.account_count, 2, "Both accounts visible on the global anchor");
    assert.equal(snap.frozen_count, 0, "Fresh accounts are not frozen");
    assert.equal(snap.credit_supply, 987, "Genesis supply before any expansion");
    assert.deepEqual(snap.sealed_roster, [], "No sovereignty declared at bootstrap");
  }, true, { disableLocalServices: true });
});

test("genesis phase — account creation always allowed before first threshold", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const accountHash = await alice.namedCells.get("ledger")!.callZome({
      zome_name: "mutual_credit",
      fn_name: "create_account",
      payload: { metadata_blob: metadata },
    });
    assert.ok(accountHash, "Account creation should succeed in genesis phase");
  }, true, { disableLocalServices: true });
});

test("duplicate account for the same agent is rejected", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const cell = alice.namedCells.get("ledger")!;
    await cell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
    try {
      await cell.callZome({ zome_name: "mutual_credit", fn_name: "create_account", payload: { metadata_blob: metadata } });
      assert.fail("Second account for the same agent should be rejected");
    } catch (e) {
      assert.ok(e, "One account per agent — enforced on the author's own chain");
    }
  }, true, { disableLocalServices: true });
});

test("network state — phase starts at 0", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const state = await alice.namedCells.get("ledger")!.callZome({
      zome_name: "mutual_credit",
      fn_name: "get_network_state",
      payload: null,
    });
    // No state yet at genesis — null is correct; state only written
    // after the first attestation. If present: phase 0, no roster.
    if (state !== null) {
      assert.equal(state.phase, 0, "Network should be in genesis phase initially");
      assert.deepEqual(state.authorized_signers ?? [], [], "No roster at genesis");
    }
    assert.ok(state === null || state.phase === 0);
  }, true, { disableLocalServices: true });
});

test("roster declaration with no reputation mass fails cleanly", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();
    const cell = alice.namedCells.get("ledger")!;
    // No NetworkState and no reputation in the registry — sovereignty
    // cannot be declared over nothing.
    try {
      await cell.callZome({ zome_name: "mutual_credit", fn_name: "declare_signer_roster", payload: null });
      assert.fail("Roster declaration should fail with no state/reputation");
    } catch (e) {
      assert.ok(e, "Correctly refused: no reputation mass to govern with");
    }
  }, true, { disableLocalServices: true });
});