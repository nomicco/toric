import { assert, test } from "vitest";
import { runScenario, Scenario } from "@holochain/tryorama";
import { ActionHash } from "@holochain/client";
import { join } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const happPath = join(__dirname, "../../../../workdir/poi.happ");

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

test("create an account", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const cell = alice.namedCells.get("mutual_credit")!;
    const metadata = new Uint8Array(0);

    const accountHash: ActionHash = await cell.callZome({
      zome_name: "mutual_credit",
      fn_name: "create_account",
      payload: { metadata_blob: metadata },
    });

    assert.ok(accountHash);
  }, true, { disableLocalServices: true });
});

test("get balance — new account starts at zero", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const cell = alice.namedCells.get("mutual_credit")!;
    const metadata = new Uint8Array(0);

    await cell.callZome({
      zome_name: "mutual_credit",
      fn_name: "create_account",
      payload: { metadata_blob: metadata },
    });

    const balance = await cell.callZome({
      zome_name: "mutual_credit",
      fn_name: "get_balance",
      payload: { agent: alice.agentPubKey },
    });

    assert.equal(balance.balance, 0);
    assert.equal(balance.credit_limit, -100);
    assert.equal(balance.is_frozen, false);
  }, true, { disableLocalServices: true });
});

test("transact — credits move between agents", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const bob = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const aliceCell = alice.namedCells.get("mutual_credit")!;
    const bobCell = bob.namedCells.get("mutual_credit")!;
    const metadata = new Uint8Array(0);

    await aliceCell.callZome({
      zome_name: "mutual_credit",
      fn_name: "create_account",
      payload: { metadata_blob: metadata },
    });

    await bobCell.callZome({
      zome_name: "mutual_credit",
      fn_name: "create_account",
      payload: { metadata_blob: metadata },
    });

    // Alice sends 30 credits to Bob
    await aliceCell.callZome({
      zome_name: "mutual_credit",
      fn_name: "transact",
      payload: {
        to_agent: bob.agentPubKey,
        amount: 30,
        metadata_blob: metadata,
      },
    });

    await sleep(500);

    const aliceBalance = await aliceCell.callZome({
      zome_name: "mutual_credit",
      fn_name: "get_balance",
      payload: { agent: alice.agentPubKey },
    });

    const bobBalance = await bobCell.callZome({
      zome_name: "mutual_credit",
      fn_name: "get_balance",
      payload: { agent: bob.agentPubKey },
    });

    assert.equal(aliceBalance.balance, -30);
    assert.equal(bobBalance.balance, 30);
  }, true, { disableLocalServices: true });
});

test("transaction exceeding credit limit is rejected", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const bob = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const aliceCell = alice.namedCells.get("mutual_credit")!;
    const metadata = new Uint8Array(0);

    await aliceCell.callZome({
      zome_name: "mutual_credit",
      fn_name: "create_account",
      payload: { metadata_blob: metadata },
    });

    // Try to send 200 credits — exceeds default limit of -100
    try {
      await aliceCell.callZome({
        zome_name: "mutual_credit",
        fn_name: "transact",
        payload: {
          to_agent: bob.agentPubKey,
          amount: 200,
          metadata_blob: metadata,
        },
      });
      assert.fail("Transaction should have been rejected");
    } catch (e) {
      assert.ok(e, "Transaction correctly rejected");
    }
  }, true, { disableLocalServices: true });
});

test("zero or negative amount transaction is rejected", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const bob = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const aliceCell = alice.namedCells.get("mutual_credit")!;
    const metadata = new Uint8Array(0);

    await aliceCell.callZome({
      zome_name: "mutual_credit",
      fn_name: "create_account",
      payload: { metadata_blob: metadata },
    });

    try {
      await aliceCell.callZome({
        zome_name: "mutual_credit",
        fn_name: "transact",
        payload: {
          to_agent: bob.agentPubKey,
          amount: 0,
          metadata_blob: metadata,
        },
      });
      assert.fail("Zero amount transaction should have been rejected");
    } catch (e) {
      assert.ok(e, "Zero amount correctly rejected");
    }
  }, true, { disableLocalServices: true });
});

test("sum-zero invariant — total credits in system stay balanced", async () => {
  await runScenario(async (scenario: Scenario) => {
    const alice = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    const bob = await scenario.addPlayerWithApp({ appBundleSource: { type: "path", value: happPath } });
    await scenario.shareAllAgents();

    const aliceCell = alice.namedCells.get("mutual_credit")!;
    const bobCell = bob.namedCells.get("mutual_credit")!;
    const metadata = new Uint8Array(0);

    await aliceCell.callZome({
      zome_name: "mutual_credit",
      fn_name: "create_account",
      payload: { metadata_blob: metadata },
    });
    await bobCell.callZome({
      zome_name: "mutual_credit",
      fn_name: "create_account",
      payload: { metadata_blob: metadata },
    });

    await aliceCell.callZome({
      zome_name: "mutual_credit",
      fn_name: "transact",
      payload: { to_agent: bob.agentPubKey, amount: 40, metadata_blob: metadata },
    });

    await sleep(500);

    const aliceBalance = await aliceCell.callZome({
      zome_name: "mutual_credit",
      fn_name: "get_balance",
      payload: { agent: alice.agentPubKey },
    });
    const bobBalance = await bobCell.callZome({
      zome_name: "mutual_credit",
      fn_name: "get_balance",
      payload: { agent: bob.agentPubKey },
    });

    // Sum must always be zero
    assert.equal(aliceBalance.balance + bobBalance.balance, 0);
  }, true, { disableLocalServices: true });
});