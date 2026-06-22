# Toric

A decentralized AI model trust and validation network built on Holochain. Toric attests to the integrity of AI model manifests through agent-staked commit-reveal quorum, weighted by demonstrated validation history, producing trust scores that are permanent, auditable, and traversable by provenance.

## Architecture

Four DNAs:
- **registry** — manifests, attestations, warrants, trust/reputation scoring
- **coordination** — commit-reveal validation protocol, quorum logic, evidence
- **mutual_credit** — balances, credit limits, Fibonacci expansion, network state
- **identity** — agent manifests, capability indexing

Plus a Node.js validator client (connects directly to a local conductor), an Express API (serves the UI), and a Tauri desktop wrapper.

## Environment Setup

> PREREQUISITE: set up the [Holochain development environment](https://developer.holochain.org/docs/install/).

Enter the nix shell from the project root:

```bash
nix develop
npm install
```

Run all other commands from inside this nix shell.

## Development

```bash
./dev.sh
```

Starts the conductor, API, and validator for local development.

## Validator

Each validator connects directly to its own local conductor — no intermediary required.

```bash
TORIC_AGENT=<your-agent-pubkey> node validator/index.js
```

## Packaging

```bash
npm run package
```

Produces `toric.webhapp` in `workdir/` for distribution via the Holochain Launcher.

## Documentation

- [`@holochain/client`](https://www.npmjs.com/package/@holochain/client) — client library used by the validator and API
- [`hc`](https://github.com/holochain/holochain/tree/develop/crates/hc) — Holochain CLI