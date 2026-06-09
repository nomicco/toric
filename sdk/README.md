# @poai/connector-sdk

Register AI models, datasets, training runs, and inference endpoints on the PoAI network.

## Install

```bash
npm install @poai/connector-sdk
```

## Quick Start

```js
import { PoAI } from '@poai/connector-sdk';

const poai = new PoAI('http://localhost:3000');

// Register a model
const { manifest_hash } = await poai.registerModel({
  content_hash: 'abc123...',
  architecture: 'llama',
  parameter_count: 7_000_000_000,
  connector_source: 'local',
  description: 'My fine-tuned model',
  license: 'apache-2.0',
  tags: ['my-project'],
});

console.log('Registered:', manifest_hash);

// Check trust score
const trust = await poai.getTrustScore(manifest_hash);
console.log('Trust:', trust); // { score: 0, status: 'unverified', attestations: 0, warrants: 0 }
```

## API

### `new PoAI(apiUrl)`

Create a client. `apiUrl` defaults to `http://localhost:3000`.

---

### `poai.registerModel(opts)` → `{ manifest_hash, validation_request_hash }`

Register an AI model.

| Field | Required | Description |
|-------|----------|-------------|
| `content_hash` | ✓ | SHA256 of model weights |
| `architecture` | ✓ | e.g. `"llama"`, `"mistral"`, `"gpt2"` |
| `parameter_count` | ✓ | Number of parameters |
| `connector_source` | | `"huggingface"`, `"bittensor"`, `"akash"`, `"poai"`, `"local"` |
| `upstream_hashes` | | Manifest hashes of training runs or datasets |
| `version` | | Git commit hash or version string |
| `description` | | |
| `license` | | e.g. `"apache-2.0"`, `"mit"` |
| `artifact_timestamp` | | Unix timestamp (defaults to now) |
| `fine_tuned_from` | | Base model identifier |
| `training_data` | | Description of training data |
| `quantization` | | e.g. `"fp16"`, `"int8"`, `"gguf"` |
| `context_length` | | |
| `tags` | | Array of strings |
| `request_validation` | | Auto-request validation (default: `true`) |

---

### `poai.registerDataset(opts)` → `{ manifest_hash, validation_request_hash }`

| Field | Required | Description |
|-------|----------|-------------|
| `content_hash` | ✓ | SHA256 of dataset files |
| `dataset_type` | ✓ | `"instruction"`, `"pretraining"`, `"rlhf"`, `"eval"` |
| `record_count` | | Number of examples |
| `connector_source` | | |
| `upstream_hashes` | | |
| `description` | | |
| `license` | | |
| `tags` | | |

---

### `poai.registerTrainingRun(opts)` → `{ manifest_hash, validation_request_hash }`

| Field | Required | Description |
|-------|----------|-------------|
| `content_hash` | ✓ | SHA256 of final checkpoint |
| `upstream_hashes` | | Dataset + base model manifest hashes |
| `connector_source` | | `"gensyn"`, `"bittensor"`, `"poai"`, `"local"` |
| `compute_hours` | | |
| `hardware` | | e.g. `"8xH100"` |
| `framework` | | `"pytorch"`, `"jax"` |
| `hyperparameters` | | Object (will be JSON stringified) |
| `tags` | | |

---

### `poai.registerEndpoint(opts)` → `{ manifest_hash, validation_request_hash }`

| Field | Required | Description |
|-------|----------|-------------|
| `content_hash` | ✓ | Hash of running container/image |
| `model_manifest_hash` | ✓ | Manifest hash of the model being served |
| `connector_source` | | `"akash"`, `"runpod"`, `"local"` |
| `endpoint_type` | | `"http"`, `"websocket"`, `"grpc"` |
| `tags` | | |

---

### `poai.fileWarrant(opts)` → `{ warrant_hash }`

Report a tampered or fraudulent model.

| Field | Required | Description |
|-------|----------|-------------|
| `manifest_hash` | ✓ | Hash of the manifest being reported |
| `reason` | ✓ | `"tampered_weights"`, `"misrepresented_performance"`, `"false_attestation"` |
| `details` | ✓ | Human-readable explanation |
| `evidence` | | JSON string with supporting evidence |

---

### `poai.getTrustScore(manifest_hash)` → `{ score, status, attestations, warrants }`

- `score`: 0–100
- `status`: `"unverified"`, `"verified"`, `"disputed"`, `"failing"`

---

### Utilities

```js
import { hashFile, hashDirectory } from '@poai/connector-sdk';

// Hash a single weights file
const hash = await hashFile('./model.safetensors');

// Hash a directory of dataset files (deterministic, sorted)
const datasetHash = await hashDirectory('./my-dataset/');
```

## Building a Connector

A connector is any script that calls the SDK. Example — Akash inference endpoint connector:

```js
import { PoAI, hashFile } from '@poai/connector-sdk';
import crypto from 'crypto';

const poai = new PoAI(process.env.POAI_API || 'http://localhost:3000');

// 1. Get the model being served
const res = await fetch('https://my-akash-deployment.net/api/tags');
const { models } = await res.json();
const modelName = models[0].name; // e.g. "llama3.1:8b"

// 2. Hash the running container (use image digest if available)
const content_hash = crypto.createHash('sha256')
  .update(`akash:${modelName}:${Date.now()}`)
  .digest('hex');

// 3. Register
const { manifest_hash } = await poai.registerEndpoint({
  content_hash,
  model_manifest_hash: process.env.MODEL_MANIFEST_HASH,
  connector_source: 'akash',
  tags: [`model:${modelName}`, `akash_owner:${process.env.AKASH_ADDRESS}`],
});

console.log('Registered endpoint:', manifest_hash);
```

## Full Provenance Chain

```js
// 1. Register dataset
const { manifest_hash: dataset_hash } = await poai.registerDataset({
  content_hash: await hashDirectory('./my-dataset'),
  dataset_type: 'instruction',
  record_count: 50000,
  license: 'cc-by-4.0',
});

// 2. Register training run (links to dataset)
const { manifest_hash: run_hash } = await poai.registerTrainingRun({
  content_hash: await hashFile('./checkpoints/final.pt'),
  upstream_hashes: [dataset_hash],
  connector_source: 'local',
  hardware: '4xA100',
  framework: 'pytorch',
  hyperparameters: { lr: 2e-5, epochs: 3, batch_size: 32 },
});

// 3. Register final model (links to training run)
const { manifest_hash: model_hash } = await poai.registerModel({
  content_hash: await hashFile('./model.safetensors'),
  architecture: 'llama',
  parameter_count: 7_000_000_000,
  upstream_hashes: [run_hash, dataset_hash],
  connector_source: 'poai',
  license: 'apache-2.0',
});

console.log('Full provenance chain registered');
console.log('Model:', model_hash);
```
