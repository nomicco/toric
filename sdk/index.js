/**
 * Toric Connector SDK
 *
 * Register AI models, datasets, training runs, and inference endpoints
 * on the Toric network. Use this SDK to build push connectors for any
 * AI infrastructure — cloud, decentralized, or local.
 *
 * Usage (recommended — auto-connects and manages agent identity):
 *   import { Toric } from '@toric/connector-sdk';
 *   const toric = await Toric.connect();
 *   const { manifest_hash } = await toric.registerModel({ ... });
 *
 * Usage (manual — if you manage your own API connection):
 *   const toric = new Toric('http://localhost:3000');
 *   const { manifest_hash } = await toric.registerModel({ ... });
 */

export class Toric {
  #agentPubKey = null;

  constructor(apiUrl = 'http://localhost:3000') {
    this.apiUrl = apiUrl.replace(/\/$/, '');
  }

  // ─────────────────────────────────────────────
  // Connection factory
  // ─────────────────────────────────────────────

  /**
   * Connect to a running Toric node and return an initialized SDK instance.
   * Handles agent key retrieval automatically.
   *
   * @param {object} [opts]
   * @param {string} [opts.apiUrl]     - Toric API URL (default: http://localhost:3000)
   * @param {number} [opts.retries]    - connection retries (default: 5)
   * @param {number} [opts.retryDelay] - ms between retries (default: 3000)
   * @returns {Toric}
   *
   * @example
   * const toric = await Toric.connect();
   * const { manifest_hash } = await toric.registerModel({ ... });
   */
  static async connect(opts = {}) {
    const apiUrl = opts.apiUrl || process.env.TORIC_API || 'http://localhost:3000';
    const retries = opts.retries ?? 5;
    const retryDelay = opts.retryDelay ?? 3000;

    const instance = new Toric(apiUrl);

    // Wait for API to be ready
    for (let i = 0; i < retries; i++) {
      try {
        await instance.#get('/status');
        break;
      } catch(e) {
        if (i === retries - 1) throw new ToricError(
          `Cannot connect to Toric API at ${apiUrl} after ${retries} attempts`,
          0, '/status'
        );
        console.log(`[toric] Waiting for API... (${i + 1}/${retries})`);
        await new Promise(r => setTimeout(r, retryDelay));
      }
    }

    // Fetch agent pubkey from live conductor
    const { agent } = await instance.#get('/agent/me');
    instance.#agentPubKey = agent;

    console.log(`[toric] Connected — agent: ${agent.slice(0, 20)}...`);
    return instance;
  }

  // ─────────────────────────────────────────────
  // Agent identity
  // ─────────────────────────────────────────────

  /**
   * Returns the agent pubkey for this node.
   * Only available after Toric.connect().
   */
  get agentPubKey() {
    return this.#agentPubKey;
  }

  /**
   * Fetch current reputation score for this node's agent.
   */
  async myReputation() {
    if (!this.#agentPubKey) throw new ToricError('Not connected — use Toric.connect()', 0, '/agent/me');
    return this.#get(`/agent/${this.#agentPubKey}/reputation`);
  }

  /**
   * Fetch current credit balance for this node's agent.
   */
  async myBalance() {
    if (!this.#agentPubKey) throw new ToricError('Not connected — use Toric.connect()', 0, '/agent/me');
    return this.#get(`/agent/${this.#agentPubKey}/balance`);
  }

  /**
   * Fetch manifests registered by this node's agent.
   */
  async myManifests() {
    if (!this.#agentPubKey) throw new ToricError('Not connected — use Toric.connect()', 0, '/agent/me');
    return this.#get(`/agent/${this.#agentPubKey}/manifests`);
  }

  // ─────────────────────────────────────────────
  // Core API
  // ─────────────────────────────────────────────

  async #post(path, body) {
    const res = await fetch(`${this.apiUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const json = await res.json();
    if (!res.ok) throw new ToricError(json.error || 'API error', res.status, path);
    return json;
  }

  async #get(path) {
    const res = await fetch(`${this.apiUrl}${path}`);
    const json = await res.json();
    if (!res.ok) throw new ToricError(json.error || 'API error', res.status, path);
    return json;
  }

  // ─────────────────────────────────────────────
  // Status
  // ─────────────────────────────────────────────

  async status() {
    return this.#get('/status');
  }

  // ─────────────────────────────────────────────
  // Models
  // ─────────────────────────────────────────────

  /**
   * Register an AI model manifest.
   *
   * @param {object} opts
   * @param {string} opts.content_hash        - SHA256 of model weights (required)
   * @param {string} opts.architecture        - e.g. "llama", "mistral", "gpt2" (required)
   * @param {number} opts.parameter_count     - number of parameters (required)
   * @param {string} [opts.connector_source]  - "huggingface", "bittensor", "akash", "local", "toric"
   * @param {string[]} [opts.upstream_hashes] - manifest hashes of training runs, datasets
   * @param {string} [opts.version]           - git commit hash or version string
   * @param {string} [opts.description]
   * @param {string} [opts.license]           - e.g. "apache-2.0", "mit"
   * @param {number} [opts.artifact_timestamp]- unix timestamp
   * @param {string} [opts.fine_tuned_from]   - base model identifier
   * @param {string} [opts.training_data]     - description of training data
   * @param {string} [opts.quantization]      - e.g. "fp16", "int8", "gguf"
   * @param {number} [opts.context_length]
   * @param {string[]} [opts.tags]
   * @param {boolean} [opts.request_validation] - auto-request validation (default: true)
   * @returns {{ manifest_hash, validation_request_hash }}
   */
  async registerModel(opts) {
    const blob = {
      blob_type: 'ai_model',
      content_hash: opts.content_hash,
      architecture: opts.architecture,
      parameter_count: opts.parameter_count,
      upstream_manifest_hashes: opts.upstream_hashes || [],
      connector_source: opts.connector_source || 'local',
      version: opts.version || null,
      description: opts.description || null,
      license: opts.license || null,
      artifact_timestamp: opts.artifact_timestamp || Math.floor(Date.now() / 1000),
      fine_tuned_from: opts.fine_tuned_from || null,
      training_data_description: opts.training_data || null,
      quantization: opts.quantization || null,
      context_length: opts.context_length || null,
      tags: opts.tags || [],
    };

    const { hash: manifest_hash } = await this.#post('/manifest', { blob });
    let validation_request_hash = null;

    if (opts.request_validation !== false) {
      const { hash } = await this.#post('/validation/request', {
        manifest_hash,
        metadata: { connector_source: opts.connector_source || 'local' },
      });
      validation_request_hash = hash;
    }

    return { manifest_hash, validation_request_hash };
  }

  // ─────────────────────────────────────────────
  // Datasets
  // ─────────────────────────────────────────────

  /**
   * Register a dataset manifest.
   *
   * @param {object} opts
   * @param {string} opts.content_hash     - SHA256 of dataset files (required)
   * @param {string} opts.dataset_type     - "instruction", "pretraining", "rlhf", "eval" (required)
   * @param {number} [opts.record_count]   - number of records/examples
   * @param {string} [opts.connector_source]
   * @param {string[]} [opts.upstream_hashes]
   * @param {string} [opts.description]
   * @param {string} [opts.license]
   * @param {number} [opts.artifact_timestamp]
   * @param {string[]} [opts.tags]
   * @param {boolean} [opts.request_validation]
   * @returns {{ manifest_hash, validation_request_hash }}
   */
  async registerDataset(opts) {
    const blob = {
      blob_type: 'dataset',
      content_hash: opts.content_hash,
      dataset_type: opts.dataset_type,
      record_count: opts.record_count || null,
      connector_source: opts.connector_source || 'local',
      upstream_manifest_hashes: opts.upstream_hashes || [],
      description: opts.description || null,
      license: opts.license || null,
      artifact_timestamp: opts.artifact_timestamp || Math.floor(Date.now() / 1000),
      tags: opts.tags || [],
    };

    const { hash: manifest_hash } = await this.#post('/manifest', { blob });
    let validation_request_hash = null;

    if (opts.request_validation !== false) {
      const { hash } = await this.#post('/validation/request', {
        manifest_hash,
        metadata: { connector_source: opts.connector_source || 'local' },
      });
      validation_request_hash = hash;
    }

    return { manifest_hash, validation_request_hash };
  }

  // ─────────────────────────────────────────────
  // Training Runs
  // ─────────────────────────────────────────────

  /**
   * Register a training run manifest.
   * Links a dataset and base model to a training process and output model.
   *
   * @param {object} opts
   * @param {string} opts.content_hash          - SHA256 of final checkpoint (required)
   * @param {string[]} [opts.upstream_hashes]   - dataset + base model manifest hashes
   * @param {string} [opts.connector_source]    - "gensyn", "bittensor", "toric", "local"
   * @param {number} [opts.compute_hours]
   * @param {string} [opts.hardware]            - e.g. "8xH100", "4xA100"
   * @param {string} [opts.framework]           - "pytorch", "jax", "tensorflow"
   * @param {object} [opts.hyperparameters]     - will be JSON stringified
   * @param {number} [opts.artifact_timestamp]
   * @param {string[]} [opts.tags]
   * @param {boolean} [opts.request_validation]
   * @returns {{ manifest_hash, validation_request_hash }}
   */
  async registerTrainingRun(opts) {
    const blob = {
      blob_type: 'training_run',
      content_hash: opts.content_hash,
      upstream_manifest_hashes: opts.upstream_hashes || [],
      connector_source: opts.connector_source || 'local',
      compute_hours: opts.compute_hours || null,
      hardware: opts.hardware || null,
      framework: opts.framework || null,
      hyperparameters: opts.hyperparameters
        ? JSON.stringify(opts.hyperparameters) : null,
      artifact_timestamp: opts.artifact_timestamp || Math.floor(Date.now() / 1000),
      tags: opts.tags || [],
    };

    const { hash: manifest_hash } = await this.#post('/manifest', { blob });
    let validation_request_hash = null;

    if (opts.request_validation !== false) {
      const { hash } = await this.#post('/validation/request', {
        manifest_hash,
        metadata: { connector_source: opts.connector_source || 'local' },
      });
      validation_request_hash = hash;
    }

    return { manifest_hash, validation_request_hash };
  }

  // ─────────────────────────────────────────────
  // Inference Endpoints
  // ─────────────────────────────────────────────

  /**
   * Register an inference endpoint.
   *
   * @param {object} opts
   * @param {string} opts.content_hash        - hash of running container/image (required)
   * @param {string} opts.model_manifest_hash - manifest hash of the model being served (required)
   * @param {string} [opts.connector_source]  - "akash", "runpod", "local"
   * @param {string} [opts.endpoint_type]     - "http", "websocket", "grpc"
   * @param {number} [opts.artifact_timestamp]
   * @param {string[]} [opts.tags]
   * @param {boolean} [opts.request_validation]
   * @returns {{ manifest_hash, validation_request_hash }}
   */
  async registerEndpoint(opts) {
    const blob = {
      blob_type: 'inference_endpoint',
      content_hash: opts.content_hash,
      model_manifest_hash: opts.model_manifest_hash,
      upstream_manifest_hashes: [opts.model_manifest_hash],
      connector_source: opts.connector_source || 'local',
      endpoint_type: opts.endpoint_type || 'http',
      artifact_timestamp: opts.artifact_timestamp || Math.floor(Date.now() / 1000),
      tags: opts.tags || [],
    };

    const { hash: manifest_hash } = await this.#post('/manifest', { blob });
    let validation_request_hash = null;

    if (opts.request_validation !== false) {
      const { hash } = await this.#post('/validation/request', {
        manifest_hash,
        metadata: { connector_source: opts.connector_source || 'local' },
      });
      validation_request_hash = hash;
    }

    return { manifest_hash, validation_request_hash };
  }

  // ─────────────────────────────────────────────
  // Warrants
  // ─────────────────────────────────────────────

  /**
   * File a warrant against a manifest.
   * Evidence is recorded first — severity is computed from measurements,
   * never chosen by the caller.
   *
   * @param {object} opts
   * @param {string} opts.manifest_hash   - hash of the manifest being reported
   * @param {string} opts.reason          - "tampered_weights" | "misrepresented_performance" |
   *                                        "false_attestation" | "connector_misbehavior"
   * @param {string} opts.expected        - what the manifest claimed (hash, score, field count)
   * @param {string} opts.actual          - what was measured
   * @param {object} [opts.metadata]      - additional measurement context
   * @param {string} [opts.description]   - human-readable explanation
   * @returns {{ evidence_hash, warrant_hash, computed_severity }}
   */
  async fileWarrant(opts) {
    const evidenceTypeMap = {
      tampered_weights:           'hash_mismatch',
      misrepresented_performance: 'performance_delta',
      connector_misbehavior:      'connector_output',
      false_attestation:          'hash_mismatch',
    };
    const evidence_type = evidenceTypeMap[opts.reason] || 'hash_mismatch';

    // Step 1 — record evidence, backend computes severity from measurements
    const evidenceRes = await this.#post('/evidence', {
      manifest_hash: opts.manifest_hash,
      evidence_type,
      expected: String(opts.expected),
      actual: String(opts.actual),
      metadata: opts.metadata || {},
    });
    const { hash: evidence_hash, computed_severity } = evidenceRes;

    // Step 2 — file warrant pointing at evidence entry
    const blobTypeMap = {
      tampered_weights:           'tampered_weights',
      misrepresented_performance: 'misrepresented_performance',
      connector_misbehavior:      'connector_misbehavior',
      false_attestation:          'false_attestation',
    };

    const blob = {
      blob_type: blobTypeMap[opts.reason] || 'tampered_weights',
      evidence_hash,
      computed_severity,
      description: opts.description || null,
    };

    if (opts.reason === 'tampered_weights') {
      blob.expected_hash = String(opts.expected);
      blob.found_hash    = String(opts.actual);
    }
    if (opts.reason === 'misrepresented_performance') {
      blob.claimed_score  = parseFloat(opts.expected);
      blob.actual_score   = parseFloat(opts.actual);
      blob.benchmark_type = opts.metadata?.benchmark_type || 'custom';
    }
    if (opts.reason === 'connector_misbehavior') {
      blob.connector_manifest_hash = opts.metadata?.connector_manifest_hash;
      blob.misbehavior_type        = opts.metadata?.misbehavior_type || 'schema_violation';
    }
    if (opts.reason === 'false_attestation') {
      blob.disputed_attestation_hash = opts.metadata?.disputed_attestation_hash;
    }

    const { hash: warrant_hash } = await this.#post('/warrant', {
      manifest_hash: opts.manifest_hash,
      blob,
    });

    return { evidence_hash, warrant_hash, computed_severity };
  }

  // ─────────────────────────────────────────────
  // Queries
  // ─────────────────────────────────────────────

  async getManifest(hash) {
    return this.#get(`/manifest/${hash}`);
  }

  async getAttestations(manifest_hash) {
    return this.#get(`/manifest/${manifest_hash}/attestations`);
  }

  async getWarrants(manifest_hash) {
    return this.#get(`/manifest/${manifest_hash}/warrants`);
  }

  async getUpstreams(manifest_hash) {
    return this.#get(`/manifest/${manifest_hash}/upstreams`);
  }

  async getDerivatives(manifest_hash) {
    return this.#get(`/manifest/${manifest_hash}/derivatives`);
  }

  async getValidators(manifest_hash) {
    return this.#get(`/manifest/${manifest_hash}/validators`);
  }

  async getValidationHistory(manifest_hash) {
    return this.#get(`/manifest/${manifest_hash}/validation-history`);
  }

  async getEvidence(manifest_hash) {
    return this.#get(`/manifest/${manifest_hash}/evidence`);
  }

  async getConvergence(content_hash) {
    return this.#get(`/content/${content_hash}/manifests`);
  }

  async getReputation(agent_pubkey) {
    return this.#get(`/agent/${agent_pubkey}/reputation`);
  }

  async getAgentAttestations(agent_pubkey) {
    return this.#get(`/agent/${agent_pubkey}/attestations`);
  }

  async getAgentManifests(agent_pubkey) {
    return this.#get(`/agent/${agent_pubkey}/manifests`);
  }

  async getNetworkState() {
    return this.#get('/network/state');
  }

  /**
   * Get the φ-weighted trust score for a manifest.
   * Includes direct attestations, upstream provenance, convergence, and warrant penalties.
   * Score is 0.0–1.0. Passes threshold is φ⁻¹ ≈ 0.618.
   */
  async getTrustScore(manifest_hash) {
    const result = await this.#get(`/manifest/${manifest_hash}/trust-score`);
    const score100 = Math.round(result.score * 100);
    const status = result.passes
      ? 'verified'
      : result.attestation_count === 0
        ? 'unverified'
        : 'failing';
    return {
      score: score100,
      raw: result.score,
      status,
      attestations: result.attestation_count,
      passes: result.passes,
    };
  }
}

// ─────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────

export class ToricError extends Error {
  constructor(message, status, path) {
    super(message);
    this.name = 'ToricError';
    this.status = status;
    this.path = path;
  }
}

/**
 * Hash a local file for use as content_hash.
 * Node.js only.
 */
export async function hashFile(filePath) {
  const { createHash } = await import('crypto');
  const { createReadStream } = await import('fs');
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    stream.on('data', d => hash.update(d));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

/**
 * Hash a directory of files (sorted, deterministic).
 * Useful for datasets stored as a folder.
 */
export async function hashDirectory(dirPath) {
  const { createHash } = await import('crypto');
  const { readdirSync, statSync } = await import('fs');
  const { join } = await import('path');

  function collectFiles(dir) {
    const entries = readdirSync(dir).sort();
    const files = [];
    for (const entry of entries) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        files.push(...collectFiles(full));
      } else {
        files.push(full);
      }
    }
    return files;
  }

  const files = collectFiles(dirPath);
  const hash = createHash('sha256');
  for (const f of files) {
    const fileHash = await hashFile(f);
    hash.update(`${f}:${fileHash}\n`);
  }
  return hash.digest('hex');
}

export default Toric;