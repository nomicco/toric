// toric-geometry
//
// φ constants, Fibonacci helpers, and threshold crossing detection.
// No HDI or HDK dependency — pure Rust, safe to use from any zome.
//
// These values were previously duplicated as local `const` definitions
// in registry, coordination, and mutual_credit coordinator zomes.
// Single source of truth is here. When GeometryParams moves to a live
// DHT entry in Phase 5.5, TAU_US and MIN_VALIDATORS migrate there;
// the pure-math constants (φ ratios, Fibonacci) stay here permanently.

use serde::{Serialize, Deserialize};

// ─────────────────────────────────────────────
// φ ratios
// ─────────────────────────────────────────────

/// φ  — the golden ratio.
pub const PHI: f64 = 1.618_033_988_749_895;

/// φ²
pub const PHI_SQ: f64 = 2.618_033_988_749_895;

/// φ³
pub const PHI_CU: f64 = 4.236_067_977_499_790;

/// φ⁴  — quorum threshold exponent; reveal deadline multiplier.
pub const PHI_4: f64 = 6.854_101_966_249_685;

/// φ⁻¹ = 1/φ = φ − 1
pub const INV_PHI: f64 = 0.618_033_988_749_895;

/// φ⁻²
pub const INV_PHI_SQ: f64 = 0.381_966_011_250_105;

/// φ⁻³
pub const INV_PHI_CU: f64 = 0.236_067_977_499_790;

/// φ⁻⁴  — negligibility threshold; upstream contributions below this
/// weight are not worth computing. Also the max-recursion-depth derivation
/// anchor (INV_PHI_4 = NEGLIGIBILITY_THRESHOLD in prior code).
pub const INV_PHI_4: f64 = 0.145_898_033_750_315;

// ─────────────────────────────────────────────
// Genesis economy constants
//
// Moved here from the mutual_credit coordinator so integrity zomes can
// enforce them. They are geometry, not policy: both sit on the
// Fibonacci sequence so every expansion lands on the next Fibonacci
// number.
// ─────────────────────────────────────────────

/// F(16). Genesis credit supply — first expansion lands on F(17) = 1597.
pub const GENESIS_CREDIT_SUPPLY: i64 = 987;

/// F(15). Numerator of the rational φ⁻¹ used in consensus-critical
/// integer arithmetic: 610/987 = F(15)/F(16), error from φ⁻¹ ≈ 5×10⁻⁷.
pub const INV_PHI_NUM: u64 = 610;
/// F(14). Numerator of the rational φ⁻²: 377/987 = F(14)/F(16).
/// Consecutive-but-one Fibonacci ratios give consecutive φ powers over
/// the same denominator: 610/987 → φ⁻¹, 377/987 → φ⁻².
pub const INV_PHI_SQ_NUM: u64 = 377;
/// F(16). Shared denominator of the rational φ powers. Same number as
/// GENESIS_CREDIT_SUPPLY — the tower reuses its own terms.
pub const INV_PHI_DEN: u64 = 987;

/// Default (unsealed) credit limit for a given credit supply:
/// −⌊supply × φ⁻²⌋, the zero-reputation floor. Integer-exact via the
/// rational φ⁻² = F(14)/F(16) = 377/987 so integrity validation never
/// touches floats. Truncated division = floor, so the granted borrowing
/// power is never larger than the real φ⁻² share — conservative in the
/// only direction that matters for a limit.
pub fn default_credit_limit(credit_supply: i64) -> i64 {
    let supply = credit_supply.max(0) as u64;
    -((supply * INV_PHI_SQ_NUM / INV_PHI_DEN) as i64)
}

/// Number of roster signatures required to seal a membrane-crossing
/// entry (CreditLimit, governed NetworkState, PaymentReceipt):
/// ⌈roster × φ⁻¹⌉.
///
/// φ⁻¹, not the φ⁻² quorum threshold — membrane crossings are the
/// highest-privilege writes, so they take the complement threshold:
/// φ⁻² is enough weight to decide, φ⁻¹ = 1 − φ⁻² is enough to
/// re-anchor identity. Integer-exact via F(15)/F(16); ceiling division
/// so the threshold never rounds down to a weaker requirement.
/// Empty roster ⇒ 0 (sealing not yet active — bootstrap).
pub fn seal_threshold(roster_len: usize) -> usize {
    let n = roster_len as u64;
    ((n * INV_PHI_NUM + INV_PHI_DEN - 1) / INV_PHI_DEN) as usize
}

/// True iff n is a Fibonacci number (n ≥ 1). Lets integrity validation
/// enforce that expansion thresholds stay on the sequence.
pub fn is_fibonacci(n: u64) -> bool {
    if n == 0 {
        return false;
    }
    let (mut a, mut b): (u64, u64) = (1, 1);
    while b < n {
        let c = match a.checked_add(b) {
            Some(c) => c,
            None => return false,
        };
        a = b;
        b = c;
    }
    b == n || a == n
}

// ─────────────────────────────────────────────
// Threshold crossing
// ─────────────────────────────────────────────

/// Returns true when `current` has reached or crossed `threshold`.
///
/// Generalized form of the crossing check used throughout the network
/// for Fibonacci expansion gates, quorum weight gates, and drift
/// accumulator gates. Same correctness properties everywhere: monotonic
/// accumulator, fires once on the event where value first meets threshold.
///
/// Edge case: equal values count as crossed. This matches the existing
/// behavior of `attestation_count >= current_threshold` in
/// `on_attestation_created` and `commitment_weight >= phi_4_threshold`
/// in `check_quorum`.
pub fn threshold_crossed<T: PartialOrd>(current: T, threshold: T) -> bool {
    current >= threshold
}

// ─────────────────────────────────────────────
// Fibonacci helpers
// ─────────────────────────────────────────────

/// Returns the smallest Fibonacci number strictly greater than `n`.
///
/// Used to advance to the next expansion threshold after a crossing.
/// Sequence begins 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233,
/// 377, 610, 987, ... (GENESIS_CREDIT_SUPPLY = F(16) = 987).
///
/// Panics if the next Fibonacci number would overflow u64, which
/// cannot occur within any realistic attestation count.
pub fn next_fibonacci(n: u64) -> u64 {
    let mut a: u64 = 1;
    let mut b: u64 = 1;
    loop {
        let c = a.checked_add(b).expect("Fibonacci overflow — attestation count unreachable");
        if c > n {
            return c;
        }
        a = b;
        b = c;
    }
}

/// Returns the largest Fibonacci number strictly less than `n`.
///
/// Used to compute cycle progress within the current Fibonacci interval:
/// `progress = (count − previous_fibonacci(threshold)) /
///             (threshold − previous_fibonacci(threshold))`.
///
/// Returns 1 for n ≤ 2 (previous of the first two Fibonacci numbers
/// is conventionally 1).
pub fn previous_fibonacci(n: u64) -> u64 {
    let mut a: u64 = 1;
    let mut b: u64 = 1;
    loop {
        let c = a.checked_add(b).expect("Fibonacci overflow");
        if c >= n {
            return a;
        }
        a = b;
        b = c;
    }
}

// ─────────────────────────────────────────────
// Closure / deviation signal shape
//
// Computed in a coordinator (reads DHT state), serialized into the
// SerializedBytes closure_status field of NetworkRoundManifest and
// NetworkStateManifest. Defined here so the producing coordinator and
// every consumer share one shape without an hdi-dependent crate.
//
// Hashes are raw bytes — toric-geometry has no hdk/hdi and never
// dereferences them. Coordinators convert at the boundary via
// ActionHash::try_from / .into().
//
// No timestamp field — one round is one action; the timestamp lives on
// the enclosing entry's action header and is shared by every signal in
// the round. A DeviationSignal is interpreted together with that header,
// not as a self-contained record.
// ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DeviationSignal {
    pub probe_id: u8,
    pub deviation_magnitude: f64,
    pub expected: f64,
    pub actual: f64,
    pub geometry_params_hash: Vec<u8>,
    pub manifest_hash: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ClosureStatus {
    pub passed: bool,
    pub signals: Vec<DeviationSignal>,
}

impl ClosureStatus {
    /// Largest deviation magnitude across recorded signals.
    /// `None` when no signals were recorded — this means missing or
    /// failed probe data, NOT a healthy round. A healthy round returns
    /// `Some(small_magnitude)`. Callers must treat `None` as
    /// investigate, never as pass.
    pub fn worst_deviation(&self) -> Option<f64> {
        self.signals
            .iter()
            .map(|s| s.deviation_magnitude)
            .fold(None, |acc, m| Some(acc.map_or(m, |a: f64| a.max(m))))
    }
}

/// φ-derived health-reference targets for the closure probes. Pure
/// multipliers and thresholds — no live network state. `check_closure`
/// and NetworkGoalManifest's read-time derivation both call derive_targets
/// so they cannot diverge on what "the target" means.
///
/// Takes the primitive tau_us, not the GeometryParams entry type, because
/// toric-geometry is hdi-free and cannot name registry_integrity types.
/// Callers extract tau_us from the fetched GeometryParams and pass it in.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Targets {
    /// Multiplier applied to total network reputation to get the *ideal*
    /// quorum weight (probe 2's `expected`). φ⁻¹, one φ-rung above the
    /// φ⁻² minimum-resolution threshold enforced separately in check_quorum.
    /// Ideal = total_rep × INV_PHI = total_rep / φ. Applied to live
    /// total_rep at the call site, never stored here.
    pub quorum_weight_multiplier: f64,
    /// Target network reveal rate (probe 3's `expected`). φ⁻¹ — the same
    /// pass line used everywhere else in the system (attestation scoring,
    /// honest-rep threshold, trust score pass line). A second constant here
    /// would break that single-threshold consistency.
    pub reveal_rate_target: f64,
}

/// Derive φ targets from geometry. Currently tau_us does not influence the
/// targets (they are pure φ powers), but routing through this function
/// keeps the seam: when GeometryParams grows fields that *do* shift the
/// targets, they derive from it here without any caller signature change.
pub fn derive_targets(_tau_us: u64) -> Targets {
    Targets {
        quorum_weight_multiplier: INV_PHI,
        reveal_rate_target: INV_PHI,
    }
}

/// Normalized deviation magnitude in [0, 1], shared by all four closure
/// probes so the zero-semantics cannot drift between call sites.
///
/// Two probe families call this with different meanings of `expected`:
///   - measured-vs-target (probes 2,3): expected = GeometryParams-derived target
///   - recompute-vs-stored (probes 1,4): expected = stored/cached value
/// The math is identical; only the caller's interpretation differs.
///
/// Zero handling is per-case, not a blanket rule:
///   - expected == 0 && actual == 0 → 0.0: genuine agreement on nothing.
///     The common legitimate case (manifest with no upstream chain, fresh
///     TrustScoreCache). Must NOT read as deviant.
///   - expected == 0 && actual != 0 → 1.0: total divergence, cannot
///     normalize against a zero base. For probes 1/4 this is the auditability
///     failure; for probes 2/3 it means degenerate GeometryParams / empty
///     network — both "max signal, investigate".
///
/// The `.min(1.0)` clamp is INTENTIONAL and load-bearing: `worst_deviation`
/// and every ClosureStatus consumer rely on magnitudes staying within [0,1].
/// Deviations beyond 100% of `expected` saturate at 1.0, so 2×expected and
/// 100×expected both report 1.0 and are indistinguishable here. That signal
/// loss is an accepted cost of the [0,1] contract. Do NOT "fix" this into an
/// unbounded value; doing so breaks the contract.
pub fn normalized_deviation(expected: f64, actual: f64) -> f64 {
    if expected == 0.0 && actual == 0.0 {
        0.0
    } else if expected == 0.0 {
        1.0
    } else {
        ((actual - expected).abs() / expected).min(1.0)
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phi_identity() {
        // φ = 1 + 1/φ  — the defining equation.
        let lhs = PHI;
        let rhs = 1.0 + INV_PHI;
        assert!((lhs - rhs).abs() < 1e-12, "φ identity broken: {lhs} ≠ {rhs}");
    }

    #[test]
    fn phi_product_identity() {
        // φ × φ⁻¹ = 1
        assert!((PHI * INV_PHI - 1.0).abs() < 1e-12);
        assert!((PHI_SQ * INV_PHI_SQ - 1.0).abs() < 1e-12);
        assert!((PHI_CU * INV_PHI_CU - 1.0).abs() < 1e-12);
        assert!((PHI_4 * INV_PHI_4 - 1.0).abs() < 1e-12);
    }

    #[test]
    fn phi_power_chain() {
        // Each power is the previous times φ.
        assert!((PHI_SQ - PHI * PHI).abs() < 1e-10);
        assert!((PHI_CU - PHI * PHI_SQ).abs() < 1e-10);
        assert!((PHI_4 - PHI * PHI_CU).abs() < 1e-10);
    }

    #[test]
    fn threshold_crossed_semantics() {
        assert!(threshold_crossed(5u64, 5u64));   // equal counts as crossed
        assert!(threshold_crossed(6u64, 5u64));   // above threshold
        assert!(!threshold_crossed(4u64, 5u64));  // below threshold
        assert!(threshold_crossed(0.619_f64, INV_PHI)); // float case
    }

    #[test]
    fn next_fibonacci_known_values() {
        // F sequence: 1,1,2,3,5,8,13,21,34,55,89,144,233,377,610,987
        assert_eq!(next_fibonacci(0), 2);  // 2 is first Fibonacci strictly > 0
        assert_eq!(next_fibonacci(1), 2);   // strictly greater than 1
        assert_eq!(next_fibonacci(20), 21);
        assert_eq!(next_fibonacci(21), 34); // strictly greater than 21
        assert_eq!(next_fibonacci(610), 987);
        assert_eq!(next_fibonacci(986), 987);
        assert_eq!(next_fibonacci(987), 1597);
    }

    #[test]
    fn previous_fibonacci_known_values() {
        // Returns the largest Fibonacci `a` whose successor a+b is still < n.
        // For n on the sequence this is two steps back, not one — this is the
        // production behavior copied verbatim from mutual_credit, relied on by
        // admission_allowance for current-interval lower bounds. Do not change
        // the function to make these read as "one step back".
        assert_eq!(previous_fibonacci(2), 1);
        assert_eq!(previous_fibonacci(21), 8);
        assert_eq!(previous_fibonacci(22), 13);
        assert_eq!(previous_fibonacci(987), 377);
    }

    #[test]
    fn genesis_credit_supply_is_fibonacci() {
        // GENESIS_CREDIT_SUPPLY = 987. next_fibonacci gives the next expansion
        // threshold (1597). previous_fibonacci returns 377 by its two-steps-back
        // definition above, not 610 — see previous_fibonacci_known_values.
        let supply: u64 = 987;
        assert_eq!(next_fibonacci(supply), 1597);
        assert_eq!(previous_fibonacci(supply), 377);
    }

    #[test]
    fn worst_deviation_empty_is_none() {
        let cs = ClosureStatus { passed: true, signals: vec![] };
        assert_eq!(cs.worst_deviation(), None);
    }

    #[test]
    fn worst_deviation_returns_max() {
        let mk = |m: f64| DeviationSignal {
            probe_id: 1,
            deviation_magnitude: m,
            expected: 0.0,
            actual: m,
            geometry_params_hash: vec![],
            manifest_hash: None,
        };
        let cs = ClosureStatus {
            passed: false,
            signals: vec![mk(0.1), mk(0.4), mk(0.2)],
        };
        assert_eq!(cs.worst_deviation(), Some(0.4));
    }

    #[test]
    fn normalized_deviation_both_zero_is_healthy() {
        assert_eq!(normalized_deviation(0.0, 0.0), 0.0);
    }

    #[test]
    fn normalized_deviation_zero_expected_nonzero_actual_is_max() {
        assert_eq!(normalized_deviation(0.0, 0.5), 1.0);
        assert_eq!(normalized_deviation(0.0, 1_000_000.0), 1.0);
    }

    #[test]
    fn normalized_deviation_normal_case() {
        assert!((normalized_deviation(1.0, 0.8) - 0.2).abs() < 1e-12);
        assert_eq!(normalized_deviation(1.0, 1.0), 0.0);
        assert!((normalized_deviation(2.0, 3.0) - 0.5).abs() < 1e-12);
    }

    #[test]
    fn normalized_deviation_clamps_at_one() {
        assert_eq!(normalized_deviation(1.0, 3.0), 1.0);
        assert_eq!(normalized_deviation(1.0, 101.0), 1.0);
        assert_eq!(
            normalized_deviation(1.0, 3.0),
            normalized_deviation(1.0, 101.0)
        );
    }

    #[test]
    fn derive_targets_are_phi_consistent() {
        let t = derive_targets(10_000_000);
        assert_eq!(t.quorum_weight_multiplier, INV_PHI);
        assert_eq!(t.reveal_rate_target, INV_PHI);
        // This asserts an ABSENCE of behavior: tau_us currently does not
        // shift the targets. It is a regression guard for today's state, NOT
        // a design invariant. When GeometryParams grows a field that should
        // move the targets, this assertion must be DELETED and replaced with
        // one asserting the new dependence — not kept, or it would assert the
        // new field is being ignored. Do not "fix" a tau-sensitive target to
        // keep this line green.
        assert_eq!(derive_targets(1), derive_targets(999_999_999));
    }

    #[test]
    fn seal_threshold_is_ceiling_of_inv_phi() {
        // ⌈n × φ⁻¹⌉ against the float value for every roster size that
        // will exist in practice. The rational 610/987 must agree with
        // the real φ⁻¹ ceiling for all n up to F(16); beyond that the
        // approximation error (≈5×10⁻⁷) could shift the ceiling by 1 —
        // acceptable, and the rational is the canonical value.
        for n in 1usize..=987 {
            let expected = ((n as f64) * INV_PHI).ceil() as usize;
            assert_eq!(seal_threshold(n), expected, "n = {}", n);
        }
        assert_eq!(seal_threshold(0), 0); // bootstrap — sealing inactive
        assert_eq!(seal_threshold(1), 1); // sole signer must sign
        assert_eq!(seal_threshold(2), 2); // φ⁻¹ of 2 ⇒ both
        assert_eq!(seal_threshold(3), 2);
        assert_eq!(seal_threshold(5), 4);
    }

    #[test]
    fn seal_threshold_is_complement_of_quorum() {
        // The identity that motivates the power: 1 − φ⁻² = φ⁻¹.
        assert!(((1.0 - INV_PHI_SQ) - INV_PHI).abs() < 1e-12);
        // And a sealing coalition always exceeds a deciding coalition.
        for n in 1usize..=200 {
            let quorum = ((n as f64) * INV_PHI_SQ).ceil() as usize;
            assert!(seal_threshold(n) >= quorum, "n = {}", n);
        }
    }

    #[test]
    fn default_credit_limit_matches_float_and_is_never_looser() {
        for supply in [GENESIS_CREDIT_SUPPLY, 1597, 2584, 4181, 6765] {
            let integer = default_credit_limit(supply);
            let float = -((supply as f64 * INV_PHI_SQ) as i64);
            // Within one unit of the float version, and never more
            // borrowing power (limits are negative: never smaller).
            assert!((integer - float).abs() <= 1, "supply = {}", supply);
            // Truncated rational never exceeds the float share:
            assert!(integer >= float, "supply = {}", supply);
        }
        assert_eq!(default_credit_limit(0), 0);
    }

    #[test]
    fn is_fibonacci_known_values() {
        for f in [1u64, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 987, 1597] {
            assert!(is_fibonacci(f), "{} should be Fibonacci", f);
        }
        for n in [0u64, 4, 6, 7, 9, 10, 20, 22, 100, 986, 988] {
            assert!(!is_fibonacci(n), "{} should not be Fibonacci", n);
        }
    }

    #[test]
    fn rational_inv_phi_is_fibonacci_ratio() {
        assert!(is_fibonacci(INV_PHI_NUM));
        assert!(is_fibonacci(INV_PHI_DEN));
        assert_eq!(INV_PHI_DEN, GENESIS_CREDIT_SUPPLY as u64);
        let rational = INV_PHI_NUM as f64 / INV_PHI_DEN as f64;
        assert!((rational - INV_PHI).abs() < 1e-6);
    }
}
// ─────────────────────────────────────────────
// Sovereignty roster — a function, not a membership list
//
// The roster is the minimal prefix of agents, sorted by trust score
// descending (ties by key bytes ascending), whose cumulative score
// reaches φ⁻¹ of total reputation: the smallest set holding a sealing
// coalition's worth of the network. Sovereignty is standing, recomputed
// each rotation — entrenchment must fight the reputation dynamics, not
// hide in a succession rule. Keys are raw bytes: this crate never
// dereferences agents.
// ─────────────────────────────────────────────

pub fn derive_roster(scored: &[(Vec<u8>, f64)]) -> Vec<Vec<u8>> {
    let total: f64 = scored.iter().map(|(_, s)| s.max(0.0)).sum();
    if total <= 0.0 {
        return vec![];
    }
    let mut sorted: Vec<(&Vec<u8>, f64)> =
        scored.iter().map(|(k, s)| (k, s.max(0.0))).collect();
    sorted.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(core::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(b.0))
    });
    let target = total * INV_PHI;
    let mut cumulative = 0.0;
    let mut roster = Vec::new();
    for (key, score) in sorted {
        if cumulative >= target {
            break;
        }
        cumulative += score;
        roster.push(key.clone());
    }
    roster
}

/// Jaccard distance between two key sets: |sym-diff| / |union|.
/// The roster-conformance deviation — 0.0 when the sealed roster equals
/// the reputation-derived one, 1.0 when disjoint.
pub fn jaccard_distance(a: &[Vec<u8>], b: &[Vec<u8>]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let in_both = a.iter().filter(|k| b.contains(k)).count();
    let union = a.len() + b.len() - in_both;
    if union == 0 {
        return 0.0;
    }
    (union - in_both) as f64 / union as f64
}

/// Expected credit supply after `cycle` Fibonacci crossings: genesis
/// folded through ⌊supply × φ⌋ per crossing — the same arithmetic
/// integrity enforces per step, replayed from origin. Probe 5 compares
/// live supply against this; any mismatch means a step escaped the law.
pub fn expected_supply(cycle: u64) -> i64 {
    let mut supply = GENESIS_CREDIT_SUPPLY;
    for _ in 0..cycle {
        supply = (supply as f64 * PHI).floor() as i64;
    }
    supply
}

/// Deviation against a negligibility ceiling: 0.0 while actual ≤ ceiling,
/// then grows toward 1.0. For quantities expected to stay negligible
/// (frozen-account mass) rather than track a target — probe 7's shape.
pub fn ceiling_deviation(ceiling: f64, actual: f64) -> f64 {
    if ceiling <= 0.0 {
        return if actual > 0.0 { 1.0 } else { 0.0 };
    }
    if actual <= ceiling {
        return 0.0;
    }
    ((actual - ceiling) / ceiling).min(1.0)
}

/// Probe identifiers — economic domain. 1–4 are the registry/coordination
/// domain (hash, quorum weight, reveal discipline, trust drift).
pub const PROBE_SUPPLY_POSITION: u8 = 5;
pub const PROBE_ROSTER_CONFORMANCE: u8 = 6;
pub const PROBE_FROZEN_FRACTION: u8 = 7;

#[cfg(test)]
mod sovereignty_tests {
    use super::*;

    fn k(n: u8) -> Vec<u8> {
        vec![n]
    }

    #[test]
    fn roster_is_minimal_phi_inverse_mass() {
        // Scores: 50, 30, 15, 5 — total 100, target 61.8.
        let scored = vec![(k(1), 50.0), (k(2), 30.0), (k(3), 15.0), (k(4), 5.0)];
        let roster = derive_roster(&scored);
        // 50 < 61.8 → need 2nd; 80 ≥ 61.8 → stop. Roster = top two.
        assert_eq!(roster, vec![k(1), k(2)]);
    }

    #[test]
    fn roster_single_whale() {
        // One agent holding ≥ φ⁻¹ of mass IS the roster — concentration
        // is a reputation-distribution fact, surfaced by probe 6/closure,
        // not hidden by the roster function.
        let scored = vec![(k(9), 70.0), (k(1), 20.0), (k(2), 10.0)];
        assert_eq!(derive_roster(&scored), vec![k(9)]);
    }

    #[test]
    fn roster_deterministic_under_ties() {
        let a = vec![(k(2), 10.0), (k(1), 10.0), (k(3), 10.0)];
        let b = vec![(k(3), 10.0), (k(2), 10.0), (k(1), 10.0)];
        assert_eq!(derive_roster(&a), derive_roster(&b)); // key-ordered
        assert_eq!(derive_roster(&a), vec![k(1), k(2)]); // 20/30 ≥ φ⁻¹
    }

    #[test]
    fn roster_empty_and_zero_score_networks() {
        assert!(derive_roster(&[]).is_empty());
        assert!(derive_roster(&[(k(1), 0.0)]).is_empty());
        assert!(derive_roster(&[(k(1), -5.0), (k(2), 0.0)]).is_empty());
    }

    #[test]
    fn jaccard_distance_cases() {
        assert_eq!(jaccard_distance(&[], &[]), 0.0);
        assert_eq!(jaccard_distance(&[k(1), k(2)], &[k(1), k(2)]), 0.0);
        assert_eq!(jaccard_distance(&[k(1)], &[k(2)]), 1.0);
        let d = jaccard_distance(&[k(1), k(2)], &[k(2), k(3)]);
        assert!((d - 2.0 / 3.0).abs() < 1e-12); // sym-diff 2, union 3
    }

    #[test]
    fn expected_supply_walks_fibonacci_neighborhood() {
        assert_eq!(expected_supply(0), GENESIS_CREDIT_SUPPLY);
        // ⌊987φ⌋ = 1596 — one below F(17); floor-chaining is the law
        // integrity enforces, so the probe expects the chained value,
        // not the pure Fibonacci number.
        assert_eq!(expected_supply(1), 1596);
        assert_eq!(expected_supply(2), (1596.0 * PHI).floor() as i64);
    }

    #[test]
    fn ceiling_deviation_shape() {
        assert_eq!(ceiling_deviation(INV_PHI_4, 0.0), 0.0);
        assert_eq!(ceiling_deviation(INV_PHI_4, INV_PHI_4), 0.0);
        assert!(ceiling_deviation(INV_PHI_4, INV_PHI_4 * 1.5) > 0.0);
        assert_eq!(ceiling_deviation(INV_PHI_4, 1.0), 1.0);
        assert_eq!(ceiling_deviation(0.0, 0.5), 1.0);
    }
}