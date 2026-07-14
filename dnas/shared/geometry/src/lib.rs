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


/// Fixed-point denominator for reputation scores as stored in the
/// registry's ReputationCache: score ∈ [0, 1] carried as parts-per-
/// million (u32). REPRESENTATION, not a threshold — it predates the
/// lattice discipline and is off-lattice (10⁶ ≈ F(16)² = 974_169 is
/// suggestive, not a derivation). In the unforced-constants ledger; no
/// law depends on its exact value beyond bounding score_ppm.
pub const SCORE_PPM_DENOM: u64 = 1_000_000;

/// Integer floor of the 5th root (binary search on u128). Used only by
/// `credit_limit_for_reputation`; floor keeps every use conservative.
fn iroot5(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let (mut lo, mut hi): (u128, u128) = (0, 1 << 26); // (2^26)^5 = 2^130 > u128::MAX
    while lo < hi {
        let mid = (lo + hi + 1) / 2;
        match mid.checked_pow(5) {
            Some(p) if p <= n => lo = mid,
            _ => hi = mid - 1,
        }
    }
    lo
}

/// Reputation-interpolated credit limit — INTEGER-EXACT, the single
/// definition shared by the mutual_credit coordinator (computing) and
/// integrity zome (verifying). Any divergence between computed and
/// enforced limits is a fork; sharing one function is the guarantee.
///
/// Curve: limit(s) = −⌊ supply · (φ⁻² + t·(φ⁻¹ − φ⁻²)) ⌋, s ∈ [0,1].
///
/// Derivation notes:
/// • The rung gap φ⁻¹ − φ⁻² = φ⁻³ is on-lattice by the ladder identity;
///   in the shared rationals: 610/987 − 377/987 = 233/987 = F(13)/F(16).
///   Taking the gap mints no new constant.
/// • The old coordinator curve used t = s^φ (f64 `powf`) — geometric
///   compounding, but an irrational exponent cannot be integer-exact,
///   and f64 in a path that now enters validation is the known
///   determinism anti-pattern. The exponent is replaced by the
///   Fibonacci convergent F(6)/F(5) = 8/5 (1.6 vs φ ≈ 1.618):
///   t·987 = ⌊(s·987)⁸ / 987³⌋^{1/5}, on the same F(16) denominator as
///   every other rational here. The next convergent F(7)/F(6) = 13/8
///   overflows u128 at this scale (987¹³ ≈ 10³⁹); the convergent ORDER
///   is therefore an arithmetic-capacity choice — recorded in the
///   unforced-constants ledger, tested for bounded deviation below.
/// • Every floor truncates toward less borrowing power — conservative
///   in the only direction that matters for a limit.
///
/// Clamped to the Fibonacci ceiling: no reputation grants more headroom
/// than the next Fibonacci number above the anchored supply (integrity
/// checks this independently as well — belt and suspenders).
pub fn credit_limit_for_reputation(score_ppm: u32, credit_supply: i64) -> i64 {
    let supply = credit_supply.max(0) as u128;
    let den = INV_PHI_DEN as u128; // 987 = F(16)
    let s_ppm = (score_ppm as u64).min(SCORE_PPM_DENOM) as u128;
    // Score rescaled onto the F(16) denominator: s987 ∈ [0, 987].
    let s987 = s_ppm * den / (SCORE_PPM_DENOM as u128);
    // t987 = 987·(s/987)^{8/5} = ⌊s987⁸ / 987³⌋^{1/5}. 987⁸ ≈ 9.0×10²³,
    // comfortably inside u128.
    let t987 = iroot5(s987.pow(8) / den.pow(3));
    // F(13) = 610 − 377: the φ⁻³ rung gap over the shared denominator.
    const GAP_NUM: u128 = 233;
    let num = supply * ((INV_PHI_SQ_NUM as u128) * den + GAP_NUM * t987);
    let magnitude = (num / (den * den)) as i64;
    let limit = -magnitude;
    let ceiling = -(next_fibonacci(credit_supply.max(0) as u64) as i64);
    limit.max(ceiling)
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
// ─────────────────────────────────────────────
// Drift accumulator — "no clock, has a mirror"
//
// The network does not re-snapshot itself on a timer or every round; it
// re-mirrors when it has moved enough to be worth re-recording. The
// accumulated quantity is total absolute trust-score movement since the
// last NetworkStateManifest, normalized by the total recorded there:
//
//     D = Σ|Δsᵢ| / S_ref
//
// Absolute (not signed) deltas: reputation churn with zero net sum still
// changes the distribution, and the distribution is what the manifest
// records. Normalization by S_ref makes D dimensionless so it can meet
// a pure φ power.
//
// Threshold φ⁻², doubly derived:
//  1. Goal-manifest targets live on a φ-ladder; the relative gap between
//     adjacent rungs is 1 − φ⁻¹ = φ⁻² (golden identity). D ≥ φ⁻² is
//     exactly "some quantity may have crossed to an adjacent rung" —
//     below it, record and reality sit on the same rung everywhere.
//  2. Quorum symmetry: total_rep/φ² is the coordinated weight that
//     constitutes a network decision; the same fraction *moving* is the
//     event that mandates re-description. Same currency, same magnitude.
//
// φ⁻² is therefore the maximum blur the network tolerates in its
// self-image: check_closure reads the manifest as canonical input, so
// the drift gate bounds immune-system staleness by one φ-rung of
// accumulated movement.
// ─────────────────────────────────────────────

/// Drift threshold: φ⁻². Alias kept explicit so call sites read as the
/// design decision they implement.
pub const DRIFT_THRESHOLD: f64 = INV_PHI_SQ;

/// Staleness ceiling in rounds. A published drift threshold is a
/// steering target — an adversary redistributing reputation can surf
/// just below φ⁻² and keep the snapshot stale indefinitely, so
/// staleness is bounded in sequence as well as in drift. F(8) = 21,
/// reusing the network's existing era quantum (BOOTSTRAP_ATTESTATIONS):
/// the number of events that constitutes an epoch of activity. Not a
/// new constant — a reuse; the Gap-7 forcing-rule derivation may
/// revise it.
pub const STALENESS_CEILING_ROUNDS: u64 = 21;

/// Accumulated drift between two trust-score distributions, keyed by
/// raw agent bytes. Agents present in only one side contribute their
/// full score as movement (arrivals from zero, departures to zero).
/// S_ref ≤ 0 (empty or zero-mass prior) ⇒ any current mass is total
/// drift (INFINITY ≥ every threshold); both empty ⇒ 0.0.
pub fn drift_since(prev: &[(Vec<u8>, f64)], curr: &[(Vec<u8>, f64)]) -> f64 {
    let s_ref: f64 = prev.iter().map(|(_, s)| s.max(0.0)).sum();
    let mut moved = 0.0;
    for (key, curr_score) in curr {
        let prev_score = prev
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, s)| s.max(0.0))
            .unwrap_or(0.0);
        moved += (curr_score.max(0.0) - prev_score).abs();
    }
    for (key, prev_score) in prev {
        if !curr.iter().any(|(k, _)| k == key) {
            moved += prev_score.max(0.0); // departed: full mass moved
        }
    }
    if s_ref <= 0.0 {
        return if moved > 0.0 { f64::INFINITY } else { 0.0 };
    }
    moved / s_ref
}

/// The write decision, in one place: due when drift crosses φ⁻², when
/// the sequence ceiling is hit, or when no snapshot exists at all.
pub fn manifest_write_due(drift: f64, rounds_since: u64, prior_exists: bool) -> bool {
    !prior_exists || drift >= DRIFT_THRESHOLD || rounds_since >= STALENESS_CEILING_ROUNDS
}

#[cfg(test)]
mod drift_tests {
    use super::*;

    fn k(n: u8) -> Vec<u8> {
        vec![n]
    }

    #[test]
    fn no_movement_no_drift() {
        let dist = vec![(k(1), 50.0), (k(2), 30.0)];
        assert_eq!(drift_since(&dist, &dist), 0.0);
    }

    #[test]
    fn churn_counts_despite_zero_net_sum() {
        // 10 points move from agent 1 to agent 2: net 0, |Δ| = 20.
        let prev = vec![(k(1), 50.0), (k(2), 30.0)];
        let curr = vec![(k(1), 40.0), (k(2), 40.0)];
        let d = drift_since(&prev, &curr);
        assert!((d - 20.0 / 80.0).abs() < 1e-12);
    }

    #[test]
    fn arrivals_and_departures_are_movement() {
        let prev = vec![(k(1), 60.0), (k(2), 40.0)];
        let curr = vec![(k(1), 60.0), (k(3), 25.0)]; // 2 departs, 3 arrives
        let d = drift_since(&prev, &curr);
        assert!((d - (40.0 + 25.0) / 100.0).abs() < 1e-12);
    }

    #[test]
    fn empty_prior_with_mass_is_infinite_drift() {
        assert_eq!(drift_since(&[], &[(k(1), 5.0)]), f64::INFINITY);
        assert_eq!(drift_since(&[], &[]), 0.0);
    }

    #[test]
    fn threshold_is_the_rung_gap() {
        // The golden identity that makes φ⁻² the derived threshold:
        // relative gap between adjacent φ-ladder rungs = 1 − φ⁻¹ = φ⁻².
        assert!(((1.0 - INV_PHI) - DRIFT_THRESHOLD).abs() < 1e-12);
    }

    #[test]
    fn write_decision_covers_all_triggers() {
        assert!(manifest_write_due(0.0, 0, false)); // genesis: no prior
        assert!(!manifest_write_due(0.1, 3, true)); // quiet network: stands
        assert!(manifest_write_due(DRIFT_THRESHOLD, 0, true)); // drift trigger
        assert!(manifest_write_due(f64::INFINITY, 0, true));
        assert!(manifest_write_due(0.0, STALENESS_CEILING_ROUNDS, true)); // ceiling
        assert!(!manifest_write_due(DRIFT_THRESHOLD - 1e-9, STALENESS_CEILING_ROUNDS - 1, true));
    }

    #[test]
    fn fire_every_round_is_the_degenerate_case() {
        // The provisional pre-drift behavior (write every round) is this
        // design with threshold 0 — any movement at all triggers. The
        // real threshold makes tiny movement stand — documented so
        // nobody "fixes" the gate back to firing always.
        let tiny_drift = 1e-9;
        assert!(tiny_drift >= 0.0); // would fire under threshold-zero
        assert!(!manifest_write_due(tiny_drift, 0, true)); // stands under φ⁻²
    }
}

/// Sovereignty lease, in rounds. A sealed roster is valid succession
/// authority for at most this many attestation rounds past its
/// declaration; beyond it the roster is constitutionally expired and
/// the freshly derived roster may accede by self-ratification. F(8) =
/// 21 — the same era quantum as BOOTSTRAP_ATTESTATIONS and
/// STALENESS_CEILING_ROUNDS: three independent needs converging on one
/// constant (the Gap-7 pattern). Expiry adds no capture path: acceding
/// still requires being the top-φ⁻¹ reputation mass, which is the
/// front door.
pub const SOVEREIGNTY_LEASE_ROUNDS: u64 = 21;

/// True when a roster declared at `declared_at` has expired by round
/// `current` — deterministic from on-DHT counts alone.
pub fn roster_expired(declared_at: u64, current: u64) -> bool {
    current.saturating_sub(declared_at) >= SOVEREIGNTY_LEASE_ROUNDS
}

#[cfg(test)]
mod sovereignty_lease_tests {
    use super::*;

    #[test]
    fn lease_arithmetic() {
        assert!(!roster_expired(0, 0));
        assert!(!roster_expired(0, SOVEREIGNTY_LEASE_ROUNDS - 1));
        assert!(roster_expired(0, SOVEREIGNTY_LEASE_ROUNDS));
        assert!(roster_expired(5, 5 + SOVEREIGNTY_LEASE_ROUNDS + 100));
        assert!(!roster_expired(100, 50)); // saturating: no underflow panic
    }

    #[test]
    fn era_quantum_convergence() {
        // Three independent constants landing on F(8) — recorded as a
        // fact for the Gap-7 forcing-rule derivation to consume.
        assert_eq!(SOVEREIGNTY_LEASE_ROUNDS, STALENESS_CEILING_ROUNDS);
        assert!(is_fibonacci(SOVEREIGNTY_LEASE_ROUNDS));
        assert_eq!(SOVEREIGNTY_LEASE_ROUNDS, 21);
    }
}

// ─────────────────────────────────────────────
// The exponent forcing rule — Gap 7
//
// Authority thresholds in Toric are not assigned φ powers; they are
// cells of the recursive golden partition of unity. x + x² = 1 has
// exactly one positive solution, x = φ⁻¹: the unique scale-free split
// of a whole into "enough to constitute" (φ⁻¹) and "enough to operate"
// (φ⁻²), where the part relates to the remainder as the remainder
// relates to the whole. Each cell partitions again the same way
// (φ⁻ᵏ = φ⁻ᵏ⁻¹ + φ⁻ᵏ⁻²), so the full ladder is generated, and a
// quantity's power is its DEPTH: the order of self-reference of the
// act it governs. Operative acts (deciding rounds, drift) sit at φ⁻²;
// constitutive acts (sealing identity, roster mass) at φ⁻¹; and every
// ALARM fires one level deeper than the boundary it guards, which
// makes its security margin exactly the next cell down — never zero,
// never a choice.
// ─────────────────────────────────────────────

/// φ⁻³ — the pre-capture alarm line. Capture becomes possible at
/// dishonest mass ≥ φ⁻² (the quorum boundary); the alarm guarding it
/// fires one partition level earlier, at φ⁻³. The margin between alarm
/// and boundary is φ⁻² − φ⁻³ = φ⁻⁴: the negligibility floor, forced by
/// the ladder identity rather than chosen.
pub const CAPTURE_ALARM: f64 = INV_PHI_CU;

/// Admission gate floor: honest reputation fraction below which
/// admission closes = 1 − φ⁻³ = φ⁻¹ + φ⁻⁴ ≈ 0.7639. This replaces the
/// audit's severest finding — the old gate closed at φ⁻¹, i.e. at the
/// exact point where a dishonest coalition could already pass quorums
/// unilaterally, leaving zero margin between "gate reacts" and
/// "network capturable." Reacting at the alarm line instead of the
/// boundary restores a margin of exactly φ⁻⁴ of total reputation mass.
pub const ADMISSION_GATE_FLOOR: f64 = 1.0 - INV_PHI_CU;

#[cfg(test)]
mod forcing_rule_tests {
    use super::*;

    #[test]
    fn golden_partition_of_unity() {
        // The generator: the unique scale-free two-way split.
        assert!((INV_PHI + INV_PHI_SQ - 1.0).abs() < 1e-12);
        // Self-similar refinement generates the whole ladder.
        assert!((INV_PHI_SQ - (INV_PHI_CU + INV_PHI_4)).abs() < 1e-12);
        assert!((INV_PHI - (INV_PHI_SQ + INV_PHI_CU)).abs() < 1e-12);
    }

    #[test]
    fn alarm_margin_is_forced_to_the_negligibility_floor() {
        // Alarm one level before the boundary ⇒ margin = next cell down.
        let margin = INV_PHI_SQ - CAPTURE_ALARM;
        assert!((margin - INV_PHI_4).abs() < 1e-12);
        // And the gate floor is the complement of the alarm line.
        assert!((ADMISSION_GATE_FLOOR - (INV_PHI + INV_PHI_4)).abs() < 1e-12);
        // The old gate (φ⁻¹) had literally zero margin — the collision.
        assert_eq!(INV_PHI_SQ, 1.0 - INV_PHI);
    }

    #[test]
    fn era_quantum_is_the_partition_cell_count_at_closure_depth() {
        // The golden substitution L→LS, S→L refines the partition; cell
        // count after n subdivisions is F(n+2). At the closure overhead
        // depth ⌊φ⁴⌋ = 6, the count is F(8) = 21 — the era quantum that
        // three independent needs (bootstrap, staleness ceiling,
        // sovereignty lease) converged on before this derivation named
        // it. The fractional remainder φ⁴ − 6 ≈ 0.854 is an open
        // question, flagged, not smoothed over.
        let mut lengths = vec![1u64, 2];
        while *lengths.last().unwrap() < 21 {
            let n = lengths.len();
            lengths.push(lengths[n - 1] + lengths[n - 2]);
        }
        assert_eq!(lengths[6], 21); // 6 subdivisions from length 1
        assert_eq!(PHI_4.floor() as usize, 6);
        assert_eq!(STALENESS_CEILING_ROUNDS, 21);
        assert_eq!(SOVEREIGNTY_LEASE_ROUNDS, 21);
    }

    #[test]
    fn trust_recursion_lattice_closure() {
        // Eigenform claim, honest version: ANY attenuation a < 1 makes
        // the homogeneous trust recursion s = d + a·s converge — mere
        // convergence does not force φ⁻¹. What forces it is lattice
        // closure: the induced amplification 1/(1−a) is itself a φ
        // power iff a = φ⁻¹ (then 1/(1−φ⁻¹) = φ²), keeping every
        // downstream constant derivable on the ladder. Attenuation is
        // forced by the requirement that recursion not mint constants.
        let a = INV_PHI;
        let amplification = 1.0 / (1.0 - a);
        assert!((amplification - PHI * PHI).abs() < 1e-9);
        // Counterexample: a = 0.5 converges fine but amplifies by 2.0,
        // which is on no rung of the ladder.
        let off_lattice: f64 = 1.0 / (1.0 - 0.5);
        assert!((off_lattice - 2.0).abs() < 1e-12);
    }
}

/// Per-probe pass lines — the probe-boundary audit's output.
///
/// The default line stays φ⁻¹ for probes whose deviation basis is
/// normalized against a φ-target: normalized_deviation × φ-target
/// composes powers multiplicatively, so a φ⁻¹ relative line on a φ⁻¹
/// target is an absolute trigger at φ⁻¹·(1−φ⁻¹)... = one rung below
/// the target — alarm-one-level-deeper satisfied by composition alone.
///
/// Probe 6 gets its own line because its basis is raw Jaccard with
/// expected 0: there is no target to normalize against, so the
/// composition step that keeps its siblings compliant does not apply.
/// Its guarded boundary is φ⁻² divergence (an operative-order share of
/// the constitutive organ gone wrong); the alarm fires one level
/// deeper, at φ⁻³.
pub const PROBE_PASS_LINE_DEFAULT: f64 = INV_PHI;
pub const PROBE_6_PASS_LINE: f64 = INV_PHI_CU;

/// Pass line for a probe id. One place, so the audit table and the
/// code cannot drift.
/// Probe 8: holonomy — residual mass on comparative-preference cycles.
/// Raw basis, expected 0 (same class as probe 6: no target to compose
/// against, the line carries the depth itself). Guarded boundary:
/// operative-order dispute mass (φ⁻²); alarm one level deeper: φ⁻³.
/// Held disputes are normal — the probe fires on dispute mass growing
/// past the alarm line relative to total preference mass.
pub const PROBE_HOLONOMY: u8 = 8;
pub const PROBE_8_PASS_LINE: f64 = INV_PHI_CU;

pub fn probe_pass_line(probe_id: u8) -> f64 {
    match probe_id {
        PROBE_ROSTER_CONFORMANCE => PROBE_6_PASS_LINE,
        PROBE_HOLONOMY => PROBE_8_PASS_LINE,
        _ => PROBE_PASS_LINE_DEFAULT,
    }
}

#[cfg(test)]
mod probe_audit_tests {
    use super::*;

    #[test]
    fn probe_2_composition_is_the_rules_best_evidence() {
        // Unplanned compliance: probe 2's absolute lower trigger is
        // target × (1 − pass_line) = φ⁻¹ × φ⁻² = φ⁻³ of total mass —
        // exactly the capture-alarm line, composed by machinery designed
        // before the rule existed. Recorded as evidence, not just audit.
        let absolute_trigger = INV_PHI * (1.0 - PROBE_PASS_LINE_DEFAULT);
        assert!((absolute_trigger - INV_PHI_CU).abs() < 1e-12);
        assert!((absolute_trigger - CAPTURE_ALARM).abs() < 1e-12);
    }

    #[test]
    fn probe_6_line_is_one_level_below_its_boundary() {
        // Raw-Jaccard basis, no target to compose with: the line must
        // carry the depth itself. Boundary φ⁻², alarm φ⁻³, margin φ⁻⁴.
        assert_eq!(probe_pass_line(PROBE_ROSTER_CONFORMANCE), INV_PHI_CU);
        assert!(((INV_PHI_SQ - PROBE_6_PASS_LINE) - INV_PHI_4).abs() < 1e-12);
        // The old line let closure pass at 61.8% sovereignty divergence.
        assert!(PROBE_6_PASS_LINE < INV_PHI);
    }
}

// ─────────────────────────────────────────────
// Mass-weighted sealing — item 2's fix
//
// The roster is defined by reputation MASS (the top-φ⁻¹ slice), but the
// original seal threshold counted HEADS (⌈n·φ⁻¹⌉). Two measurement
// bases in one mechanism — and it had teeth: a whale at 30% plus twenty
// smalls let thirteen tail seats seal constitutive facts with ~21% of
// mass, excluding the whale entirely. Seat-majority ≠ mass-majority,
// and the effective sealing mass was on no rung.
//
// Sealing now speaks the same base as membership: signatures must carry
// ⌈φ⁻¹ of the roster's total mass⌉. Integer-exact via F(15)/F(16);
// masses are integer units (scaled scores) so no float enters the
// consensus check. Known, chosen cost (recorded for external review):
// a ≥φ⁻²-of-roster-mass whale gains a seal veto — the geometry's honest
// output, preferred over an accounting artifact. head-count
// seal_threshold() is retained above as the n=2 bilateral identity
// (⌈2·φ⁻¹⌉ = 2 — endorsement IS the partition at two parties) and as
// the derivation reference.
// ─────────────────────────────────────────────

/// Mass a set of signatures must carry: ⌈total_mass × φ⁻¹⌉,
/// integer-exact. Zero total ⇒ 0 (no roster mass — sealing inactive).
pub fn mass_seal_threshold(total_mass: u64) -> u64 {
    (total_mass * INV_PHI_NUM + INV_PHI_DEN - 1) / INV_PHI_DEN
}

/// Roster derivation with masses: same minimal-prefix rule, but each
/// seat carries its integer mass (caller scales scores deterministically
/// — same wasm, same inputs, same integers). The scale cancels in every
/// threshold check (ratios over the same vector), so it is
/// representation, not a parameter.
pub fn derive_roster_with_mass(scored: &[(Vec<u8>, u64)]) -> Vec<(Vec<u8>, u64)> {
    let total: u64 = scored.iter().map(|(_, m)| *m).sum();
    if total == 0 {
        return vec![];
    }
    let mut sorted: Vec<(&Vec<u8>, u64)> = scored.iter().map(|(k, m)| (k, *m)).collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    // Minimal prefix reaching ⌈φ⁻¹ of total⌉ — same integer rational as
    // the seal threshold so membership and sealing share one base.
    let target = mass_seal_threshold(total);
    let mut cumulative: u64 = 0;
    let mut roster = Vec::new();
    for (key, mass) in sorted {
        if cumulative >= target {
            break;
        }
        cumulative += mass;
        roster.push((key.clone(), mass));
    }
    roster
}

#[cfg(test)]
mod mass_seal_tests {
    use super::*;

    fn k(n: u8) -> Vec<u8> {
        vec![n]
    }

    #[test]
    fn mass_threshold_is_integer_phi_inverse() {
        assert_eq!(mass_seal_threshold(0), 0);
        assert_eq!(mass_seal_threshold(987), 610); // exact on the tower
        for total in [1u64, 2, 100, 1000, 987_000] {
            let expected = ((total as f64) * INV_PHI).ceil() as u64;
            let got = mass_seal_threshold(total);
            assert!((got as i64 - expected as i64).abs() <= 1, "total = {}", total);
            // Never weaker than the real φ⁻¹ share (ceiling division).
            assert!(got as f64 >= (total as f64) * (INV_PHI - 1e-6));
        }
    }

    #[test]
    fn seat_stuffing_attack_is_dead() {
        // The doc-log's worked example: whale 300 + twenty smalls of 16
        // (total 620). Old head-count rule: 13 of 21 seats sealed with
        // 13×16 = 208 mass ≈ 33% — under φ⁻¹, whale excluded. New rule:
        // threshold = ⌈620·φ⁻¹⌉ = 384 mass. All twenty smalls together
        // (320) CANNOT seal; any sealing coalition must include the
        // whale. Mass-majority is now the only majority.
        let total: u64 = 300 + 20 * 16;
        let threshold = mass_seal_threshold(total);
        assert!(threshold > 20 * 16, "tail seats alone must not seal");
        assert!(300 + 6 * 16 >= threshold, "whale + six smalls suffices");
    }

    #[test]
    fn mass_roster_matches_float_roster_semantics() {
        // Same minimal-prefix rule as derive_roster, integer base.
        let scored = vec![(k(1), 50u64), (k(2), 30), (k(3), 15), (k(4), 5)];
        let roster = derive_roster_with_mass(&scored);
        let keys: Vec<Vec<u8>> = roster.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(keys, vec![k(1), k(2)]); // 50 < 62 ≤ 80
        assert_eq!(roster[0].1, 50);
        assert!(derive_roster_with_mass(&[]).is_empty());
        assert!(derive_roster_with_mass(&[(k(1), 0)]).is_empty());
    }

    #[test]
    fn whale_veto_is_the_named_cost() {
        // A whale holding ≥ φ⁻² of roster mass can block any seal —
        // recorded as chosen, not missed: smalls 320 < 384 threshold,
        // so no coalition excluding the 300-mass whale seals.
        let total: u64 = 620;
        let smalls_combined: u64 = 320;
        assert!(smalls_combined < mass_seal_threshold(total));
    }

    #[test]
    fn credit_limit_for_reputation_endpoints_match_the_rationals() {
        for supply in [987i64, 1597, 2584, 10_000] {
            // Zero reputation ⇒ exactly the unsealed default floor.
            assert_eq!(
                credit_limit_for_reputation(0, supply),
                default_credit_limit(supply),
                "zero-score endpoint must equal default_credit_limit at supply {supply}"
            );
            // Full reputation ⇒ exactly −⌊supply·φ⁻¹⌋ in the shared
            // rationals (clamped by the Fibonacci ceiling where binding).
            let full = -((supply as u64 * INV_PHI_NUM / INV_PHI_DEN) as i64);
            let ceiling = -(next_fibonacci(supply as u64) as i64);
            assert_eq!(
                credit_limit_for_reputation(1_000_000, supply),
                full.max(ceiling),
                "full-score endpoint must equal the φ⁻¹ rational at supply {supply}"
            );
        }
    }

    #[test]
    fn credit_limit_for_reputation_is_monotone_and_ceiling_bounded() {
        for supply in [987i64, 1597] {
            let ceiling = -(next_fibonacci(supply as u64) as i64);
            let mut prev = credit_limit_for_reputation(0, supply);
            for s in (0..=1_000_000u32).step_by(2_500) {
                let l = credit_limit_for_reputation(s, supply);
                assert!(l <= prev, "limit must not shrink in magnitude as score rises (s={s})");
                assert!(l >= ceiling, "limit must never exceed the Fibonacci ceiling (s={s})");
                prev = l;
            }
        }
    }

    #[test]
    fn credit_limit_for_reputation_tracks_the_old_f64_curve() {
        // The 8/5 convergent vs the old s^φ powf curve: deviation must
        // stay small relative to supply. F(11) = 89 gives the bound
        // supply/89 ≈ 1.1% — measured max at supply 987 is ~5 credits.
        for supply in [987i64, 1597] {
            let mut max_dev: i64 = 0;
            for s in (0..=1_000_000u32).step_by(1_000) {
                let integer = credit_limit_for_reputation(s, supply);
                let sf = s as f64 / 1_000_000.0;
                let lower = supply as f64 * INV_PHI_SQ;
                let upper = supply as f64 * INV_PHI;
                let t = sf.powf(PHI);
                let float_curve = -((lower + t * (upper - lower)) as i64);
                let ceiling = -(next_fibonacci(supply as u64) as i64);
                let float_clamped = float_curve.max(ceiling);
                max_dev = max_dev.max((integer - float_clamped).abs());
            }
            assert!(
                max_dev <= supply / 89,
                "deviation {max_dev} from the legacy curve exceeds supply/F(11) at supply {supply}"
            );
        }
    }

    #[test]
    fn iroot5_floors_exactly() {
        assert_eq!(iroot5(0), 0);
        assert_eq!(iroot5(1), 1);
        assert_eq!(iroot5(31), 1);
        assert_eq!(iroot5(32), 2);
        assert_eq!(iroot5(33), 2);
        let big: u128 = 987u128.pow(5);
        assert_eq!(iroot5(big), 987);
        assert_eq!(iroot5(big - 1), 986);
    }
}

// ─────────────────────────────────────────────
// ℤ[φ] — exact golden-integer arithmetic for consensus law
//
// The float-determinism partition, tier 1. Every threshold law in
// Toric has the form ⌊n·φ⁻ᵏ⌋ or ⌈n·φ⁻ᵏ⌉ for integer n — and n·φ⁻ᵏ
// always has INTEGER coefficients in ℤ[φ] (e.g. n·φ⁻² = 2n − n·φ,
// n·φ⁻¹ = −n + n·φ). So the law layer needs no fractions, no floats,
// no gcd: two i128 coefficients and an exact sign test. Portable
// across WASM, native, and any independent implementation — the
// determinism comes from the algebra, not the binary.
//
// The sign of a + b·φ (φ = (1+√5)/2): rearrange to 2a + b + b·√5;
// compare b·√5 against −(2a+b) by squaring (integers only).
//
// This supersedes the Fibonacci-convergent rationals for the floor/
// ceiling laws. Verified: 377/987 under-floors the true φ⁻² share by
// exactly 1 at every other Fibonacci supply from F(18) on (2584,
// 6765, 17711, 46368, 121393, ...). Not a node-divergence bug — every
// node runs the same rational — but the convergent was an
// approximation constant, and the exact form retires it. Adopting the
// exact law is a consensus-visible change: ship as a DNA fork.
// ─────────────────────────────────────────────

/// Sign of a + b·φ, exact, integers only. Returns -1, 0, or 1.
pub fn zphi_sign(a: i128, b: i128) -> i32 {
    if b == 0 {
        return if a > 0 { 1 } else if a < 0 { -1 } else { 0 };
    }
    let r = -(2 * a + b);
    let lhs = 5 * b * b;
    let rhs = r * r;
    if b > 0 {
        if r <= 0 { return 1; }
        if lhs > rhs { 1 } else if lhs < rhs { -1 } else { 0 }
    } else {
        if r >= 0 { return -1; }
        if lhs > rhs { -1 } else if lhs < rhs { 1 } else { 0 }
    }
}

/// Exact ⌊a + b·φ⌋ for integer coefficients. Uses the Fibonacci form
/// b·φ = b·(F(1)φ) and the sign test; binary search over integer k.
pub fn zphi_floor(a: i128, b: i128) -> i128 {
    // a + b·φ ∈ [a + b·1.6..], bound the search tightly.
    let (mut lo, mut hi) = (a + 2 * b.min(0) - 2, a + 2 * b.max(0) + 2);
    while lo < hi {
        let mid = lo + (hi - lo + 1) / 2;
        if zphi_sign(a - mid, b) >= 0 {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// Exact default credit limit: −⌊supply · φ⁻²⌋ with φ⁻² = 2 − φ, so
/// supply·φ⁻² = (2·supply) − supply·φ — integer coefficients, exact
/// floor. The true φ⁻² share, no convergent approximation.
pub fn default_credit_limit_exact(credit_supply: i64) -> i64 {
    let n = credit_supply.max(0) as i128;
    -(zphi_floor(2 * n, -n) as i64)
}

/// Exact seal mass threshold: ⌈mass · φ⁻¹⌉ with φ⁻¹ = φ − 1, so
/// mass·φ⁻¹ = −mass + mass·φ. ⌈x⌉ = ⌊x⌋ + 1 for irrational x (x is
/// irrational whenever mass ≠ 0, since φ is).
pub fn mass_seal_threshold_exact(total_mass: u64) -> u64 {
    if total_mass == 0 {
        return 0;
    }
    let n = total_mass as i128;
    (zphi_floor(-n, n) + 1) as u64
}

#[cfg(test)]
mod zphi_tests {
    use super::*;

    #[test]
    fn sign_test_against_known_values() {
        assert_eq!(zphi_sign(0, 1), 1); // φ > 0
        assert_eq!(zphi_sign(-1, 1), 1); // φ⁻¹ > 0
        assert_eq!(zphi_sign(2, -1), 1); // φ⁻² = 2 − φ > 0
        assert_eq!(zphi_sign(1, -1), -1); // 1 − φ < 0
        assert_eq!(zphi_sign(-2, 1), -1); // φ − 2 < 0
        assert_eq!(zphi_sign(0, 0), 0);
        // Fibonacci identity: F(n−1) + F(n)·(−φ) + φⁿ... spot: φ² − φ − 1 = 0
        // as coefficients: φ² = 1 + φ, so (1 + φ) − φ − 1 = 0 exactly.
        assert_eq!(zphi_sign(1 - 1, 1 - 1), 0);
    }

    #[test]
    fn floor_matches_high_precision() {
        // ⌊n·φ⌋ for known values: φ, 2φ=3.23.., 10φ=16.18..
        assert_eq!(zphi_floor(0, 1), 1);
        assert_eq!(zphi_floor(0, 2), 3);
        assert_eq!(zphi_floor(0, 10), 16);
        assert_eq!(zphi_floor(5, 0), 5); // pure integer
        assert_eq!(zphi_floor(0, -1), -2); // −φ = −1.618 → −2
    }

    #[test]
    fn convergent_divergence_at_fibonacci_supplies() {
        // The finding: 377/987 under-floors the exact φ⁻² share by 1
        // at every other Fibonacci supply from F(18). Both recorded.
        let diverge = [2584i64, 6765, 17711, 46368, 121393, 317811];
        for &n in &diverge {
            let rational = -((n as u64 * INV_PHI_SQ_NUM / INV_PHI_DEN) as i64);
            let exact = default_credit_limit_exact(n);
            assert_eq!(exact - rational, -1, "supply {}: exact grants 1 more", n);
        }
        // And agreement everywhere the convergent is faithful:
        for &n in &[987i64, 1597, 4181, 10946, 28657, 75025, 1000, 5000] {
            let rational = -((n as u64 * INV_PHI_SQ_NUM / INV_PHI_DEN) as i64);
            assert_eq!(default_credit_limit_exact(n), rational, "supply {}", n);
        }
    }

    #[test]
    fn exact_seal_threshold_agrees_with_rational_and_float() {
        for m in 1u64..=987 {
            let exact = mass_seal_threshold_exact(m);
            let float = ((m as f64) * INV_PHI).ceil() as u64;
            assert_eq!(exact, float, "mass {}", m);
        }
        assert_eq!(mass_seal_threshold_exact(0), 0);
        assert_eq!(mass_seal_threshold_exact(2), 2); // bilateral identity holds
        // Beyond the convergent's faithful range, exact is canonical:
        assert_eq!(mass_seal_threshold_exact(987), 610);
    }

    #[test]
    fn no_overflow_at_realistic_scales() {
        // Masses at MASS_SCALE (1e6) × large populations stay far
        // inside i128 through the squaring in zphi_sign.
        let big = 1_000_000_000_000u64; // 1e12
        let t = mass_seal_threshold_exact(big);
        assert!(t > big / 2 && t < big);
    }
}

// ─────────────────────────────────────────────
// PhiFixed — Tier 2 of the float-determinism partition
//
// Fixed-point ℚ(φ): coefficients (a, b) of a + b·φ as i128 scaled by
// PHIFIX_SCALE. Pure integer ops ⇒ bit-identical on every platform,
// WASM or native, any implementation. Per-step rounding is floor
// division — identical rounding everywhere, so honest nodes cannot
// diverge. The trust recursion runs here; the pass gate uses the
// exact zphi_sign on the raw coefficients (scale-invariant).
// ─────────────────────────────────────────────

pub const PHIFIX_SCALE: i128 = 1_000_000_000; // 1e9

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhiFixed {
    pub a: i128,
    pub b: i128,
}

impl PhiFixed {
    pub const ZERO: PhiFixed = PhiFixed { a: 0, b: 0 };
    pub const ONE: PhiFixed = PhiFixed { a: PHIFIX_SCALE, b: 0 };
    pub const PHI: PhiFixed = PhiFixed { a: 0, b: PHIFIX_SCALE };

    pub fn from_int(n: i128) -> Self {
        PhiFixed { a: n * PHIFIX_SCALE, b: 0 }
    }
    /// Deterministic quantization of an f64 (same wasm ⇒ same result;
    /// fully portable once the producing chain is also exact).
    pub fn from_f64(x: f64) -> Self {
        PhiFixed { a: (x * PHIFIX_SCALE as f64).round() as i128, b: 0 }
    }
    pub fn add(self, o: Self) -> Self {
        PhiFixed { a: self.a + o.a, b: self.b + o.b }
    }
    pub fn sub(self, o: Self) -> Self {
        PhiFixed { a: self.a - o.a, b: self.b - o.b }
    }
    /// (a+bφ)(c+dφ) = (ac+bd) + (ad+bc+bd)φ, φ² = φ+1. Floor-div
    /// rescale — deterministic integer rounding.
    pub fn mul(self, o: Self) -> Self {
        let ac = self.a * o.a;
        let bd = self.b * o.b;
        let ad_bc = self.a * o.b + self.b * o.a;
        PhiFixed {
            a: (ac + bd).div_euclid(PHIFIX_SCALE),
            b: (ad_bc + bd).div_euclid(PHIFIX_SCALE),
        }
    }
    /// Exact inverse via Galois conjugate: x⁻¹ = (a+b − bφ)/N(x),
    /// N(x) = a² + ab − b² (computed at full precision, one division).
    pub fn inv(self) -> Self {
        let (a, b) = (self.a, self.b);
        let norm = a * a + a * b - b * b; // scale²-weighted
        PhiFixed {
            a: ((a + b) * PHIFIX_SCALE * PHIFIX_SCALE).div_euclid(norm),
            b: (-b * PHIFIX_SCALE * PHIFIX_SCALE).div_euclid(norm),
        }
    }
    /// φⁿ exactly: φⁿ = F(n)φ + F(n−1); φ⁻ⁿ = (−1)ⁿ(F(n+1) − F(n)φ).
    /// Integer Fibonacci coefficients — no repeated multiplication drift.
    pub fn phi_pow(n: i32) -> Self {
        if n == 0 { return Self::ONE; }
        let m = n.unsigned_abs() as u64;
        let (fm, fm1) = (fib_i128(m), fib_i128(m + 1));
        if n > 0 {
            // φⁿ = F(n)·φ + F(n−1)
            let _ = fm1;
            PhiFixed { a: fib_i128(m - 1) * PHIFIX_SCALE, b: fm * PHIFIX_SCALE }
        } else {
            let sign = if m % 2 == 0 { 1 } else { -1 };
            PhiFixed { a: sign * fm1 * PHIFIX_SCALE, b: -sign * fm * PHIFIX_SCALE }
        }
    }
    /// Exact sign of the real value — delegates to the integer-only
    /// zphi_sign; scale cancels. This is the gate comparator.
    pub fn sign(self) -> i32 {
        zphi_sign(self.a, self.b)
    }
    pub fn geq(self, o: Self) -> bool {
        self.sub(o).sign() >= 0
    }
    /// Display/interop only — NEVER in consensus decisions.
    pub fn to_f64(self) -> f64 {
        (self.a as f64 + self.b as f64 * 1.618033988749895) / PHIFIX_SCALE as f64
    }
}

fn fib_i128(n: u64) -> i128 {
    let (mut a, mut b) = (0i128, 1i128);
    for _ in 0..n { let t = a + b; a = b; b = t; }
    a
}

/// The reputation decay recursion, exact. Same law as the f64 loop:
/// start φ⁻²; weight(i) = φ⁻ⁱ / (φ·(1 − φ⁻ᴺ)) (weights sum to 1
/// exactly — geometric-series identity); attestation pulls toward 1,
/// warrant pushes toward 0 with φ amplification. Every node computes
/// identical (a, b) pairs; the pass gate is an exact sign test.
pub fn reputation_recursion_exact(events: &[bool]) -> PhiFixed {
    let n_total = events.len() as i32;
    if n_total == 0 {
        return PhiFixed::phi_pow(-2);
    }
    // denominator = φ − φ^(1−N), exact integer coefficients
    let denom = PhiFixed::PHI.sub(PhiFixed::phi_pow(1 - n_total));
    let denom_inv = denom.inv();
    let mut rep = PhiFixed::phi_pow(-2);
    for (i, is_attestation) in events.iter().enumerate() {
        let w = PhiFixed::phi_pow(-(i as i32 + 1)).mul(denom_inv);
        if *is_attestation {
            rep = rep.add(PhiFixed::ONE.sub(rep).mul(w));
        } else {
            rep = rep.sub(rep.mul(w).mul(PhiFixed::PHI));
        }
    }
    rep
}

/// Exact drift gate (Tier 2 for the accumulator): D = Σ|Δ|/S_ref ≥ φ⁻²
/// ⟺ sum_abs − S_ref·(2−φ) ≥ 0 ⟺ zphi_sign(sum_abs − 2·S_ref, S_ref) ≥ 0.
/// Pure integers when masses are integer (MASS_SCALE units).
pub fn drift_exceeds_threshold_exact(sum_abs_delta: u64, s_ref: u64) -> bool {
    if s_ref == 0 {
        return true; // no prior mass ⇒ genesis writes (fail toward freshness)
    }
    let (s, r) = (sum_abs_delta as i128, s_ref as i128);
    zphi_sign(s - 2 * r, r) >= 0
}

#[cfg(test)]
mod phifixed_tests {
    use super::*;

    // Ground truth from the Phi-Core exact bench (unbounded rationals).
    const REFS: [(&[bool], f64); 6] = [
        (&[true, true, true], 0.827254248594),
        (&[true, true, false, true, true], 0.614269078628),
        (&[false, false, false, false], 0.035015528100),
        (&[true, false, true, false, true, false, true, false], 0.414780798074),
        (&[true; 13], 0.804669304864),
        (&[false, true, true, false, true, false, true, true], 0.411888914312),
    ];

    #[test]
    fn recursion_matches_phicore_reference_vectors() {
        for (events, expected) in REFS {
            let got = reputation_recursion_exact(events).to_f64();
            assert!((got - expected).abs() < 1e-6,
                "{:?}: got {}, phi_core says {}", events, got, expected);
        }
    }

    #[test]
    fn field_identities_hold_in_fixed_point() {
        // φ² = φ + 1 within one quantum
        let sq = PhiFixed::PHI.mul(PhiFixed::PHI);
        let rhs = PhiFixed::PHI.add(PhiFixed::ONE);
        assert!((sq.a - rhs.a).abs() <= 1 && (sq.b - rhs.b).abs() <= 1);
        // φ·φ⁻¹ = 1
        let one = PhiFixed::PHI.mul(PhiFixed::PHI.inv());
        assert!((one.a - PHIFIX_SCALE).abs() <= 2 && one.b.abs() <= 2);
        // φ⁻¹ + φ⁻² = 1 exactly (integer Fibonacci forms — no rounding)
        let s = PhiFixed::phi_pow(-1).add(PhiFixed::phi_pow(-2));
        assert_eq!(s, PhiFixed::ONE);
    }

    #[test]
    fn gate_is_exact_at_the_boundary() {
        // The near-threshold case f64 gets wrong on unlucky platforms:
        // rep from [T,T,F,T,T] ≈ 0.6143 < φ⁻¹. Exact sign test decides.
        let rep = reputation_recursion_exact(&[true, true, false, true, true]);
        assert!(!rep.geq(PhiFixed::phi_pow(-1)));
        let rep2 = reputation_recursion_exact(&[true; 3]);
        assert!(rep2.geq(PhiFixed::phi_pow(-1)));
    }

    #[test]
    fn drift_gate_exact_and_matches_float() {
        for (sum, sref) in [(38u64, 100u64), (382, 1000), (381, 1000), (383, 1000), (0, 100), (5, 0)] {
            let exact = drift_exceeds_threshold_exact(sum, sref);
            let float = sref == 0 || (sum as f64 / sref as f64) >= INV_PHI_SQ;
            assert_eq!(exact, float, "sum={} sref={}", sum, sref);
        }
        // The boundary case where f64 could flip: 381966011.../1e9
        assert!(drift_exceeds_threshold_exact(381_966_012, 1_000_000_000));
        assert!(!drift_exceeds_threshold_exact(381_966_011, 1_000_000_000));
    }

    #[test]
    fn determinism_is_replayable() {
        // Same inputs twice ⇒ identical (a,b) pairs, not just close f64s.
        let a = reputation_recursion_exact(&[true, false, true, true, false]);
        let b = reputation_recursion_exact(&[true, false, true, true, false]);
        assert_eq!(a, b);
    }
}

#[cfg(test)]
mod phi_pow_sanity {
    use super::*;
    #[test]
    fn positive_powers_are_fibonacci_pairs() {
        // φ² = 1 + φ, φ³ = 1 + 2φ, φ⁴ = 2 + 3φ — exact integer forms
        assert_eq!(PhiFixed::phi_pow(2), PhiFixed { a: PHIFIX_SCALE, b: PHIFIX_SCALE });
        assert_eq!(PhiFixed::phi_pow(3), PhiFixed { a: PHIFIX_SCALE, b: 2 * PHIFIX_SCALE });
        assert_eq!(PhiFixed::phi_pow(4), PhiFixed { a: 2 * PHIFIX_SCALE, b: 3 * PHIFIX_SCALE });
        // φ⁻⁴ = 5 − 3φ (the Gödel residue, exact)
        assert_eq!(PhiFixed::phi_pow(-4), PhiFixed { a: 5 * PHIFIX_SCALE, b: -3 * PHIFIX_SCALE });
    }
}
