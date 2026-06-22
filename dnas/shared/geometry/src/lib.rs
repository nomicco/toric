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
        assert_eq!(previous_fibonacci(2), 1);
        assert_eq!(previous_fibonacci(21), 13); // previous of 21 is 13
        assert_eq!(previous_fibonacci(22), 21);
        assert_eq!(previous_fibonacci(987), 610);
    }

    #[test]
    fn genesis_credit_supply_is_fibonacci() {
        // GENESIS_CREDIT_SUPPLY = 987 = F(16). Verify next/prev bracket it.
        let supply: u64 = 987;
        assert_eq!(next_fibonacci(supply), 1597);
        assert_eq!(previous_fibonacci(supply), 610);
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
}