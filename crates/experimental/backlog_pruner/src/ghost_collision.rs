//! # Ghost Collision Detector
//!
//! Detects when a PR targets architecture that has decayed on `master`.
//!
//! ## Algorithm
//! 1. Extract the fully-qualified names (`module::Class::method`) of all
//!    functions modified by the PR's patch (supplied by the caller as
//!    `modified_functions`).
//! 2. For each modified function, look it up in the `MasterIndex` — the
//!    Anatomist-derived registry of current `master` branch symbols.
//! 3. Compute the *decay ratio*: functions that are missing from `master`
//!    **or** whose structural hash has diverged by > 40% of hash bits.
//! 4. If the decay ratio exceeds 50%, the PR is `GHOST_COLLISION`.
//!
//! ## Structural Hash Divergence
//! Hash divergence is measured as the normalised Hamming distance between the
//! two 32-byte BLAKE3 hashes (256 bits).  Two hashes are considered diverged
//! when more than 40% of bits differ.

/// An entry in the master-branch symbol index.
///
/// The caller populates this from the Anatomist registry for the functions
/// that were modified by the PR.  `structural_hash` is the BLAKE3 hash of
/// the function body's structural skeleton (see [`crate::semantic_null`]).
#[derive(Debug, Clone)]
pub struct MasterEntry {
    /// Fully-qualified function name (e.g., `engine::renderer::draw_mesh`).
    pub qualified_name: String,
    /// BLAKE3 structural skeleton hash of the function on `master`.
    pub structural_hash: [u8; 32],
}

/// Index of the current `master` branch's symbol registry.
///
/// Build this from the Anatomist scan of the `master` branch before running
/// the pruner.  Only functions referenced by the PR need to be included —
/// the caller is responsible for filtering.
pub struct MasterIndex {
    entries: Vec<MasterEntry>,
}

impl MasterIndex {
    /// Create a new `MasterIndex` from a list of master-branch entries.
    pub fn new(entries: Vec<MasterEntry>) -> Self {
        Self { entries }
    }

    /// Look up a function by fully-qualified name.
    ///
    /// Returns `None` if the function does not exist on `master`.
    pub fn get(&self, qualified_name: &str) -> Option<&MasterEntry> {
        self.entries
            .iter()
            .find(|e| e.qualified_name == qualified_name)
    }
}

/// Fraction of hash bits that must differ to classify a function as
/// structurally diverged from `master`.
const DIVERGENCE_THRESHOLD: f64 = 0.40;

/// Returns `true` if the two BLAKE3 hashes have diverged by more than
/// [`DIVERGENCE_THRESHOLD`] of their 256 bits.
fn is_diverged(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let differing_bits: u32 = a
        .iter()
        .zip(b.iter())
        .map(|(&x, &y)| (x ^ y).count_ones())
        .sum();
    let ratio = differing_bits as f64 / 256.0;
    ratio > DIVERGENCE_THRESHOLD
}

/// Returns `true` if the PR targets decayed architecture — `GHOST_COLLISION`.
///
/// # Parameters
/// - `modified_functions`: Fully-qualified names of functions modified by the PR.
/// - `pr_hashes`: Structural BLAKE3 hashes of those functions in the PR branch,
///   parallel to `modified_functions`.
/// - `master`: The current master-branch symbol index.
///
/// # Panics
/// Panics if `modified_functions` and `pr_hashes` have different lengths.
pub fn is_ghost_collision(
    modified_functions: &[String],
    pr_hashes: &[[u8; 32]],
    master: &MasterIndex,
) -> bool {
    assert_eq!(
        modified_functions.len(),
        pr_hashes.len(),
        "modified_functions and pr_hashes must be parallel slices"
    );

    if modified_functions.is_empty() {
        return false;
    }

    let decayed = modified_functions
        .iter()
        .zip(pr_hashes.iter())
        .filter(|(name, pr_hash)| match master.get(name) {
            None => true, // function no longer exists on master
            Some(entry) => is_diverged(&entry.structural_hash, pr_hash),
        })
        .count();

    let decay_ratio = decayed as f64 / modified_functions.len() as f64;
    decay_ratio > 0.50
}
