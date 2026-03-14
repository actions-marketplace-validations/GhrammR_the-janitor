//! # Backlog Pruner — Deterministic PR Garbage Collection Engine
//!
//! Analyses pull requests against a repository's current `master` branch to identify
//! three categories of stale or meaningless contributions:
//!
//! - [`semantic_null`]: The PR changes no execution logic — only identifiers, strings,
//!   or comments differ from the base branch.
//! - [`ghost_collision`]: The PR targets architecture that has since decayed on `master`.
//!   More than 50% of modified functions no longer exist or have structurally diverged.
//! - [`unwired_island`]: The PR introduces new functions with zero callers — unreachable
//!   dead-on-arrival code that will never execute.
//!
//! Each analysis produces a [`PrunerFlag`] bundled into a
//! [`GarbageCollectionManifest`] carrying an ML-DSA-65 cryptographic signature
//! (FIPS 204 — Module-Lattice-Based Digital Signature Standard).

pub mod ghost_collision;
pub mod semantic_null;
pub mod unwired_island;

use fips204::ml_dsa_65;
use fips204::traits::Signer;

// ---------------------------------------------------------------------------
// GarbageCollectionManifest
// ---------------------------------------------------------------------------

/// The three PR-garbage categories detected by the Backlog Pruner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrunerFlag {
    /// The PR changes no execution logic; only cosmetic tokens differ.
    SemanticNull,
    /// The PR targets architecture that has decayed on `master`.
    GhostCollision,
    /// The PR introduces unreachable code: new functions with no callers.
    UnwiredIsland,
}

/// A cryptographically signed garbage-collection verdict for a single PR.
///
/// The [`signature`][Self::signature] field holds a detached ML-DSA-65 signature
/// (FIPS 204) over the canonical payload:
/// `"<pr_number>:<flag_str>:<blake3_hex>"`.
///
/// Verifiers should reconstruct the same payload and call
/// `ml_dsa_65::PublicKey::verify` with the companion public key.
pub struct GarbageCollectionManifest {
    /// The pull-request number this verdict applies to.
    pub pr_number: u64,
    /// The garbage-collection flag assigned by the pruner.
    pub flag: PrunerFlag,
    /// BLAKE3 hash of the structural skeleton that produced this verdict.
    pub skeleton_hash: [u8; 32],
    /// Detached ML-DSA-65 signature (FIPS 204) over `"<pr_number>:<flag>:<blake3_hex>"`.
    ///
    /// Heap-boxed because the signature is 3 309 bytes — too large for stack.
    pub signature: Box<[u8; ml_dsa_65::SIG_LEN]>,
}

impl GarbageCollectionManifest {
    /// Sign a pruner verdict and return the completed manifest.
    ///
    /// Uses `try_sign_with_seed` for fully deterministic signing — no OS entropy
    /// is consumed during manifest generation.  The seed is derived from the
    /// BLAKE3 hash of the skeleton itself, ensuring signing is reproducible.
    ///
    /// # Parameters
    /// - `pr_number`: The PR being evaluated.
    /// - `flag`: The [`PrunerFlag`] assigned by the analysis.
    /// - `skeleton_hash`: The BLAKE3 hash of the structural skeleton.
    /// - `signing_key`: An ML-DSA-65 private key used for attestation.
    ///
    /// # Errors
    /// Returns `Err` if the ML-DSA-65 signing operation fails.
    pub fn sign(
        pr_number: u64,
        flag: PrunerFlag,
        skeleton_hash: [u8; 32],
        signing_key: &ml_dsa_65::PrivateKey,
    ) -> anyhow::Result<Self> {
        let flag_str = flag_label(&flag);
        let blake3_hex = hex_encode(&skeleton_hash);
        let payload = format!("{pr_number}:{flag_str}:{blake3_hex}");

        let signature = signing_key
            .try_sign_with_seed(&skeleton_hash, payload.as_bytes(), &[])
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {e}"))?;

        Ok(Self {
            pr_number,
            flag,
            skeleton_hash,
            signature: Box::new(signature),
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Human-readable label for a [`PrunerFlag`] — embedded in the signed payload.
pub fn flag_label(flag: &PrunerFlag) -> &'static str {
    match flag {
        PrunerFlag::SemanticNull => "SEMANTIC_NULL",
        PrunerFlag::GhostCollision => "GHOST_COLLISION",
        PrunerFlag::UnwiredIsland => "UNWIRED_ISLAND",
    }
}

/// Lowercase hex-encode of a 32-byte array.
///
/// Implemented via a stack-allocated lookup table — no heap allocation beyond
/// the returned `String` capacity.
pub fn hex_encode(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}
