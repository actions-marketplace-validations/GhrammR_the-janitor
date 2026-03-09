//! Governance manifest: `janitor.toml`.
//!
//! [`JanitorPolicy`] is the version-controlled, maintainer-controlled
//! configuration that overrides The Janitor's global defaults.  Place a
//! `janitor.toml` at the repository root to opt into stricter or more
//! permissive slop gates — without modifying CI pipeline variables.
//!
//! # Differentiation from platform kill-switches
//!
//! GitHub's built-in merge queue and ruleset features operate as opaque
//! kill-switches: a single global threshold applies to all PRs with no
//! context about the project's risk tolerance.  `janitor.toml` encodes
//! the maintainers' *specific* slop tolerance, committed alongside the code
//! it governs.  It is reviewable, diffable, and auditable by the entire team.
//!
//! # Example `janitor.toml`
//!
//! ```toml
//! # Raise the gate threshold for a high-velocity repo.
//! min_slop_score     = 150
//!
//! # All PRs must reference a GitHub issue.
//! require_issue_link = true
//!
//! # Resurrecting previously-deleted symbols is intentional here.
//! allowed_zombies    = false
//!
//! # PRs tagged [REFACTOR] get a 30-point gate relaxation.
//! refactor_bonus     = 30
//!
//! # Project-specific antipattern detectors.
//! custom_antipatterns = ["tools/queries/no_global_state.scm"]
//! ```

use serde::{Deserialize, Serialize};
use std::path::Path;

// ---------------------------------------------------------------------------
// ForgeConfig — [forge] sub-table
// ---------------------------------------------------------------------------

/// Engine-level configuration nested under `[forge]` in `janitor.toml`.
///
/// These settings control the slop-detection engine's behaviour independently
/// of the governance gate thresholds that live at the top level of the manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ForgeConfig {
    /// Ecosystem-specific automation account handles that are exempt from the
    /// **unlinked-PR penalty only**.
    ///
    /// Use this field for accounts that lack the standard GitHub `[bot]` suffix
    /// but are verified, non-human contributors — e.g. `r-ryantm` (NixOS package
    /// updater) or `app/nixpkgs-ci`.  These accounts do not open companion GitHub
    /// Issues for their PRs by design; penalising them with `unlinked_pr × 20`
    /// systematically inflates slop scores and destroys ROI signal.
    ///
    /// **Full slop analysis still executes.** Only the issue-link check is
    /// bypassed.  Dead symbols, logic clones, and antipatterns are still scored.
    ///
    /// Matched **case-insensitively** against the PR author.  Exact handle, no
    /// glob or regex.
    ///
    /// ```toml
    /// [forge]
    /// automation_accounts = ["r-ryantm", "app/nixpkgs-ci"]
    /// ```
    pub automation_accounts: Vec<String>,
}

// ---------------------------------------------------------------------------
// JanitorPolicy
// ---------------------------------------------------------------------------

/// Governance manifest loaded from `janitor.toml` at the repository root.
///
/// All fields carry defaults that match The Janitor's built-in constants, so
/// the *absence* of a manifest is functionally identical to an all-defaults
/// configuration.  Unknown fields are silently ignored — forward-compatible
/// with future Janitor versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct JanitorPolicy {
    /// Composite slop-score threshold above which `janitor bounce` reports a
    /// gate failure.
    ///
    /// Corresponds to the `fail_on_slop` threshold in the GitHub Action.
    /// Default: **100**.  Lower values tighten the gate; higher values allow
    /// noisier PRs through.
    pub min_slop_score: u32,

    /// When `true`, any PR with no linked GitHub issue is automatically
    /// treated as failing the gate, regardless of `min_slop_score`.
    ///
    /// Default: `false`.
    pub require_issue_link: bool,

    /// When `true`, zombie-symbol re-introductions (verbatim body match to a
    /// previously deleted dead symbol) do not contribute to the score.
    ///
    /// Default: `false`.  Set to `true` only when the codebase is actively
    /// resurrecting symbols that were incorrectly deleted in a prior cleanup
    /// pass.
    pub allowed_zombies: bool,

    /// Reserved for post-quantum cryptography enforcement.
    ///
    /// When `true`, The Janitor will refuse patches that introduce pre-quantum
    /// cryptographic primitives (RSA, ECDSA, AES-128, SHA-1).
    ///
    /// Default: `false`.  Not yet implemented; this flag is a
    /// forward-compatibility placeholder for the PQC enforcement module.
    pub pqc_enforced: bool,

    /// Paths to custom `.scm` tree-sitter query files that define
    /// project-specific antipatterns.
    ///
    /// Each file must contain a named pattern `@slop` — the Slop Hunter
    /// counts each match as one antipattern finding (weight ×50 against the
    /// composite slop score).
    ///
    /// Paths are relative to the repository root.
    ///
    /// Default: `[]` (no custom queries).
    pub custom_antipatterns: Vec<String>,

    /// Score reduction applied when a PR body contains a `[REFACTOR]` or
    /// `[FIXES-DEBT]` marker — the **Refactor Bonus**.
    ///
    /// When set, the gate threshold is *raised* by this amount for marked PRs,
    /// effectively relaxing the gate for intentional restructuring work.  The
    /// threshold floors at `min_slop_score` (no negative gate).
    ///
    /// A PR body qualifies if it contains the literal string `[REFACTOR]` or
    /// `[FIXES-DEBT]` anywhere in the text.
    ///
    /// Default: `0` (no bonus).
    pub refactor_bonus: u32,

    /// Automation account handles that are exempt from the unlinked-PR penalty.
    ///
    /// Entries are matched **case-insensitively** against the PR author.  Exact
    /// handle string, no glob or regex.  Use this to suppress the
    /// `unlinked_pr = 1` penalty for known, trusted automation accounts that
    /// are unlikely to open companion issues (e.g. a project-local CI bot).
    ///
    /// **Deliberately empty by default** — maintainers must explicitly commit
    /// each trusted automation handle.  The engine hardcodes nothing; if you
    /// want `r-ryantm` or `dependabot[bot]` to be exempt, list them here.
    ///
    /// ```toml
    /// trusted_bot_authors = ["r-ryantm", "dependabot[bot]", "renovate[bot]"]
    /// ```
    ///
    /// Default: `[]` (no exemptions — all authors are investigated equally).
    pub trusted_bot_authors: Vec<String>,

    /// Engine-level settings nested under `[forge]`.
    ///
    /// See [`ForgeConfig`] for available fields.  Defaults to an empty
    /// configuration when the `[forge]` section is absent from `janitor.toml`.
    pub forge: ForgeConfig,
}

impl Default for JanitorPolicy {
    fn default() -> Self {
        Self {
            min_slop_score: 100,
            require_issue_link: false,
            allowed_zombies: false,
            pqc_enforced: false,
            custom_antipatterns: Vec::new(),
            refactor_bonus: 0,
            trusted_bot_authors: Vec::new(),
            forge: ForgeConfig::default(),
        }
    }
}

impl JanitorPolicy {
    // -----------------------------------------------------------------------
    // Loading
    // -----------------------------------------------------------------------

    /// Attempts to load `janitor.toml` from `repo_root`.
    ///
    /// Returns the default policy when:
    /// - `janitor.toml` does not exist (silent, expected case)
    /// - the file cannot be read (emits a warning to stderr)
    /// - the file contains invalid TOML or unknown fields (emits a warning)
    ///
    /// Policy load **never fails the bounce pipeline** — a malformed manifest
    /// falls back to defaults rather than blocking CI.
    pub fn load(repo_root: &Path) -> Self {
        let path = repo_root.join("janitor.toml");
        if !path.exists() {
            return Self::default();
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "warning: janitor.toml — failed to read {}: {}. Using defaults.",
                    path.display(),
                    e
                );
                return Self::default();
            }
        };
        match toml::from_str::<Self>(&raw) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: janitor.toml — parse error: {e}. Using defaults.");
                Self::default()
            }
        }
    }

    // -----------------------------------------------------------------------
    // Automation account detection
    // -----------------------------------------------------------------------

    /// Returns `true` when `author` is a recognized automation account.
    ///
    /// Three detection layers, evaluated in order — all zero-allocation in the
    /// hot path (no `String` clones):
    ///
    /// 1. **GitHub App suffix** — any author ending with `[bot]` is
    ///    unconditionally recognized (Dependabot, Renovate, GitHub Actions apps,
    ///    etc.).  No configuration required.
    ///
    /// 2. **`trusted_bot_authors`** — handles listed at the top level of
    ///    `janitor.toml`.  Backwards-compatible with existing manifests.
    ///
    /// 3. **`[forge].automation_accounts`** — handles listed in the `[forge]`
    ///    sub-section of `janitor.toml`.  Designed for ecosystem accounts that
    ///    lack the `[bot]` suffix (e.g. `r-ryantm`, `app/nixpkgs-ci`).
    ///
    /// Matching is **case-insensitive** and exact (no globs, no prefix matching).
    ///
    /// When all lists are empty (the default), only the `[bot]` suffix rule
    /// fires — no author is unconditionally exempted by configuration alone.
    pub fn is_automation_account(&self, author: &str) -> bool {
        // Layer 1: standard GitHub App suffix — zero-allocation static check.
        if author.ends_with("[bot]") {
            return true;
        }
        // Layer 2 & 3: config-defined lists — `eq_ignore_ascii_case` is
        // zero-allocation (byte-level comparison, no String allocation).
        self.trusted_bot_authors
            .iter()
            .any(|b| b.eq_ignore_ascii_case(author))
            || self
                .forge
                .automation_accounts
                .iter()
                .any(|a| a.eq_ignore_ascii_case(author))
    }

    /// Returns `true` when `author` appears in [`Self::trusted_bot_authors`].
    ///
    /// Delegates to [`Self::is_automation_account`], which additionally
    /// checks the standard GitHub `[bot]` suffix and `[forge].automation_accounts`.
    pub fn is_trusted_bot(&self, author: &str) -> bool {
        self.is_automation_account(author)
    }

    // -----------------------------------------------------------------------
    // Gate logic
    // -----------------------------------------------------------------------

    /// Returns `true` if the PR body contains a Refactor Bonus marker.
    ///
    /// Recognised markers: `[REFACTOR]`, `[FIXES-DEBT]`.
    pub fn is_refactor_pr(pr_body: Option<&str>) -> bool {
        pr_body
            .map(|b| b.contains("[REFACTOR]") || b.contains("[FIXES-DEBT]"))
            .unwrap_or(false)
    }

    /// Returns the effective gate threshold for this PR.
    ///
    /// If the PR carries a refactor marker and `refactor_bonus > 0`, the
    /// threshold is raised by `refactor_bonus` (the gate is relaxed for
    /// intentional restructuring work).
    pub fn effective_gate(&self, pr_body: Option<&str>) -> u32 {
        if self.refactor_bonus > 0 && Self::is_refactor_pr(pr_body) {
            self.min_slop_score.saturating_add(self.refactor_bonus)
        } else {
            self.min_slop_score
        }
    }

    /// Returns `true` when the composite score passes the policy gate.
    ///
    /// Equivalent to `score < self.effective_gate(pr_body)`.
    pub fn gate_passes(&self, score: u32, pr_body: Option<&str>) -> bool {
        score < self.effective_gate(pr_body)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_gate_is_100() {
        let p = JanitorPolicy::default();
        assert_eq!(p.min_slop_score, 100);
        assert!(p.gate_passes(99, None));
        assert!(!p.gate_passes(100, None));
    }

    #[test]
    fn refactor_bonus_raises_threshold() {
        let p = JanitorPolicy {
            min_slop_score: 100,
            refactor_bonus: 30,
            ..Default::default()
        };
        // Without marker: gate at 100.
        assert!(!p.gate_passes(100, Some("Normal PR")));
        // With marker: gate raised to 130.
        assert!(p.gate_passes(100, Some("Refactoring internals [REFACTOR]")));
        assert!(p.gate_passes(129, Some("[REFACTOR]")));
        assert!(!p.gate_passes(130, Some("[REFACTOR]")));
    }

    #[test]
    fn fixes_debt_marker_also_qualifies() {
        let p = JanitorPolicy {
            min_slop_score: 100,
            refactor_bonus: 20,
            ..Default::default()
        };
        assert!(p.gate_passes(110, Some("Remove dead helpers [FIXES-DEBT]")));
    }

    #[test]
    fn zero_bonus_has_no_effect_on_gate() {
        let p = JanitorPolicy::default(); // refactor_bonus = 0
        assert!(!p.gate_passes(100, Some("[REFACTOR]")));
    }

    #[test]
    fn roundtrip_toml_serialization() {
        let original = JanitorPolicy {
            min_slop_score: 150,
            require_issue_link: true,
            allowed_zombies: false,
            pqc_enforced: false,
            custom_antipatterns: vec!["tools/queries/no_global.scm".to_owned()],
            refactor_bonus: 25,
            trusted_bot_authors: vec!["release-bot".to_owned()],
            forge: ForgeConfig::default(),
        };
        let serialised = toml::to_string(&original).unwrap();
        let deserialised: JanitorPolicy = toml::from_str(&serialised).unwrap();
        assert_eq!(original, deserialised);
    }

    #[test]
    fn trusted_bot_empty_by_default() {
        let p = JanitorPolicy::default();
        assert!(p.trusted_bot_authors.is_empty());
        // With empty lists, [bot]-suffix authors ARE detected (layer 1 — no config required).
        assert!(p.is_trusted_bot("dependabot[bot]"));
        // Non-[bot] authors with no config entry must NOT be exempt.
        assert!(!p.is_trusted_bot("r-ryantm"));
        assert!(!p.is_trusted_bot(""));
    }

    #[test]
    fn trusted_bot_exact_case_insensitive_match() {
        let p = JanitorPolicy {
            trusted_bot_authors: vec!["release-bot".to_owned(), "R-RyanTM".to_owned()],
            ..Default::default()
        };
        assert!(p.is_trusted_bot("release-bot"));
        assert!(p.is_trusted_bot("RELEASE-BOT")); // case-insensitive
        assert!(p.is_trusted_bot("r-ryantm")); // mixed-case entry normalised
        assert!(!p.is_trusted_bot("release")); // prefix match must not fire
        assert!(!p.is_trusted_bot(""));
    }

    #[test]
    fn trusted_bot_roundtrip_toml() {
        let raw = "trusted_bot_authors = [\"release-bot\", \"ci-runner\"]\n";
        let p: JanitorPolicy = toml::from_str(raw).unwrap();
        assert_eq!(p.trusted_bot_authors, ["release-bot", "ci-runner"]);
        assert!(p.is_trusted_bot("ci-runner"));
        // [bot]-suffix authors are detected via layer-1 even when not in trusted_bot_authors.
        assert!(p.is_trusted_bot("dependabot[bot]"));
    }

    // --- Automation shield ---

    #[test]
    fn bot_suffix_detected_without_config() {
        // Any author ending with "[bot]" is recognised automatically — no
        // trusted_bot_authors or automation_accounts entry required.
        let p = JanitorPolicy::default();
        assert!(p.is_automation_account("dependabot[bot]"));
        assert!(p.is_automation_account("renovate[bot]"));
        assert!(p.is_automation_account("github-actions[bot]"));
        assert!(p.is_automation_account("app/nixpkgs-ci[bot]"));
    }

    #[test]
    fn non_bot_suffix_not_detected_without_config() {
        // Accounts without [bot] suffix and not in any config list must NOT fire.
        let p = JanitorPolicy::default();
        assert!(!p.is_automation_account("r-ryantm"));
        assert!(!p.is_automation_account("app/nixpkgs-ci"));
        assert!(!p.is_automation_account(""));
    }

    #[test]
    fn forge_automation_accounts_detected() {
        let p = JanitorPolicy {
            forge: ForgeConfig {
                automation_accounts: vec!["r-ryantm".to_owned(), "app/nixpkgs-ci".to_owned()],
            },
            ..Default::default()
        };
        assert!(p.is_automation_account("r-ryantm"));
        assert!(p.is_automation_account("R-RyanTM")); // case-insensitive
        assert!(p.is_automation_account("app/nixpkgs-ci"));
        assert!(!p.is_automation_account("some-human"));
    }

    #[test]
    fn forge_automation_accounts_roundtrip_toml() {
        let raw = "[forge]\nautomation_accounts = [\"r-ryantm\", \"app/nixpkgs-ci\"]\n";
        let p: JanitorPolicy = toml::from_str(raw).unwrap();
        assert_eq!(p.forge.automation_accounts, ["r-ryantm", "app/nixpkgs-ci"]);
        assert!(p.is_automation_account("r-ryantm"));
        assert!(p.is_automation_account("app/nixpkgs-ci"));
        assert!(!p.is_automation_account("human-author"));
    }

    #[test]
    fn is_trusted_bot_delegates_to_is_automation_account() {
        // is_trusted_bot() is a backwards-compat alias — must match is_automation_account().
        let p = JanitorPolicy {
            forge: ForgeConfig {
                automation_accounts: vec!["r-ryantm".to_owned()],
            },
            ..Default::default()
        };
        assert_eq!(
            p.is_trusted_bot("r-ryantm"),
            p.is_automation_account("r-ryantm")
        );
        assert_eq!(
            p.is_trusted_bot("dependabot[bot]"),
            p.is_automation_account("dependabot[bot]")
        );
    }

    #[test]
    fn load_missing_file_returns_default() {
        let tmp = std::env::temp_dir().join("janitor_policy_missing_test");
        let p = JanitorPolicy::load(&tmp);
        assert_eq!(p, JanitorPolicy::default());
    }

    #[test]
    fn load_valid_toml() {
        let dir = std::env::temp_dir().join("janitor_policy_test_load");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("janitor.toml"),
            "min_slop_score = 200\nrequire_issue_link = true\n",
        )
        .unwrap();
        let p = JanitorPolicy::load(&dir);
        assert_eq!(p.min_slop_score, 200);
        assert!(p.require_issue_link);
    }
}
