# ARCHITECTURE.md
**VERSION:** v6.13.0
**DATE:** 2026-03-14
**CONTEXT:** v6.13.0 — Swarm Clustering (cross-PR LSH structural clone detection; `collided_pr_numbers` in BounceLogEntry); Ouroboros Hotfix (self-collision exclusion in LshIndex query); Ingestion Pipeline Purification (vendor-directory pre-filter removed; domain router receives raw diffs); UI Purification (governor Check Run expunges "Adaptive Brain"; LSH Integrity Score surfaced); Backlog Pruner experimental crate (`semantic_null`, `ghost_collision`, `unwired_island`; ML-DSA-65 manifest signing); 338 tests; 23 grammars.

---

## I. THE ANATOMIST: CST PARSING & ENTITY EXTRACTION

**Crate**: `crates/anatomist`
**Role**: Converts polyglot source into zero-copy `Entity` facts for the dead-symbol pipeline.

### 1.1 Core Architecture

- **Parser Host**: Tree-sitter (23 grammars via `crates/polyglot`) + `memmap2::Mmap` zero-copy file reads.
- **Languages (entity extraction)**: Python, Rust, C, C++, Java, C#, Go, JavaScript, TypeScript, GLSL, ObjC, Bash, Scala, Ruby, PHP, Swift, Lua.
- **Languages (grammar-only, polyglot dispatch)**: YAML, HCL/Terraform, Nix, GDScript, Kotlin.
- **CST Generation**: Builds Concrete Syntax Tree preserving all tokens.
- **Entity Extraction**: Converts CST nodes → `Entity` structs with byte ranges, qualified names, parent classes, decorators, structural hashes. Per-language S-expression queries compiled once per process via `OnceLock<Result<Query, String>>`.
- **Graph Building**: Directed reference graph (Symbol A references Symbol B).
- **Reference Linking**: Resolves imports, attribute access, function calls (Python + C++ `#include`).
- **Induction Bridge**: For unknown extensions, issues a remote POST to the cloud inference endpoint to classify the file and learn entity patterns. Results cached in local wisdom store.

### 1.2 Entity Struct

**Zero-Copy Design** (defined in `crates/common/src/lib.rs`, rkyv-serializable):

```rust
pub struct Entity {
    pub name: String,
    pub entity_type: EntityType,
    pub start_byte: u32,
    pub end_byte: u32,
    pub start_line: u32,
    pub end_line: u32,
    pub file_path: String,
    pub qualified_name: String,
    pub parent_class: Option<String>,
    pub base_classes: Vec<String>,
    pub protected_by: Option<Protection>,
    pub decorators: Vec<String>,
    pub structural_hash: Option<u64>,
}
```

### 1.3 Query Compilation Contract

Each language has a per-language S-expression constant (e.g., `RUBY_ENTITY_S_EXPR`) and a corresponding `patterns: &[(&str, &str, EntityType)]` array. The patterns array has **exactly one entry per S-expression pattern** at the same index — this is a hard invariant. Two patterns sharing capture names still require two separate array entries. Violation causes silent entity drop (capture name mismatch → `continue`).

### 1.4 Manifest Scanner

- `scan_manifests(root: &Path) -> DependencyRegistry` — WalkDir depth-3; skips `node_modules`, `target`, `__pycache__`, `.venv`.
- `find_zombie_deps_in_blobs(blobs, registry) -> Vec<String>` — O(PR-diff) AhoCorasick scan; used in `PatchBouncer` to detect zombie dep additions without full repo scan.
- **Parsers**: `package.json`, `Cargo.toml`, `requirements.txt`, `pyproject.toml`, `go.mod`, `spin.toml`, `wrangler.toml`.
- **Registry**: `DependencyRegistry` — rkyv zero-copy; entries carry `DependencyEntry { name, version, ecosystem, dev }`.

---

## II. DEAD SYMBOL PIPELINE: THE 6-STAGE GATE SYSTEM

**Status**: **[COMPLETE]**

| Stage | Filter | Protection Variant |
|-------|--------|--------------------|
| 0 | Directory filter (`tests/`, `migrations/`, etc.) | `Directory` |
| 1 | Reference graph (in-degree > 0) | `Referenced` |
| 2+4 | Wisdom heuristics + `__all__` exports (single mmap pass) | Various |
| 3 | Library mode: all `pub` symbols protected | `LibraryMode` |
| 5 | Grep shield: Aho-Corasick scan of non-source files | `GrepShield` |

### 2.1 Protection Enum (17 variants, `common::Protection`, `#[repr(u8)]`)

```
Directory=0, Referenced=1, WisdomRule=2, LibraryMode=3, PackageExport=4,
ConfigReference=5, MetaprogrammingDanger=6, LifecycleMethod=7, EntryPoint=8,
QtAutoSlot=9, SqlAlchemyMeta=10, OrmLifecycle=11, PydanticAlias=12,
FastApiOverride=13, PytestFixture=14, GrepShield=15, TestReference=16
```

### 2.2 Wisdom Registry

`ImmortalityRule` patterns loaded from `crates/anatomist/src/wisdom.rs`. Shields:
- **Build-script names**: `BUILD_SCRIPT_NAMES` — files matching common CI/build entry point names are unconditionally protected.
- **Type-stub shield**: `.pyi` files and `TYPE_CHECKING`-guarded blocks are protected as stub infrastructure.
- **Lifecycle relaxation** (v6.9.0+): `LifecycleMethod` protection applied when decorator OR name matches; `parent_class.is_some()` requirement removed.

---

## III. THE REAPER: TEST FINGERPRINTING & SAFE DELETION

**Crate**: `crates/reaper`

### 3.1 SafeDeleter Protocol

1. Backup source to `.janitor/ghost/{ts}_{filename}.bak` on first touch.
2. Sort targets **descending** by `start_byte` (bottom-to-top splice — preserves byte offsets above each deletion point).
3. Drain byte ranges (`delete_symbols`) or splice-replace (`replace_symbols`).
4. UTF-8 hardened: `snap_char_boundary_bwd/fwd` via `str::is_char_boundary()`.
5. `commit()` → delete backups. `restore_all()` → copy backups back.
6. `f.sync_all()` after every write — survives SIGKILL mid-operation.

### 3.2 Test Fingerprinting

- `collect_test_ids()` runs `pytest --collect-only -q`. Returns `Err` when pytest not found — this invariant is non-negotiable.
- Test names matched to symbol names → `Protection::TestReference`.
- Physical deletion is blocked unless test verification succeeds.

### 3.3 Remote Attestation

- `AuditLog::flush(token)` POSTs completed audit entries to `https://api.thejanitor.app/v1/attest`.
- Each entry signed with Ed25519 over `{timestamp}{file_path}{sha256_pre_cleanup}`.
- Binary embeds only `VERIFYING_KEY_BYTES` (public key). No private signing material in the distributed binary. `TEST_SIGNING_KEY_SEED` exists `#[cfg(test)]` only.
- Failure mode: network error or invalid token → `audit_log.json` not written. Zero residue on attestation failure.

---

## IV. THE FORGE: SLOP DETECTION ENGINE

**Crate**: `crates/forge`

### 4.1 Slop Score

`SlopScore { dead_symbols_added, logic_clones_found, zombie_symbols_added, antipatterns_found }`

```
score() = dead_symbols_added   × 10
        + logic_clones_found   ×  5
        + zombie_symbols_added × 15
        + antipatterns_found   × 50
```

Additional fields in bounce JSON output: `gate_passed`, `effective_gate`, `comment_violation_details`, `antipattern_details`, `zombie_dep_names`.

### 4.2 Patch Bouncer Pipeline (`PatchBouncer::bounce`)

```
gh pr diff / git diff / --patch file
    → extract_patch_blobs()         [slop_filter.rs — splits unified diff by extension]
    → IAC_TEXT_EXTS bypass          [nix, lock, json, toml, yaml, yml, csv → skip shield]
    → Circuit Breaker               [>1 MiB blob → skip tree-sitter entirely]
    → ByteLatticeAnalyzer::classify [agnostic_shield.rs — entropy gate]
    → find_slop()                   [slop_hunter.rs — AST antipattern detection]
    → AstSimHasher                  [hashing.rs — fuzzy clone detection]
    → CommentScanner                [metadata.rs — social forensics]
    → find_zombie_deps_in_blobs     [manifest.rs — O(PR-diff) dep scan]
    → SlopScore { ... }
    → BounceLogEntry → .janitor/bounce_log.ndjson
```

### 4.3 Agnostic Shield (`ByteLatticeAnalyzer`)

File: `crates/forge/src/agnostic_shield.rs`

- `ByteLatticeAnalyzer::classify(bytes) -> TextClass` — language-agnostic binary/generated-code detector.
- **Algorithm**: Shannon entropy over byte frequency distribution.
  - Entropy > 7.0 → `AnomalousBlob` (likely binary, encoded blob, or minified output).
  - Entropy outside `(2.0..=5.5)` → `AnomalousBlob` (statistical outlier for human-authored text).
  - Within range → `NormalText`.
- **IAC bypass** (`IAC_TEXT_EXTS`): Extensions `["nix", "lock", "json", "toml", "yaml", "yml", "csv"]` skip the shield entirely. Rationale: Nix sha256 hashes (base64-encoded, ~6 bits/char) produce entropy outside the normal text band, causing false `AnomalousBlob` classifications on legitimate IaC patches.
- **Data integrity invariant**: When the shield fires, `antipattern_details` must be non-empty (`antipatterns.len() == antipatterns_found`).

### 4.4 Fuzzy Clone Detection (`AstSimHasher`)

File: `crates/forge/src/hashing.rs`

- **Trait**: `FuzzyHash { fuzzy_hash(node, source) -> u64; similarity(a, b) -> f64; classify(a, b) -> Similarity }`
- **Struct**: `AstSimHasher` — SimHash over CST token feature vectors extracted from tree-sitter nodes.
- **`SIM_SKIP_KINDS`**: Node kinds excluded from the hash (punctuation, numeric literals). Numeric literal exclusion prevents version-bump PRs (e.g., `nixpkgs` `r-ryantm` bumping `version = "1.2.3"`) from triggering false `Zombie` classifications.
- **Classification thresholds**:

| Range | Class | Action |
|-------|-------|--------|
| `> 0.95` | `Similarity::Refactor` | Suppressed — rename-only diff, no penalty |
| `0.85–0.95` | `Similarity::Zombie` | Penalised ×15; logic clone boundary |
| `≤ 0.85` | `Similarity::NewCode` | Admitted without penalty |

### 4.5 Slop Hunter (`find_slop`)

File: `crates/forge/src/slop_hunter.rs`

Direct AST-walk antipattern detection per language:

| Language | Detected Pattern |
|----------|-----------------|
| Python | Import inside function body, imported name never used in that scope |
| Rust | `unsafe` block containing no pointer dereference, FFI call, or inline assembly |
| Go | Goroutine closure capturing loop variable by reference |

Returns `Vec<SlopFinding { description }>` into `SlopScore.antipattern_details`.

### 4.6 Shadow-Git Merge Simulation

File: `crates/forge/src/shadow_git.rs`

- `simulate_merge(repo, base_oid, head_oid) -> Result<MergeSnapshot>` — pure in-memory merge simulation via libgit2. Zero disk checkout. O(PR-diff) not O(repo-size).
- `iter_by_priority()` (Chemotaxis) — feeds high-slop-vector language files first: Python, JavaScript, TypeScript before C#, Go, etc.

### 4.7 PR Collider & Swarm Clustering (`LshIndex`)

File: `crates/forge/src/pr_collider.rs`

- **Signature**: `PrDeltaSignature` — 64 MinHash values over byte 3-grams of the unified diff.
- **Index**: `LshIndex` — 8 bands × 8 rows stored in `ArcSwap<IndexSnapshot>` for lock-free concurrent reads. Each snapshot stores `signatures: Vec<PrDeltaSignature>` and `pr_numbers: Vec<u32>` as parallel arrays — `pr_numbers[i]` is the PR number that produced `signatures[i]`. `0` is the sentinel for daemon-mode entries where no PR number is available.
- **`insert(sig, pr_number)`** — clone-and-swap of the full snapshot; O(n) cost; suitable for one-per-PR-bounce workloads.
- **`query(sig, threshold) -> Vec<u32>`** — returns PR numbers of all stored signatures with Jaccard similarity ≥ `threshold`. Lock-free read guard.
- **Swarm Clustering** (`cmd_bounce`): on each invocation, loads all prior `BounceLogEntry` records from `.janitor/bounce_log.ndjson`, rebuilds a fresh `LshIndex` in memory, and queries at Jaccard ≥ 0.85. Matching PR numbers are written to `SlopScore.collided_pr_numbers` and persisted in the log entry. Does not contribute to `score()`.
- **Ouroboros Hotfix** (v6.13.0): prior log entries whose `pr_number` equals the current PR being evaluated are excluded from the index before the query — prevents self-collision at Jaccard 1.0.
- **`just parallel-audit <owner/repo> [LIMIT] [TIMEOUT]`** is the unified engine for single-repo intelligence package generation: runs `parallel-bounce` across all PRs, appends to `.janitor/bounce_log.ndjson`, then invokes `janitor report --format pdf` + `janitor export` to produce the PDF and CSV deliverables.

### 4.8 Comment Scanner

File: `crates/forge/src/metadata.rs`

- `CommentScanner::collect_comments(source)` — extracts all comment nodes from CST.
- `is_pr_unlinked(pr_body)` — returns true if body contains no issue reference (`#NNN`, `closes`, `fixes`, `resolves`). Adds 20 to slop score when triggered (`NO-ISSUE` tag in bounce output).

---

## V. THE SHIELD: GOVERNANCE MANIFEST

**Crate**: `crates/common/src/policy.rs`

`JanitorPolicy` — loaded from `janitor.toml` at repo root.

| Field | Default | Description |
|-------|---------|-------------|
| `min_slop_score` | 100 | Gate threshold |
| `require_issue_link` | false | Fail PRs with no issue reference |
| `allowed_zombies` | `[]` | Dep names exempt from zombie classification |
| `pqc_enforced` | false | PQC compliance mode |
| `custom_antipatterns` | `[]` | User-defined AST antipatterns |
| `refactor_bonus` | 0 | Score reduction for `[REFACTOR]`/`[FIXES-DEBT]` PRs |
| `forge.automation_accounts` | `[]` | Additional bot authors |

`effective_gate(pr_body)` — raises threshold for `[REFACTOR]`/`[FIXES-DEBT]` PRs by `refactor_bonus`.

### 5.1 Automation Shield (4-Layer Bot Classification)

`is_automation_account(author: &str) -> bool`:

1. **`app/` prefix** — GitHub Apps API format. `app/dependabot`, `app/renovate`, `app/github-actions`, `app/nixpkgs-ci` classified as bot with zero config.
2. **`[bot]` suffix** — legacy GitHub bot account format.
3. **`trusted_bot_authors`** — hardcoded list (`r-ryantm`, `dependabot`, `renovate-bot`, etc.).
4. **`[forge].automation_accounts`** — user-defined list in `janitor.toml`.

Bot-classified PRs score 0 unconditionally. No clone detection, no antipattern scan.

---

## VI. THE POLYGLOT REGISTRY

**Crate**: `crates/polyglot`

### 6.1 `LazyGrammarRegistry`

Single public API: `LazyGrammarRegistry::get(ext: &str) -> Option<&'static Language>`

23 `OnceLock<Language>` module-level statics. Each grammar initialised exactly once on first request, pinned for process lifetime. Thread-safe: concurrent calls for the same extension are safe — only one thread performs initialisation; all others observe the cached result.

**Memory cost**: One uninitialised `OnceLock<Language>` = 8 bytes (one pointer-sized word, 64-bit). 23 statics = 184 bytes static overhead until first use.

### 6.2 Grammar Table

| Static | Crate | Extensions |
|--------|-------|------------|
| `PYTHON` | `tree-sitter-python 0.25` | `py` |
| `RUST` | `tree-sitter-rust 0.23` | `rs` |
| `TYPESCRIPT` | `tree-sitter-typescript 0.23` | `ts` |
| `TSX` | `tree-sitter-typescript 0.23` | `tsx` |
| `JAVASCRIPT` | `tree-sitter-javascript 0.25` | `js`, `jsx`, `mjs`, `cjs` |
| `CPP` | `tree-sitter-cpp 0.23` | `cpp`, `cxx`, `cc`, `hpp`, `hxx` |
| `C` | `tree-sitter-c 0.23` | `c`, `h` |
| `JAVA` | `tree-sitter-java 0.23` | `java` |
| `CSHARP` | `tree-sitter-c-sharp 0.23` | `cs` |
| `GO` | `tree-sitter-go 0.23` | `go` |
| `GLSL` | `tree-sitter-glsl 0.2.0` | `glsl`, `vert`, `frag` |
| `OBJC` | `tree-sitter-objc 3.0.2` | `m`, `mm` |
| `YAML` | `tree-sitter-yaml 0.7.2` | `yaml`, `yml` |
| `BASH` | `tree-sitter-bash 0.23` | `sh`, `bash`, `cmd`, `zsh` |
| `SCALA` | `tree-sitter-scala 0.24` | `scala` |
| `RUBY` | `tree-sitter-ruby 0.23` | `rb` |
| `PHP` | `tree-sitter-php 0.24` | `php` (uses `LANGUAGE_PHP` variant — parses `<?php` context) |
| `SWIFT` | `tree-sitter-swift 0.7` | `swift` |
| `LUA` | `tree-sitter-lua 0.5` | `lua` |
| `HCL` | `tree-sitter-hcl 1.1.0` | `tf`, `hcl` |
| `NIX` | `tree-sitter-nix 0.3.0` | `nix` |
| `GDSCRIPT` | `tree-sitter-gdscript 6.1.0` | `gd` |
| `KOTLIN` | `tree-sitter-kotlin-ng 1.1.0` | `kt`, `kts` |

**Rejected**: `tree-sitter-dockerfile 0.2` — exports `pub fn language()` (old tree-sitter ^0.20 API), incompatible with workspace tree-sitter 0.26. Not on crates.io with a compatible newer version.

### 6.3 API Compatibility Invariant

All grammar crates must export `pub const LANGUAGE: LanguageFn` (new API, requires `tree-sitter-language ^0.1`). The old API (`pub fn language() -> Language`) is incompatible with tree-sitter 0.26 and will fail to link. Verify new grammar candidates in an isolated test crate before adding to workspace.

---

## VII. THE SHADOW: SYMLINK OVERLAY

**Crate**: `crates/shadow`

### 7.1 Shadow Tree

- `ShadowManager::initialize(source, shadow)` — creates `.janitor/shadow_src/` with symlinks pointing to source files.
- `ShadowManager::open(source, shadow)` — opens existing shadow tree.
- `ShadowManager::unmap(rel)` — removes symlink (simulation step — tests run against broken symlinks).
- `ShadowManager::remap(rel)` — restores symlink on test failure.
- `ShadowManager::move_to_ghost(rel)` — Ghost Protocol: real file → `.janitor/ghost/`. Windows junction support included.

### 7.2 Clean Command (`janitor clean <path> --token <token>`)

1. Verify Ed25519 token via `vault::SigningOracle::verify_token`.
2. Run 6-stage pipeline → get kill list.
3. Initialize (or open) shadow tree.
4. Unmap symlinks for dead-symbol files.
5. Run pytest in shadow tree.
6. **Pass**: `SafeDeleter::delete_symbols` on source files → `commit()` → remote attestation.
7. **Fail**: `remap()` all unmapped symlinks → abort. No source files modified.

---

## VIII. THE VAULT: ED25519 TOKEN GATE

**Crate**: `crates/vault`

- `SigningOracle::verify_token(token: &str) -> bool`
- Token = base64-encoded Ed25519 signature of `"JANITOR_PURGE_AUTHORIZED"`.
- Binary embeds only `VERIFYING_KEY_BYTES` (32-byte public key). **No private key material in binary.**
- `TEST_SIGNING_KEY_SEED` exists `#[cfg(test)]` only — never in release builds.
- Rotation cycle: `VERIFYING_KEY_BYTES` rotated via `cargo run -p mint-token -- generate` before each major release. Last rotation: v6.8.0 cycle.
- Required by: `janitor clean --token`, `janitor dedup --apply --token`, MCP `janitor_clean`.

### 8.1 90-Day Immaturity Hard-Gate

`SigningOracle::enforce_maturity(file, mtime_secs, override_tax)` returns `Err(VaultError::ImmatureCode)` when a dead symbol's source file was modified fewer than 90 days ago. Pass `--override-tax` to bypass deliberately.

---

## IX. THE DAEMON: HOT-REGISTRY UDS SERVER

**File**: `crates/cli/src/daemon.rs`

```
janitor serve --socket /tmp/janitor.sock [--registry <path>]
```

### 9.1 Architecture

- **`HotRegistry`**: `Arc<ArcSwap<SymbolRegistry>>` — lock-free hot-swap of the symbol registry without daemon restart.
- **`DaemonState`**: `{ registry: HotRegistry, lsh_index: Arc<ArcSwap<LshIndex>> }` — shared across all connection handlers via `Arc`.
- **Transport**: Unix Domain Socket (`/tmp/janitor.sock`). ndjson request/response protocol (one JSON object per line).
- **Backpressure**: `SystemHeart::beat()` (Physarum Protocol) — RAM utilization gating.

### 9.2 Physarum Protocol (`crates/common/src/physarum.rs`)

`SystemHeart::beat() -> Pulse`:

| RAM Utilization | Pulse | Semaphore |
|-----------------|-------|-----------|
| ≤ 75% | `Flow` | `flow_semaphore` (4 slots) |
| 75–90% | `Constrict` | `constrict_semaphore` (2 slots) |
| > 90% | `Stop` | Request rejected — 503 |

System-aware backpressure. The daemon never OOMs.

---

## X. MCP SERVER: JSON-RPC 2.0 STDIO INTERFACE

**Crate**: `crates/mcp`

Four tools exposed over the MCP protocol (JSON-RPC 2.0 over stdio):

| Tool | Auth | Returns |
|------|------|---------|
| `janitor_scan` | Free | `dead_symbols`, `slop_score`, `merkle_root` |
| `janitor_dedup` | Free | Structural clone groups with `structural_hash` |
| `janitor_clean` | Lead Specialist token | Shadow simulate → delete → remote attest |
| `janitor_dep_check` | Free | `zombie_deps[]`, `total_declared`, `zombie_count` |

---

## XI. THE CLI: COMMAND SURFACE

**Crate**: `crates/cli`

```bash
# Dead-symbol scan (library repos: add --library)
janitor scan <path> [--library] [--format json|text]

# Structural clone deduplication
janitor dedup <path> [--apply --token <tok>]

# Patch/PR quality gate
janitor bounce <repo_path> --repo <path> --base <sha> --head <sha> \
  --pr-number <N> --author <str> --format json
janitor bounce <repo_path> --patch <file.diff> [--registry <path>]

# Aggregate bounce log reports
janitor report [--repo <path>] [--top <N>] [--format markdown|json|pdf] [--global]

# Export bounce log to CSV
janitor export [--repo <path>] [--out <file>] [--global] [--gauntlet-dir <dir>]

# Ratatui TUI dashboard
janitor dashboard <path>

# UDS daemon
janitor serve --socket <path> [--registry <path>]

# MCP server (stdio)
janitor mcp
```

### 11.1 Bounce Log

`BounceLogEntry` written to `.janitor/bounce_log.ndjson` (append-only, `sync_all()` after write). One JSON object per line. Schema stable since v6.9.0 (`schema_version: "6.9.0"`).

### 11.2 Export

`cmd_export` — 10-column CSV: `PR_Number, Author, Score, Mesa_Triggered, Trust_Delta, Unlinked_PR, Dead_Code_Count, Logic_Clones, Zombie_Syms, Zombie_Deps, Violation_Reasons, Time_Saved_Hours, Operational_Savings_USD, Timestamp, PR_State, Is_Bot, Repo_Slug`.

`cmd_export_global` — aggregates all `.janitor/bounce_log.ndjson` files under `--gauntlet-dir` into a single CSV.

---

## XII. THE GAUNTLET: COMMERCIAL VALIDATION ORCHESTRATOR

**Crate**: `tools/gauntlet-runner`

```bash
just run-gauntlet [--pr-limit N] [--timeout S] [--targets FILE] \
                  [--gauntlet-dir DIR] [--out-dir DIR]
```

### 12.1 Architecture

- Reads `gauntlet_targets.txt` (one `owner/repo` per line, `#` comments ok).
- Repos processed **sequentially** (one at a time).
- PRs within each repo: 2-thread rayon pool (RAM gate).
- `GIT_LOCK` mutex serialises `gh pr diff` fetches within each pool — prevents file descriptor exhaustion.
- Fetches live PR metadata via `gh pr list --json`; filters `CONFLICTING` before fetching diffs.
- Before rayon dispatch for each repo: purges `.janitor/bounce_log.ndjson` — clean-slate invariant.

### 12.2 Output Artifacts

After all repos complete, generates in parallel:
- `gauntlet_intelligence_report.pdf` — per-repo pages + global summary (pandoc → LaTeX → PDF).
- `gauntlet_export.csv` — all entries from all 22 repos aggregated.

### 12.3 Validated Target Matrix (v6.12.5)

22 repositories validated in the Global Audit 2026 (2,090 PRs analyzed):

```
godotengine/godot      NixOS/nixpkgs          microsoft/vscode
kubernetes/kubernetes  pytorch/pytorch        apache/kafka
rust-lang/rust         tauri-apps/tauri       redis/redis
vercel/next.js         home-assistant/core    ansible/ansible
cloudflare/workers-sdk langchain-ai/langchain denoland/deno
rails/rails            laravel/framework      apple/swift
dotnet/aspnetcore      square/okhttp          hashicorp/terraform
neovim/neovim
```

Global Audit 2026 results: **2,090 PRs | Total Slop Score: 38,685 | 124 antipatterns | $360 estimated operational savings**.

---

## XIII. THE GOVERNOR: SAAS INTERCEPTOR

**Repository**: `the-governor` (separate repo, same `~/dev/` workspace)
**Deployed**: `https://the-governor.fly.dev/`
**Platform**: Fly.io, region `sjc`, single shared-CPU machine, 512 MB RAM

### 13.1 Process Architecture

The Governor container runs two processes orchestrated by `entrypoint.sh`:

```
[entrypoint.sh]
  │
  ├─1. Seed blank registry → /data/.janitor/symbols.rkyv (first boot only)
  │
  ├─2. janitor serve --socket /tmp/janitor.sock (background)
  │       Waits for /tmp/janitor.sock to exist (100ms poll)
  │
  └─3. exec the-governor (foreground, PID 1)
```

If the Janitor daemon crashes mid-flight, `JanitorClient::bounce()` emits a `JanitorCrash` telemetry event and the Governor marks the GitHub Check Run as failed — no silent data loss.

### 13.2 Request Flow: Webhook → Engine

```
GitHub PR event
    → GitHub App webhook (HMAC-SHA256 verified)
    → the-governor (axum HTTP server, port 3000)
    → Install token acquisition (octocrab)
    → gh pr diff fetch / patch assembly
    → janitor bounce (UDS /tmp/janitor.sock)
    → SlopScore → BounceLogEntry
    → GitHub Check Run created/updated (pass/fail)
    → Optional: remote attestation POST → api.thejanitor.app
```

### 13.3 Fly.io Deployment

```toml
app            = 'the-governor'
primary_region = 'sjc'

[mounts]
  source      = "governor_data"     # persistent volume for symbols.rkyv
  destination = "/data"

[[vm]]
  memory    = '512mb'
  cpu_kind  = 'shared'
  cpus      = 1

[http_service]
  internal_port = 3000
  force_https   = true
  auto_stop_machines   = 'stop'
  auto_start_machines  = true
  min_machines_running = 0

  [[http_service.checks]]
    grace_period = "15s"    # covers entrypoint cold-start
    interval     = "30s"
    path         = "/health"
    # /health returns 503 until /tmp/janitor.sock exists
```

**Deploy command** (must run from `~/dev/`, not `~/dev/the-governor/`):
```bash
fly deploy -a the-governor --config the-governor/fly.toml \
           --dockerfile the-governor/Dockerfile .
```

The Dockerfile build context must be `~/dev/` so Docker can reach both `the-janitor/` and `the-governor/` source trees.

### 13.4 Docker Image Build

**Stage 1 (builder)**: `rust:1-slim-bookworm`
- Installs: `pkg-config`, `libssl-dev`, `libgit2-dev`
- Builds `the-janitor` (full workspace release) → extracts `janitor` binary
- Runs `janitor scan /tmp/seed` → produces blank `symbols.rkyv`
- Builds `the-governor` binary

**Stage 2 (runtime)**: `debian:bookworm-slim`
- Installs: `ca-certificates`, `libgit2-dev`, `git`
- Copies: `/usr/local/bin/janitor`, `/usr/local/bin/the-governor`
- Copies: `/etc/governor/blank-registry.rkyv`
- Entrypoint: `/entrypoint.sh`
- Exposed port: 3000

Final image size: ~66 MB.

---

## XIV. INFRASTRUCTURE & SUPPLY CHAIN

### 14.1 Nix Hermetic Shell

`flake.nix` defines the mandatory development environment. All build, audit, and release operations must occur inside this shell.

```bash
# Enforced by justfile recipes (audit, build):
if [[ -z "${IN_NIX_SHELL:-}" ]] && command -v nix &>/dev/null; then
    exec nix develop --command just <recipe>
fi
```

Toolchain: `rust-toolchain.toml` pins `channel = "1.88.0"` (bumped for RUSTSEC-2026-0002).

Key shell provisions:
- `rust-overlay` (exact Rust version)
- `LIBGIT2_SYS_USE_PKG_CONFIG=1` (git2-sys uses Nix libgit2, not vendored)
- `pandoc 3.7.0.2` (PDF report generation)
- `gh` CLI (PR diff fetching in gauntlet)

### 14.2 Supply Chain Standards

**GitHub Actions**: All actions pinned to 40-char commit SHAs, never version tags.

| Action | Pinned SHA | Tag |
|--------|-----------|-----|
| `step-security/harden-runner` | `5ef0c079ce82195b2a36a210272d6b661572d83e` | v2.14.2 |
| `actions/checkout` | `11bd71901bbe5b1630ceea73d27597364c9af683` | v4.2.2 |
| `actions/setup-python` | `0b93645e9fea7318ecaed2b359559ac225c90a2b` | v5.3.0 |
| `ossf/scorecard-action` | `62b2cac7ed8198b15735ed49ab1e5cf35480ba46` | v2.4.0 |
| `actions/dependency-review-action` | `3c4e3dcb1aa7874d2c16be7d79418e9b7efd6261` | v4 |

All new workflow files must include `step-security/harden-runner` as their first step.

### 14.3 Zero-Leak Security Protocol

**Absolutely forbidden from commits**: Ed25519 seeds, PEM files, `.env` files, `*.token`, `*.key`, `*.seed`.

1. `git check-ignore <filename>` before creating any secret-bearing file.
2. Pre-commit: `trufflehog git file://.` for secret scanning.
3. Exposure response: `git filter-repo --path <file> --invert-paths --force` + force-push + key rotation.
4. `cargo audit` must exit 0. `cargo deny check` must pass `deny.toml`.

### 14.4 Task Protocol (Justfile)

| Recipe | Purpose |
|--------|---------|
| `just audit` | **Definition of Done**: `cargo fmt --check` + `cargo clippy -D warnings` + `cargo check` + `cargo test` |
| `just build` | Release binary: `cargo build --release --workspace` |
| `just run-gauntlet [ARGS]` | Multi-repo PR audit via gauntlet-runner |
| `just parallel-audit REPO [LIMIT] [TIMEOUT]` | Single-repo parallel bounce |
| `just bump-version <X.Y.Z>` | Manifest version updates |
| `just release <X.Y.Z>` | Audit → Bump → Build → Strip → Tag → Push → GH Release → mkdocs |
| `just sync` | Rsync to Windows mount at `/mnt/c/Projects/the-janitor/` |
| `just deploy-docs` | MkDocs gh-deploy |

---

## XV. MACHINE INTERFACE: JSON API

### 15.1 `janitor scan --format json`

```json
{
  "slop_score": 0.042,
  "dead_symbols": [
    { "id": "module.unused_helper", "reason": "DEAD_SYMBOL" }
  ],
  "merkle_root": "3f9a1b2c..."
}
```

`merkle_root`: BLAKE3 over newline-joined sorted dead qualified names. Deterministic across identical codebase states.

### 15.2 `janitor bounce --format json`

```json
{
  "slop_score": 85,
  "dead_symbols_added": 1,
  "logic_clones_found": 0,
  "zombie_symbols_added": 0,
  "antipatterns_found": 1,
  "gate_passed": false,
  "effective_gate": 100,
  "unlinked_pr": true,
  "antipattern_details": ["Rust: vacuous unsafe block — no pointer dereference or FFI call"],
  "comment_violation_details": [],
  "zombie_dep_names": [],
  "merkle_root": "a1b2c3d4..."
}
```

`merkle_root`: BLAKE3 of raw patch bytes — ties score to the specific diff.

### 15.3 Signed Audit Logs

Every `AuditEntry` in `.janitor/audit_log.json` carries an Ed25519 `signature` field from remote attestation. Algorithm: signature over `{timestamp}{file_path}{sha256_pre_cleanup}`. Backward compat: `#[serde(default)]` ensures old entries deserialize.

---

## XVI. RESOURCE-EFFICIENT ARCHITECTURE (INVARIANTS)

Engineering constraints for correctness and minimal memory overhead. These are non-negotiable.

1. **Zero-Copy File Reads**: `memmap2::Mmap` for all file reads in hot paths. No `std::fs::read` or `read_to_string` in execution paths.
2. **Lazy/Streaming Only**: Never collect a full file tree into memory. `walkdir` iterators, `BufReader` line-by-line.
3. **Absolute Paths Only**: No relative path resolution anywhere in the codebase. `dunce::canonicalize` at every ingestion boundary.
4. **Symlinks Over Copies**: Shadow tree uses zero additional disk for source files.
5. **Zero-Copy Serialization**: `rkyv` for all IPC/registry persistence. `serde_json` only for audit logs and MCP transport.
6. **No Batch Allocation in Hot Loops**: No `String` clones in scan loops. Single `OnceLock<AhoCorasick>` per pattern group. Single `OnceLock<Language>` per grammar.
7. **Safety**: No `unwrap()` or `expect()` outside `#[cfg(test)]`. `anyhow` for binaries, `thiserror` for libs.
8. **UTF-8 Hardened**: All byte-range operations guarded by `str::is_char_boundary()`.
9. **Circuit Breakers**: Files > 1 MiB skipped before tree-sitter parsing. Bounce invocations cap at 30s timeout in shell scripts.
10. **RAM Ceiling**: Physarum Protocol enforces 8 GB effective ceiling (>90% system RAM → `Stop` pulse, daemon rejects request).

---

## XVII. ROADMAP — ALL PHASES COMPLETE

| Phase | Description | Status |
|-------|-------------|--------|
| **1** | Anatomist Core: Tree-sitter parsing, Entity extraction | **[COMPLETE]** |
| **2** | Reference Linking: directed graph, import resolution | **[COMPLETE]** |
| **3** | Dead Symbol Pipeline: 6-stage gate, WisdomRegistry | **[COMPLETE]** |
| **3.5** | Polyglot: Rust, JS, TS, C++ parsers; plugin shield | **[COMPLETE]** |
| **3.6** | C++ Integration: `#include` edges | **[COMPLETE]** |
| **3.7** | Omni-Polyglot: C, Java, C#, Go; polyglot graph walker; O(1) stability | **[COMPLETE] ★ 77k entities, 157MB RAM (Godot Siege)** |
| **4** | Reaper: UTF-8 SafeDeleter, test fingerprinting | **[COMPLETE]** |
| **5** | Forge: BLAKE3 structural hashing, Safe Proxy Pattern | **[COMPLETE]** |
| **6** | Shadow: symlink overlay, Ghost Protocol | **[COMPLETE]** |
| **7** | Vault: Ed25519 token gate, TUI dashboard | **[COMPLETE]** |
| **8** | Machine Interface: `--format json`, `bounce`, signed audit logs | **[COMPLETE]** |
| **9** | Induction Bridge: remote extension inference | **[COMPLETE]** — v6.2.0 |
| **10** | SimHash Fuzzy Clone Detection: AstSimHasher | **[COMPLETE]** — v6.4.0 |
| **11** | Sovereign Unification: polyglot registry, MinHash LSH, shadow-git, slop hunter | **[COMPLETE]** — v6.5.0 |
| **12** | MCP Server: JSON-RPC 2.0 stdio, 4 tools, token gate | **[COMPLETE]** — v6.5.0 |
| **13** | Legacy Autopsy: dep manifest scanner, OTLP ingest consolidation | **[COMPLETE]** — v6.6.0 |
| **14** | Governor SaaS: Fly.io deployment, GitHub App webhook interceptor | **[COMPLETE]** — v6.8.0 |
| **15** | Governance Manifest: `janitor.toml`, `JanitorPolicy`, `effective_gate` | **[COMPLETE]** — v6.9.0 |
| **16** | Gauntlet Runner: deterministic Rust orchestrator, PDF/CSV output | **[COMPLETE]** — v6.11.6 |
| **17** | Automation Shield: 4-layer bot classification, IaC bypass | **[COMPLETE]** — v6.11.7–v6.11.8 |
| **18** | Universal Bot Shield: `app/` prefix detection | **[COMPLETE]** — v6.12.1 |
| **19** | Tier-1 Grammar Expansion: Ruby, PHP, Swift, Lua (23 grammars total) | **[COMPLETE]** — v6.12.5 |

---

**THE CODE IS THE ASSET. THE JANITOR IS THE FIDUCIARY.**
**VERSION: v6.13.0**
