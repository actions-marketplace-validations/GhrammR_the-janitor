# Safety Guarantees: Shadow Tree Isolation & Atomic Rollback

This document explains in plain English how The Janitor protects your codebase from accidental data loss. No code changes are permanent until they pass a full test run.

---

## The Core Promise

> **No file is permanently modified unless your test suite agrees it is safe to do so.**

The Janitor operates in two distinct phases: **Simulation** and **Excision**. Physical file modifications only occur after simulation succeeds. If any step fails, all changes are reversed automatically.

---

## Phase 1: Shadow Tree Isolation

Before touching any source file, The Janitor creates a **Shadow Tree** — a mirror of your project directory that uses zero additional disk space.

### How It Works

| Platform | Technique | Privilege Required |
|----------|-----------|-------------------|
| Linux / macOS | Symbolic links per file | None |
| Windows | Hard links per file | None (no Admin, no Developer Mode) |

Each file in the Shadow Tree is a link to the original source file. The shadow directory structure exists, but no file content is duplicated.

### Why This Matters

When The Janitor identifies a dead symbol, it does not delete the real file. Instead, it **removes the link** from the Shadow Tree. The original file remains intact in your source directory.

Your test suite then runs against the Shadow Tree — a view of the project where the "deleted" files simply do not exist.

```
Source Tree             Shadow Tree
/src/app.py  ─────────► /shadow/src/app.py   (link → active)
/src/dead.py ─────────► /shadow/src/dead.py  (link removed)
/src/utils.py ────────► /shadow/src/utils.py (link → active)
```

Test runners see `dead.py` as absent. If the tests pass, the symbol was genuinely unused. If they fail, `dead.py` was more important than the static analysis suggested.

---

## Phase 2: Atomic Rollback

There are two rollback layers, applied in order if any step fails.

### Layer 1: Shadow Rollback (always active)

If the test suite **fails** against the Shadow Tree:

1. All removed links are immediately **restored**.
2. The source tree is in its original, unmodified state.
3. The Janitor exits with a non-zero status and a clear failure message.

No file has been physically changed at this point.

### Layer 2: Backup Rollback (active during physical excision)

If the test suite **passes** and physical excision begins, `SafeDeleter` creates a backup before modifying any file:

1. The file is copied to `.janitor/ghost/<timestamp>_<filename>.bak` before the first write.
2. Symbol byte ranges are removed **bottom-to-top** (descending byte order) so that upstream offsets are never invalidated during the splice.
3. UTF-8 character boundaries are verified before every splice to prevent corrupting multi-byte characters.

If any write operation fails partway through:

- `restore_all()` copies every `.bak` file back to its original path.
- The project is restored to its pre-excision state.

### The `janitor undo` Command

After a successful excision, you can reverse the changes:

```sh
# In a git repository: stashes all uncommitted changes
janitor undo ./src

# Without git: restores files from .janitor/ghost/
janitor undo ./src
```

---

## The Dry-Run Default

All destructive commands default to **dry-run mode**. Nothing is modified unless you explicitly request it:

```sh
# Safe: reports what would be deleted
janitor clean ./src

# Requires explicit intent + a valid token
janitor clean ./src --force-purge --token <TOKEN>
```

This prevents accidental excisions from CI pipelines, IDE integrations, or scripted runs.

---

## Audit Log

Every physical excision is recorded in `.janitor/audit_log.json`:

```json
[
  {
    "timestamp": "2026-02-16T14:30:00Z",
    "file_path": "/abs/path/src/module.py",
    "symbol_name": "unused_helper",
    "sha256_pre_cleanup": "a3b4c5d6...",
    "heuristic_id": "DEAD_SYMBOL",
    "lines_removed": 14
  }
]
```

The `sha256_pre_cleanup` field captures the SHA-256 hash of the entire file *before* modification. This allows auditors to verify that the pre-cleanup state matches any backup copy, and provides a forensic trail for compliance reviews.

---

## The Shadow Merger

Before the slop pipeline evaluates a PR, The Janitor must synthesise what the merged
codebase will look like. Naively cloning the repository and applying patches risks
executing malicious build scripts, triggering CMake, or running Makefile targets embedded
in the PR itself.

**The Shadow Merger eliminates this attack surface entirely.**

### How It Works

`shadow_git.rs` exposes a single entry point:

```rust
pub fn simulate_merge(
    repo: &Repository,
    base_oid: Oid,
    head_oid: Oid,
) -> Result<MergeSnapshot, MergeError>
```

Internally, `simulate_merge` uses libgit2's tree-diff API to compute the set of changed
blobs between `base_oid` and `head_oid`. Every operation is in-memory:

| Step | What Happens | Disk I/O |
|:-----|:------------|:--------:|
| Open existing repo | Read `.git/objects/` (already on disk) | Read-only |
| Resolve OIDs | Deref commits → trees in object store | Read-only |
| Tree diff | Compute changed path → blob mappings | None |
| Blob load | Decompress blob data into heap | None |
| Return `MergeSnapshot` | `HashMap<PathBuf, Vec<u8>>` in RAM | **None** |

**No file is checked out. No working directory is modified. No build tool is invoked.**

The `MergeSnapshot` is a pure in-memory map from file path to file content. The slop
pipeline receives this map and parses each blob directly from the heap buffer — tree-sitter
operates on `&[u8]`, not on file paths.

### Why This Matters

A compromised PR could include:

- `CMakeLists.txt` that runs a `add_custom_command(POST_BUILD ...)` shell payload
- `Makefile` targets executed by `make` during a build-triggered scan
- `setup.py` / `pyproject.toml` with `setup_requires` that pip-installs malware
- `.github/actions/` that a naive tool might evaluate locally

The Shadow Merger never materialises any of these to disk. The malicious content exists
only as a byte array in heap memory — unexecutable, unreachable by the OS process loader.

### Security Boundary

```
┌─────────────────────────────────────────────────────┐
│                  janitor bounce                      │
│                                                      │
│  simulate_merge() ──► MergeSnapshot (heap)          │
│       │                     │                        │
│  libgit2 read-only     find_slop() ◄── tree-sitter  │
│  object store access   (parses &[u8], never executes)│
│                                                      │
│  ══════════════════════════════════════════════════  │
│  ISOLATION BOUNDARY: zero shell execution below      │
└─────────────────────────────────────────────────────┘
```

No shell is spawned. No temporary files are created. The process never drops privileges —
it never needs elevated access to begin with.

---

## Cryptographic Key Rotation & Token Revocation

The signed attestation pipeline (Lead Specialist / Industrial Core) is protected by an
**ML-DSA-65 keypair (NIST FIPS 204)** embedded in the binary. ML-DSA-65 is a
Module Lattice Digital Signature Algorithm standardised by NIST in August 2024 as part
of the Post-Quantum Cryptography (PQC) standard suite. It provides 128-bit post-quantum
security and is resistant to attacks from both classical and quantum adversaries.

### How Tokens Are Verified

A Lead Specialist token is a base64-encoded ML-DSA-65 signature of the string
`JANITOR_PURGE_AUTHORIZED`, signed by the private signing key held exclusively by
thejanitor.app. The binary contains only the corresponding **verifying key**. Verification
is a pure offline computation — no network call, no lookup table, no telemetry.

### Token Revocation via Keypair Rotation

Because each token is a deterministic function of the keypair, **revocation is achieved by rotating the keypair**:

1. A new ML-DSA-65 keypair is generated (`cargo run -p mint-token -- generate`).
2. The new verifying key is embedded in a reissued binary (a new patch release).
3. All existing tokens — signed against the old private key — are **cryptographically invalid** against the new verifying key. No database lookup, no revocation list, no network check is required.
4. New tokens are issued to valid licensees via the standard token delivery process.

This model has a clear, auditable change-management trail:
- Each keypair rotation produces a new binary release (git tag, GitHub Release, signed binary hash).
- The release commit records the rotation event in the changelog.
- Licensees receive new tokens via the same channel as initial issuance.

### Rotation Cadence & Emergency Rotation

| Trigger | Response |
|---------|----------|
| Scheduled annual rotation | New binary released at license renewal |
| Suspected token compromise | Emergency binary release; all licensees notified via sales@thejanitor.app |
| Binary integrity failure | Binary replaced; SHA-256 hash published on GitHub Release |

Industrial Core licensees receive a **contractual rotation SLA**: an emergency keypair rotation and new binary delivery within 4 hours of a confirmed compromise report.

### Post-Quantum Rationale

Classical elliptic-curve schemes are broken by Shor's algorithm on a sufficiently capable
quantum computer. ML-DSA-65 (FIPS 204) is lattice-based and provides no known quantum
speedup for signature forgery. Migrating now eliminates exposure to "harvest now, decrypt
later" attacks against signed attestation logs.

### Forensic Traceability

Every physical excision event signed with a valid token includes a per-event ML-DSA-65 signature in the audit log:

```json
{
  "timestamp": "2026-02-19T10:00:00Z",
  "file_path": "/abs/path/src/module.py",
  "sha256_pre_cleanup": "a3b4c5d6...",
  "attestation_signature": "<base64-mldsa65-sig>"
}
```

The `attestation_signature` field covers `{timestamp}{file_path}{sha256_pre_cleanup}`. Auditors can verify this signature independently using only the public verifying key embedded in the binary at the time of excision — no server access required.

---

## Summary: What Can Go Wrong?

| Failure Mode | What Happens |
|--------------|--------------|
| Test suite fails in Shadow Tree | Links restored, source unchanged, exit 1 |
| File write fails during excision | Backup restored, source in original state |
| Process killed mid-excision | Run `janitor undo` to restore from `.janitor/ghost/` |
| Accidental run without intent | Default dry-run prints report, modifies nothing |

The Janitor does not rely on reversible operations being "atomic" at the OS level. Every destructive operation is preceded by a backup, every batch is processed bottom-to-top, and every failure triggers an explicit restore.
