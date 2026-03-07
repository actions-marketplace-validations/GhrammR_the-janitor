# Hermetic Build Protocol

> **Audience**: Contributors, security auditors, and enterprise buyers verifying that
> The Janitor's own build process is reproducible and supply-chain-clean.

---

## Why Hermetic Builds?

The Janitor audits other projects for dead symbols, zombie dependencies, and supply-chain
drift. It would be inconsistent to tolerate those same failure modes in its own toolchain.
A hermetic build guarantees that every developer, CI runner, and release pipeline produces
**bit-identical artefacts** from the same source revision — regardless of OS version,
globally installed packages, or ambient PATH contents.

| Risk | Mitigated By |
|------|-------------|
| "Works on my machine" | Nix Flake pins exact package revisions |
| Rust toolchain drift | `rust-toolchain.toml` pins Rust 1.85.0 |
| Pandoc / TeX version skew | Nix devShell provides pinned pandoc + texlive |
| libgit2 / OpenSSL ABI mismatch | Nix provides C library headers; `pkg-config` wires them into Cargo |
| CI/CD supply chain | GitHub Actions steps are SHA-pinned (see [Security Posture](security.md)) |

---

## Prerequisite: Install Nix

Nix works on Linux, macOS, and WSL2. The recommended installer is the Determinate Systems
installer, which enables Nix Flakes and the nix-command feature by default:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://install.determinate.systems/nix | sh
```

Verify the installation:

```bash
nix --version
# nix (Nix) 2.x.y
```

---

## Entering the Dev Shell

```bash
# From the repository root:
just shell
# — or equivalently —
nix develop
```

The shell provisions:

| Tool | Version source | Purpose |
|------|---------------|---------|
| `rustc` / `cargo` | `rust-toolchain.toml` → rust-overlay | Compile, test, lint |
| `rustfmt` / `clippy` | same toolchain | `just audit` |
| `pandoc` | nixpkgs unstable | PDF report generation |
| `texlive` (scheme-medium) | nixpkgs unstable | LaTeX backend for pandoc |
| `ffmpeg` | nixpkgs unstable | Demo video processing |
| `gh` | nixpkgs unstable | Gauntlet PR audits |
| `jq` | nixpkgs unstable | JSON slicing in shell tools |
| `git` | nixpkgs unstable | Source control |
| `uv` | nixpkgs unstable | MkDocs deployment |

The shell also exports the C-library environment variables (`OPENSSL_DIR`,
`LIBGIT2_SYS_USE_PKG_CONFIG`, `PKG_CONFIG_PATH`) so that Cargo build scripts locate
the Nix-provided libraries rather than whatever is installed system-wide.

---

## Auto-Wrap: Running `just audit` Outside the Shell

`just audit` and `just build` detect whether they are running inside the Nix devShell
by inspecting the `IN_NIX_SHELL` environment variable that `nix develop` sets
automatically. If Nix is installed but the shell is not active, the recipe transparently
re-execs itself under `nix develop --command just <recipe>`:

```
$ just audit          # called from a plain bash session
↳ Entering Nix hermetic shell for reproducible audit...
# ... Nix shell activates, then just audit runs inside it ...
✅ System Clean.
```

If Nix is not installed (e.g., a CI runner with a pre-installed Rust toolchain), the
recipe falls through and uses whatever toolchain is in PATH — with a warning in the
shell hook that reproducibility is not guaranteed.

---

## Pinning Strategy

### Rust Toolchain

`rust-toolchain.toml` at the repository root declares the exact channel:

```toml
[toolchain]
channel = "1.85.0"
components = ["rustfmt", "clippy", "rust-src"]
targets = ["x86_64-unknown-linux-gnu"]
```

`rustup` (inside the Nix shell via `rust-overlay`) reads this file automatically.
Any attempt to run `cargo` with a different toolchain version fails immediately.

### Nix Inputs

`flake.lock` (generated on first `nix develop` or `nix flake update`) pins every
Nix input — including `nixpkgs` and `rust-overlay` — to an exact git commit SHA.
Commit `flake.lock` alongside `flake.nix` so that CI and all contributors use
identical package revisions.

```bash
# Refresh all Nix inputs to latest:
nix flake update

# Refresh a single input:
nix flake lock --update-input nixpkgs
```

After updating, re-run `just audit` to verify nothing broke.

---

## Docker Equivalence

The production `Dockerfile` pins its base images to `@sha256:<digest>`:

```dockerfile
FROM rust:1.85-slim@sha256:3490aa77d179a59d67e94239cca96dd84030b564470859200f535b942bdffedf AS builder
FROM debian:bookworm-slim@sha256:6458e6ce2b6448e31bfdced4be7d8aa88d389e6694ab09f5a718a694abe147f4 AS runtime
```

The Nix devShell and the Docker builder use the same Rust release (`1.85.0`). The
resulting artefact is functionally identical; the Docker image is used exclusively for
production deployment, not for local development.

---

## Compliance Note

Hermetic builds are a prerequisite for
[SLSA Level 2](https://slsa.dev/spec/v1.0/levels#build-l2) provenance. The GitHub
Actions release workflow uses SHA-pinned steps (documented in
[Security Posture](security.md#4-supply-chain-integrity-pinned-dependencies-self-audited-ci))
and produces a release binary whose build environment is fully described by this
`flake.nix` and `rust-toolchain.toml`.
