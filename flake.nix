{
  description = "The Janitor — hermetic development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        # Pinned Rust toolchain — version driven by rust-toolchain.toml.
        # rust-overlay reads the file at evaluation time so the flake and the
        # toolchain file always agree.
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        # Minimal TeX live subset sufficient for pandoc → PDF generation.
        # scheme-medium (~350 MB) includes the packages pandoc depends on
        # (lmodern, geometry, xcolor, hyperref, booktabs, longtable, fancyhdr).
        texPackages = pkgs.texlive.combine {
          inherit (pkgs.texlive) scheme-medium;
        };
      in
      {
        devShells.default = pkgs.mkShell {
          name = "janitor";

          buildInputs = with pkgs; [
            # ── Rust toolchain (pinned via rust-toolchain.toml) ───────────────
            rustToolchain

            # ── C libraries required by Rust crates ───────────────────────────
            # openssl: ureq native-tls backend
            openssl.dev
            # libgit2: git2 crate (LIBGIT2_SYS_USE_PKG_CONFIG=1 below)
            libgit2
            # zlib: transitive dep of libgit2 and flate2
            zlib
            # pkg-config: lets build scripts locate the above via .pc files
            pkg-config

            # ── PDF report generation ─────────────────────────────────────────
            pandoc
            texPackages

            # ── Media processing ──────────────────────────────────────────────
            ffmpeg

            # ── CI / Gauntlet tooling ─────────────────────────────────────────
            # Note: the `release` justfile recipe explicitly invokes the Windows
            # binary at /mnt/c/Program Files/GitHub CLI/gh.exe for cross-compat
            # with WSL2. This `gh` covers non-release operations (audit_real_prs,
            # generate_client_package, etc.).
            gh
            jq
            git

            # ── Python env manager (mkdocs deploy) ───────────────────────────
            uv
          ];

          # ── Environment variables ────────────────────────────────────────────
          # Exposed to the shell and inherited by all child processes, including
          # cargo build scripts.

          # OpenSSL — points openssl-sys to the Nix store paths.
          OPENSSL_DIR = "${pkgs.openssl.dev}";
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";

          # libgit2 — prefer the Nix-provided library over the bundled copy
          # that git2-sys would otherwise compile from source.
          LIBGIT2_SYS_USE_PKG_CONFIG = "1";
          PKG_CONFIG_PATH =
            "${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.libgit2}/lib/pkgconfig";

          # Project shortcuts — override in the calling shell if needed.
          # JANITOR points at the release binary produced by `just build`.
          JANITOR = "./target/release/janitor";

          shellHook = ''
            echo ""
            echo "┌─────────────────────────────────────────────────┐"
            echo "│  The Janitor — Hermetic Development Shell        │"
            echo "│  Rust : $(rustc --version)   │"
            echo "│  Pandoc: $(pandoc --version | head -1)         │"
            echo "└─────────────────────────────────────────────────┘"
            echo ""
            echo "  just audit   — fmt + clippy + check + test"
            echo "  just build   — release binary"
            echo "  just shell   — re-enter this shell"
            echo ""
          '';
        };
      }
    );
}
