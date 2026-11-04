#!/usr/bin/env bash
# Vérification complète, la même partout : hook pre-push, CI (GitHub Actions), avant une release.
#   scripts/check.sh            # tout
#   RCM_CARGO="..." scripts/check.sh   # commande cargo à employer pour le natif (file de compilation)
# Étapes : format, interface (clippy wasm puis trunk build : le binaire embarque web/dist),
# clippy natif, tests, cargo deny (natif et interface), cargo audit (natif et interface).
# Outils : rustup target wasm32-unknown-unknown, trunk 0.21.14, wasm-bindgen-cli 0.2.129,
# wasm-opt (binaryen version_133), cargo-deny, cargo-audit (voir CONTRIBUTING.md).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
CARGO=${RCM_CARGO:-cargo}
# Temporaires et sorties dans target/ (jamais ailleurs sur le disque système).
mkdir -p target/tmp-os
export TMP="$root/target/tmp-os" TEMP="$root/target/tmp-os" TMPDIR="$root/target/tmp-os"

step() { printf '\n== %s\n' "$*"; }

step "format"
cargo fmt --all --check
(cd web && cargo fmt --check)

step "interface : clippy wasm"
(cd web && CARGO_TARGET_DIR="$root/target/wasm" cargo clippy --release --target wasm32-unknown-unknown -- -D warnings)

step "interface : trunk build"
(cd web && CARGO_TARGET_DIR="$root/target/wasm" NO_COLOR=true trunk build --release --offline)

step "clippy natif"
$CARGO clippy --release --workspace --all-targets -- -D warnings

step "tests"
$CARGO test --release --workspace

step "cargo deny"
cargo deny check
(cd web && cargo deny check)

step "cargo audit"
# RUSTSEC-2023-0071 (`rsa`) et RUSTSEC-2026-0387 (`crypto-bigint`) : passkeys, vérification de
# signatures seulement ; voir deny.toml.
cargo audit --deny warnings --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0387 --file Cargo.lock
# Interface : `paste` (macro de compilation de leptos) n'est plus maintenu, sans faille ; voir deny.toml.
(cd web && cargo audit --deny warnings --ignore RUSTSEC-2024-0436 --file Cargo.lock)

step "tout est bon"
