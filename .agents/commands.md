# Commands

Run everything from the workspace root. `cargo xtask` is an alias for `cargo run -p xtask --` (`.cargo/config.toml`).

## Build

```sh
cargo build --release -p concord-desktop   # target/release/concord
```

Release uses fat LTO over BoringSSL and aws-lc and takes minutes; build it only when the release binary is what you
need (size, speed, a bench). Android's `libconcord.so` is built by FlClash's `cargoCore` Gradle task with the NDK
environment it sets up; the variables a host sets are in `embedding.md`.

Windows compiles BoringSSL from source with CMake, the MSVC build tools and LLVM (`libclang` for bindgen), plus NASM
for `x86_64-pc-windows-msvc`, or `clang-cl` and Ninja for `aarch64-pc-windows-msvc` (its assembly is `.S`, which the
Visual Studio generator cannot build). `.cargo/config.toml` points `boring-sys` at `cmake/boring-*-windows.cmake`,
so run cargo from the workspace root. Do not set `OPENSSL_NO_ASM` or your own `CMAKE_TOOLCHAIN_FILE`: without
assembly AES-GCM is about 150 times slower, and BoringSSL sees no AES hardware and offers ChaCha20 first, unlike a
browser. `BUILD_TESTING` is off because BoringSSL's benchmark feature check fails under `/W4 /WX` once `cmake-rs`
drops `/EHsc`.

## Test Scope

Size every run to the change, and keep the full gate for the two cases below.

- While editing, run `cargo test -p <crate>` for the crates you changed, narrowed with `--test <file>` or a test name
  where that covers the change; never `--workspace`.
- Before each review round, run `cargo fmt --check`, then clippy and `cargo test` with `-p` for every changed crate,
  every crate that depends on one, and `xtask`, whose source checks hold every change. Add each `cargo xtask` check the
  change touches: `schema --check` for config or the API, `check-layers` and `cargo deny check` for a `Cargo.toml`.
  A crate with default features (the loop in The Full Gate lists them) also runs both with `--no-default-features`:
  the workspace build turns those features on, so only a crate built alone shows what they gate.
- Run the full gate only when the change touches a shared base, or in a branch's last review round; no other round
  runs it. The shared bases are the root `Cargo.toml` and `Cargo.lock`, `rust-toolchain.toml`, `vendor/`,
  `crates/common`, `crates/platform` and `crates/test-support`. Most of the workspace depends on those three crates,
  so `-p` would name it anyway.
- Keep the last round's full gate: CI runs only on `main` and pull requests, and in a private repository only when
  started by hand, so nothing else runs it before a branch lands.
- Run a test that only runs on another platform (a `cfg(target_os = ...)` test, the Windows tests) on a machine of
  that platform; on the host, run only that platform's clippy.
- When a Linux container or VM gets the tree as an archive made on macOS, create it with `COPYFILE_DISABLE=1 tar` and
  extract with `tar -xm`. Otherwise the AppleDouble `._*` files break the golden tests and old mtimes make cargo reuse
  stale artifacts.

## The Full Gate

A branch is done when all of these pass; Test Scope says which rounds run them. `.github/workflows/ci.yaml` runs
them on Linux with `--locked`, split into parallel jobs, and fails if they changed a tracked file; it also runs clippy
and the tests on macOS, clippy for the three Android ABIs FlClash ships and for Windows (the Windows job does not fail
the run yet), the arm64-v8a release `libconcord.so` against its size budget, and the interop tests that need only
mihomo or OpenSSH. Run the clippy of every platform whose code the change touches.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
for crate in concord-common concord-engine concord-mitm; do  # every member with default features
  cargo clippy -p "$crate" --no-default-features --all-targets -- -D warnings
  cargo test -p "$crate" --no-default-features
done
cargo xtask check-layers
cargo xtask schema --check
cargo deny check
cargo check --manifest-path fuzz/Cargo.toml
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo xtask check-commits dev..HEAD                      # rules.md, Commits
cargo build --release -p concord-desktop
cargo xtask check-size target/release/concord <bytes>   # CI's CORE_MAX_BYTES
```

Weekly workflows run what is too slow or too noisy for every change; each can also be started by hand:
`audit.yaml` (`cargo deny check advisories`, also on a lockfile change), `toolchain-drift.yaml` (the lint steps on
floating stable; a failure means bump `rust-toolchain.toml`), `feature-powerset.yaml` (`cargo hack check
--feature-powerset`), `fuzz-smoke.yaml` (each fuzz target for two minutes), `coverage.yaml` (an lcov artifact, no
threshold), `bench-smoke.yaml` (one short quick-tier round to show the harness runs; its numbers are not read) and
`platforms.yaml` (the Windows tests, clippy for Windows on Arm and Intel macOS, the tests on Linux arm64, and the
release `libconcord.so` of the other two Android ABIs against their budgets).

- `cargo test --workspace` also runs xtask's source checks: `stream_policy` holds every `Stream` wrapper to its
  declared capability policy (`rules.md`, Layering And Ownership); `vendor_patches` holds `vendor/` to the files
  `vendor/PATCHES.md` lists, by the hashes in `vendor/UPSTREAM.sha256`; `reference_choices` holds each choice in
  `reference-choices.md` to its Entry Shape; `unsafe_policy` holds `allow(unsafe_code)` to the crates and files
  `rules.md` names and every member to `[lints] workspace = true`; `doc_paths` holds every repository path the docs
  name in backticks to a file or line that exists; `ratchets` holds file and function sizes and `Result<_, String>`
  counts to `xtask/ratchets.txt`.
  `tunables` holds every numeric or `Duration` `const` and `static` to a row with its basis in `reference-choices.md`
  "Tunables", a wire or format line there, or `xtask/tunables.txt` (`rules.md`, Tunables); after adding or changing
  one, `cargo test -p xtask tunables::tests::list_unregistered -- --ignored --nocapture` prints what is missing.
  After a change that moves one, `cargo test -p xtask ratchets::tests::regenerate -- --ignored` rewrites the file,
  keeping raise notes and marking a new growth `raised from <old>: ?` for you to replace with the reason.
- `cargo xtask schema` rewrites `schema/config-schema.json` and `schema/api.json`; commit them with the change.
- `cargo xtask mihomo-keys <mihomo checkout>` rewrites `schema/mihomo-keys.json`, the keys mihomo's
  `config/config.go` decodes per section, from the reference commit it names. Rerun it when the reference moves;
  `schema::tests::every_key_mihomo_decodes_has_a_tier` then fails on each new key until it has a tier.
- `cargo xtask public-suffix` rewrites the public suffix table in `crates/group/data/public-suffix/` from the
  `public_suffix_list.dat` beside it; xtask's `public_suffix` test fails when the table, the list or the sha256 in
  `VERSION` disagree. To move the list, take `public_suffix_list.dat` from a publicsuffix/list commit, record that
  commit and the file's sha256 in `VERSION`, run the command, and pin `psl` in `Cargo.toml` to the release built
  from the same list (its `data/rules.txt` holds the same rules) and record that version in `VERSION`:
  `concord-group`'s `public_suffix` tests compare every rule against it. One commit, apart from code changes.
- A change to config parsing that changes output: `CONCORD_BLESS=1 cargo test -p concord-config --test golden`
  rewrites the golden files, and the diff is reviewed like code.
- The MITM module tests read the samples in `crates/config/tests/data/modules`, written for the test on reserved
  hosts. Published third-party modules stay out of the repository in a private corpus: a directory of modules, each
  with its `<module>.expect.json`, and a `remote.json` of `{name, url, sha256}` for the ones fetched on demand.
  `CONCORD_MODULE_CORPUS=<dir> cargo test -p concord-config --test module_corpus` reads it as well (without the variable
  the test reads the samples alone and says so), `cargo xtask module-corpus` fetches its `remote.json` entries into it,
  `corpus_lookups` (`concord-mitm`, ignored) measures it, and the bench's `mitm-modules` case embeds it when it is set
  at build time. `CONCORD_BLESS=1` rewrites the expectations of both.
- Clippy for Android (`--target aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`) runs with
  `-A clippy::missing_const_for_thread_local`. On those targets the lint fires on every `thread_local!` whose
  initializer is already `const { … }`; macOS and Linux do not report it. Seen with toolchain 1.100.0: when the
  toolchain moves, recheck whether the flag can go.
- `#[ignore]`d tests need an external peer named by an environment variable. An interop test run without its peer
  fails rather than passing silently. mihomo's Snell listener can lose a frame when its peek deadline falls between
  the two reads of that frame, so the Snell interop cases retry TCP once. Run the ones a change touches, for example
  `CONCORD_MIHOMO=<mihomo> cargo test -p concord-proxy --test interop -- --ignored`.
  CI's `interop` job fetches each peer through an action in `.github/actions/` and skips a test only with a comment
  that names it; `cargo xtask check-interop-peers` (in the lint job and `cargo test -p xtask`) holds the two together.

  | Variable | Peer |
  |---|---|
  | `CONCORD_MIHOMO` | An upstream mihomo binary, for protocol interop |
  | `CONCORD_GOST2`, `CONCORD_GOST3` | gost v2 and v3, for the gost plugin and relay interop tests and the `ss-gost` and `gost-relay` bench cases |
  | `CONCORD_XRAY` | Xray-core for xhttp over HTTP/3 interop (`--test interop xhttp_h3_talks_to_xray -- --ignored`) and `vless-xhttp-h3-*` bench cases |
  | `CONCORD_WGSERVER` | A WireGuard test server |
  | `CONCORD_SSHD`, `CONCORD_SSH_KEYGEN` | OpenSSH |
  | `CONCORD_SSRCLIENT` | A ShadowsocksR test client |
  | `CONCORD_HY1_SERVER` | A Hysteria v1 server |
  | `CONCORD_LARGE_PROFILE` | A large YAML profile; reports heap per stage |

- `fuzz/` is a separate workspace of libFuzzer targets for config parsing, profile loading, share links, rule
  parsing and, as `tls_record_read`, the read side of the TLS record engine (`concord_tls::fuzzing`, behind the
  crate's `fuzzing` feature). With nightly and `cargo-fuzz` they build as usual; point `CARGO_TARGET_DIR` at the
  main `target`. It depends on `libfuzzer-sys`, which is partly `NCSA`-licensed, so `cargo deny` does not check it.
  Only `tls_record_read` has been run, 31 minutes on the Linux VM; the others are compiled only. It was built on
  the pinned stable toolchain, with coverage instrumentation and no sanitizer:

  ```sh
  RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
    -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table \
    -Cllvm-args=-sanitizer-coverage-trace-compares -Cdebug-assertions -Coverflow-checks -Ccodegen-units=1" \
    cargo build --manifest-path fuzz/Cargo.toml --release --target aarch64-unknown-linux-gnu --bin tls_record_read
  ```

  The explicit `--target` keeps the flags off build scripts. `--cfg fuzzing` is left out: it compiles the vendored
  h2's `fuzz_bridge`, which fails that crate's `missing_docs` lint.
- `deny.toml`'s advisory exceptions each carry the reason the advisory does not reach Concord; keep that true when
  adding one.
- When a check cannot run (no `cargo-deny`, no peer binary, no Windows), say which and why instead of dropping it.

## Benchmarks

```sh
cargo xtask bench --quick --base <ref before the change> --mihomo <mihomo>   # while changing code
cargo xtask bench --full  --base <ref before the change> --mihomo <mihomo>   # only when the user asks
```

The quick tier is the SOCKS part of the representative set (`direct`, `ss-aes128`, `trojan-tls`, `vmess-grpc-tls`,
`hysteria2`; `performance.md` has the rest); the full tier covers every case and workload. The tier lists live in
`tools/bench/src/plan.rs` so a tier always measures the same thing. `--only`, `--workloads`, `--rounds` and `--secs`
narrow or tighten a run; `concord-bench list` prints cases, workloads and tiers;
`concord-bench compare <base.json> <new.json>` compares two runs. Use an upstream mihomo build; a fork that leaves listeners to its host app cannot serve.
Running it, Windows and Android: `.agents/benchmarking.md`. What a result must show and the pitfalls:
`.agents/performance.md`.

Run nothing else on the machine while a bench measures, and a full run only on a quiet host.

## Target Directory And Disk

- Every worktree of this repository on one machine builds into the main checkout's `target/`: set `CARGO_TARGET_DIR`
  to that one path in every worktree, never to a directory of the worktree's own, so dependencies compile once. A
  worktree that builds while another may sets its own cfg for its whole run,
  `RUSTFLAGS="--cfg concord_<name>_gate"`: cargo gives a path crate the same unit hash in every worktree and decides
  freshness by mtime, so without a distinct cfg one worktree links another's artifacts, and `xtask` tests then read
  the other tree through `CARGO_MANIFEST_DIR`. Touching the changed sources alone does not prevent it while another
  worktree builds. Before a gate, also touch `xtask/**/*.rs`, and confirm by name that the new tests ran.
- A comparison whose arms must not share artifacts builds each arm under a cfg no other build uses; `xtask bench
  --base` builds the base into `target/bench/rev-target`.
- Do not give a worktree, a crate or an agent a target of its own: every dependency compiles again, in a tree that
  already passes 10 GB.
- Build only what the step needs: `-p` the packages it uses, and for a release measurement `-p concord-desktop` or the
  binary measured. Clippy for another platform (the Android ABIs, Windows) covers the crates the change touches and
  runs once per head sent for review.
- Keep debug builds small: `CARGO_INCREMENTAL=0` and `CARGO_PROFILE_DEV_DEBUG=line-tables-only`.
- Check `du -sh target` before and after a round. Cargo keeps each compiled unit whole in
  `target/debug/build/<package>/<hash>/`, and a round of tests leaves several hashes of the same package; keep the
  two most recent per package and delete the rest, and clear `target/debug/incremental`. Find a binary through
  cargo's JSON messages or the copy cargo places in `target/debug/`, not by its path under `build/`.
  First check that no one else is building in this checkout (`pgrep -f "cargo (test|build|clippy|check)"`).
- Keep that target warm between builds, also on a measurement VM: prune hashes no recent build used rather than
  deleting the tree. Delete the whole target when the toolchain changes or the disk is short.
- Delete scratch worktrees, extracted trees and probe binaries when they are no longer needed, and stop any process you
  started by its pid.
- Errors that name a symbol the source plainly has (stale metadata after parallel edits in one target): confirm the
  tree is clean, `find crates -name '*.rs' -exec touch {} +`, and rebuild. `cargo clean -p` on one crate is not enough.
  Any test or bench result taken in that state is rerun.
