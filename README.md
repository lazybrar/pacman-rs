# pacman-rs

An experimental, compatible reimplementation of
[pacman](https://gitlab.archlinux.org/pacman/pacman) and libalpm, written in Rust.
It reads the same database and `pacman.conf`, takes the same flags and aims to
print exactly the same output.

**Status: early, read-only.** It reads your system's package state but cannot
install, remove or upgrade anything yet. Commands that would change the system
exit with "not implemented yet". Keep using pacman.

## Why

pacman works well, and this project does not say otherwise. Rewriting it is
not the goal. It exists to try out a few features that are easier to build from
a fresh codebase, while staying 100% compatible with pacman so you can switch
back and forth on the same system at any time:

- recovery after a power cut or crash in the middle of an upgrade
- transaction history and rollback from the package cache
- cache cleaning that keeps what rollback needs
- machine-readable output (`--json`) for scripts and tools
- common pacman-contrib style helpers (checkupdates, pactree, pacdiff) built in
- a Rust library over the pacman database, for Rust tools that want one

None of these change pacman's database format or the output of existing
commands. Anything new goes behind new flags.

## Not affiliated with Arch Linux

This is an independent hobby project, not part of Arch Linux or the pacman
project, and it does not ask them to change anything. Please report bugs in
pacman-rs **here**, never to the pacman or Arch bug trackers.

All credit for the design and behaviour goes to the pacman developers. This port
follows their code file by file, and its tests treat the real pacman as the
reference: when the two disagree, pacman is right and this project has a bug.

## What works

| Command | Notes |
|---|---|
| `pacman-rs -Q...` | query installed packages (`-Qi`, `-Ql`, `-Qs`, `-Qo`, `-Qe`, `-Qd`, `-Qm`, `-Qt`, `-Qk`, `-Qp` ...) |
| `pacman-rs -Ss / -Si / -Sl / -Sg` | search and inspect sync repos (uses existing DBs, never refreshes) |
| `pacman-rs -T` | dependency test |
| `pacman-conf` | config dump, identical to upstream's |
| `vercmp` | version compare, identical to upstream's |

"Identical" is tested, not claimed: the test suite runs the same commands
through the system's pacman and through this port and diffs stdout, stderr and
exit codes (`LC_ALL=C` for now; translations are not ported yet).

## Layout

- `crates/libalpm-rs`: the library. One module per upstream `lib/libalpm/*.c` file.
- `crates/pacman-rs`: the CLI. One module per upstream `src/pacman/*.c` file.
- `PORTMAP.md`: which upstream files are ported.

Upstream reference: pacman `v7.1.0-9-g54d94116` (branch `release/7.1.x`),
the build Arch ships as `7.1.0.r9.g54d9411`.

## Build and test

```sh
cargo build --workspace --release
cargo test --workspace   # differential tests need an Arch system with pacman installed
```

Build output goes to `/tmp/pacman-rs-test/target` (see `.cargo/config.toml`).

## Roadmap

1. Read-only parity (this MVP; `-F` next).
2. Dependency resolution, signature checking, downloads.
3. Transactions (install/remove/upgrade), verified with upstream's pactest suite in throwaway roots.
4. Hooks and scriptlets.
5. Extras: crash-safe transactions, history and rollback, rollback-aware cache cleaning, `--json`, and absorbed community tools (checkupdates, pactree, pacdiff, ...).

Do not use it to manage a real system until step 3 is done and passes pactest.

## License

GPL-2.0-or-later, the same as pacman. This is a derivative work of pacman:
Copyright (c) 2006-2025 Pacman Development Team, Copyright (c) 2002-2006 Judd Vinet,
and the other upstream authors.
