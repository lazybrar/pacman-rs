# pacman-rs

An experimental Rust port of [pacman](https://gitlab.archlinux.org/pacman/pacman) and libalpm.
It reads the same database and `pacman.conf`, takes the same flags and prints the same output.

**Status: early, read-only.** It cannot install, remove or upgrade anything yet; those commands
exit with "not implemented yet". Keep using pacman.

Not affiliated with Arch Linux or the pacman project. Report bugs here, not to them.

## Works today

- `pacman-rs -Q...`, `-Ss`, `-Si`, `-Sl`, `-Sg`, `-T`, `-F` (`-Fl`, `-Fx`, `--machinereadable`)
- `pacman-conf`, `vercmp`

Tests diff stdout, stderr and exit codes against the system's pacman (`LC_ALL=C`).

## Build

```sh
cargo build --workspace --release
cargo test --workspace   # needs an Arch system with pacman installed
```

`PORTMAP.md` lists which upstream files are ported. Reference: pacman `7.1.0.r9`.

## License

GPL-2.0-or-later, same as pacman. Derived from pacman (Copyright Pacman Development Team, Judd Vinet and others).
