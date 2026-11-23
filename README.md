# pacman-rs

Rust port of pacman 7.1 + libalpm. Drop-in: same flags, same output, same DB/config.
Spec = upstream source (~/work/refs/pacman @ v7.1.0) + pactest suite (test/pacman/tests).
Never run against the real root while writing; tests use temp roots.
