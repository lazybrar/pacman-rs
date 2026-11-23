# Port map

C file -> Rust module -> status. libalpm-rs modules are in `crates/libalpm-rs/src/`; CLI modules in `crates/pacman-rs/src/`.

## lib/libalpm -> libalpm-rs

| C file | Rust module | Status |
|---|---|---|
| add.c | add.rs | todo |
| alpm.c | alpm.rs | todo |
| alpm_list.c | (Vec, no module) | n/a |
| backup.c | backup.rs | done |
| base64.c | base64.rs | todo |
| be_local.c | be_local.rs | partial (read side; write, mtree todo) |
| be_package.c | be_package.rs | todo |
| be_sync.c | be_sync.rs | partial (read side; update, db signature checks todo) |
| conflict.c | conflict.rs | todo |
| db.c | db.rs | partial (read side; search, sync registration todo) |
| deps.c | deps.rs | partial (alpm_dep_from_string, alpm_dep_compute_string) |
| diskspace.c | diskspace.rs | todo |
| dload.c | dload.rs | todo |
| error.c | error.rs | done |
| filelist.c | filelist.rs | done |
| graph.c | graph.rs | todo |
| group.c | group.rs | done |
| handle.c | handle.rs | partial (dbpath, log callback, pm_errno) |
| hook.c | hook.rs | todo |
| log.c | log.rs | partial (_alpm_log) |
| package.c | package.rs | partial (accessors, check_meta, xdata; requiredby, dup, should_ignore todo) |
| pkghash.c | (HashMap, no module) | n/a |
| rawstr.c | rawstr.rs | todo |
| remove.c | remove.rs | todo |
| sandbox.c | sandbox.rs | todo |
| sandbox_fs.c | sandbox_fs.rs | todo |
| sandbox_syscalls.c | sandbox_syscalls.rs | todo |
| signing.c | signing.rs | todo |
| sync.c | sync.rs | todo |
| trans.c | trans.rs | todo |
| util.c | util.rs, archive.rs | partial (archive open/fgets (tar+gz/bz2/xz/zst/lz4), CFile/fgets, splitname, hash_sdbm, parsedate, strtoofft, fnmatch) |
| version.c | version.rs | done |

## src/pacman -> pacman-rs

| C file | Rust module | Status |
|---|---|---|
| callback.c | callback.rs | todo |
| check.c | check.rs | todo |
| conf.c | conf.rs | partial (config model + file parsing + setdefaults; libalpm setup/callbacks todo) |
| database.c | database.rs | todo |
| deptest.c | deptest.rs | todo |
| files.c | files.rs | todo |
| ini.c | ini.rs | done |
| package.c | package.rs | partial (accessors, check_meta, xdata; requiredby, dup, should_ignore todo) |
| pacman-conf.c | src/bin/pacman-conf.rs | done |
| pacman.c | pacman.rs | todo |
| query.c | query.rs | todo |
| remove.c | remove.rs | todo |
| sighandler.c | sighandler.rs | todo |
| sync.c | sync.rs | todo |
| upgrade.c | upgrade.rs | todo |
| util-common.c | util_common.rs | partial (strtrim, wordsplit) |
| util.c | util.rs | partial (pm_printf, resolve_path) |

## src/util

| C file | Rust module | Status |
|---|---|---|
| vercmp.c | src/bin/vercmp.rs | done |
| testpkg.c | src/bin/testpkg.rs | todo |
| util-common.c | (shared with src/pacman/util-common.c) | todo |

## Support modules (no C file)

| Rust module | Purpose |
|---|---|
| getopt.rs | GNU getopt_long (permutation, glibc messages), used by all CLI binaries |
