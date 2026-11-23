# Port map

C file -> Rust module -> status. libalpm-rs modules are in `crates/libalpm-rs/src/`; CLI modules in `crates/pacman-rs/src/`.

## lib/libalpm -> libalpm-rs

| C file | Rust module | Status |
|---|---|---|
| add.c | add.rs | todo |
| alpm.c | alpm.rs | partial (alpm_initialize, register_syncdb; release/lock/capabilities todo) |
| alpm_list.c | (Vec, no module) | n/a |
| backup.c | backup.rs | done |
| base64.c | base64.rs | done |
| be_local.c | be_local.rs | partial (read side; write, mtree todo) |
| be_package.c | be_package.rs | partial (_alpm_pkg_load_internal, changelog; alpm_pkg_load/validate need signing.c) |
| be_sync.c | be_sync.rs | partial (read side; update, db signature checks todo) |
| conflict.c | conflict.rs | todo |
| db.c | db.rs | partial (read side, search, add_server; unregister/update todo) |
| deps.c | deps.rs | partial (from_string, compute_string, depcmp, find_satisfier; checkdeps, resolvedeps, sort todo) |
| diskspace.c | diskspace.rs | todo |
| dload.c | dload.rs | todo |
| error.c | error.rs | done |
| filelist.c | filelist.rs | done |
| graph.c | graph.rs | todo |
| group.c | group.rs | done |
| handle.c | handle.rs | partial (options used by pacman, log/event callbacks; lock, other callbacks todo) |
| hook.c | hook.rs | todo |
| log.c | log.rs | partial (_alpm_log) |
| package.c | package.rs | partial (accessors, check_meta, xdata, should_ignore, requiredby; dup todo) |
| pkghash.c | (HashMap, no module) | n/a |
| rawstr.c | rawstr.rs | todo |
| remove.c | remove.rs | todo |
| sandbox.c | sandbox.rs | todo |
| sandbox_fs.c | sandbox_fs.rs | todo |
| sandbox_syscalls.c | sandbox_syscalls.rs | todo |
| signing.c | signing.rs | partial (decode_signature, extract_keyid; gpgme verification todo) |
| sync.c | sync.rs | partial (alpm_sync_get_new_version; transaction logic todo) |
| trans.c | trans.rs | todo |
| util.c | util.rs, archive.rs | partial (archive open/fgets (tar+gz/bz2/xz/zst/lz4), CFile/fgets, splitname, hash_sdbm, parsedate, strtoofft, fnmatch) |
| version.c | version.rs | done |

## src/pacman -> pacman-rs

| C file | Rust module | Status |
|---|---|---|
| callback.c | callback.rs | partial (cb_log and the database-missing event live in conf.rs) |
| check.c | check.rs | done |
| conf.c | conf.rs | done (xfercommand download callback todo) |
| database.c | database.rs | todo |
| deptest.c | deptest.rs | done |
| files.c | files.rs | todo |
| ini.c | ini.rs | done |
| package.c | package.rs | done (signature display of package files needs gpgme) |
| pacman-conf.c | src/bin/pacman-conf.rs | done |
| pacman.c | pacman.rs | done (-D -R -U -F and -S transactions refuse with "not implemented yet") |
| query.c | query.rs | done |
| remove.c | remove.rs | todo |
| sighandler.c | sighandler.rs | todo |
| sync.c | sync.rs | partial (-Ss -Sg -Si -Sl; -Sy -Sc and transactions todo) |
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
