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
| be_package.c | be_package.rs | partial (_alpm_pkg_load_internal, alpm_pkg_load with signature validation, _alpm_pkg_validate_internal, changelog) |
| be_sync.c | be_sync.rs | done (read side, db signature checks, alpm_db_update) |
| conflict.c | conflict.rs | todo |
| db.c | db.rs | partial (read side, search, add_server; unregister/update todo) |
| deps.c | deps.rs | done (recursedeps adds borrowed packages instead of _alpm_pkg_dup copies; no transaction flags beyond nodepversion) |
| diskspace.c | diskspace.rs | todo |
| dload.c | dload.rs | done (curl crate multi interface; ParallelDownloads, server failover, resume, If-Modified-Since, sig payloads, sandboxed child over a pipe, fetch callback, alpm_fetch_pkgurl; the sandboxed path as real root is a user test) |
| error.c | error.rs | done |
| filelist.c | filelist.rs | done |
| graph.c | graph.rs | done |
| group.c | group.rs | done |
| handle.c | handle.rs | partial (options used by pacman, log/event/question/download/fetch callbacks, lock, logaction; other callbacks todo) |
| hook.c | hook.rs | todo |
| log.c | log.rs | partial (_alpm_log) |
| package.c | package.rs | partial (accessors, check_meta, xdata, should_ignore, requiredby; dup todo) |
| pkghash.c | (HashMap, no module) | n/a |
| rawstr.c | rawstr.rs | todo |
| remove.c | remove.rs | todo |
| sandbox.c | sandbox.rs | done |
| sandbox_fs.c | sandbox_fs.rs | done (landlock crate) |
| sandbox_syscalls.c | sandbox_syscalls.rs | done (libseccomp crate) |
| signing.c | signing.rs | done (gpgme crate; gpgme_set_locale not called, no binding) |
| sync.c | sync.rs | partial (alpm_sync_get_new_version, download_files; transaction logic todo) |
| trans.c | trans.rs | todo |
| util.c | util.rs, archive.rs | partial (archive open/fgets, CFile/fgets, splitname, hash_sdbm, parsedate, strtoofft, fnmatch, access, makepath, filecache_*, download_dir_setup, reset_signals) |
| version.c | version.rs | done |

## src/pacman -> pacman-rs

| C file | Rust module | Status |
|---|---|---|
| callback.c | callback.rs | partial (cb_log queue, retrieve events, plain cb_download without progress bars; bars arrive with T16) |
| check.c | check.rs | done |
| conf.c | conf.rs | done |
| database.c | database.rs | todo |
| deptest.c | deptest.rs | done |
| files.c | files.rs | done |
| ini.c | ini.rs | done |
| package.c | package.rs | done |
| pacman-conf.c | src/bin/pacman-conf.rs | done |
| pacman.c | pacman.rs | done (-D -R -U and -S installs refuse with "not implemented yet"; the command line is logged for root operations) |
| query.c | query.rs | done |
| remove.c | remove.rs | todo |
| sighandler.c | sighandler.rs | todo |
| sync.c | sync.rs | partial (-Ss -Sg -Si -Sl, -Sy, -Sw without a transaction; -Sc and installs todo) |
| upgrade.c | upgrade.rs | todo |
| util-common.c | util_common.rs | partial (strtrim, wordsplit) |
| util.c | util.rs | partial (pm_printf, resolve_path, sync_syncdbs lives in sync.rs) |

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
