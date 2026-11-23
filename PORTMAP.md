# Port map

C file -> Rust module -> status. libalpm-rs modules are in `crates/libalpm-rs/src/`; CLI modules in `crates/pacman-rs/src/`.

## lib/libalpm -> libalpm-rs

| C file | Rust module | Status |
|---|---|---|
| add.c | add.rs | todo |
| alpm.c | alpm.rs | todo |
| alpm_list.c | (Vec, no module) | n/a |
| backup.c | backup.rs | todo |
| base64.c | base64.rs | todo |
| be_local.c | be_local.rs | todo |
| be_package.c | be_package.rs | todo |
| be_sync.c | be_sync.rs | todo |
| conflict.c | conflict.rs | todo |
| db.c | db.rs | todo |
| deps.c | deps.rs | todo |
| diskspace.c | diskspace.rs | todo |
| dload.c | dload.rs | todo |
| error.c | error.rs | done |
| filelist.c | filelist.rs | todo |
| graph.c | graph.rs | todo |
| group.c | group.rs | todo |
| handle.c | handle.rs | todo |
| hook.c | hook.rs | todo |
| log.c | log.rs | todo |
| package.c | package.rs | todo |
| pkghash.c | (HashMap, no module) | n/a |
| rawstr.c | rawstr.rs | todo |
| remove.c | remove.rs | todo |
| sandbox.c | sandbox.rs | todo |
| sandbox_fs.c | sandbox_fs.rs | todo |
| sandbox_syscalls.c | sandbox_syscalls.rs | todo |
| signing.c | signing.rs | todo |
| sync.c | sync.rs | todo |
| trans.c | trans.rs | todo |
| util.c | util.rs | todo |
| version.c | version.rs | done |

## src/pacman -> pacman-rs

| C file | Rust module | Status |
|---|---|---|
| callback.c | callback.rs | todo |
| check.c | check.rs | todo |
| conf.c | conf.rs | todo |
| database.c | database.rs | todo |
| deptest.c | deptest.rs | todo |
| files.c | files.rs | todo |
| ini.c | ini.rs | todo |
| package.c | package.rs | todo |
| pacman-conf.c | pacman_conf.rs | todo |
| pacman.c | pacman.rs | todo |
| query.c | query.rs | todo |
| remove.c | remove.rs | todo |
| sighandler.c | sighandler.rs | todo |
| sync.c | sync.rs | todo |
| upgrade.c | upgrade.rs | todo |
| util-common.c | util_common.rs | todo |
| util.c | util.rs | todo |

## src/util

| C file | Rust module | Status |
|---|---|---|
| vercmp.c | src/bin/vercmp.rs | done |
| testpkg.c | src/bin/testpkg.rs | todo |
| util-common.c | (shared with src/pacman/util-common.c) | todo |
