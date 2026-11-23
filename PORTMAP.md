# Port map

C file (pacman 7.1.0) -> Rust module. Status: todo / done.

## libalpm (crates/libalpm-rs/src)

| C file | Rust module | Status |
|---|---|---|
| lib/libalpm/add.c | `add` | todo |
| lib/libalpm/alpm.c | `alpm` | todo |
| lib/libalpm/alpm_list.c | n/a (Vec) | n/a |
| lib/libalpm/backup.c | `backup` | todo |
| lib/libalpm/base64.c | `base64` | todo |
| lib/libalpm/be_local.c | `be_local` | todo |
| lib/libalpm/be_package.c | `be_package` | todo |
| lib/libalpm/be_sync.c | `be_sync` | todo |
| lib/libalpm/conflict.c | `conflict` | todo |
| lib/libalpm/db.c | `db` | todo |
| lib/libalpm/deps.c | `deps` | todo |
| lib/libalpm/diskspace.c | `diskspace` | todo |
| lib/libalpm/dload.c | `dload` | todo |
| lib/libalpm/error.c | `error` | done |
| lib/libalpm/filelist.c | `filelist` | todo |
| lib/libalpm/graph.c | `graph` | todo |
| lib/libalpm/group.c | `group` | todo |
| lib/libalpm/handle.c | `handle` | todo |
| lib/libalpm/hook.c | `hook` | todo |
| lib/libalpm/log.c | `log` | todo |
| lib/libalpm/package.c | `package` | todo |
| lib/libalpm/pkghash.c | n/a (HashMap) | n/a |
| lib/libalpm/rawstr.c | `rawstr` | todo |
| lib/libalpm/remove.c | `remove` | todo |
| lib/libalpm/sandbox.c | `sandbox` | todo |
| lib/libalpm/sandbox_fs.c | `sandbox_fs` | todo |
| lib/libalpm/sandbox_syscalls.c | `sandbox_syscalls` | todo |
| lib/libalpm/signing.c | `signing` | todo |
| lib/libalpm/sync.c | `sync` | todo |
| lib/libalpm/trans.c | `trans` | todo |
| lib/libalpm/util.c | `util` | todo |
| lib/libalpm/version.c | `version` | done |

## pacman CLI (crates/pacman-rs/src)

| C file | Rust module | Status |
|---|---|---|
| src/pacman/callback.c | `callback` | todo |
| src/pacman/check.c | `check` | todo |
| src/pacman/conf.c | `conf` | todo |
| src/pacman/database.c | `database` | todo |
| src/pacman/deptest.c | `deptest` | todo |
| src/pacman/files.c | `files` | todo |
| src/pacman/ini.c | `ini` | todo |
| src/pacman/package.c | `package` | todo |
| src/pacman/pacman-conf.c | `pacman_conf` | todo |
| src/pacman/pacman.c | `pacman` | todo |
| src/pacman/query.c | `query` | todo |
| src/pacman/remove.c | `remove` | todo |
| src/pacman/sighandler.c | `sighandler` | todo |
| src/pacman/sync.c | `sync` | todo |
| src/pacman/upgrade.c | `upgrade` | todo |
| src/pacman/util-common.c | `util_common` | todo |
| src/pacman/util.c | `util` | todo |

## Tools

| C file | Rust target | Status |
|---|---|---|
| src/util/vercmp.c | `src/bin/vercmp.rs` | done |
| src/util/testpkg.c | todo | todo |
