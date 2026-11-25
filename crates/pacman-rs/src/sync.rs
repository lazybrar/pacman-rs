//! Port of src/pacman/sync.c: -Ss, -Sg, -Si, -Sl, database synchronisation (-Sy), the transaction setup and
//! preparation of -S/-Su/-Sw/--print. Installing packages (the commit) and -Sc are not implemented and refuse to run.
use crate::conf::*;
use crate::package::{dump_pkg_full, dump_pkg_search, print_installed};
use crate::pm_printf;
use crate::pr;
use crate::util::{LOG_ERROR, LOG_WARNING};
use crate::util_pacman::{
    check_syncdbs, colon_printf, display_targets, multiselect_question, print_packages, select_display,
    yesno,
};
use libalpm_rs::add::add_pkg;
use libalpm_rs::alpm::Alpm;
use libalpm_rs::consts::DB_USAGE_INSTALL;
use libalpm_rs::db::Db;
use libalpm_rs::deps::{DepMod, dep_compute_string, find_dbs_satisfier};
use libalpm_rs::error::Error;
use libalpm_rs::package::Pkg;
use libalpm_rs::sync::{find_group_pkgs, sync_sysupgrade};
use libalpm_rs::trans::{Trans, TransData};

/// sync_search
fn sync_search(cfg: &Config, syncs: &[Db], targets: &[String]) -> i32 {
    let mut found = 0;
    for db in syncs {
        let ret = dump_pkg_search(cfg, db, targets, true);
        if ret == -1 {
            let err = cfg
                .alpm
                .as_ref()
                .unwrap()
                .handle
                .errno()
                .map_or("unexpected error", |e| e.strerror());
            pm_printf!(LOG_ERROR, "search failed: {}\n", err);
            return 1;
        }
        found += (ret == 0) as i32;
    }
    (found == 0) as i32
}

/// sync_group
fn sync_group(cfg: &Config, level: u16, syncs: &[Db], targets: &[String]) -> i32 {
    let mut ret = 0;
    if !targets.is_empty() {
        for grpname in targets {
            let mut found = 0;
            for db in syncs {
                if let Ok(Some(grp)) = db.get_group(grpname) {
                    found += 1;
                    // get names of packages in group
                    for pkg in db.group_packages(grp) {
                        if !cfg.quiet {
                            pr!("{} {}\n", grpname, pkg.name);
                        } else {
                            pr!("{}\n", pkg.name);
                        }
                    }
                }
            }
            if found == 0 {
                pm_printf!(LOG_ERROR, "package group '{}' was not found\n", grpname);
                ret = 1;
            }
        }
    } else {
        ret = 1;
        let mut seen: Vec<&str> = Vec::new();
        for db in syncs {
            for grp in db.get_groupcache().unwrap_or(&[]) {
                ret = 0;
                if level > 1 {
                    for pkg in db.group_packages(grp) {
                        pr!("{} {}\n", grp.name, pkg.name);
                    }
                } else if !seen.contains(&grp.name.as_str()) {
                    // print grp names only, no package names
                    seen.push(&grp.name);
                    pr!("{}\n", grp.name);
                }
            }
        }
    }
    ret
}

/// sync_info
fn sync_info(cfg: &Config, syncs: &[Db], targets: &[String]) -> i32 {
    let mut ret = 0;
    if !targets.is_empty() {
        for target in targets {
            let (repo, pkgstr) = match target.split_once('/') {
                Some((r, p)) => (Some(r), p),
                None => (None, target.as_str()),
            };
            let (mut foundpkg, mut founddb) = (false, false);
            for db in syncs {
                if repo.is_some_and(|r| r != db.name()) {
                    continue;
                }
                founddb = true;
                if let Some(pkg) = db
                    .get_pkgcache()
                    .unwrap_or(&[])
                    .iter()
                    .find(|p| p.name == pkgstr)
                {
                    dump_pkg_full(cfg, pkg, cfg.op_s_info > 1);
                    foundpkg = true;
                    // break only leaves the package loop: other repos are still searched
                }
            }
            if !founddb {
                pm_printf!(
                    LOG_ERROR,
                    "repository '{}' does not exist\n",
                    repo.unwrap_or("")
                );
                ret += 1;
            }
            if !foundpkg {
                pm_printf!(LOG_ERROR, "package '{}' was not found\n", target);
                ret += 1;
            }
        }
    } else {
        for db in syncs {
            for pkg in db.get_pkgcache().unwrap_or(&[]) {
                dump_pkg_full(cfg, pkg, cfg.op_s_info > 1);
            }
        }
    }
    ret
}

/// sync_list
fn sync_list(cfg: &Config, syncs: &[Db], targets: &[String]) -> i32 {
    let db_local = &cfg.alpm.as_ref().unwrap().localdb;
    let mut ret = 0;
    let ls: Vec<&Db> = if !targets.is_empty() {
        let mut v = Vec::new();
        for repo in targets {
            match syncs.iter().find(|d| d.name() == repo) {
                Some(d) => v.push(d),
                None => {
                    pm_printf!(LOG_ERROR, "repository \"{}\" was not found.\n", repo);
                    ret = 1;
                }
            }
        }
        v
    } else {
        syncs.iter().collect()
    };
    for db in ls {
        for pkg in db.get_pkgcache().unwrap_or(&[]) {
            if !cfg.quiet {
                let c = &cfg.colstr;
                pr!(
                    "{}{} {}{} {}{}{}",
                    c.repo,
                    db.name(),
                    c.title,
                    pkg.name,
                    c.version,
                    pkg.version,
                    c.nocolor
                );
                print_installed(cfg, db_local, pkg);
                pr!("\n");
            } else {
                pr!("{}\n", pkg.name);
            }
        }
    }
    ret
}

/// sync_syncdbs (util.c): refresh the sync databases; false on failure
pub fn sync_syncdbs(cfg: &mut Config, level: i32) -> bool {
    let force = level >= 2;
    let alpm = cfg.alpm.as_mut().unwrap();
    let handle = alpm.handle.clone();
    let ret = libalpm_rs::be_sync::db_update(&handle, &mut alpm.syncdbs, force);
    if ret < 0 {
        pm_printf!(
            LOG_ERROR,
            "failed to synchronize all databases ({})\n",
            handle.errno().map_or("unexpected error", |e| e.strerror())
        );
    }
    ret >= 0
}

/// get_db
fn get_db<'a>(alpm: &'a Alpm, dbname: &str) -> Option<&'a Db> {
    alpm.syncdbs.iter().find(|d| d.name() == dbname)
}

/// process_pkg
fn process_pkg<'a>(
    alpm: &'a Alpm,
    trans: &mut Trans<'a>,
    explicit_adds: &mut Vec<&'a Pkg>,
    pkg: &'a Pkg,
) -> i32 {
    let ret = add_pkg(alpm, trans, pkg);
    if ret == -1 {
        let err = alpm.handle.errno().map_or("unexpected error", |e| e.strerror());
        pm_printf!(LOG_ERROR, "'{}': {}\n", pkg.name, err);
        return 1;
    }
    explicit_adds.push(pkg);
    0
}

/// group_exists
fn group_exists(dbs: &[&Db], name: &str) -> bool {
    dbs.iter().any(|db| matches!(db.get_group(name), Ok(Some(_))))
}

/// process_group
fn process_group<'a>(
    cfg: &Config,
    alpm: &'a Alpm,
    trans: &mut Trans<'a>,
    explicit_adds: &mut Vec<&'a Pkg>,
    dbs: &[&'a Db],
    group: &str,
    error: i32,
) -> i32 {
    let pkgs = find_group_pkgs(alpm, dbs, group);
    let count = pkgs.len();
    if count == 0 {
        if group_exists(dbs, group) {
            return 0;
        }
        pm_printf!(LOG_ERROR, "target not found: {}\n", group);
        return 1;
    }
    if error != 0 {
        // we already know another target errored. there is no reason to prompt the user here; we already
        // validated the group name so just move on since we won't actually be installing anything anyway.
        return 0;
    }
    if !cfg.print {
        let c = &cfg.colstr;
        colon_printf(
            cfg,
            &if count == 1 {
                format!("There is {count} member in group {}{group}{}:\n", c.groups, c.title)
            } else {
                format!("There are {count} members in group {}{group}{}:\n", c.groups, c.title)
            },
        );
        select_display(cfg, &pkgs);
        let Some(array) = multiselect_question(count) else {
            return 1;
        };
        for (n, pkg) in pkgs.iter().enumerate() {
            if !array[n] {
                continue;
            }
            if process_pkg(alpm, trans, explicit_adds, pkg) == 1 {
                return 1;
            }
        }
    } else {
        for pkg in &pkgs {
            if process_pkg(alpm, trans, explicit_adds, pkg) == 1 {
                return 1;
            }
        }
    }
    0
}

/// process_targname
fn process_targname<'a>(
    cfg: &Config,
    alpm: &'a Alpm,
    trans: &mut Trans<'a>,
    explicit_adds: &mut Vec<&'a Pkg>,
    dblist: &[&'a Db],
    targname: &str,
    error: i32,
) -> i32 {
    let pkg = find_dbs_satisfier(alpm, dblist, targname).ok().flatten();
    // skip ignored packages when user says no
    if alpm.handle.errno() == Some(Error::PkgIgnored) {
        pm_printf!(LOG_WARNING, "skipping target: {}\n", targname);
        return 0;
    }
    if let Some(pkg) = pkg {
        return process_pkg(alpm, trans, explicit_adds, pkg);
    }
    // fallback on group
    process_group(cfg, alpm, trans, explicit_adds, dblist, targname, error)
}

/// process_target
fn process_target<'a>(
    cfg: &Config,
    alpm: &'a Alpm,
    trans: &mut Trans<'a>,
    explicit_adds: &mut Vec<&'a Pkg>,
    target: &str,
    error: i32,
) -> i32 {
    let ret = match target.split_once('/').filter(|(d, _)| !d.is_empty()) {
        Some((dbname, targname)) => match get_db(alpm, dbname) {
            None => {
                pm_printf!(LOG_ERROR, "database not found: {}\n", dbname);
                1
            }
            Some(db) => {
                // explicitly mark this repo as valid for installs since a repo name was given with the target
                let usage = db.usage.get();
                db.set_usage(usage | DB_USAGE_INSTALL);
                let r = process_targname(cfg, alpm, trans, explicit_adds, &[db], targname, error);
                // restore old usage so we don't possibly disturb later targets
                db.set_usage(usage);
                r
            }
        },
        None => {
            let dblist: Vec<&Db> = alpm.syncdbs.iter().collect();
            process_targname(cfg, alpm, trans, explicit_adds, &dblist, target, error)
        }
    };
    if ret != 0 && access_read(target) {
        pm_printf!(
            LOG_WARNING,
            "'{}' is a file, did you mean {} instead of {}?\n",
            target,
            "-U/--upgrade",
            "-S/--sync"
        );
    }
    ret
}

/// access(path, R_OK) == 0
fn access_read(path: &str) -> bool {
    std::ffi::CString::new(path)
        // SAFETY: valid C string
        .is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::R_OK) } == 0)
}

/// trans_init_error
fn trans_init_error(alpm: &Alpm) {
    let handle = &alpm.handle;
    let err = handle.errno();
    pm_printf!(
        LOG_ERROR,
        "failed to init transaction ({})\n",
        err.map_or("unexpected error", |e| e.strerror())
    );
    if err == Some(Error::HandleLock) {
        let lockfile = handle.lockfile();
        pm_printf!(
            LOG_ERROR,
            "could not lock database: {}\n",
            libalpm_rs::util::strerror(&std::io::Error::last_os_error())
        );
        if access_exists(&lockfile) {
            eprint!(
                "  if you're sure a package manager is not already\n  running, you can remove {lockfile}\n"
            );
        }
    }
}

fn access_exists(path: &str) -> bool {
    std::ffi::CString::new(path)
        // SAFETY: valid C string
        .is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::F_OK) } == 0)
}

/// trans_init
fn trans_init(cfg: &Config, flags: i32, check_valid: bool) -> Option<Trans<'_>> {
    check_syncdbs(cfg, 0, check_valid);
    let alpm = cfg.alpm.as_ref().unwrap();
    match libalpm_rs::trans::trans_init(alpm, flags) {
        Ok(t) => Some(t),
        Err(_) => {
            trans_init_error(alpm);
            None
        }
    }
}

/// trans_release
fn trans_release(cfg: &Config, trans: Trans) -> i32 {
    let alpm = cfg.alpm.as_ref().unwrap();
    if trans.release(alpm) == -1 {
        pm_printf!(
            LOG_ERROR,
            "failed to release transaction ({})\n",
            alpm.handle.errno().map_or("unexpected error", |e| e.strerror())
        );
        return -1;
    }
    0
}

/// sync_trans
fn sync_trans(cfg: &Config, targets: &[String]) -> i32 {
    let alpm = cfg.alpm.as_ref().unwrap();
    let mut retval = 0;
    // Step 1: create a new transaction...
    let Some(mut trans) = trans_init(cfg, cfg.flags, true) else {
        return 1;
    };
    let mut explicit_adds: Vec<&Pkg> = Vec::new();
    // process targets
    for targ in targets {
        if process_target(cfg, alpm, &mut trans, &mut explicit_adds, targ, retval) == 1 {
            retval = 1;
        }
    }
    if retval != 0 {
        trans_release(cfg, trans);
        return retval;
    }
    if cfg.op_s_upgrade != 0 {
        if !cfg.print {
            colon_printf(cfg, "Starting full system upgrade...\n");
            alpm.handle
                .logaction("PACMAN", format_args!("starting full system upgrade\n"));
        }
        if sync_sysupgrade(alpm, &mut trans, cfg.op_s_upgrade >= 2) == -1 {
            pm_printf!(
                LOG_ERROR,
                "{}\n",
                alpm.handle.errno().map_or("unexpected error", |e| e.strerror())
            );
            trans_release(cfg, trans);
            return 1;
        }
    }
    sync_prepare_execute(cfg, alpm, trans, &explicit_adds)
}

/// print_broken_dep
fn print_broken_dep(cfg: &Config, trans: &Trans, miss: &libalpm_rs::deps::DepMissing) {
    let depstring = dep_compute_string(&miss.depend);
    match &miss.causingpkg {
        None => {
            // package being installed/upgraded has unresolved dependency
            colon_printf(
                cfg,
                &format!(
                    "unable to satisfy dependency '{}' required by {}\n",
                    depstring, miss.target
                ),
            );
        }
        Some(causing) => {
            if let Some(pkg) = trans.find_add(causing) {
                // upgrading a package breaks a local dependency
                colon_printf(
                    cfg,
                    &format!(
                        "installing {} ({}) breaks dependency '{}' required by {}\n",
                        causing, pkg.version, depstring, miss.target
                    ),
                );
            } else {
                // removing a package breaks a local dependency
                colon_printf(
                    cfg,
                    &format!(
                        "removing {} breaks dependency '{}' required by {}\n",
                        causing, depstring, miss.target
                    ),
                );
            }
        }
    }
}

/// sync_prepare_execute
fn sync_prepare_execute<'a>(
    cfg: &'a Config,
    alpm: &'a Alpm,
    mut trans: Trans<'a>,
    explicit_adds: &[&'a Pkg],
) -> i32 {
    let handle = &alpm.handle;
    let mut data = TransData::default();
    let mut retval = 0;
    // Step 2: "compute" the transaction based on targets and flags
    if trans.prepare(alpm, &mut data) == -1 {
        let err = handle.errno();
        pm_printf!(
            LOG_ERROR,
            "failed to prepare transaction ({})\n",
            err.map_or("unexpected error", |e| e.strerror())
        );
        match err {
            Some(Error::PkgInvalidArch) => {
                for pkg in &data.invalid_arch {
                    colon_printf(
                        cfg,
                        &format!("package {pkg} does not have a valid architecture\n"),
                    );
                }
            }
            Some(Error::UnsatisfiedDeps) => {
                for miss in &data.missing {
                    print_broken_dep(cfg, &trans, miss);
                }
            }
            Some(Error::ConflictingDeps) => {
                for conflict in &data.conflicts {
                    let (p1, p2) = (conflict.package1, conflict.package2);
                    // only print reason if it contains new information
                    if conflict.reason.depmod == DepMod::Any {
                        colon_printf(
                            cfg,
                            &format!(
                                "{}-{} and {}-{} are in conflict\n",
                                p1.name, p1.version, p2.name, p2.version
                            ),
                        );
                    } else {
                        colon_printf(
                            cfg,
                            &format!(
                                "{}-{} and {}-{} are in conflict ({})\n",
                                p1.name,
                                p1.version,
                                p2.name,
                                p2.version,
                                dep_compute_string(&conflict.reason)
                            ),
                        );
                    }
                }
            }
            _ => {}
        }
        trans_release(cfg, trans);
        return 1;
    }

    if trans.add.is_empty() {
        // nothing to do: just exit without complaining
        if !cfg.print {
            pr!(" there is nothing to do\n");
        }
    } else {
        // Step 3: actually perform the operation
        if cfg.print {
            print_packages(cfg, &trans.add);
        } else {
            retval = confirm_and_commit(cfg, alpm, &mut trans, &mut data, explicit_adds);
        }
    }

    // Step 4: release transaction resources
    if trans_release(cfg, trans) == -1 {
        retval = 1;
    }
    retval
}

/// the confirmation and commit part of sync_prepare_execute
fn confirm_and_commit<'a>(
    cfg: &Config,
    alpm: &'a Alpm,
    trans: &mut Trans<'a>,
    data: &mut TransData<'a>,
    explicit_adds: &[&'a Pkg],
) -> i32 {
    display_targets(cfg, trans, explicit_adds);
    pr!("\n");
    let confirm = if cfg.op_s_downloadonly {
        yesno(format_args!("Proceed with download?"))
    } else {
        yesno(format_args!("Proceed with installation?"))
    };
    if !confirm {
        return 1;
    }
    if !cfg.op_s_downloadonly {
        // installing and removing packages is P2
        pm_printf!(LOG_ERROR, "installing packages is not implemented yet\n");
        return 1;
    }
    if trans.commit(alpm, data) == -1 {
        let err = alpm.handle.errno();
        pm_printf!(
            LOG_ERROR,
            "failed to commit transaction ({})\n",
            err.map_or("unexpected error", |e| e.strerror())
        );
        if matches!(
            err,
            Some(Error::PkgInvalid | Error::PkgInvalidChecksum | Error::PkgInvalidSig)
        ) {
            for f in &data.invalid_files {
                eprintln!("{f} is invalid or corrupted");
            }
        }
        // TODO: stderr?
        pr!("Errors occurred, no packages were upgraded.\n");
        return 1;
    }
    0
}

/// pacman_sync
pub fn pacman_sync(cfg: &mut Config, targets: &[String]) -> i32 {
    // clean the cache
    if cfg.op_s_clean != 0 {
        return crate::not_implemented("-Sc");
    }
    if check_syncdbs(cfg, 1, false) != 0 {
        return 1;
    }
    if cfg.op_s_sync != 0 {
        // grab a fresh package list
        colon_printf(cfg, "Synchronizing package databases...\n");
        cfg.alpm
            .as_ref()
            .unwrap()
            .handle
            .logaction("PACMAN", format_args!("synchronizing package lists\n"));
        if !sync_syncdbs(cfg, cfg.op_s_sync as i32) {
            return 1;
        }
    }
    let cfg = &*cfg;
    let sync_dbs = &cfg.alpm.as_ref().unwrap().syncdbs;
    if check_syncdbs(cfg, 1, true) != 0 {
        return 1;
    }
    // search for a package
    if cfg.op_s_search {
        return sync_search(cfg, sync_dbs, targets);
    }
    // look for groups
    if cfg.group != 0 {
        return sync_group(cfg, cfg.group, sync_dbs, targets);
    }
    // get package info
    if cfg.op_s_info != 0 {
        return sync_info(cfg, sync_dbs, targets);
    }
    // get a listing of files in sync DBs
    if cfg.op_q_list {
        return sync_list(cfg, sync_dbs, targets);
    }
    if targets.is_empty() {
        if cfg.op_s_upgrade != 0 {
            // proceed
        } else if cfg.op_s_sync != 0 {
            return 0;
        } else {
            // don't proceed here unless we have an operation that doesn't require a target list
            pm_printf!(LOG_ERROR, "no targets specified (use -h for help)\n");
            return 1;
        }
    }
    sync_trans(cfg, targets)
}
