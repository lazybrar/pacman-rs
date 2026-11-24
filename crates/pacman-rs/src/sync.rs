//! Port of src/pacman/sync.c: -Ss, -Sg, -Si, -Sl, database synchronisation (-Sy) and download-only package
//! fetches (-Sw). Installing (transactions) and -Sc are not implemented and refuse to run.
use crate::conf::*;
use crate::package::{dump_pkg_full, dump_pkg_search, print_installed};
use crate::pm_printf;
use crate::pr;
use crate::util::LOG_ERROR;
use crate::util_pacman::{check_syncdbs, colon_printf};
use libalpm_rs::db::Db;

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

/// the -Sw path: resolve the targets and their dependencies and download the packages. This stands in
/// for sync_trans/sync_prepare_execute with the DOWNLOADONLY flag.
/// shortcut: no transaction (T13): no conflict/ignore/replaces handling, no prompts or summary, and the
/// downloaded files are not validated (check_validity); groups and `-u` are not handled.
fn sync_download_only(cfg: &Config, targets: &[String]) -> i32 {
    use libalpm_rs::deps::{find_dbs_satisfier, resolvedeps};
    use libalpm_rs::package::Pkg;
    let alpm = cfg.alpm.as_ref().unwrap();
    let handle = &alpm.handle;
    if handle.lock() != 0 {
        pm_printf!(
            LOG_ERROR,
            "failed to init transaction (unable to lock database)\n"
        );
        pm_printf!(
            LOG_ERROR,
            "could not lock database: {}\n",
            libalpm_rs::util::strerror(&std::io::Error::last_os_error())
        );
        return 1;
    }
    let mut retval = 0;
    let mut add: Vec<&Pkg> = Vec::new();
    let all: Vec<&Db> = alpm.syncdbs.iter().collect();
    let local: Vec<&Pkg> = alpm.localdb.get_pkgcache().unwrap_or(&[]).iter().collect();
    for targ in targets {
        let (dbs, name): (Vec<&Db>, &str) = match targ.split_once('/') {
            Some((repo, name)) => match all.iter().find(|d| d.name() == repo) {
                Some(d) => (vec![*d], name),
                None => {
                    pm_printf!(LOG_ERROR, "database not found: {}\n", repo);
                    retval = 1;
                    continue;
                }
            },
            None => (all.clone(), targ.as_str()),
        };
        match find_dbs_satisfier(alpm, &dbs, name) {
            Ok(Some(pkg)) => {
                let mut data = Vec::new();
                if resolvedeps(alpm, &local, pkg, &[], &mut add, &[], Some(&mut data)) != 0 {
                    pm_printf!(
                        LOG_ERROR,
                        "failed to prepare transaction ({})\n",
                        handle.errno().map_or("unexpected error", |e| e.strerror())
                    );
                    for m in &data {
                        pm_printf!(
                            LOG_ERROR,
                            "{}: unable to satisfy dependency '{}' required by {}\n",
                            "target",
                            libalpm_rs::deps::dep_compute_string(&m.depend),
                            m.target
                        );
                    }
                    retval = 1;
                }
            }
            _ => {
                pm_printf!(LOG_ERROR, "target not found: {}\n", targ);
                retval = 1;
            }
        }
    }
    if retval == 0 && libalpm_rs::sync::download_files(alpm, &add) != 0 {
        pm_printf!(
            LOG_ERROR,
            "failed to commit transaction ({})\n",
            handle.errno().map_or("unexpected error", |e| e.strerror())
        );
        retval = 1;
    }
    handle.unlock();
    retval
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
    if cfg.op_s_downloadonly && cfg.op_s_upgrade == 0 {
        return sync_download_only(cfg, targets);
    }
    crate::not_implemented("-S transactions")
}
