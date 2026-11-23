//! Port of src/pacman/sync.c, read-only operations (-Ss, -Sg, -Si, -Sl). Everything that would
//! install or download (transactions, -Sy, -Sc) is not implemented and refuses to run.
use crate::conf::*;
use crate::package::{dump_pkg_full, dump_pkg_search, print_installed};
use crate::pm_printf;
use crate::pr;
use crate::util::LOG_ERROR;
use crate::util_pacman::check_syncdbs;
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

/// pacman_sync
pub fn pacman_sync(cfg: &Config, targets: &[String]) -> i32 {
    // clean the cache
    if cfg.op_s_clean != 0 {
        return crate::not_implemented("-Sc");
    }
    if check_syncdbs(cfg, 1, false) != 0 {
        return 1;
    }
    let sync_dbs = &cfg.alpm.as_ref().unwrap().syncdbs;
    if cfg.op_s_sync != 0 {
        // grab a fresh package list
        return crate::not_implemented("-Sy");
    }
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
    crate::not_implemented("-S transactions")
}
