//! Port of src/pacman/files.c: -F (file lists from `.files` databases; -Fy is not implemented).
use crate::conf::Config;
use crate::package::{dump_pkg_files_f, print_groups, print_installed};
use crate::pm_printf;
use crate::pr;
use crate::util::LOG_ERROR;
use crate::util_pacman::check_syncdbs;
use libalpm_rs::db::Db;
use libalpm_rs::package::Pkg;
use libalpm_rs::regex::Regex;
use std::io::Write;

/// print_line_machinereadable: repo, pkgname, pkgver, filename separated with \0
fn print_line_machinereadable(db: &Db, pkg: &Pkg, filename: &str) {
    let mut o = std::io::stdout().lock();
    let _ = write!(
        o,
        "{}\0{}\0{}\0{}\n",
        db.name(),
        pkg.name,
        pkg.version,
        filename
    );
}

/// dump_pkg_machinereadable
fn dump_pkg_machinereadable(db: &Db, pkg: &Pkg) {
    for file in &pkg.files().files {
        print_line_machinereadable(db, pkg, &file.name);
    }
}

/// print_owned_by
fn print_owned_by(cfg: &Config, db: &Db, pkg: &Pkg, filename: &str) {
    let c = &cfg.colstr;
    pr!(
        "{} is owned by {}{}/{}{} {}{}{}\n",
        filename,
        c.repo,
        db.name(),
        c.title,
        pkg.name,
        c.version,
        pkg.version,
        c.nocolor
    );
}

/// print_match
fn print_match(cfg: &Config, matches: &[&str], repo: &Db, pkg: &Pkg, exact_file: bool) {
    let db_local = &cfg.alpm.as_ref().unwrap().localdb;
    let c = &cfg.colstr;
    if cfg.op_f_machinereadable {
        for f in matches {
            print_line_machinereadable(repo, pkg, f);
        }
    } else if cfg.quiet {
        pr!("{}/{}\n", repo.name(), pkg.name);
    } else if exact_file {
        for f in matches {
            print_owned_by(cfg, repo, pkg, f);
        }
    } else {
        pr!(
            "{}{}/{}{} {}{}{}",
            c.repo,
            repo.name(),
            c.title,
            pkg.name,
            c.version,
            pkg.version,
            c.nocolor
        );
        print_groups(cfg, pkg);
        print_installed(cfg, db_local, pkg);
        pr!("\n");
        for f in matches {
            pr!("    {}\n", f);
        }
    }
}

struct FileTarget<'a> {
    targ: &'a str,
    exact_file: bool,
    reg: Option<Regex>,
}

/// files_search
fn files_search(cfg: &Config, syncs: &[Db], targets: &[String], regex: bool) -> i32 {
    let mut ret = 0;
    let mut filetargs: Vec<FileTarget> = Vec::new();
    for t in targets {
        let mut targ: &str = t;
        let exact_file = targ.contains('/');
        if exact_file {
            while targ.len() > 1 && targ.starts_with('/') {
                targ = &targ[1..];
            }
        }
        let mut reg = None;
        if regex {
            match Regex::new_ere_icase(targ) {
                Some(r) => reg = Some(r),
                None => {
                    pm_printf!(LOG_ERROR, "invalid regular expression '{}'\n", targ);
                    ret = 1;
                    continue;
                }
            }
        }
        filetargs.push(FileTarget {
            targ,
            exact_file,
            reg,
        });
    }
    if ret != 0 {
        return ret;
    }
    for ft in &filetargs {
        let mut found = false;
        for repo in syncs {
            for pkg in repo.get_pkgcache().unwrap_or(&[]) {
                let files = pkg.files();
                let mut matches: Vec<&str> = Vec::new();
                if ft.exact_file {
                    if let Some(reg) = &ft.reg {
                        for f in &files.files {
                            if reg.is_match(&f.name) {
                                matches.push(&f.name);
                                found = true;
                            }
                        }
                    } else if files.contains(ft.targ).is_some() {
                        matches.push(ft.targ);
                        found = true;
                    }
                } else {
                    for f in &files.files {
                        if let Some(p) = f.name.rfind('/') {
                            let base = &f.name[p + 1..];
                            if !base.is_empty() {
                                let m = match &ft.reg {
                                    Some(reg) => reg.is_match(base),
                                    None => base == ft.targ,
                                };
                                if m {
                                    matches.push(&f.name);
                                    found = true;
                                }
                            }
                        }
                    }
                }
                if !matches.is_empty() {
                    print_match(cfg, &matches, repo, pkg, ft.exact_file);
                }
            }
        }
        if !found {
            ret = 1;
        }
    }
    ret
}

/// files_list
fn files_list(cfg: &Config, syncs: &[Db], targets: &[String]) -> i32 {
    let mut ret = 0;
    if !targets.is_empty() {
        for target in targets {
            let mut found = false;
            let (repo, targ) = match target.find('/') {
                Some(c) => {
                    if c + 1 == target.len() {
                        pm_printf!(LOG_ERROR, "invalid package: '{}'\n", target);
                        ret += 1;
                        continue;
                    }
                    (Some(&target[..c]), &target[c + 1..])
                }
                None => (None, target.as_str()),
            };
            for db in syncs {
                if repo.is_some_and(|r| db.name() != r) {
                    continue;
                }
                if let Ok(pkg) = db.get_pkg(targ) {
                    found = true;
                    if cfg.op_f_machinereadable {
                        dump_pkg_machinereadable(db, pkg);
                    } else {
                        dump_pkg_files_f(cfg, pkg);
                    }
                    break;
                }
            }
            if !found {
                pm_printf!(LOG_ERROR, "package '{}' was not found\n", target);
                ret += 1;
            }
        }
    } else {
        for db in syncs {
            for pkg in db.get_pkgcache().unwrap_or(&[]) {
                if cfg.op_f_machinereadable {
                    dump_pkg_machinereadable(db, pkg);
                } else {
                    dump_pkg_files_f(cfg, pkg);
                }
            }
        }
    }
    ret
}

/// pacman_files
pub fn pacman_files(cfg: &Config, targets: &[String]) -> i32 {
    if check_syncdbs(cfg, 1, false) != 0 {
        return 1;
    }
    let files_dbs = &cfg.alpm.as_ref().unwrap().syncdbs;
    if cfg.op_s_sync != 0 {
        // grab a fresh package list
        return crate::not_implemented("-Fy");
    }
    // get a listing of files in sync DBs
    if cfg.op_q_list {
        return files_list(cfg, files_dbs, targets);
    }
    if targets.is_empty() && cfg.op_s_sync == 0 {
        pm_printf!(LOG_ERROR, "no targets specified (use -h for help)\n");
        return 1;
    }
    // search for a file
    files_search(cfg, files_dbs, targets, cfg.op_f_regex)
}
