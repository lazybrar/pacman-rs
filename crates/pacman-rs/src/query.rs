//! Port of src/pacman/query.c: the -Q operation.
use crate::check::{check_pkg_fast, check_pkg_full};
use crate::conf::*;
use crate::package::{dump_pkg_changelog, dump_pkg_files, dump_pkg_full, dump_pkg_search};
use crate::pm_printf;
use crate::pr;
use crate::util::{LOG_ERROR, LOG_WARNING};
use crate::util_pacman::check_syncdbs;
use libalpm_rs::be_package::pkg_load;
use libalpm_rs::deps::find_satisfier;
use libalpm_rs::package::*;
use libalpm_rs::sync::sync_get_new_version;

const LOCAL_PREFIX: &str = "local/";
const PATH_MAX: usize = 4096;

/// search_path: check if filename exists in PATH
fn search_path(filename: &str) -> Option<(String, std::fs::Metadata)> {
    let envpath = std::env::var("PATH").ok()?;
    for path in envpath.split(':') {
        // strip the trailing slash if one exists
        let mut p = path;
        while p.ends_with('/') {
            p = &p[..p.len() - 1];
        }
        let fullname = format!("{p}/{filename}");
        if let Ok(m) = std::fs::symlink_metadata(&fullname) {
            return Some((fullname, m));
        }
    }
    None
}

/// print_query_fileowner
fn print_query_fileowner(cfg: &Config, filename: &str, info: &Pkg) {
    if !cfg.quiet {
        let c = &cfg.colstr;
        pr!(
            "{} is owned by {}{} {}{}{}\n",
            filename,
            c.title,
            info.name,
            c.version,
            info.version,
            c.nocolor
        );
    } else {
        pr!("{}\n", info.name);
    }
}

fn realpath(p: &str) -> Option<String> {
    std::fs::canonicalize(p)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// mdirname
fn mdirname(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    match path.rfind('/') {
        Some(0) => "/".into(),
        Some(p) => path[..p].to_string(),
        None => ".".into(),
    }
}

/// lrealpath: canonicalized absolute path of a symlink (the last component is not resolved)
fn lrealpath(path: &str) -> Option<String> {
    let bname = path.rsplit('/').next().unwrap_or(path);
    if bname == "." || bname == ".." {
        // the entire path needs to be resolved
        return realpath(path);
    }
    let rpath = realpath(&mdirname(path))?;
    let mut r = rpath;
    if !r.ends_with('/') {
        r.push('/');
    }
    r.push_str(bname);
    Some(r)
}

/// query_fileowner
fn query_fileowner(cfg: &Config, targets: &[String]) -> i32 {
    let alpm = cfg.alpm.as_ref().unwrap();
    let root = alpm.handle.root();
    let rootlen = root.len();
    let mut ret = 0;
    // This code is here for safety only
    if targets.is_empty() {
        pm_printf!(LOG_ERROR, "no file was specified for --owns\n");
        return 1;
    }
    let packages = alpm.localdb.get_pkgcache().unwrap_or(&[]);
    for t in targets {
        let mut found = 0u32;
        'target: {
            let mut filename = t.clone();
            if filename.is_empty() {
                pm_printf!(LOG_ERROR, "empty string passed to file owner query\n");
                break 'target;
            }
            // trailing '/' causes lstat to dereference directory symlinks
            let mut is_dir = false;
            let mut len = filename.len() - 1;
            while len > 0 && filename.as_bytes()[len] == b'/' {
                filename.truncate(len);
                len -= 1;
                // If a non-dir file exists, S_ISDIR will correct this later.
                is_dir = true;
            }
            let mut is_missing = false;
            let mut buf = std::fs::symlink_metadata(&filename).ok();
            if buf.is_none() {
                is_missing = true;
                // if it is not a path but a program name, then check in PATH
                if !filename.contains('/')
                    && let Some((full, m)) = search_path(&filename)
                {
                    filename = full;
                    buf = Some(m);
                    is_missing = false;
                }
            }
            // Can't canonicalize path, try to proceed anyway
            let mut rpath = lrealpath(&filename).unwrap_or_else(|| filename.clone());
            if !rpath.starts_with(&root) {
                // file is outside root, we know nothing can own it
                pm_printf!(LOG_ERROR, "No package owns {}\n", filename);
                break 'target;
            }
            let dir_now = if is_missing && is_dir {
                true
            } else if !is_missing {
                is_dir = buf.as_ref().is_some_and(|m| m.is_dir());
                is_dir
            } else {
                false
            };
            if dir_now {
                if rpath.len() + 2 >= PATH_MAX {
                    pm_printf!(LOG_ERROR, "path too long: {}/\n", rpath);
                    break 'target;
                }
                rpath.push('/');
            }
            // rel_path points into rpath upstream, so it sees the appended slash too
            let rel_path = rpath[rootlen..].to_string();
            for pkg in packages {
                if !(found == 0 || is_dir) {
                    break;
                }
                if pkg.files().contains(&rel_path).is_some() {
                    print_query_fileowner(cfg, &rpath, pkg);
                    found = 1;
                }
            }
            if found == 0 {
                pm_printf!(LOG_ERROR, "No package owns {}\n", filename);
            }
        }
        if found == 0 {
            ret += 1;
        }
    }
    ret
}

/// query_search: search the local database for a matching package
fn query_search(cfg: &Config, targets: &[String]) -> i32 {
    let db_local = &cfg.alpm.as_ref().unwrap().localdb;
    let ret = dump_pkg_search(cfg, db_local, targets, false);
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
    ret
}

/// pkg_get_locality
fn pkg_get_locality(cfg: &Config, pkg: &Pkg) -> u16 {
    let alpm = cfg.alpm.as_ref().unwrap();
    for db in &alpm.syncdbs {
        if db.get_pkg(&pkg.name).is_ok() {
            return PKG_LOCALITY_NATIVE;
        }
    }
    PKG_LOCALITY_FOREIGN
}

/// is_unrequired
fn is_unrequired(cfg: &Config, pkg: &Pkg, level: u16) -> bool {
    let alpm = cfg.alpm.as_ref().unwrap();
    let mut requiredby = compute_requiredby(alpm, pkg, false);
    if requiredby.is_empty() {
        if level == 1 {
            requiredby = compute_requiredby(alpm, pkg, true);
        }
        if requiredby.is_empty() {
            return true;
        }
    }
    false
}

/// filter
fn filter(cfg: &Config, pkg: &Pkg) -> bool {
    let alpm = cfg.alpm.as_ref().unwrap();
    let reason = pkg.desc().reason;
    // check if this package was explicitly installed
    if cfg.op_q_explicit && reason != PkgReason::Explicit {
        return false;
    }
    // check if this package was installed as a dependency
    if cfg.op_q_deps && reason != PkgReason::Depend {
        return false;
    }
    // check if this pkg is or isn't in a sync DB
    if cfg.op_q_locality != 0 && cfg.op_q_locality != pkg_get_locality(cfg, pkg) {
        return false;
    }
    // check if this pkg is unrequired
    if cfg.op_q_unrequired != 0 && !is_unrequired(cfg, pkg, cfg.op_q_unrequired) {
        return false;
    }
    // check if this pkg is outdated
    if cfg.op_q_upgrade && sync_get_new_version(pkg, &alpm.syncdbs).is_none() {
        return false;
    }
    true
}

/// display
fn display(cfg: &Config, pkg: &Pkg) -> i32 {
    let alpm = cfg.alpm.as_ref().unwrap();
    let mut ret = 0;
    if cfg.op_q_info != 0 {
        dump_pkg_full(cfg, pkg, cfg.op_q_info > 1);
    }
    if cfg.op_q_list {
        dump_pkg_files(cfg, pkg, cfg.quiet);
    }
    if cfg.op_q_changelog {
        dump_pkg_changelog(cfg, pkg);
    }
    if cfg.op_q_check != 0 {
        ret = if cfg.op_q_check == 1 {
            check_pkg_fast(cfg, pkg)
        } else {
            check_pkg_full(cfg, pkg)
        };
    }
    if cfg.op_q_info == 0 && !cfg.op_q_list && !cfg.op_q_changelog && cfg.op_q_check == 0 {
        if !cfg.quiet {
            let c = &cfg.colstr;
            pr!(
                "{}{} {}{}{}",
                c.title,
                pkg.name,
                c.version,
                pkg.version,
                c.nocolor
            );
            if cfg.op_q_upgrade {
                // filter() guaranteed a newer version exists
                if let Some((db, newpkg)) = sync_get_new_version(pkg, &alpm.syncdbs) {
                    let usage = db.usage.get();
                    pr!(" -> {}{}{}", c.version, newpkg.version, c.nocolor);
                    if pkg_should_ignore(&alpm.handle, pkg)
                        || usage & libalpm_rs::consts::DB_USAGE_UPGRADE == 0
                    {
                        pr!(" {}", "[ignored]");
                    }
                }
            }
            pr!("\n");
        } else {
            pr!("{}\n", pkg.name);
        }
    }
    ret
}

/// query_group
fn query_group(cfg: &Config, targets: &[String]) -> i32 {
    let db_local = &cfg.alpm.as_ref().unwrap().localdb;
    let mut ret = 0;
    if targets.is_empty() {
        for grp in db_local.get_groupcache().unwrap_or(&[]) {
            for pkg in db_local.group_packages(grp) {
                if !filter(cfg, pkg) {
                    continue;
                }
                pr!("{} {}\n", grp.name, pkg.name);
            }
        }
    } else {
        for grpname in targets {
            match db_local.get_group(grpname) {
                Ok(Some(grp)) => {
                    for pkg in db_local.group_packages(grp) {
                        if !filter(cfg, pkg) {
                            continue;
                        }
                        if !cfg.quiet {
                            pr!("{} {}\n", grpname, pkg.name);
                        } else {
                            pr!("{}\n", pkg.name);
                        }
                    }
                }
                _ => {
                    pm_printf!(LOG_ERROR, "group '{}' was not found\n", grpname);
                    ret += 1;
                }
            }
        }
    }
    ret
}

/// pacman_query
pub fn pacman_query(cfg: &Config, targets: &[String]) -> i32 {
    let alpm = cfg.alpm.as_ref().unwrap();
    let mut ret = 0;
    let mut matched = false;

    // First: operations that do not require targets

    // search for a package
    if cfg.op_q_search {
        return query_search(cfg, targets);
    }
    // looking for groups
    if cfg.group != 0 {
        return query_group(cfg, targets);
    }
    if (cfg.op_q_locality != 0 || cfg.op_q_upgrade) && check_syncdbs(cfg, 1, true) != 0 {
        return 1;
    }
    let db_local = &alpm.localdb;

    // operations on all packages in the local DB; valid: no-op (plain -Q), list, info, check
    // invalid: isfile, owns
    if targets.is_empty() {
        if cfg.op_q_isfile || cfg.op_q_owns {
            pm_printf!(LOG_ERROR, "no targets specified (use -h for help)\n");
            return 1;
        }
        for pkg in db_local.get_pkgcache().unwrap_or(&[]) {
            if filter(cfg, pkg) {
                if display(cfg, pkg) != 0 {
                    ret = 1;
                }
                matched = true;
            }
        }
        if !matched {
            ret = 1;
        }
        return ret;
    }

    // Second: operations that require target(s)

    // determine the owner of a file
    if cfg.op_q_owns {
        return query_fileowner(cfg, targets);
    }

    // operations on named packages in the local DB; valid: no-op (plain -Q), list, info, check
    for strname in targets {
        let loaded;
        let pkg: Option<&Pkg> = if cfg.op_q_isfile {
            match pkg_load(&alpm.handle, strname, true, 0) {
                Ok(p) => {
                    loaded = p;
                    Some(&loaded)
                }
                Err(e) => {
                    pm_printf!(
                        LOG_ERROR,
                        "could not load package '{}': {}\n",
                        strname,
                        e.strerror()
                    );
                    None
                }
            }
        } else {
            // strip leading part of "local/pkgname"
            let name = strname.strip_prefix(LOCAL_PREFIX).unwrap_or(strname);
            let mut p = db_local.get_pkg(name).ok();
            if p.is_none() {
                p = find_satisfier(db_local.get_pkgcache().unwrap_or(&[]), name);
            }
            if p.is_none() {
                pm_printf!(LOG_ERROR, "package '{}' was not found\n", name);
                let c = std::ffi::CString::new(name).unwrap_or_default();
                // SAFETY: valid C string
                if !cfg.op_q_isfile && unsafe { libc::access(c.as_ptr(), libc::R_OK) } == 0 {
                    pm_printf!(
                        LOG_WARNING,
                        "'{}' is a file, you might want to use {}.\n",
                        name,
                        "-p/--file"
                    );
                }
            }
            p
        };
        let Some(pkg) = pkg else {
            ret = 1;
            continue;
        };
        if filter(cfg, pkg) {
            if display(cfg, pkg) != 0 {
                ret = 1;
            }
            matched = true;
        }
    }
    if !matched {
        ret = 1;
    }
    ret
}
