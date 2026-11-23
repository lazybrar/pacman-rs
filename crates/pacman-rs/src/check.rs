//! Port of src/pacman/check.c: -Qk and -Qkk.
use crate::conf::Config;
use crate::pm_printf;
use crate::pr;
use crate::util::{LOG_ERROR, LOG_WARNING};
use libalpm_rs::archive::{AE_IFDIR, AE_IFREG, MtreeEntry};
use libalpm_rs::package::Pkg;
use libalpm_rs::util::{compute_sha256sum, hex};
use std::os::unix::fs::MetadataExt;

const AE_IFLNK: u32 = 0o120000;
const AE_IFMT: u32 = 0o170000;
const PATH_MAX: usize = 4096;

fn strerror_of(e: &std::io::Error) -> String {
    libalpm_rs::util::strerror(e)
}

/// llstat: lstat that treats a trailing slash like no slash
fn llstat(path: &str) -> std::io::Result<std::fs::Metadata> {
    let mut p = path;
    while p.len() > 1 && p.ends_with('/') {
        p = &p[..p.len() - 1];
    }
    std::fs::symlink_metadata(p)
}

/// check_file_exists: 0 exists, 1 missing (reported), -1 missing but NoExtract
fn check_file_exists(
    cfg: &Config,
    pkgname: &str,
    filepath: &str,
    rootlen: usize,
) -> (i32, Option<std::fs::Metadata>) {
    // use lstat to prevent errors from symlinks
    match llstat(filepath) {
        Ok(m) => (0, Some(m)),
        Err(e) => {
            if cfg
                .alpm
                .as_ref()
                .unwrap()
                .handle
                .match_noextract(&filepath[rootlen..])
                == 0
            {
                // NoExtract
                (-1, None)
            } else {
                if cfg.quiet {
                    pr!("{} {}\n", pkgname, filepath);
                } else {
                    pm_printf!(
                        LOG_WARNING,
                        "{}: {} ({})\n",
                        pkgname,
                        filepath,
                        strerror_of(&e)
                    );
                }
                (1, None)
            }
        }
    }
}

fn check_file_type(
    cfg: &Config,
    pkgname: &str,
    filepath: &str,
    st: &std::fs::Metadata,
    e: &MtreeEntry,
) -> i32 {
    let archive_type = e.filetype;
    let ft = st.file_type();
    if (archive_type == AE_IFREG && !ft.is_file())
        || (archive_type == AE_IFDIR && !ft.is_dir())
        || (archive_type == AE_IFLNK && !ft.is_symlink())
    {
        if cfg.quiet {
            pr!("{} {}\n", pkgname, filepath);
        } else {
            pm_printf!(
                LOG_WARNING,
                "{}: {} (File type mismatch)\n",
                pkgname,
                filepath
            );
        }
        return 1;
    }
    0
}

fn check_file_permissions(
    cfg: &Config,
    pkgname: &str,
    filepath: &str,
    st: &std::fs::Metadata,
    e: &MtreeEntry,
) -> i32 {
    let mut errors = 0;
    if st.uid() as i64 != e.uid {
        errors += 1;
        if !cfg.quiet {
            pm_printf!(LOG_WARNING, "{}: {} (UID mismatch)\n", pkgname, filepath);
        }
    }
    if st.gid() as i64 != e.gid {
        errors += 1;
        if !cfg.quiet {
            pm_printf!(LOG_WARNING, "{}: {} (GID mismatch)\n", pkgname, filepath);
        }
    }
    // mode
    let fsmode = st.mode() & 0o7777;
    if fsmode != (!AE_IFMT & e.mode) {
        errors += 1;
        if !cfg.quiet {
            pm_printf!(
                LOG_WARNING,
                "{}: {} (Permissions mismatch)\n",
                pkgname,
                filepath
            );
        }
    }
    (errors != 0) as i32
}

fn backup_notice(cfg: &Config, pkgname: &str, filepath: &str, what: &str) {
    if !cfg.quiet {
        pr!(
            "{}{}{}: ",
            cfg.colstr.title,
            "backup file",
            cfg.colstr.nocolor
        );
        pr!("{}: {} ({})\n", pkgname, filepath, what);
    }
}

fn check_file_time(
    cfg: &Config,
    pkgname: &str,
    filepath: &str,
    st: &std::fs::Metadata,
    e: &MtreeEntry,
    backup: bool,
) -> i32 {
    if st.mtime() != e.mtime {
        if backup {
            backup_notice(cfg, pkgname, filepath, "Modification time mismatch");
            return 0;
        }
        if !cfg.quiet {
            pm_printf!(
                LOG_WARNING,
                "{}: {} (Modification time mismatch)\n",
                pkgname,
                filepath
            );
        }
        return 1;
    }
    0
}

fn check_file_link(
    cfg: &Config,
    pkgname: &str,
    filepath: &str,
    st: &std::fs::Metadata,
    e: &MtreeEntry,
) -> i32 {
    let target = std::fs::read_link(filepath);
    let ok_len = target.as_ref().is_ok_and(|t| {
        use std::os::unix::ffi::OsStrExt;
        t.as_os_str().as_bytes().len() as u64 == st.size()
    });
    let Some(target) = target.ok().filter(|_| ok_len) else {
        // this should not happen
        pm_printf!(LOG_ERROR, "unable to read symlink contents: {}\n", filepath);
        return 1;
    };
    if target.to_string_lossy() != e.link.as_deref().unwrap_or("") {
        if !cfg.quiet {
            pm_printf!(
                LOG_WARNING,
                "{}: {} (Symlink path mismatch)\n",
                pkgname,
                filepath
            );
        }
        return 1;
    }
    0
}

fn check_file_size(
    cfg: &Config,
    pkgname: &str,
    filepath: &str,
    st: &std::fs::Metadata,
    e: &MtreeEntry,
    backup: bool,
) -> i32 {
    if st.size() as i64 != e.size {
        if backup {
            backup_notice(cfg, pkgname, filepath, "Size mismatch");
            return 0;
        }
        if !cfg.quiet {
            pm_printf!(LOG_WARNING, "{}: {} (Size mismatch)\n", pkgname, filepath);
        }
        return 1;
    }
    0
}

fn check_file_sha256sum(
    cfg: &Config,
    pkgname: &str,
    filepath: &str,
    e: &MtreeEntry,
    backup: bool,
) -> i32 {
    let cksum_calc = compute_sha256sum(filepath);
    let cksum_mtree = hex(&e.sha256);
    let Some(calc) = cksum_calc else {
        if !cfg.quiet {
            pm_printf!(
                LOG_WARNING,
                "{}: {} (failed to calculate {} checksum)\n",
                pkgname,
                filepath,
                "SHA256"
            );
        }
        return 1;
    };
    if calc != cksum_mtree {
        if backup {
            backup_notice(cfg, pkgname, filepath, "SHA256 checksum mismatch");
            return 0;
        }
        if !cfg.quiet {
            pm_printf!(
                LOG_WARNING,
                "{}: {} (SHA256 checksum mismatch)\n",
                pkgname,
                filepath
            );
        }
        return 1;
    }
    0
}

fn plural(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}

/// check_pkg_fast: loop through the files of the package to check if they exist
pub fn check_pkg_fast(cfg: &Config, pkg: &Pkg) -> i32 {
    let root = cfg.alpm.as_ref().unwrap().handle.root();
    let rootlen = root.len();
    if rootlen + 1 > PATH_MAX {
        // we are in trouble here
        pm_printf!(LOG_ERROR, "path too long: {}{}\n", root, "");
        return 1;
    }
    let mut errors = 0usize;
    let files = &pkg.files().files;
    for file in files {
        let path = &file.name;
        if rootlen + 1 + path.len() > PATH_MAX {
            pm_printf!(LOG_WARNING, "path too long: {}{}\n", root, path);
            continue;
        }
        let filepath = format!("{root}{path}");
        let (exists, st) = check_file_exists(cfg, &pkg.name, &filepath, rootlen);
        if exists == 0 {
            let expect_dir = path.ends_with('/');
            let is_dir = st.unwrap().is_dir();
            if expect_dir != is_dir {
                pm_printf!(
                    LOG_WARNING,
                    "{}: {} (File type mismatch)\n",
                    pkg.name,
                    filepath
                );
                errors += 1;
            }
        } else if exists == 1 {
            errors += 1;
        }
    }
    if !cfg.quiet {
        pr!(
            "{}: {} total {}, ",
            pkg.name,
            files.len(),
            plural(files.len(), "file", "files")
        );
        pr!("{} missing {}\n", errors, plural(errors, "file", "files"));
    }
    (errors != 0) as i32
}

/// check_pkg_full: loop though files in a package and perform full file property checking
pub fn check_pkg_full(cfg: &Config, pkg: &Pkg) -> i32 {
    let alpm = cfg.alpm.as_ref().unwrap();
    let root = alpm.handle.root();
    let rootlen = root.len();
    if rootlen + 1 > PATH_MAX {
        pm_printf!(LOG_ERROR, "path too long: {}{}\n", root, "");
        return 1;
    }
    let Some(entries) = pkg.local_mtree() else {
        // TODO upstream: check error to confirm failure due to no mtree file
        if !cfg.quiet {
            pr!("{}: no mtree file\n", pkg.name);
        }
        return 0;
    };
    let (mut errors, mut file_count) = (0usize, 0usize);
    for e in &entries {
        let mut path = e.path.as_str();
        // strip leading "./" from path entries
        if let Some(p) = path.strip_prefix("./") {
            path = p;
        }
        let filepath;
        if path.starts_with('.') {
            let dbfile = match path {
                ".INSTALL" => "install",
                ".CHANGELOG" => "changelog",
                _ => continue,
            };
            // Do not append root directory as alpm_option_get_dbpath is already an absolute path
            filepath = format!(
                "{}local/{}-{}/{}",
                alpm.handle.dbpath, pkg.name, pkg.version, dbfile
            );
            if filepath.len() >= PATH_MAX {
                pm_printf!(
                    LOG_WARNING,
                    "path too long: {}local/{}-{}/{}\n",
                    alpm.handle.dbpath,
                    pkg.name,
                    pkg.version,
                    dbfile
                );
                continue;
            }
        } else {
            filepath = format!("{root}{path}");
            if filepath.len() >= PATH_MAX {
                pm_printf!(LOG_WARNING, "path too long: {}{}\n", root, path);
                continue;
            }
        }
        file_count += 1;
        let (exists, st) = check_file_exists(cfg, &pkg.name, &filepath, rootlen);
        if exists == 1 {
            errors += 1;
            continue;
        } else if exists == -1 {
            // NoExtract
            continue;
        }
        let st = st.unwrap();
        let ftype = e.filetype;
        if ftype != AE_IFDIR && ftype != AE_IFREG && ftype != AE_IFLNK {
            pm_printf!(LOG_WARNING, "file type not recognized: {}{}\n", root, path);
            continue;
        }
        if check_file_type(cfg, &pkg.name, &filepath, &st, e) == 1 {
            errors += 1;
            continue;
        }
        let mut file_errors = check_file_permissions(cfg, &pkg.name, &filepath, &st, e);
        if ftype == AE_IFLNK {
            file_errors += check_file_link(cfg, &pkg.name, &filepath, &st, e);
        }
        // the following checks are expected to fail if a backup file has been modified
        let backup = pkg.backup().iter().any(|b| b.name == path);
        if ftype != AE_IFDIR {
            // file or symbolic link
            file_errors += check_file_time(cfg, &pkg.name, &filepath, &st, e, backup);
        }
        if ftype == AE_IFREG {
            file_errors += check_file_size(cfg, &pkg.name, &filepath, &st, e, backup);
            file_errors += check_file_sha256sum(cfg, &pkg.name, &filepath, e, backup);
        }
        if cfg.quiet && file_errors != 0 {
            pr!("{} {}\n", pkg.name, filepath);
        }
        errors += (file_errors != 0) as usize;
    }
    if !cfg.quiet {
        pr!(
            "{}: {} total {}, ",
            pkg.name,
            file_count,
            plural(file_count, "file", "files")
        );
        pr!("{} altered {}\n", errors, plural(errors, "file", "files"));
    }
    (errors != 0) as i32
}
