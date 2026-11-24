//! Port of src/pacman/package.c: package information display.
use crate::conf::Config;
use crate::ffi::{mb_chars, strftime_c, wcs_width};
use crate::pr;
use crate::util::{LOG_ERROR, flush_stdout};
use crate::util_pacman::{
    getcols, humanize_size, indentprint, list_display, list_display_linebreak, string_display,
};
use libalpm_rs::db::Db;
use libalpm_rs::deps::{dep_compute_string, find_satisfier};
use libalpm_rs::package::*;
use std::sync::OnceLock;

// indices into the titles array
const T_ARCHITECTURE: usize = 0;
const T_BACKUP_FILES: usize = 1;
const T_BUILD_DATE: usize = 2;
const T_COMPRESSED_SIZE: usize = 3;
const T_CONFLICTS_WITH: usize = 4;
const T_DEPENDS_ON: usize = 5;
const T_DESCRIPTION: usize = 6;
const T_DOWNLOAD_SIZE: usize = 7;
const T_GROUPS: usize = 8;
const T_INSTALL_DATE: usize = 9;
const T_INSTALL_REASON: usize = 10;
const T_INSTALL_SCRIPT: usize = 11;
const T_INSTALLED_SIZE: usize = 12;
const T_LICENSES: usize = 13;
const T_MD5_SUM: usize = 14;
const T_NAME: usize = 15;
const T_OPTIONAL_DEPS: usize = 16;
const T_OPTIONAL_FOR: usize = 17;
const T_PACKAGER: usize = 18;
const T_PROVIDES: usize = 19;
const T_REPLACES: usize = 20;
const T_REPOSITORY: usize = 21;
const T_REQUIRED_BY: usize = 22;
const T_SHA_256_SUM: usize = 23;
const T_SIGNATURES: usize = 24;
const T_URL: usize = 25;
const T_VALIDATED_BY: usize = 26;
const T_VERSION: usize = 27;

/// make_aligned_titles: titles padded with spaces to the widest one, then " :"
fn titles() -> &'static [String] {
    static T: OnceLock<Vec<String>> = OnceLock::new();
    T.get_or_init(|| {
        let buf = [
            "Architecture",
            "Backup Files",
            "Build Date",
            "Compressed Size",
            "Conflicts With",
            "Depends On",
            "Description",
            "Download Size",
            "Groups",
            "Install Date",
            "Install Reason",
            "Install Script",
            "Installed Size",
            "Licenses",
            "MD5 Sum",
            "Name",
            "Optional Deps",
            "Optional For",
            "Packager",
            "Provides",
            "Replaces",
            "Repository",
            "Required By",
            "SHA-256 Sum",
            "Signatures",
            "URL",
            "Validated By",
            "Version",
        ];
        let wcol: Vec<i32> = buf.iter().map(|b| wcs_width(&mb_chars(b))).collect();
        let maxcol = *wcol.iter().max().unwrap();
        buf.iter()
            .zip(wcol)
            .map(|(b, w)| format!("{}{} :", b, " ".repeat((maxcol - w) as usize)))
            .collect()
    })
}

/// deplist_display
fn deplist_display(cfg: &Config, title: &str, deps: &[libalpm_rs::deps::Dep], cols: u16) {
    let text: Vec<String> = deps.iter().map(dep_compute_string).collect();
    list_display(cfg, Some(title), &text, cols);
}

/// optdeplist_display
fn optdeplist_display(cfg: &Config, pkg: &Pkg, cols: u16) {
    let alpm = cfg.alpm.as_ref().unwrap();
    let mut text = Vec::new();
    for optdep in &pkg.desc().optdepends {
        let mut depstring = dep_compute_string(optdep);
        if pkg.origin == PkgFrom::LocalDb
            && find_satisfier(alpm.localdb.get_pkgcache().unwrap_or(&[]), &depstring).is_some()
        {
            depstring.push_str(" [installed]");
        }
        text.push(depstring);
    }
    list_display_linebreak(cfg, Some(&titles()[T_OPTIONAL_DEPS]), &text, cols);
}

/// dump_pkg_full
pub fn dump_pkg_full(cfg: &Config, pkg: &Pkg, extra: bool) {
    let t = titles();
    let alpm = cfg.alpm.as_ref().unwrap();
    let from = pkg.origin;
    let d = pkg.desc();

    // set variables here, do all output below
    let bdate = d.builddate;
    let bdatestr = if bdate != -1 {
        strftime_c(bdate)
    } else {
        String::new()
    };
    let idate = d.installdate;
    let idatestr = if idate != -1 {
        strftime_c(idate)
    } else {
        String::new()
    };
    let reason = match d.reason {
        PkgReason::Explicit => "Explicitly installed",
        PkgReason::Depend => "Installed as a dependency for another package",
        _ => "Unknown",
    };
    let v = d.validation;
    let mut validation: Vec<&str> = Vec::new();
    if v != 0 {
        if v & PKG_VALIDATION_NONE != 0 {
            validation.push("None");
        } else {
            if v & PKG_VALIDATION_MD5SUM != 0 {
                validation.push("MD5 Sum");
            }
            if v & PKG_VALIDATION_SHA256SUM != 0 {
                validation.push("SHA-256 Sum");
            }
            if v & PKG_VALIDATION_SIGNATURE != 0 {
                validation.push("Signature");
            }
        }
    } else {
        validation.push("Unknown");
    }
    let (requiredby, optionalfor) = if extra || from == PkgFrom::LocalDb {
        // compute this here so we don't get a pause in the middle of output
        (
            compute_requiredby(alpm, pkg, false),
            compute_requiredby(alpm, pkg, true),
        )
    } else {
        (Vec::new(), Vec::new())
    };
    let cols = getcols();

    // actual output
    if from == PkgFrom::SyncDb {
        string_display(cfg, Some(&t[T_REPOSITORY]), pkg.dbname.as_deref(), cols);
    }
    string_display(cfg, Some(&t[T_NAME]), Some(&pkg.name), cols);
    string_display(cfg, Some(&t[T_VERSION]), Some(&pkg.version), cols);
    string_display(cfg, Some(&t[T_DESCRIPTION]), d.desc.as_deref(), cols);
    string_display(cfg, Some(&t[T_ARCHITECTURE]), d.arch.as_deref(), cols);
    string_display(cfg, Some(&t[T_URL]), d.url.as_deref(), cols);
    list_display(cfg, Some(&t[T_LICENSES]), &d.licenses, cols);
    list_display(cfg, Some(&t[T_GROUPS]), &d.groups, cols);
    deplist_display(cfg, &t[T_PROVIDES], &d.provides, cols);
    deplist_display(cfg, &t[T_DEPENDS_ON], &d.depends, cols);
    optdeplist_display(cfg, pkg, cols);
    if extra || from == PkgFrom::LocalDb {
        list_display(cfg, Some(&t[T_REQUIRED_BY]), &requiredby, cols);
        list_display(cfg, Some(&t[T_OPTIONAL_FOR]), &optionalfor, cols);
    }
    deplist_display(cfg, &t[T_CONFLICTS_WITH], &d.conflicts, cols);
    deplist_display(cfg, &t[T_REPLACES], &d.replaces, cols);

    let (size, mut label) = humanize_size(pkg.size, '\0', 2);
    if from == PkgFrom::SyncDb {
        pr!(
            "{}{}{} {:.2} {}\n",
            cfg.colstr.title,
            t[T_DOWNLOAD_SIZE],
            cfg.colstr.nocolor,
            size,
            label
        );
    } else if from == PkgFrom::File {
        pr!(
            "{}{}{} {:.2} {}\n",
            cfg.colstr.title,
            t[T_COMPRESSED_SIZE],
            cfg.colstr.nocolor,
            size,
            label
        );
    } else {
        // autodetect size for "Installed Size"
        label = "";
    }
    let (size, label) = humanize_size(d.isize, label.chars().next().unwrap_or('\0'), 2);
    pr!(
        "{}{}{} {:.2} {}\n",
        cfg.colstr.title,
        t[T_INSTALLED_SIZE],
        cfg.colstr.nocolor,
        size,
        label
    );

    string_display(cfg, Some(&t[T_PACKAGER]), d.packager.as_deref(), cols);
    string_display(cfg, Some(&t[T_BUILD_DATE]), Some(&bdatestr), cols);
    if from == PkgFrom::LocalDb {
        string_display(cfg, Some(&t[T_INSTALL_DATE]), Some(&idatestr), cols);
        string_display(cfg, Some(&t[T_INSTALL_REASON]), Some(reason), cols);
    }
    if from == PkgFrom::File || from == PkgFrom::LocalDb {
        string_display(
            cfg,
            Some(&t[T_INSTALL_SCRIPT]),
            Some(if pkg.has_scriptlet() { "Yes" } else { "No" }),
            cols,
        );
    }

    if from == PkgFrom::SyncDb && extra {
        let keys: Vec<String> = match &pkg.base64_sig {
            Some(sig) => {
                let mut keys = Vec::new();
                if let Some(data) = libalpm_rs::signing::decode_signature(sig) {
                    let _ = libalpm_rs::signing::extract_keyid(
                        &pkg.handle,
                        &pkg.name,
                        &data,
                        &mut keys,
                    );
                }
                keys
            }
            None => vec!["None".to_string()],
        };
        string_display(cfg, Some(&t[T_MD5_SUM]), pkg.md5sum.as_deref(), cols);
        string_display(cfg, Some(&t[T_SHA_256_SUM]), pkg.sha256sum.as_deref(), cols);
        list_display(cfg, Some(&t[T_SIGNATURES]), &keys, cols);
    } else {
        list_display(cfg, Some(&t[T_VALIDATED_BY]), &validation, cols);
    }

    if from == PkgFrom::File {
        match libalpm_rs::signing::pkg_check_pgp_signature(pkg) {
            Err(libalpm_rs::error::Error::SigMissing) => {
                string_display(cfg, Some(&t[T_SIGNATURES]), Some("None"), cols)
            }
            Err(e) => string_display(cfg, Some(&t[T_SIGNATURES]), Some(e.strerror()), cols),
            Ok(siglist) => {
                crate::util_pacman::signature_display(cfg, Some(&t[T_SIGNATURES]), &siglist, cols)
            }
        }
    }

    // Print additional package info if info flag passed more than once
    if from == PkgFrom::LocalDb && extra {
        dump_pkg_backups(cfg, pkg, cols);
    }

    if extra {
        let text: Vec<String> = d
            .xdata
            .iter()
            .map(|x| format!("{}={}", x.name, x.value))
            .collect();
        list_display_linebreak(cfg, Some("Extended Data   :"), &text, cols);
    }

    // final newline to separate packages
    pr!("\n");
}

/// get_backup_file_status
fn get_backup_file_status(root: &str, backup: &libalpm_rs::backup::Backup) -> Option<&'static str> {
    let path = format!("{}{}", root, backup.name);
    // if we find the file, calculate checksums, otherwise it is missing
    let c = std::ffi::CString::new(path.clone()).ok()?;
    // SAFETY: valid C string
    if unsafe { libc::access(c.as_ptr(), libc::R_OK) } == 0 {
        let Some(md5) = libalpm_rs::util::compute_md5sum(&path) else {
            crate::pm_printf!(LOG_ERROR, "could not calculate checksums for {}\n", path);
            return None;
        };
        // if checksums don't match, file has been modified
        Some(if Some(md5.as_str()) != backup.hash.as_deref() {
            "[modified]"
        } else {
            "[unmodified]"
        })
    } else {
        Some(match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EACCES) => "[unreadable]",
            Some(libc::ENOENT) => "[missing]",
            _ => "[unknown]",
        })
    }
}

/// dump_pkg_backups: list of backup files and their modification states
pub fn dump_pkg_backups(cfg: &Config, pkg: &Pkg, cols: u16) {
    let root = cfg.alpm.as_ref().unwrap().handle.root();
    let mut text = Vec::new();
    // package has backup files, so print them
    for backup in pkg.backup() {
        if backup.hash.is_none() {
            continue;
        }
        // a NULL status (unreadable checksum) would crash upstream's snprintf; print nothing for it
        let value = get_backup_file_status(&root, backup).unwrap_or("(null)");
        text.push(format!("{}{} {}", root, backup.name, value));
    }
    list_display_linebreak(cfg, Some(&titles()[T_BACKUP_FILES]), &text, cols);
}

/// dump_pkg_files: list all files contained in a package
pub fn dump_pkg_files(cfg: &Config, pkg: &Pkg, quiet: bool) {
    let root = cfg.alpm.as_ref().unwrap().handle.root();
    for file in &pkg.files().files {
        // Regular: '<pkgname> <root><filepath>\n'   Quiet: '<root><filepath>\n'
        if !quiet {
            pr!("{}{}{} ", cfg.colstr.title, pkg.name, cfg.colstr.nocolor);
        }
        pr!("{}{}\n", root, file.name);
    }
    flush_stdout();
}

/// dump_pkg_changelog
pub fn dump_pkg_changelog(cfg: &Config, pkg: &Pkg) {
    let _ = cfg;
    let data: Option<Vec<u8>> = match pkg.origin {
        PkgFrom::LocalDb => pkg.changelog_open().and_then(|mut f| {
            use std::io::Read;
            let mut v = Vec::new();
            f.read_to_end(&mut v).ok().map(|_| v)
        }),
        PkgFrom::File => libalpm_rs::be_package::pkg_changelog_read_all(pkg),
        PkgFrom::SyncDb => None,
    };
    match data {
        None => crate::pm_printf!(LOG_ERROR, "no changelog available for '{}'.\n", pkg.name),
        Some(d) => {
            use std::io::Write;
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "Changelog for {}:", pkg.name);
            let _ = out.write_all(&d);
            let _ = out.write_all(b"\n");
        }
    }
}

/// print_installed
pub fn print_installed(cfg: &Config, db_local: &Db, pkg: &Pkg) {
    if let Ok(lpkg) = db_local.get_pkg(&pkg.name) {
        if lpkg.version == pkg.version {
            pr!(" {}[installed]{}", cfg.colstr.meta, cfg.colstr.nocolor);
        } else {
            pr!(
                " {}[installed: {}]{}",
                cfg.colstr.meta,
                lpkg.version,
                cfg.colstr.nocolor
            );
        }
    }
}

/// print_groups
pub fn print_groups(cfg: &Config, pkg: &Pkg) {
    let g = &pkg.desc().groups;
    if !g.is_empty() {
        pr!(
            " {}({}){}",
            cfg.colstr.groups,
            g.join(" "),
            cfg.colstr.nocolor
        );
    }
}

/// dump_pkg_search: -1 on error, 0 if there were matches, 1 if there were not
pub fn dump_pkg_search(cfg: &Config, db: &Db, targets: &[String], show_status: bool) -> i32 {
    let alpm = cfg.alpm.as_ref().unwrap();
    let searchlist: Vec<&Pkg> = if !targets.is_empty() {
        match db.search(targets) {
            Ok(v) => v,
            Err(_) => return -1,
        }
    } else {
        db.get_pkgcache().unwrap_or(&[]).iter().collect()
    };
    if searchlist.is_empty() {
        return 1;
    }
    let cols = getcols();
    for pkg in searchlist {
        if cfg.quiet {
            pr!("{}", pkg.name);
        } else {
            pr!(
                "{}{}/{}{} {}{}{}",
                cfg.colstr.repo,
                db.name(),
                cfg.colstr.title,
                pkg.name,
                cfg.colstr.version,
                pkg.version,
                cfg.colstr.nocolor
            );
            print_groups(cfg, pkg);
            if show_status {
                print_installed(cfg, &alpm.localdb, pkg);
            }
            // we need a newline and initial indent first
            pr!("\n    ");
            indentprint(pkg.desc().desc.as_deref().unwrap_or(""), 4, cols);
        }
        pr!("\n");
    }
    0
}

#[allow(dead_code)]
const _: usize = T_DEPENDS_ON + T_DESCRIPTION + T_GROUPS + T_NAME;

/// dump_file_list (files.c): '<pkgname> <filepath>' or, with --quiet, '<filepath>'
pub fn dump_pkg_files_f(cfg: &Config, pkg: &Pkg) {
    for file in &pkg.files().files {
        if !cfg.quiet {
            pr!("{}{}{} ", cfg.colstr.title, pkg.name, cfg.colstr.nocolor);
        }
        pr!("{}\n", file.name);
    }
    flush_stdout();
}
