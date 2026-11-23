//! Port of lib/libalpm/be_sync.c, read side: sync database validation (without signature checks, which
//! belong to signing.c), registration and population from `.db`/`.files` archives.
//! shortcut: database signature verification is skipped (as with SigLevel Never) until signing.c is ported.
use crate::alpm_log;
use crate::archive::{ArchiveLines, Fgets, open_archive};
use crate::backup::Backup;
use crate::db::*;
use crate::deps::{Dep, dep_from_string};
use crate::error::Error;
use crate::filelist::{File, FileList};
use crate::handle::{Event, Handle};
use crate::log::*;
use crate::package::*;
use crate::util::*;
use std::io::Read;
use std::rc::Rc;

/// Everything gathered about a package over its archive entries (desc, depends, files).
#[derive(Default)]
struct Building {
    name: String,
    version: String,
    name_hash: u64,
    filename: Option<String>,
    md5sum: Option<String>,
    sha256sum: Option<String>,
    base64_sig: Option<String>,
    size: i64,
    desc: Desc,
    files: Option<FileList>,
}

/// _alpm_access(handle, NULL, path, R_OK)
fn access_r_ok(handle: &Handle, path: &str) -> Result<(), i32> {
    let Ok(c) = std::ffi::CString::new(path) else {
        return Err(libc::ENOENT);
    };
    // SAFETY: valid C string
    let r = unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            c.as_ptr(),
            libc::R_OK,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 {
        let e = std::io::Error::last_os_error();
        alpm_log!(
            handle,
            LOG_DEBUG,
            "\"{}\" is not readable: {}\n",
            path,
            strerror(&e)
        );
        return Err(e.raw_os_error().unwrap_or(0));
    }
    Ok(())
}

pub struct SyncOps;

impl DbOps for SyncOps {
    /// sync_db_validate
    fn validate(&self, db: &Db) -> i32 {
        let st = db.status.get();
        if st & DB_STATUS_VALID != 0 || st & DB_STATUS_MISSING != 0 {
            return 0;
        }
        if st & DB_STATUS_INVALID != 0 {
            db.handle.pm_errno.set(Some(Error::DbInvalidSig));
            return -1;
        }
        let dbpath = db.path();
        // we can skip any validation if the database doesn't exist
        if access_r_ok(&db.handle, dbpath) == Err(libc::ENOENT) {
            db.handle.event(&Event::DatabaseMissing {
                dbname: db.treename.clone(),
            });
            db.status
                .set((db.status.get() & !DB_STATUS_EXISTS) | DB_STATUS_MISSING);
        } else {
            db.status
                .set((db.status.get() | DB_STATUS_EXISTS) & !DB_STATUS_MISSING);
        }
        db.status
            .set((db.status.get() | DB_STATUS_VALID) & !DB_STATUS_INVALID);
        0
    }

    /// sync_db_populate
    fn populate(&self, db: &Db) -> Result<Vec<Pkg>, Error> {
        let h = &db.handle;
        if db.status.get() & DB_STATUS_INVALID != 0 {
            return h.err(Error::DbInvalid);
        }
        if db.status.get() & DB_STATUS_MISSING != 0 {
            return h.err(Error::DbNotFound);
        }
        let mut archive = match open_archive(h, db.path(), Error::DbOpen) {
            Ok(a) => a,
            Err(e) => {
                db.status
                    .set((db.status.get() & !DB_STATUS_VALID) | DB_STATUS_INVALID);
                return Err(e.err);
            }
        };
        let mut pkgs: Vec<Building> = Vec::new();
        let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut likely: Option<usize> = None;
        let mut ret = 0;
        let mut read_err: Option<String> = None;
        match archive.entries() {
            Err(e) => read_err = Some(e.to_string()),
            Ok(entries) => {
                for ent in entries {
                    let mut ent = match ent {
                        Ok(e) => e,
                        Err(e) => {
                            read_err = Some(archive_error(&e));
                            break;
                        }
                    };
                    if ent.header().entry_type().is_dir() {
                        continue;
                    }
                    // we have desc or depends - parse it
                    let name = lossy(&ent.path_bytes());
                    let mut data = Vec::new();
                    if let Err(e) = ent.read_to_end(&mut data) {
                        read_err = Some(archive_error(&e));
                        break;
                    }
                    if sync_db_read(
                        db,
                        &name,
                        ArchiveLines::new(data),
                        &mut pkgs,
                        &mut index,
                        &mut likely,
                    ) != 0
                    {
                        alpm_log!(
                            h,
                            LOG_ERROR,
                            "could not parse package description file '{}' from db '{}'\n",
                            name,
                            db.treename
                        );
                        ret = -1;
                    }
                }
            }
        }
        // the db file was successfully read, but contained errors
        if ret == -1 {
            db.status
                .set((db.status.get() & !DB_STATUS_VALID) | DB_STATUS_INVALID);
            return h.err(Error::DbInvalid);
        }
        // reading the db file failed
        if let Some(msg) = read_err {
            alpm_log!(
                h,
                LOG_ERROR,
                "could not read db '{}' ({})\n",
                db.treename,
                msg
            );
            return h.err(Error::Libarchive);
        }
        let mut out: Vec<Pkg> = pkgs.into_iter().map(|b| finish(h, b)).collect();
        out.sort_by(pkg_cmp);
        alpm_log!(
            h,
            LOG_DEBUG,
            "added {} packages to package cache for db '{}'\n",
            out.len(),
            db.treename
        );
        Ok(out)
    }
}

/// libarchive-style error text for a read failure
fn archive_error(e: &std::io::Error) -> String {
    let s = e.to_string();
    if s.contains("archive header") || s.contains("invalid") || s.contains("checksum") {
        "Unrecognized archive format".to_string()
    } else {
        strerror(e)
    }
}

/// Turn gathered data into a `Pkg` (the sync `get_validation` op is computed here).
fn finish(h: &Rc<Handle>, b: Building) -> Pkg {
    let mut p = Pkg::new(
        Rc::clone(h),
        b.name,
        b.version,
        b.name_hash,
        PkgFrom::SyncDb,
    );
    p.filename = b.filename;
    p.md5sum = b.md5sum;
    p.sha256sum = b.sha256sum;
    p.base64_sig = b.base64_sig;
    p.size = b.size;
    let mut d = b.desc;
    if d.validation == 0 {
        if p.md5sum.is_some() {
            d.validation |= PKG_VALIDATION_MD5SUM;
        }
        if p.sha256sum.is_some() {
            d.validation |= PKG_VALIDATION_SHA256SUM;
        }
        if p.base64_sig.is_some() {
            d.validation |= PKG_VALIDATION_SIGNATURE;
        }
        if d.validation == 0 {
            d.validation |= PKG_VALIDATION_NONE;
        }
    }
    p.set_desc(d);
    p.set_files(FilesData {
        files: b.files.unwrap_or_default(),
        backup: Vec::<Backup>::new(),
    });
    p.set_scriptlet(false);
    p
}

/// _alpm_validate_filename
fn validate_filename(db: &Db, pkgname: &str, filename: &str) -> i32 {
    if filename.starts_with('.') || filename.contains('/') {
        alpm_log!(
            db.handle,
            LOG_ERROR,
            "{} database is inconsistent: filename of package {} is illegal\n",
            db.treename,
            pkgname
        );
        return -1;
    } else if filename.len() > 4096 {
        alpm_log!(
            db.handle,
            LOG_ERROR,
            "{} database is inconsistent: filename of package {} is too long\n",
            db.treename,
            pkgname
        );
        return -1;
    }
    0
}

/// load_pkg_for_entry: find or create the package for an entry name; (index, filename part).
fn load_pkg_for_entry(
    db: &Db,
    entryname: &str,
    pkgs: &mut Vec<Building>,
    index: &mut std::collections::HashMap<String, usize>,
    likely: Option<usize>,
) -> Option<(usize, Option<String>)> {
    let filename = entryname.rfind('/').map(|p| entryname[p + 1..].to_string());
    let Some((pkgname, pkgver, hash)) = splitname(entryname) else {
        alpm_log!(
            db.handle,
            LOG_ERROR,
            "invalid name for database entry '{}'\n",
            entryname
        );
        return None;
    };
    let found = match likely {
        Some(l) if pkgs[l].name_hash == hash && pkgs[l].name == pkgname => Some(l),
        _ => index.get(&pkgname).copied(),
    };
    let idx = match found {
        Some(i) => i,
        None => {
            let probe = Pkg::new(
                Rc::clone(&db.handle),
                pkgname.clone(),
                pkgver.clone(),
                hash,
                PkgFrom::SyncDb,
            );
            if pkg_check_meta(&probe) != 0 {
                db.handle.pm_errno.set(Some(Error::PkgInvalid));
                return None;
            }
            alpm_log!(
                db.handle,
                LOG_FUNCTION,
                "adding '{}' to package cache for db '{}'\n",
                pkgname,
                db.treename
            );
            pkgs.push(Building {
                name: pkgname.clone(),
                version: pkgver,
                name_hash: hash,
                ..Default::default()
            });
            index.insert(pkgname, pkgs.len() - 1);
            pkgs.len() - 1
        }
    };
    Some((idx, filename))
}

/// sync_db_read: 0 on success, -1 on error.
fn sync_db_read(
    db: &Db,
    entryname: &str,
    mut lines: ArchiveLines,
    pkgs: &mut Vec<Building>,
    index: &mut std::collections::HashMap<String, usize>,
    likely: &mut Option<usize>,
) -> i32 {
    let h = &db.handle;
    alpm_log!(
        h,
        LOG_FUNCTION,
        "loading package data from archive entry {}\n",
        entryname
    );
    let Some((idx, filename)) = load_pkg_for_entry(db, entryname, pkgs, index, *likely) else {
        alpm_log!(
            h,
            LOG_DEBUG,
            "entry {} could not be loaded into {} sync database\n",
            entryname,
            db.treename
        );
        return -1;
    };
    let Some(filename) = filename else {
        // A file exists outside of a subdirectory. This isn't a read error, so return
        // success and try to continue on.
        alpm_log!(h, LOG_WARNING, "unknown database file: {}\n", entryname);
        return 0;
    };
    if !matches!(filename.as_str(), "desc" | "depends" | "files") {
        // unknown database file
        alpm_log!(h, LOG_DEBUG, "unknown database file: {}\n", filename);
        return 0;
    }
    let pkg = &mut pkgs[idx];
    // READ_NEXT & friends: any non-OK fgets (including EOF) is an error
    macro_rules! next {
        () => {
            match lines.fgets() {
                Fgets::Line(l) => {
                    let mut v = l.to_vec();
                    strip_newline(&mut v);
                    v
                }
                _ => return sync_err(h, &filename),
            }
        };
    }
    macro_rules! all {
        () => {{
            let mut v: Vec<String> = Vec::new();
            loop {
                match lines.fgets() {
                    Fgets::Line(l) => {
                        let mut b = l.to_vec();
                        if strip_newline(&mut b) == 0 {
                            break;
                        }
                        v.push(lossy(&b));
                    }
                    _ => return sync_err(h, &filename),
                }
            }
            v
        }};
    }
    macro_rules! deps {
        () => {
            all!()
                .iter()
                .map(|l| dep_from_string(l))
                .collect::<Vec<Dep>>()
        };
    }
    let ret = loop {
        let line = match lines.fgets() {
            Fgets::Line(l) => {
                let mut v = l.to_vec();
                if strip_newline(&mut v) == 0 {
                    continue;
                }
                v
            }
            Fgets::Eof => break 1, // ARCHIVE_EOF
            Fgets::Err => break -1,
        };
        match line.as_slice() {
            b"%NAME%" => {
                if next!() != pkg.name.as_bytes() {
                    alpm_log!(
                        h,
                        LOG_ERROR,
                        "{} database is inconsistent: name mismatch on package {}\n",
                        db.treename,
                        pkg.name
                    );
                }
            }
            b"%VERSION%" => {
                if next!() != pkg.version.as_bytes() {
                    alpm_log!(
                        h,
                        LOG_ERROR,
                        "{} database is inconsistent: version mismatch on package {}\n",
                        db.treename,
                        pkg.name
                    );
                }
            }
            b"%FILENAME%" => {
                let f = lossy(&next!());
                pkg.filename = Some(f.clone());
                if validate_filename(db, &pkg.name, &f) < 0 {
                    return -1;
                }
            }
            b"%BASE%" => pkg.desc.base = Some(lossy(&next!())),
            b"%DESC%" => pkg.desc.desc = Some(lossy(&next!())),
            b"%GROUPS%" => pkg.desc.groups.extend(all!()),
            b"%URL%" => pkg.desc.url = Some(lossy(&next!())),
            b"%LICENSE%" => pkg.desc.licenses.extend(all!()),
            b"%ARCH%" => pkg.desc.arch = Some(lossy(&next!())),
            b"%BUILDDATE%" => pkg.desc.builddate = parsedate(&next!()),
            b"%PACKAGER%" => pkg.desc.packager = Some(lossy(&next!())),
            b"%CSIZE%" => pkg.size = strtoofft(&next!()),
            b"%ISIZE%" => pkg.desc.isize = strtoofft(&next!()),
            b"%MD5SUM%" => pkg.md5sum = Some(lossy(&next!())),
            b"%SHA256SUM%" => pkg.sha256sum = Some(lossy(&next!())),
            b"%PGPSIG%" => pkg.base64_sig = Some(lossy(&next!())),
            b"%REPLACES%" => pkg.desc.replaces.extend(deps!()),
            b"%DEPENDS%" => pkg.desc.depends.extend(deps!()),
            b"%OPTDEPENDS%" => pkg.desc.optdepends.extend(deps!()),
            b"%MAKEDEPENDS%" => pkg.desc.makedepends.extend(deps!()),
            b"%CHECKDEPENDS%" => pkg.desc.checkdepends.extend(deps!()),
            b"%CONFLICTS%" => pkg.desc.conflicts.extend(deps!()),
            b"%PROVIDES%" => pkg.desc.provides.extend(deps!()),
            b"%FILES%" => {
                let mut files = Vec::new();
                loop {
                    let mut b = next!();
                    if strip_newline(&mut b) == 0 {
                        break;
                    }
                    files.push(File {
                        name: lossy(&b),
                        size: 0,
                        mode: 0,
                    });
                }
                let mut fl = FileList { files };
                fl.sort();
                pkg.files = Some(fl);
            }
            b"%DATA%" => {
                for l in all!() {
                    match pkg_parse_xdata(&l) {
                        Some(x) => pkg.desc.xdata.push(x),
                        None => return sync_err(h, &filename),
                    }
                }
            }
            other => {
                alpm_log!(
                    h,
                    LOG_WARNING,
                    "{}: unknown key '{}' in sync database\n",
                    pkg.name,
                    lossy(other)
                );
                let _ = all!();
            }
        }
    };
    if ret != 1 {
        return sync_err(h, &filename);
    }
    *likely = Some(idx);
    0
}

fn sync_err(h: &Handle, filename: &str) -> i32 {
    alpm_log!(h, LOG_DEBUG, "error parsing database file: {}\n", filename);
    -1
}

/// _alpm_db_register_sync (without registering into a handle's list: the caller owns the `Db`)
pub fn db_register_sync(handle: &Rc<Handle>, treename: &str, level: i32) -> Db {
    alpm_log!(
        handle,
        LOG_DEBUG,
        "registering sync database '{}'\n",
        treename
    );
    let mut db = Db::new(Rc::clone(handle), treename, false, Box::new(SyncOps));
    db.siglevel = level;
    db.get_valid_internal();
    db
}
