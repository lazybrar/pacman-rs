//! Port of lib/libalpm/be_local.c, read side: local database validation, population and the lazy
//! loading of `desc`/`files` (writing and the mtree reader come with the code that needs them).
use crate::alpm_log;
use crate::backup::split_backup;
use crate::db::*;
use crate::deps::{Dep, dep_from_string};
use crate::error::Error;
use crate::filelist::{File, FileList};
use crate::handle::Handle;
use crate::log::*;
use crate::package::*;
use crate::util::*;
use std::rc::Rc;

/// local database format version
pub const ALPM_LOCAL_DB_VERSION: u64 = 9;

/// _alpm_local_db_pkgpath: "<dbpath>name-version/<filename>"
pub fn local_db_pkgpath(db: &Db, name: &str, version: &str, filename: &str) -> String {
    format!("{}{}-{}/{}", db.path(), name, version, filename)
}

/// local_db_add_version: write the ALPM_DB_VERSION file; false on failure.
fn local_db_add_version(dbpath: &str) -> bool {
    std::fs::write(
        format!("{dbpath}ALPM_DB_VERSION"),
        format!("{ALPM_LOCAL_DB_VERSION}\n"),
    )
    .is_ok()
}

/// local_db_create
fn local_db_create(db: &Db, dbpath: &str) -> i32 {
    use std::os::unix::fs::DirBuilderExt;
    // mkdir(dbpath, 0755) (subject to umask)
    let r = std::fs::DirBuilder::new()
        .mode(0o755)
        .create(dbpath.trim_end_matches('/'));
    if let Err(e) = r {
        alpm_log!(
            db.handle,
            LOG_ERROR,
            "could not create directory {}: {}\n",
            dbpath,
            crate::util::strerror(&e)
        );
        db.handle.pm_errno.set(Some(Error::DbCreate));
        return -1;
    }
    if !local_db_add_version(dbpath) {
        return 1;
    }
    0
}

/// "%zu" via fscanf: optional whitespace and sign then digits; None when no conversion happened.
fn scan_zu(s: &[u8]) -> Option<u64> {
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_whitespace() {
        i += 1;
    }
    let neg = s.get(i) == Some(&b'-');
    if matches!(s.get(i), Some(b'-' | b'+')) {
        i += 1;
    }
    let ds = i;
    let mut v: u64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add((s[i] - b'0') as u64);
        i += 1;
    }
    if i == ds {
        return None;
    }
    Some(if neg { v.wrapping_neg() } else { v })
}

pub struct LocalOps;

impl DbOps for LocalOps {
    /// local_db_validate
    fn validate(&self, db: &Db) -> i32 {
        let st = |set: u32, clear: u32| db.status.set((db.status.get() | set) & !clear);
        if db.status.get() & DB_STATUS_VALID != 0 {
            return 0;
        }
        if db.status.get() & DB_STATUS_INVALID != 0 {
            return -1;
        }
        let dbpath = db.path();
        let dir = match std::fs::read_dir(dbpath) {
            Ok(d) => d,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                // local database dir doesn't exist yet - create it
                if local_db_create(db, dbpath) == 0 {
                    st(
                        DB_STATUS_VALID | DB_STATUS_EXISTS,
                        DB_STATUS_INVALID | DB_STATUS_MISSING,
                    );
                    return 0;
                }
                st(DB_STATUS_MISSING, DB_STATUS_EXISTS);
                return -1;
            }
            Err(_) => {
                db.handle.pm_errno.set(Some(Error::DbOpen));
                return -1;
            }
        };
        st(DB_STATUS_EXISTS, DB_STATUS_MISSING);
        let version_error = || {
            st(DB_STATUS_INVALID, DB_STATUS_VALID);
            db.handle.pm_errno.set(Some(Error::DbVersion));
            -1
        };
        match std::fs::read(format!("{dbpath}ALPM_DB_VERSION")) {
            Err(_) => {
                // create dbverfile if local database is empty - otherwise version error
                if dir.into_iter().next().is_some() {
                    return version_error();
                }
                if !local_db_add_version(dbpath) {
                    return version_error();
                }
            }
            Ok(data) => {
                if scan_zu(&data) != Some(ALPM_LOCAL_DB_VERSION) {
                    return version_error();
                }
            }
        }
        st(DB_STATUS_VALID, DB_STATUS_INVALID);
        0
    }

    /// local_db_populate
    fn populate(&self, db: &Db) -> Result<Vec<Pkg>, Error> {
        let h = &db.handle;
        if db.status.get() & DB_STATUS_INVALID != 0 {
            return h.err(Error::DbInvalid);
        }
        if db.status.get() & DB_STATUS_MISSING != 0 {
            return h.err(Error::DbNotFound);
        }
        let dbpath = db.path();
        let Ok(dir) = std::fs::read_dir(dbpath) else {
            return h.err(Error::DbOpen);
        };
        db.status
            .set((db.status.get() | DB_STATUS_EXISTS) & !DB_STATUS_MISSING);
        let mut pkgs: Vec<Pkg> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for ent in dir.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            if !ent.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            // split the db entry name
            let Some((pname, pversion, hash)) = splitname(&name) else {
                alpm_log!(h, LOG_ERROR, "invalid name for database entry '{}'\n", name);
                continue;
            };
            // duplicated database entries are not allowed
            if !seen.insert(pname.clone()) {
                alpm_log!(h, LOG_ERROR, "duplicated database entry '{}'\n", pname);
                continue;
            }
            let mut pkg = Pkg::new(Rc::clone(h), pname, pversion, hash, PkgFrom::LocalDb);
            pkg.local = Some(LocalSrc {
                dir: format!("{}{}/", dbpath, name),
                treename: db.treename.clone(),
            });
            // only BASE data is read here (a no-op), accessors load the rest
            // treat local metadata errors as warning-only,
            // they are already installed and otherwise they can't be operated on
            pkg_check_meta(&pkg);
            alpm_log!(
                h,
                LOG_FUNCTION,
                "adding '{}' to package cache for db '{}'\n",
                pkg.name,
                db.treename
            );
            pkgs.push(pkg);
        }
        pkgs.sort_by(pkg_cmp);
        alpm_log!(
            h,
            LOG_DEBUG,
            "added {} packages to package cache for db '{}'\n",
            pkgs.len(),
            db.treename
        );
        Ok(pkgs)
    }
}

/// _alpm_db_register_local
pub fn db_register_local(handle: &Rc<Handle>) -> Result<Db, Error> {
    alpm_log!(handle, LOG_DEBUG, "registering local database\n");
    let db = Db::new(Rc::clone(handle), "local", true, Box::new(LocalOps));
    if db.get_valid_internal() != 0 {
        // pm_errno set in local_db_validate()
        return Err(handle.errno().unwrap_or(Error::DbOpen));
    }
    Ok(db)
}

/// Line-oriented reader state shared by the READ_* macros.
struct Parser {
    fp: CFile,
    line: Vec<u8>,
}

impl Parser {
    /// READ_NEXT
    fn read_next(&mut self) -> Result<(), ()> {
        if !self.fp.fgets(&mut self.line, 1024) && !self.fp.eof {
            return Err(());
        }
        strip_newline(&mut self.line);
        Ok(())
    }

    /// READ_AND_STORE
    fn read_and_store(&mut self) -> Result<String, ()> {
        self.read_next()?;
        Ok(lossy(&self.line))
    }

    /// READ_AND_STORE_ALL: lines up to the first empty one (or EOF)
    fn read_all(&mut self) -> Result<Vec<String>, ()> {
        let mut v = Vec::new();
        loop {
            if !self.fp.fgets(&mut self.line, 1024) {
                if !self.fp.eof {
                    return Err(());
                }
                break;
            }
            if strip_newline(&mut self.line) == 0 {
                break;
            }
            v.push(lossy(&self.line));
        }
        Ok(v)
    }

    /// READ_AND_SPLITDEP
    fn read_deps(&mut self) -> Result<Vec<Dep>, ()> {
        Ok(self
            .read_all()?
            .iter()
            .map(|l| dep_from_string(l))
            .collect())
    }
}

/// _read_pkgreason
fn read_pkgreason(h: &Handle, pkgname: &str, line: &[u8]) -> PkgReason {
    match line {
        b"0" => PkgReason::Explicit,
        b"1" => PkgReason::Depend,
        _ => {
            alpm_log!(
                h,
                LOG_ERROR,
                "unknown install reason for package {}: {}\n",
                pkgname,
                lossy(line)
            );
            PkgReason::Unknown
        }
    }
}

impl Pkg {
    fn local_prep(&self, level: u32) -> bool {
        // INFRQ_ERROR: an earlier load failed, don't retry
        if self.failed.get() {
            return false;
        }
        alpm_log!(
            self.handle,
            LOG_FUNCTION,
            "loading package data for {} : level=0x{:x}\n",
            self.name,
            level
        );
        true
    }

    fn open_local(&self, src: &LocalSrc, file: &str) -> Option<Parser> {
        let path = format!("{}{}", src.dir, file);
        match CFile::open(&path) {
            Ok(fp) => Some(Parser {
                fp,
                line: Vec::new(),
            }),
            Err(e) => {
                alpm_log!(
                    self.handle,
                    LOG_ERROR,
                    "could not open file {}: {}\n",
                    path,
                    strerror(&e)
                );
                self.failed.set(true);
                None
            }
        }
    }

    /// local_db_read(INFRQ_DESC)
    pub(crate) fn load_desc(&self) -> Desc {
        let mut d = Desc::default();
        let Some(src) = &self.local else { return d };
        if !self.local_prep(INFRQ_DESC) {
            return d;
        }
        let Some(mut p) = self.open_local(src, "desc") else {
            return d;
        };
        if self.parse_desc(&mut d, &mut p, src).is_err() {
            self.failed.set(true);
        }
        d
    }

    fn parse_desc(&self, d: &mut Desc, p: &mut Parser, src: &LocalSrc) -> Result<(), ()> {
        let h = &self.handle;
        while !p.fp.eof {
            if !p.fp.fgets(&mut p.line, 1024) && !p.fp.eof {
                return Err(());
            }
            if strip_newline(&mut p.line) == 0 {
                // length of stripped line was zero
                continue;
            }
            match p.line.clone().as_slice() {
                b"%NAME%" => {
                    p.read_next()?;
                    if p.line != self.name.as_bytes() {
                        alpm_log!(
                            h,
                            LOG_ERROR,
                            "{} database is inconsistent: name mismatch on package {}\n",
                            src.treename,
                            self.name
                        );
                    }
                }
                b"%VERSION%" => {
                    p.read_next()?;
                    if p.line != self.version.as_bytes() {
                        alpm_log!(
                            h,
                            LOG_ERROR,
                            "{} database is inconsistent: version mismatch on package {}\n",
                            src.treename,
                            self.name
                        );
                    }
                }
                b"%BASE%" => d.base = Some(p.read_and_store()?),
                b"%DESC%" => d.desc = Some(p.read_and_store()?),
                b"%GROUPS%" => d.groups.extend(p.read_all()?),
                b"%URL%" => d.url = Some(p.read_and_store()?),
                b"%LICENSE%" => d.licenses.extend(p.read_all()?),
                b"%ARCH%" => d.arch = Some(p.read_and_store()?),
                b"%BUILDDATE%" => {
                    p.read_next()?;
                    d.builddate = parsedate(&p.line);
                }
                b"%INSTALLDATE%" => {
                    p.read_next()?;
                    d.installdate = parsedate(&p.line);
                }
                b"%PACKAGER%" => d.packager = Some(p.read_and_store()?),
                b"%REASON%" => {
                    p.read_next()?;
                    d.reason = read_pkgreason(h, &self.name, &p.line);
                }
                b"%VALIDATION%" => {
                    for v in p.read_all()? {
                        match v.as_str() {
                            "none" => d.validation |= PKG_VALIDATION_NONE,
                            "md5" => d.validation |= PKG_VALIDATION_MD5SUM,
                            "sha256" => d.validation |= PKG_VALIDATION_SHA256SUM,
                            "pgp" => d.validation |= PKG_VALIDATION_SIGNATURE,
                            _ => alpm_log!(
                                h,
                                LOG_WARNING,
                                "unknown validation type for package {}: {}\n",
                                self.name,
                                v
                            ),
                        }
                    }
                }
                b"%SIZE%" => {
                    p.read_next()?;
                    d.isize = strtoofft(&p.line);
                }
                b"%REPLACES%" => d.replaces.extend(p.read_deps()?),
                b"%DEPENDS%" => d.depends.extend(p.read_deps()?),
                b"%OPTDEPENDS%" => d.optdepends.extend(p.read_deps()?),
                b"%MAKEDEPENDS%" => d.makedepends.extend(p.read_deps()?),
                b"%CHECKDEPENDS%" => d.checkdepends.extend(p.read_deps()?),
                b"%CONFLICTS%" => d.conflicts.extend(p.read_deps()?),
                b"%PROVIDES%" => d.provides.extend(p.read_deps()?),
                b"%XDATA%" => {
                    for l in p.read_all()? {
                        d.xdata.push(pkg_parse_xdata(&l).ok_or(())?);
                    }
                }
                other => {
                    alpm_log!(
                        h,
                        LOG_WARNING,
                        "{}: unknown key '{}' in local database\n",
                        self.name,
                        lossy(other)
                    );
                    p.read_all()?;
                }
            }
        }
        Ok(())
    }

    /// local_db_read(INFRQ_FILES)
    pub(crate) fn load_files(&self) -> FilesData {
        let mut fd = FilesData::default();
        let Some(src) = &self.local else { return fd };
        if !self.local_prep(INFRQ_FILES) {
            return fd;
        }
        let Some(mut p) = self.open_local(src, "files") else {
            return fd;
        };
        while p.fp.fgets(&mut p.line, 1024) {
            strip_newline(&mut p.line);
            match p.line.as_slice() {
                b"%FILES%" => {
                    let mut files = Vec::new();
                    while p.fp.fgets(&mut p.line, 1024) && strip_newline(&mut p.line) != 0 {
                        files.push(File {
                            name: lossy(&p.line),
                            size: 0,
                            mode: 0,
                        });
                    }
                    fd.files = FileList { files };
                    fd.files.sort();
                }
                b"%BACKUP%" => {
                    while p.fp.fgets(&mut p.line, 1024) && strip_newline(&mut p.line) != 0 {
                        fd.backup.push(split_backup(&lossy(&p.line)));
                    }
                }
                _ => {}
            }
        }
        fd
    }

    /// local_db_read(INFRQ_SCRIPTLET)
    pub(crate) fn load_scriptlet(&self) -> bool {
        let Some(src) = &self.local else { return false };
        if !self.local_prep(INFRQ_SCRIPTLET) {
            return false;
        }
        std::path::Path::new(&format!("{}install", src.dir)).exists()
    }

    /// _cache_changelog_open: path of the changelog file when it can be opened.
    pub fn changelog_open(&self) -> Option<std::fs::File> {
        let src = self.local.as_ref()?;
        std::fs::File::open(format!("{}changelog", src.dir)).ok()
    }
}
