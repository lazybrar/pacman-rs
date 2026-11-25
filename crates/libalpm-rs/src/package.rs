//! Port of lib/libalpm/package.c: package data, accessors, metadata checks.
//!
//! Upstream dispatches accessors through `pkg_operations`; here a package either carries all of its data
//! (`set_desc`/`set_files`, used by file and sync backends) or loads it lazily from the local database
//! (be_local.c). Accessors are `&self`; lazily loaded data lives in `OnceCell`s.
use crate::alpm_log;
use crate::backup::Backup;
use crate::deps::Dep;
use crate::filelist::FileList;
use crate::handle::Handle;
use crate::log::LOG_ERROR;
use crate::util::fnmatch;
use crate::version::pkg_vercmp;
use std::cell::{Cell, OnceCell};
use std::rc::Rc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgFrom {
    File = 1,
    LocalDb,
    SyncDb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PkgReason {
    #[default]
    Explicit = 0,
    Depend = 1,
    Unknown = 2,
}

pub const PKG_VALIDATION_UNKNOWN: i32 = 0;
pub const PKG_VALIDATION_NONE: i32 = 1;
pub const PKG_VALIDATION_MD5SUM: i32 = 1 << 1;
pub const PKG_VALIDATION_SHA256SUM: i32 = 1 << 2;
pub const PKG_VALIDATION_SIGNATURE: i32 = 1 << 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xdata {
    pub name: String,
    pub value: String,
}

/// The fields upstream loads from a local `desc` file (INFRQ_DESC).
#[derive(Debug, Clone, Default)]
pub struct Desc {
    pub base: Option<String>,
    pub desc: Option<String>,
    pub url: Option<String>,
    pub builddate: i64,
    pub installdate: i64,
    pub packager: Option<String>,
    pub arch: Option<String>,
    pub isize: i64,
    pub reason: PkgReason,
    pub validation: i32,
    pub licenses: Vec<String>,
    pub groups: Vec<String>,
    pub replaces: Vec<Dep>,
    pub depends: Vec<Dep>,
    pub optdepends: Vec<Dep>,
    pub makedepends: Vec<Dep>,
    pub checkdepends: Vec<Dep>,
    pub conflicts: Vec<Dep>,
    pub provides: Vec<Dep>,
    pub xdata: Vec<Xdata>,
}

/// The data of a local `files` file (INFRQ_FILES).
#[derive(Debug, Clone, Default)]
pub struct FilesData {
    pub files: FileList,
    pub backup: Vec<Backup>,
}

/// Where a lazily loaded local-database package lives.
pub(crate) struct LocalSrc {
    /// "<dbpath>local/<name>-<version>/"
    pub dir: String,
    pub treename: String,
}

pub struct Pkg {
    pub handle: Rc<Handle>,
    pub name: String,
    pub version: String,
    pub name_hash: u64,
    pub origin: PkgFrom,
    /// origin_data.file for packages loaded from a file
    pub file: Option<String>,
    /// name of the database the package comes from (origin_data.db)
    pub dbname: Option<String>,
    pub filename: Option<String>,
    pub md5sum: Option<String>,
    pub sha256sum: Option<String>,
    pub base64_sig: Option<String>,
    /// package file size (sync and file packages)
    pub size: i64,
    /// pkg->download_size; None while INFRQ_DSIZE is not set
    pub dsize: Cell<Option<i64>>,
    pub(crate) desc: OnceCell<Desc>,
    pub(crate) files: OnceCell<FilesData>,
    pub(crate) scriptlet: OnceCell<bool>,
    /// INFRQ_ERROR: a load failed, never retry
    pub(crate) failed: Cell<bool>,
    pub(crate) local: Option<LocalSrc>,
}

impl Pkg {
    /// _alpm_pkg_new + name/version
    pub fn new(
        handle: Rc<Handle>,
        name: String,
        version: String,
        name_hash: u64,
        origin: PkgFrom,
    ) -> Pkg {
        Pkg {
            handle,
            name,
            version,
            name_hash,
            origin,
            file: None,
            dbname: None,
            filename: None,
            md5sum: None,
            sha256sum: None,
            base64_sig: None,
            size: 0,
            dsize: Cell::new(None),
            desc: OnceCell::new(),
            files: OnceCell::new(),
            scriptlet: OnceCell::new(),
            failed: Cell::new(false),
            local: None,
        }
    }

    /// Provide fully loaded metadata (packages that are not lazily loaded).
    pub fn set_desc(&self, d: Desc) {
        let _ = self.desc.set(d);
    }

    pub fn set_files(&self, f: FilesData) {
        let _ = self.files.set(f);
    }

    pub fn set_scriptlet(&self, s: bool) {
        let _ = self.scriptlet.set(s);
    }

    /// alpm_pkg_get_base/desc/url/...: all INFRQ_DESC fields
    pub fn desc(&self) -> &Desc {
        self.desc.get_or_init(|| self.load_desc())
    }

    /// alpm_pkg_get_files
    pub fn files(&self) -> &FileList {
        &self.files_data().files
    }

    /// alpm_pkg_get_backup
    pub fn backup(&self) -> &[Backup] {
        &self.files_data().backup
    }

    fn files_data(&self) -> &FilesData {
        self.files.get_or_init(|| self.load_files())
    }

    /// alpm_pkg_has_scriptlet
    pub fn has_scriptlet(&self) -> bool {
        *self.scriptlet.get_or_init(|| self.load_scriptlet())
    }

    /// pkg->ops->force_load: 0, or -1 when any part could not be loaded.
    pub fn force_load(&self) -> i32 {
        self.desc();
        self.files();
        self.has_scriptlet();
        if self.failed.get() { -1 } else { 0 }
    }
}

/// _alpm_pkg_parse_xdata
pub fn pkg_parse_xdata(s: &str) -> Option<Xdata> {
    let (n, v) = s.split_once('=')?;
    Some(Xdata {
        name: n.to_string(),
        value: v.to_string(),
    })
}

/// _alpm_pkg_compare_versions: is spkg an upgrade for localpkg?
pub fn pkg_compare_versions(spkg: &Pkg, localpkg: &Pkg) -> i32 {
    pkg_vercmp(
        Some(spkg.version.as_bytes()),
        Some(localpkg.version.as_bytes()),
    )
}

/// _alpm_pkg_cmp
pub fn pkg_cmp(a: &Pkg, b: &Pkg) -> std::cmp::Ordering {
    a.name.as_bytes().cmp(b.name.as_bytes())
}

/// alpm_pkg_find over a list of references
pub fn pkg_find_ref<'a>(haystack: &[&'a Pkg], needle: &str) -> Option<&'a Pkg> {
    let h = crate::util::hash_sdbm(needle);
    haystack
        .iter()
        .copied()
        .find(|p| p.name_hash == h && p.name == needle)
}

/// alpm_pkg_find
pub fn pkg_find<'a>(haystack: &'a [Pkg], needle: &str) -> Option<&'a Pkg> {
    let h = crate::util::hash_sdbm(needle);
    haystack
        .iter()
        .find(|p| p.name_hash == h && p.name == needle)
}

/// _alpm_pkg_check_meta: 0, or -1 when a problem was logged.
pub fn pkg_check_meta(pkg: &Pkg) -> i32 {
    let mut error_found = 0;
    let mut epkgmeta = |msg: &str| {
        error_found = -1;
        alpm_log!(
            pkg.handle,
            LOG_ERROR,
            "invalid metadata for package {}-{} ({})\n",
            pkg.name,
            pkg.version,
            msg
        );
    };
    if pkg.name.is_empty() || pkg.version.is_empty() {
        alpm_log!(
            pkg.handle,
            LOG_ERROR,
            "invalid package metadata (name or version missing)"
        );
        return -1;
    }
    if pkg.name.starts_with(['-', '.']) {
        epkgmeta("package name cannot start with '.' or '-'");
    }
    // sic: upstream passes the name as the fnmatch *pattern*
    if fnmatch(&pkg.name, "[![:alnum:]+_.@-]") == 0 {
        epkgmeta("package name contains invalid characters");
    }
    // multiple '-' in pkgver can cause local db entries for different packages to overlap
    if let Some(c) = pkg.version.find('-')
        && pkg.version[c + 1..].contains('-')
    {
        epkgmeta("package version contains invalid characters");
    }
    if pkg.version.contains('/') {
        epkgmeta("package version contains invalid characters");
    }
    // local db entry is <pkgname>-<pkgver>
    if pkg.name.len() + pkg.version.len() + 1 > 255 {
        epkgmeta("package name and version too long");
    }
    error_found
}

/// alpm_pkg_should_ignore
pub fn pkg_should_ignore(handle: &Handle, pkg: &Pkg) -> bool {
    let o = handle.opts.borrow();
    // first see if the package is ignored
    if o.ignorepkg.iter().any(|p| fnmatch(p, &pkg.name) == 0) {
        return true;
    }
    // next see if the package is in a group that is ignored
    pkg.desc()
        .groups
        .iter()
        .any(|g| o.ignoregroup.iter().any(|p| fnmatch(p, g) == 0))
}

/// find_requiredby
fn find_requiredby(pkg: &Pkg, db: &crate::db::Db, reqs: &mut Vec<String>, optional: bool) {
    for cachepkg in db.get_pkgcache().unwrap_or(&[]) {
        let list = if optional {
            &cachepkg.desc().optdepends
        } else {
            &cachepkg.desc().depends
        };
        for dep in list {
            if crate::deps::depcmp(pkg, dep) && !reqs.contains(&cachepkg.name) {
                reqs.push(cachepkg.name.clone());
            }
        }
    }
}

/// compute_requiredby (alpm_pkg_compute_requiredby / alpm_pkg_compute_optionalfor)
pub fn compute_requiredby(alpm: &crate::alpm::Alpm, pkg: &Pkg, optional: bool) -> Vec<String> {
    alpm.handle.pm_errno.set(None);
    let mut reqs = Vec::new();
    if pkg.origin == PkgFrom::File {
        // The sane option; search locally for things that require this.
        find_requiredby(pkg, &alpm.localdb, &mut reqs, optional);
    } else if pkg.origin == PkgFrom::LocalDb {
        find_requiredby(pkg, &alpm.localdb, &mut reqs, optional);
    } else {
        for db in &alpm.syncdbs {
            find_requiredby(pkg, db, &mut reqs, optional);
        }
        reqs.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    }
    reqs
}
