//! Port of lib/libalpm/db.c (read side: names, paths, package and group caches).
//! Searching (alpm_db_search uses POSIX regcomp) comes with the CLI code that needs it.
use crate::alpm_log;
use crate::error::Error;
use crate::group::{Group, group_new};
use crate::handle::Handle;
use crate::log::LOG_DEBUG;
use crate::package::Pkg;
use std::cell::{Cell, OnceCell};
use std::rc::Rc;

pub const DB_STATUS_VALID: u32 = 1;
pub const DB_STATUS_INVALID: u32 = 1 << 1;
pub const DB_STATUS_EXISTS: u32 = 1 << 2;
pub const DB_STATUS_MISSING: u32 = 1 << 3;
pub const DB_STATUS_LOCAL: u32 = 1 << 10;
pub const DB_STATUS_PKGCACHE: u32 = 1 << 11;
pub const DB_STATUS_GRPCACHE: u32 = 1 << 12;

pub const INFRQ_BASE: u32 = 1;
pub const INFRQ_DESC: u32 = 1 << 1;
pub const INFRQ_FILES: u32 = 1 << 2;
pub const INFRQ_SCRIPTLET: u32 = 1 << 3;
pub const INFRQ_DSIZE: u32 = 1 << 4;
pub const INFRQ_ALL: u32 = INFRQ_BASE | INFRQ_DESC | INFRQ_FILES | INFRQ_SCRIPTLET | INFRQ_DSIZE;
pub const INFRQ_ERROR: u32 = 1 << 30;

/// struct db_operations
pub trait DbOps {
    /// 0 when valid, -1 otherwise (status and pm_errno are updated)
    fn validate(&self, db: &Db) -> i32;
    /// the packages of the database sorted by name
    fn populate(&self, db: &Db) -> Result<Vec<Pkg>, Error>;
}

pub struct Db {
    pub handle: Rc<Handle>,
    pub treename: String,
    pub status: Cell<u32>,
    pub usage: i32,
    /// signature verification level (sync databases)
    pub siglevel: i32,
    path: OnceCell<String>,
    ops: Box<dyn DbOps>,
    pkgcache: Option<Vec<Pkg>>,
    grpcache: Option<Vec<Group>>,
}

impl Db {
    /// _alpm_db_new
    pub fn new(handle: Rc<Handle>, treename: &str, is_local: bool, ops: Box<dyn DbOps>) -> Db {
        Db {
            handle,
            treename: treename.to_string(),
            status: Cell::new(if is_local { DB_STATUS_LOCAL } else { 0 }),
            usage: crate::consts::DB_USAGE_ALL,
            siglevel: 0,
            path: OnceCell::new(),
            ops,
            pkgcache: None,
            grpcache: None,
        }
    }

    /// alpm_db_get_name
    pub fn name(&self) -> &str {
        &self.treename
    }

    /// _alpm_db_path
    pub fn path(&self) -> &str {
        self.path.get_or_init(|| {
            let p = if self.status.get() & DB_STATUS_LOCAL != 0 {
                format!("{}{}/", self.handle.dbpath, self.treename)
            } else {
                // all sync DBs now reside in the sync/ subdir of the dbpath
                format!(
                    "{}sync/{}{}",
                    self.handle.dbpath, self.treename, self.handle.dbext
                )
            };
            alpm_log!(
                self.handle,
                LOG_DEBUG,
                "database path for tree {} set to {}\n",
                self.treename,
                p
            );
            p
        })
    }

    /// alpm_db_get_valid: 0 when valid
    pub fn get_valid(&self) -> i32 {
        self.handle.pm_errno.set(None);
        self.ops.validate(self)
    }

    pub(crate) fn get_valid_internal(&self) -> i32 {
        self.ops.validate(self)
    }

    /// _alpm_db_free_pkgcache
    fn free_pkgcache(&mut self) {
        self.pkgcache = None;
        self.status.set(self.status.get() & !DB_STATUS_PKGCACHE);
        self.grpcache = None;
        self.status.set(self.status.get() & !DB_STATUS_GRPCACHE);
    }

    /// load_pkgcache
    fn load_pkgcache(&mut self) -> Result<(), Error> {
        self.free_pkgcache();
        alpm_log!(
            self.handle,
            LOG_DEBUG,
            "loading package cache for repository '{}'\n",
            self.treename
        );
        match self.ops.populate(self) {
            Ok(v) => {
                self.pkgcache = Some(v);
                self.status.set(self.status.get() | DB_STATUS_PKGCACHE);
                Ok(())
            }
            Err(e) => {
                alpm_log!(
                    self.handle,
                    LOG_DEBUG,
                    "failed to load package cache for repository '{}'\n",
                    self.treename
                );
                Err(e)
            }
        }
    }

    /// _alpm_db_get_pkgcache / alpm_db_get_pkgcache
    pub fn get_pkgcache(&mut self) -> Result<&[Pkg], Error> {
        self.handle.pm_errno.set(None);
        if self.status.get() & DB_STATUS_VALID == 0 {
            return self.handle.err(Error::DbInvalid);
        }
        if self.status.get() & DB_STATUS_PKGCACHE == 0 {
            self.load_pkgcache()?;
        }
        Ok(self.pkgcache.as_deref().unwrap_or(&[]))
    }

    /// alpm_db_get_pkg
    pub fn get_pkg(&mut self, name: &str) -> Result<&Pkg, Error> {
        self.handle.pm_errno.set(None);
        if name.is_empty() {
            return self.handle.err(Error::WrongArgs);
        }
        let handle = self.handle.clone();
        let cache = self.get_pkgcache()?;
        match cache.binary_search_by(|p| p.name.as_bytes().cmp(name.as_bytes())) {
            Ok(i) => Ok(&cache[i]),
            Err(_) => handle.err(Error::PkgNotFound),
        }
    }

    /// load_grpcache
    fn load_grpcache(&mut self) {
        alpm_log!(
            self.handle,
            LOG_DEBUG,
            "loading group cache for repository '{}'\n",
            self.treename
        );
        let _ = self.get_pkgcache(); // a failure just leaves the cache empty, like upstream
        let mut groups: Vec<Group> = Vec::new();
        for (idx, pkg) in self.pkgcache.iter().flatten().enumerate() {
            for grpname in &pkg.desc().groups {
                // first look through the group cache for a group with this name
                let found = groups
                    .iter_mut()
                    .find(|g| g.name == *grpname && !g.packages.contains(&idx));
                match found {
                    Some(g) => g.packages.push(idx),
                    None => {
                        let mut g = group_new(grpname);
                        g.packages.push(idx);
                        groups.push(g);
                    }
                }
            }
        }
        self.grpcache = Some(groups);
        self.status.set(self.status.get() | DB_STATUS_GRPCACHE);
    }

    /// _alpm_db_get_groupcache / alpm_db_get_groupcache
    pub fn get_groupcache(&mut self) -> Result<&[Group], Error> {
        self.handle.pm_errno.set(None);
        if self.status.get() & DB_STATUS_VALID == 0 {
            return self.handle.err(Error::DbInvalid);
        }
        if self.status.get() & DB_STATUS_GRPCACHE == 0 {
            self.load_grpcache();
        }
        Ok(self.grpcache.as_deref().unwrap_or(&[]))
    }

    /// alpm_db_get_group
    pub fn get_group(&mut self, name: &str) -> Result<Option<&Group>, Error> {
        if name.is_empty() {
            return self.handle.err(Error::WrongArgs);
        }
        Ok(self.get_groupcache()?.iter().find(|g| g.name == name))
    }

    /// The packages of a group (indices from `Group::packages` into the package cache).
    pub fn group_packages(&self, g: &Group) -> Vec<&Pkg> {
        g.packages
            .iter()
            .filter_map(|&i| self.pkgcache.as_ref()?.get(i))
            .collect()
    }
}
