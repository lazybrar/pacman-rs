//! Port of lib/libalpm/db.c (read side: names, paths, package and group caches, search).
//! Caches are `OnceCell`s so that every accessor takes `&self` (like the C handle, databases are shared).
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
    /// alpm_db_set_usage / alpm_db_get_usage
    pub usage: Cell<i32>,
    /// signature verification level (sync databases)
    pub siglevel: i32,
    pub servers: std::cell::RefCell<Vec<String>>,
    pub cache_servers: std::cell::RefCell<Vec<String>>,
    path: OnceCell<String>,
    ops: Box<dyn DbOps>,
    pkgcache: OnceCell<Vec<Pkg>>,
    grpcache: OnceCell<Vec<Group>>,
}

impl Db {
    /// _alpm_db_new
    pub fn new(handle: Rc<Handle>, treename: &str, is_local: bool, ops: Box<dyn DbOps>) -> Db {
        Db {
            handle,
            treename: treename.to_string(),
            status: Cell::new(if is_local { DB_STATUS_LOCAL } else { 0 }),
            usage: Cell::new(crate::consts::DB_USAGE_ALL),
            siglevel: 0,
            servers: Default::default(),
            cache_servers: Default::default(),
            path: OnceCell::new(),
            ops,
            pkgcache: OnceCell::new(),
            grpcache: OnceCell::new(),
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
                    self.handle.dbpath,
                    self.treename,
                    self.handle.dbext()
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

    /// alpm_db_get_siglevel: the handle default replaces SIG_USE_DEFAULT
    pub fn get_siglevel(&self) -> i32 {
        if self.siglevel & crate::consts::SIG_USE_DEFAULT != 0 {
            self.handle.opts.borrow().siglevel
        } else {
            self.siglevel
        }
    }

    /// alpm_db_set_usage
    pub fn set_usage(&self, usage: i32) {
        self.usage.set(usage);
    }

    /// alpm_db_add_server / alpm_db_add_cache_server (sanitize_url strips one trailing '/')
    fn add_url(&self, url: &str, cache: bool) -> i32 {
        self.handle.pm_errno.set(None);
        if url.is_empty() {
            self.handle.pm_errno.set(Some(Error::WrongArgs));
            return -1;
        }
        let newurl = url.strip_suffix('/').unwrap_or(url).to_string();
        let what = if cache { "cache server" } else { "server" };
        alpm_log!(
            self.handle,
            LOG_DEBUG,
            "adding new {} URL to database '{}': {}\n",
            what,
            self.treename,
            newurl
        );
        if cache {
            &self.cache_servers
        } else {
            &self.servers
        }
        .borrow_mut()
        .push(newurl);
        0
    }

    pub fn add_server(&self, url: &str) -> i32 {
        self.add_url(url, false)
    }

    pub fn add_cache_server(&self, url: &str) -> i32 {
        self.add_url(url, true)
    }

    /// load_pkgcache
    fn load_pkgcache(&self) -> Result<(), Error> {
        alpm_log!(
            self.handle,
            LOG_DEBUG,
            "loading package cache for repository '{}'\n",
            self.treename
        );
        match self.ops.populate(self) {
            Ok(v) => {
                let _ = self.pkgcache.set(v);
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
    pub fn get_pkgcache(&self) -> Result<&[Pkg], Error> {
        self.handle.pm_errno.set(None);
        if self.status.get() & DB_STATUS_VALID == 0 {
            return self.handle.err(Error::DbInvalid);
        }
        if self.pkgcache.get().is_none() {
            self.load_pkgcache()?;
        }
        Ok(self.pkgcache.get().map_or(&[], |v| v.as_slice()))
    }

    /// alpm_db_get_pkg
    pub fn get_pkg(&self, name: &str) -> Result<&Pkg, Error> {
        self.handle.pm_errno.set(None);
        if name.is_empty() {
            return self.handle.err(Error::WrongArgs);
        }
        self.pkg_from_cache(name)
            .ok_or(())
            .or_else(|_| self.handle.err(Error::PkgNotFound))
    }

    /// _alpm_db_get_pkgfromcache (None when missing or when the cache cannot be loaded)
    pub fn pkg_from_cache(&self, name: &str) -> Option<&Pkg> {
        let cache = self.get_pkgcache().ok()?;
        cache
            .binary_search_by(|p| p.name.as_bytes().cmp(name.as_bytes()))
            .ok()
            .map(|i| &cache[i])
    }

    /// load_grpcache
    fn load_grpcache(&self) -> Vec<Group> {
        alpm_log!(
            self.handle,
            LOG_DEBUG,
            "loading group cache for repository '{}'\n",
            self.treename
        );
        // a package cache failure just leaves the group cache empty, like upstream
        let cache = self.get_pkgcache().unwrap_or(&[]);
        let mut groups: Vec<Group> = Vec::new();
        for (idx, pkg) in cache.iter().enumerate() {
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
        groups
    }

    /// _alpm_db_get_groupcache / alpm_db_get_groupcache
    pub fn get_groupcache(&self) -> Result<&[Group], Error> {
        self.handle.pm_errno.set(None);
        if self.status.get() & DB_STATUS_VALID == 0 {
            return self.handle.err(Error::DbInvalid);
        }
        if self.grpcache.get().is_none() {
            let g = self.load_grpcache();
            let _ = self.grpcache.set(g);
            self.status.set(self.status.get() | DB_STATUS_GRPCACHE);
        }
        Ok(self.grpcache.get().map_or(&[], |v| v.as_slice()))
    }

    /// alpm_db_get_group
    pub fn get_group(&self, name: &str) -> Result<Option<&Group>, Error> {
        self.handle.pm_errno.set(None);
        if name.is_empty() {
            return self.handle.err(Error::WrongArgs);
        }
        Ok(self.get_groupcache()?.iter().find(|g| g.name == name))
    }

    /// The packages of a group (`Group::packages` are indices into the package cache).
    pub fn group_packages(&self, g: &Group) -> Vec<&Pkg> {
        let cache = self.pkgcache.get().map_or(&[][..], |v| v.as_slice());
        g.packages.iter().filter_map(|&i| cache.get(i)).collect()
    }

    /// alpm_db_search / _alpm_db_search: each needle narrows the previous result (AND semantics).
    /// `Err(InvalidRegex)` for a bad expression. Databases without the SEARCH usage return nothing.
    pub fn search(&self, needles: &[String]) -> Result<Vec<&Pkg>, Error> {
        self.handle.pm_errno.set(None);
        if self.usage.get() & crate::consts::DB_USAGE_SEARCH == 0 {
            return Ok(Vec::new());
        }
        let mut list: Vec<&Pkg> = self
            .get_pkgcache()
            .map_err(|_| Error::DbInvalid)
            .unwrap_or(&[])
            .iter()
            .collect();
        let mut ret: Vec<&Pkg> = Vec::new();
        for targ in needles {
            ret = Vec::new();
            alpm_log!(self.handle, LOG_DEBUG, "searching for target '{}'\n", targ);
            let Some(reg) = crate::regex::Regex::new_ere_icase(targ) else {
                return self.handle.err(Error::InvalidRegex);
            };
            for pkg in &list {
                let name = pkg.name.as_str();
                let desc = pkg.desc().desc.as_deref();
                // check name as regex AND as plain text
                let mut matched: Option<&str> = None;
                if reg.is_match(name) || name.contains(targ.as_str()) {
                    matched = Some(name);
                } else if desc.is_some_and(|d| reg.is_match(d)) {
                    matched = desc;
                }
                if matched.is_none() {
                    matched = pkg
                        .desc()
                        .provides
                        .iter()
                        .find(|p| reg.is_match(&p.name))
                        .map(|p| p.name.as_str());
                }
                if matched.is_none() {
                    matched = pkg
                        .desc()
                        .groups
                        .iter()
                        .find(|g| reg.is_match(g))
                        .map(|g| g.as_str());
                }
                if let Some(m) = matched {
                    alpm_log!(
                        self.handle,
                        LOG_DEBUG,
                        "search target '{}' matched '{}' on package '{}'\n",
                        targ,
                        m,
                        name
                    );
                    ret.push(pkg);
                }
            }
            list = ret.clone();
        }
        Ok(ret)
    }
}
