//! Port of lib/libalpm/alpm.c plus the registration functions of db.c: initialisation of a handle with
//! its local database, and the list of registered sync databases.
use crate::alpm_log;
use crate::be_local::db_register_local;
use crate::be_sync::db_register_sync;
use crate::db::Db;
use crate::error::Error;
use crate::handle::{Handle, SYSHOOKDIR, set_directory_option};
use crate::log::LOG_DEBUG;
use std::rc::Rc;

/// LIB_VERSION
pub const LIB_VERSION: &str = "16.0.1";

pub struct Alpm {
    pub handle: Rc<Handle>,
    /// handle->db_local
    pub localdb: Db,
    /// handle->dbs_sync, in registration order
    pub syncdbs: Vec<Db>,
}

/// alpm_initialize
pub fn alpm_initialize(root: &str, dbpath: &str) -> Result<Alpm, Error> {
    let root = set_directory_option(root, true)?;
    let dbpath = set_directory_option(dbpath, true)?;
    let handle = Handle::new(&dbpath);
    {
        let mut o = handle.opts.borrow_mut();
        // to concatenate root (ends with a slash) with SYSHOOKDIR (starts with a slash), skip SYSHOOKDIR[0]
        o.hookdirs = vec![format!("{}{}", root, &SYSHOOKDIR[1..])];
        o.lockfile = format!("{}db.lck", handle.dbpath);
        o.root = root;
    }
    let localdb = db_register_local(&handle)?;
    Ok(Alpm {
        handle,
        localdb,
        syncdbs: Vec::new(),
    })
}

impl Alpm {
    /// alpm_pkg_get_db: the sync database of a sync package
    pub fn pkg_db(&self, pkg: &crate::package::Pkg) -> Option<&Db> {
        if pkg.origin != crate::package::PkgFrom::SyncDb {
            return None;
        }
        self.syncdbs
            .iter()
            .find(|d| Some(&d.treename) == pkg.dbname.as_ref())
    }

    /// alpm_register_syncdb
    pub fn register_syncdb(&mut self, treename: &str, siglevel: i32) -> Result<&Db, Error> {
        if treename.is_empty() || treename.contains('/') {
            return self.handle.err(Error::WrongArgs);
        }
        // ensure database name is unique
        if treename == "local" || self.syncdbs.iter().any(|d| d.treename == treename) {
            return self.handle.err(Error::DbNotNull);
        }
        alpm_log!(
            self.handle,
            LOG_DEBUG,
            "registering sync database '{}'\n",
            treename
        );
        self.syncdbs
            .push(db_register_sync(&self.handle, treename, siglevel));
        Ok(self.syncdbs.last().unwrap())
    }
}
