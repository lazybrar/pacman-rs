//! Port of the parts of lib/libalpm/handle.c that the database code needs (paths, log callback, pm_errno).
use crate::error::Error;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

pub type LogCb = Box<dyn Fn(u32, &str)>;

pub struct Handle {
    /// base path to the DBs, always ends with '/'
    pub dbpath: String,
    /// sync DB extension
    pub dbext: String,
    pub logcb: RefCell<Option<LogCb>>,
    /// None is ALPM_ERR_OK
    pub pm_errno: Cell<Option<Error>>,
}

impl Handle {
    /// _alpm_handle_new + alpm_option_set_dbpath (trailing slash added like _alpm_set_directory_option).
    pub fn new(dbpath: &str) -> Rc<Handle> {
        let mut p = dbpath.to_string();
        if !p.ends_with('/') {
            p.push('/');
        }
        Rc::new(Handle {
            dbpath: p,
            dbext: ".db".into(),
            logcb: RefCell::new(None),
            pm_errno: Cell::new(None),
        })
    }

    /// _alpm_log
    pub fn log(&self, level: u32, args: std::fmt::Arguments) {
        if let Some(cb) = self.logcb.borrow().as_ref() {
            cb(level, &args.to_string());
        }
    }

    /// RET_ERR helper: record pm_errno and return it as the Err value.
    pub fn err<T>(&self, e: Error) -> Result<T, Error> {
        self.pm_errno.set(Some(e));
        Err(e)
    }

    /// alpm_errno
    pub fn errno(&self) -> Option<Error> {
        self.pm_errno.get()
    }
}
