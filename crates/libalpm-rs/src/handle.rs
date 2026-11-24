//! Port of lib/libalpm/handle.c: the handle with its options, log/event callbacks, pm_errno and lock file.
//! Callbacks other than log and event (download, question, progress, fetch) arrive with their consumers.
use crate::alpm_log;
use crate::deps::{Dep, DepMod};
use crate::error::Error;
use crate::log::*;
use crate::util::hash_sdbm;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

pub type LogCb = Box<dyn Fn(u32, &str)>;

/// alpm_event_t (the events raised so far)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    DatabaseMissing { dbname: String },
}

pub type EventCb = Box<dyn Fn(&Event)>;

/// alpm_question_t (the questions raised so far); the callback fills in the answer field.
pub enum Question<'a> {
    /// alpm_question_install_ignorepkg_t
    InstallIgnorepkg {
        install: bool,
        pkg: &'a crate::package::Pkg,
    },
    /// alpm_question_select_provider_t
    SelectProvider {
        use_index: i32,
        providers: Vec<&'a crate::package::Pkg>,
        depend: &'a Dep,
    },
}

pub type QuestionCb = Box<dyn for<'a> Fn(&mut Question<'a>)>;

/// SYSHOOKDIR (DATAROOTDIR/libalpm/hooks/)
pub const SYSHOOKDIR: &str = "/usr/share/libalpm/hooks/";

/// Options settable through alpm_option_set_* (handle fields upstream).
#[derive(Default)]
pub struct Options {
    pub root: String,
    pub lockfile: String,
    pub logfile: Option<String>,
    pub gpgdir: Option<String>,
    pub sandboxuser: Option<String>,
    pub hookdirs: Vec<String>,
    pub cachedirs: Vec<String>,
    pub architectures: Vec<String>,
    pub noupgrade: Vec<String>,
    pub noextract: Vec<String>,
    pub ignorepkg: Vec<String>,
    pub ignoregroup: Vec<String>,
    pub overwrite_files: Vec<String>,
    pub assumeinstalled: Vec<Dep>,
    pub checkspace: bool,
    pub usesyslog: bool,
    pub disable_dl_timeout: bool,
    pub disable_sandbox_filesystem: bool,
    pub disable_sandbox_syscalls: bool,
    pub parallel_downloads: u32,
    pub siglevel: i32,
    pub local_file_siglevel: i32,
    pub remote_file_siglevel: i32,
}

pub struct Handle {
    /// base path to the DBs, always ends with '/'
    pub dbpath: String,
    /// sync DB extension
    pub dbext: RefCell<String>,
    pub logcb: RefCell<Option<LogCb>>,
    pub eventcb: RefCell<Option<EventCb>>,
    pub questioncb: RefCell<Option<QuestionCb>>,
    /// handle->trans->flags & ALPM_TRANS_FLAG_NODEPVERSION (no transaction is false)
    pub no_dep_version: Cell<bool>,
    /// None is ALPM_ERR_OK
    pub pm_errno: Cell<Option<Error>>,
    pub opts: RefCell<Options>,
    /// getuid() at initialisation
    pub user: u32,
}

/// canonicalize_path: make sure the path ends in '/'
fn canonicalize_path(path: &str) -> String {
    if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{path}/")
    }
}

/// _alpm_set_directory_option
pub fn set_directory_option(value: &str, must_exist: bool) -> Result<String, Error> {
    let mut path = value.to_string();
    if must_exist {
        match std::fs::metadata(value) {
            Ok(m) if m.is_dir() => {}
            _ => return Err(Error::NotADir),
        }
        match std::fs::canonicalize(value) {
            Ok(p) => path = p.to_string_lossy().into_owned(),
            Err(_) => return Err(Error::NotADir),
        }
    }
    Ok(canonicalize_path(&path))
}

impl Handle {
    /// _alpm_handle_new + alpm_option_set_dbpath (trailing slash added like _alpm_set_directory_option).
    pub fn new(dbpath: &str) -> Rc<Handle> {
        Self::with_dbext(dbpath, ".db")
    }

    /// Same, with the sync DB extension chosen (".files" for file lists).
    pub fn with_dbext(dbpath: &str, dbext: &str) -> Rc<Handle> {
        Rc::new(Handle {
            dbpath: canonicalize_path(dbpath),
            dbext: RefCell::new(dbext.into()),
            logcb: RefCell::new(None),
            eventcb: RefCell::new(None),
            questioncb: RefCell::new(None),
            no_dep_version: Cell::new(false),
            pm_errno: Cell::new(None),
            opts: RefCell::new(Options {
                parallel_downloads: 1,
                ..Default::default()
            }),
            // SAFETY: getuid cannot fail
            user: unsafe { libc::getuid() },
        })
    }

    /// _alpm_log
    pub fn log(&self, level: u32, args: std::fmt::Arguments) {
        if let Some(cb) = self.logcb.borrow().as_ref() {
            cb(level, &args.to_string());
        }
    }

    /// EVENT
    pub fn event(&self, e: &Event) {
        if let Some(cb) = self.eventcb.borrow().as_ref() {
            cb(e);
        }
    }

    /// QUESTION
    pub fn question(&self, q: &mut Question) {
        if let Some(cb) = self.questioncb.borrow().as_ref() {
            cb(q);
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

    pub fn dbext(&self) -> String {
        self.dbext.borrow().clone()
    }

    /// alpm_option_set_dbext
    pub fn set_dbext(&self, dbext: &str) {
        *self.dbext.borrow_mut() = dbext.to_string();
        alpm_log!(self, LOG_DEBUG, "option 'dbext' = {}\n", dbext);
    }

    pub fn root(&self) -> String {
        self.opts.borrow().root.clone()
    }

    // --- option getters (alpm_option_get_*)
    pub fn lockfile(&self) -> String {
        self.opts.borrow().lockfile.clone()
    }
    pub fn logfile(&self) -> Option<String> {
        self.opts.borrow().logfile.clone()
    }
    pub fn gpgdir(&self) -> Option<String> {
        self.opts.borrow().gpgdir.clone()
    }
    pub fn cachedirs(&self) -> Vec<String> {
        self.opts.borrow().cachedirs.clone()
    }
    pub fn hookdirs(&self) -> Vec<String> {
        self.opts.borrow().hookdirs.clone()
    }

    // --- setters used by setup_libalpm

    /// alpm_option_set_logfile
    pub fn set_logfile(&self, logfile: &str) -> i32 {
        self.opts.borrow_mut().logfile = Some(logfile.to_string());
        alpm_log!(self, LOG_DEBUG, "option 'logfile' = {}\n", logfile);
        0
    }

    /// alpm_option_set_gpgdir
    pub fn set_gpgdir(&self, gpgdir: &str) -> i32 {
        match set_directory_option(gpgdir, false) {
            Ok(p) => {
                alpm_log!(self, LOG_DEBUG, "option 'gpgdir' = {}\n", p);
                self.opts.borrow_mut().gpgdir = Some(p);
                0
            }
            Err(e) => {
                self.pm_errno.set(Some(e));
                -1
            }
        }
    }

    /// alpm_option_add_hookdir
    pub fn add_hookdir(&self, hookdir: &str) -> i32 {
        match set_directory_option(hookdir, false) {
            Ok(p) => {
                alpm_log!(self, LOG_DEBUG, "option 'hookdir' = {}\n", p);
                self.opts.borrow_mut().hookdirs.push(p);
                0
            }
            Err(e) => {
                self.pm_errno.set(Some(e));
                -1
            }
        }
    }

    /// alpm_option_set_cachedirs: each entry gets a trailing '/'
    pub fn set_cachedirs(&self, dirs: &[String]) -> i32 {
        let mut v = Vec::new();
        for d in dirs {
            match set_directory_option(d, false) {
                Ok(p) => {
                    alpm_log!(self, LOG_DEBUG, "option 'cachedir' = {}\n", p);
                    v.push(p);
                }
                Err(e) => {
                    self.pm_errno.set(Some(e));
                    return -1;
                }
            }
        }
        self.opts.borrow_mut().cachedirs = v;
        0
    }

    /// alpm_option_add_assumeinstalled
    pub fn add_assumeinstalled(&self, dep: &Dep) -> i32 {
        if dep.depmod != DepMod::Eq && dep.depmod != DepMod::Any {
            self.pm_errno.set(Some(Error::WrongArgs));
            return -1;
        }
        let mut d = dep.clone();
        d.name_hash = hash_sdbm(&dep.name);
        self.opts.borrow_mut().assumeinstalled.push(d);
        0
    }

    /// alpm_option_match_noextract: 0 on a match, 1 on an inverted (`!`) match, -1 when nothing matches
    pub fn match_noextract(&self, path: &str) -> i32 {
        crate::util::fnmatch_patterns(&self.opts.borrow().noextract, path)
    }

    /// alpm_option_match_noupgrade
    pub fn match_noupgrade(&self, path: &str) -> i32 {
        crate::util::fnmatch_patterns(&self.opts.borrow().noupgrade, path)
    }
}
