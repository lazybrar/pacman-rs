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
    DbRetrieveStart,
    DbRetrieveDone,
    DbRetrieveFailed,
    PkgRetrieveStart { num: usize, total_size: i64 },
    PkgRetrieveDone,
    PkgRetrieveFailed,
    ResolveDepsStart,
    ResolveDepsDone,
    InterConflictsStart,
    InterConflictsDone,
    IntegrityStart,
    IntegrityDone,
    KeyringStart,
    KeyringDone,
    KeyDownloadStart,
    KeyDownloadDone,
    LoadStart,
    LoadDone,
}

pub type EventCb = Box<dyn Fn(&Event)>;

/// alpm_download_event_*_t (the event type plus its payload)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadEvent {
    /// whether this file is optional and thus the errors could be ignored
    Init {
        optional: bool,
    },
    Progress {
        downloaded: i64,
        total: i64,
    },
    /// whether the download will resume or start over
    Retry {
        resume: bool,
    },
    /// result: 0 completed, 1 up-to-date, -1 error
    Completed {
        total: i64,
        result: i32,
    },
}

/// alpm_cb_download
pub type DlCb = Box<dyn Fn(&str, &DownloadEvent)>;
/// alpm_cb_fetch: (url, localpath, force) -> 0 ok, 1 identical, -1 error
pub type FetchCb = Box<dyn Fn(&str, &str, bool) -> i32>;

/// alpm_question_t (the questions raised so far); the callback fills in the answer field.
pub enum Question<'a> {
    /// alpm_question_install_ignorepkg_t
    InstallIgnorepkg {
        install: bool,
        pkg: &'a crate::package::Pkg,
    },
    /// alpm_question_import_key_t
    ImportKey {
        import: bool,
        uid: Option<&'a str>,
        fingerprint: &'a str,
    },
    /// alpm_question_select_provider_t
    SelectProvider {
        use_index: i32,
        providers: Vec<&'a crate::package::Pkg>,
        depend: &'a Dep,
    },
    /// alpm_question_replace_t
    Replace {
        replace: bool,
        oldpkg: &'a crate::package::Pkg,
        newpkg: &'a crate::package::Pkg,
        newdb: &'a crate::db::Db,
    },
    /// alpm_question_conflict_t
    Conflict {
        remove: bool,
        conflict: &'a crate::conflict::Conflict<'a>,
    },
    /// alpm_question_remove_pkgs_t
    RemovePkgs {
        skip: bool,
        packages: Vec<&'a crate::package::Pkg>,
    },
    /// alpm_question_corrupted_t
    Corrupted {
        remove: bool,
        filepath: &'a str,
        reason: Error,
    },
}

/// alpm_progress_t (the values raised so far)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    IntegrityStart,
    LoadStart,
    KeyringStart,
}

/// alpm_cb_progress: (what, pkgname, percent, howmany, current)
pub type ProgressCb = Box<dyn Fn(Progress, &str, i32, usize, usize)>;

/// alpm_trans_t state (STATE_IDLE is "no transaction")
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransState {
    Initialized,
    Prepared,
    Downloading,
    Committing,
    Committed,
    Interrupted,
}

/// the flags and state of handle->trans (the package lists live in `trans::Trans`)
#[derive(Debug, Clone, Copy)]
pub struct TransHdr {
    pub flags: i32,
    pub state: TransState,
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
    pub progresscb: RefCell<Option<ProgressCb>>,
    /// handle->trans (None is no transaction)
    pub trans: Cell<Option<TransHdr>>,
    pub dlcb: RefCell<Option<DlCb>>,
    pub fetchcb: RefCell<Option<FetchCb>>,
    /// handle->server_errors: errors per host (-1 is a hard error)
    pub server_errors: RefCell<Vec<(String, i32)>>,
    /// handle->logstream
    pub logstream: RefCell<Option<std::fs::File>>,
    /// handle->lockfd
    pub lockfd: RefCell<Option<std::fs::File>>,
    /// handle->known_keys: fingerprints already found in the keyring
    pub known_keys: RefCell<Vec<String>>,
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
            progresscb: RefCell::new(None),
            trans: Cell::new(None),
            dlcb: RefCell::new(None),
            fetchcb: RefCell::new(None),
            server_errors: RefCell::new(Vec::new()),
            logstream: RefCell::new(None),
            lockfd: RefCell::new(None),
            known_keys: RefCell::new(Vec::new()),
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

    /// alpm_logaction: append "[ISO time] [prefix] message" to the log file (the stream is opened on first use).
    /// shortcut: syslog is not supported.
    pub fn logaction(&self, prefix: &str, args: std::fmt::Arguments) -> i32 {
        let prefix = if prefix.is_empty() { "UNKNOWN" } else { prefix };
        let mut ret = 0;
        if self.logstream.borrow().is_none()
            && let Some(path) = self.logfile()
        {
            use std::os::unix::fs::OpenOptionsExt;
            match std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o644)
                .custom_flags(libc::O_CLOEXEC)
                .open(&path)
            {
                Ok(f) => *self.logstream.borrow_mut() = Some(f),
                Err(e) => {
                    self.pm_errno.set(Some(match e.raw_os_error() {
                        Some(libc::EACCES) => Error::Badperms,
                        Some(libc::ENOENT) => Error::NotADir,
                        _ => Error::System,
                    }));
                    ret = -1;
                }
            }
        }
        if let Some(f) = self.logstream.borrow_mut().as_mut() {
            use std::io::Write;
            // SAFETY: localtime_r/strftime on local buffers
            let ts = unsafe {
                let t = libc::time(std::ptr::null_mut());
                let mut tm: libc::tm = std::mem::zeroed();
                libc::localtime_r(&t, &mut tm);
                let mut buf = [0u8; 32];
                let n = libc::strftime(buf.as_mut_ptr().cast(), 32, c"%FT%T%z".as_ptr(), &tm);
                String::from_utf8_lossy(&buf[..n]).into_owned()
            };
            if write!(f, "[{ts}] [{prefix}] {args}").is_err() {
                ret = -1;
                self.pm_errno.set(Some(Error::System));
            }
            let _ = f.flush();
        }
        ret
    }

    /// _alpm_handle_lock: 0 on success, -1 on error
    pub fn lock(&self) -> i32 {
        if self.lockfd.borrow().is_some() {
            return 0;
        }
        let lockfile = self.lockfile();
        // create the dir of the lockfile first
        let dir = lockfile
            .rfind('/')
            .map_or(lockfile.as_str(), |p| &lockfile[..p]);
        if crate::util::makepath(dir) != 0 {
            return -1;
        }
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o000)
            .custom_flags(libc::O_CLOEXEC)
            .open(&lockfile)
        {
            Ok(f) => {
                *self.lockfd.borrow_mut() = Some(f);
                0
            }
            Err(_) => -1,
        }
    }

    /// alpm_unlock: 0 on success, -1 on error (pm_errno set when the lock file cannot be removed)
    pub fn alpm_unlock(&self) -> i32 {
        let lockfile = self.lockfile();
        if lockfile.is_empty() || self.lockfd.borrow().is_none() {
            return 0;
        }
        *self.lockfd.borrow_mut() = None;
        if std::fs::remove_file(&lockfile).is_err() {
            self.pm_errno.set(Some(Error::System));
            -1
        } else {
            0
        }
    }

    /// _alpm_handle_unlock
    pub fn unlock(&self) -> i32 {
        let lockfile = self.lockfile();
        if self.alpm_unlock() != 0 {
            let missing = !std::path::Path::new(&lockfile).exists();
            if missing {
                alpm_log!(self, LOG_WARNING, "lock file missing {}\n", lockfile);
                self.logaction(
                    "ALPM",
                    format_args!("warning: lock file missing {}\n", lockfile),
                );
                return 0;
            }
            alpm_log!(
                self,
                LOG_WARNING,
                "could not remove lock file {}\n",
                lockfile
            );
            return -1;
        }
        0
    }

    /// PROGRESS
    pub fn progress(&self, what: Progress, pkgname: &str, percent: i32, howmany: usize, current: usize) {
        if let Some(cb) = self.progresscb.borrow().as_ref() {
            cb(what, pkgname, percent, howmany, current);
        }
    }

    /// handle->trans->flags (0 without a transaction)
    pub fn trans_flags(&self) -> i32 {
        self.trans.get().map_or(0, |t| t.flags)
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
        // close the stream so logaction will reopen a new stream on the new logfile
        *self.logstream.borrow_mut() = None;
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
