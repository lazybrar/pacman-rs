//! Port of the parts of src/pacman/callback.c and src/pacman/conf.c the download code needs: cb_log with the
//! output queue held back while downloading, the retrieve events, cb_download (no progress bars yet) and the
//! XferCommand fetch callback.
//! shortcut: progress bars, the total bar and the multibar UI (callback.c) arrive with T16; only the plain
//! " <name> downloading..." line of the no-progress-bar mode is printed.
use crate::pm_printf;
use crate::util::{LOG_DEBUG, LOG_ERROR, LOG_WARNING, flush_stdout, pm_sprintf};
use libalpm_rs::handle::{DownloadEvent, Event, Handle};
use std::cell::{Cell, RefCell};
use std::os::unix::process::{CommandExt, ExitStatusExt};

thread_local! {
    /// on_progress: queue log lines while a download is running
    static ON_PROGRESS: Cell<bool> = const { Cell::new(false) };
    static OUTPUT: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// cb_log
pub fn cb_log(level: u32, msg: &str) {
    if msg.is_empty() {
        return;
    }
    if ON_PROGRESS.get() {
        if let Some(s) = pm_sprintf(level, format_args!("{msg}")) {
            OUTPUT.with_borrow_mut(|o| o.push(s));
        }
    } else {
        pm_printf!(level, "{msg}");
    }
}

/// flush_output_list
fn flush_output_list() {
    flush_stdout();
    OUTPUT.with_borrow_mut(|o| {
        for s in o.drain(..) {
            eprint!("{s}");
        }
    });
}

/// cb_event for the events of the download code. `colon`/`nocolor` are the title colour strings.
pub fn cb_event(e: &Event, colon: &str, nocolor: &str) {
    match e {
        Event::DbRetrieveStart => ON_PROGRESS.set(true),
        Event::PkgRetrieveStart { .. } => {
            crate::pr!("{colon}Retrieving packages...\n{nocolor}");
            flush_stdout();
            ON_PROGRESS.set(true);
        }
        Event::DbRetrieveDone
        | Event::DbRetrieveFailed
        | Event::PkgRetrieveDone
        | Event::PkgRetrieveFailed => {
            flush_output_list();
            ON_PROGRESS.set(false);
        }
        Event::DatabaseMissing { .. } => {}
    }
}

/// clean_filename: strip package or DB extension for a cleaner look
fn clean_filename(filename: &str) -> &str {
    [".pkg", ".db", ".files"]
        .iter()
        .find_map(|e| filename.find(e))
        .map_or(filename, |p| &filename[..p])
}

/// cb_download
pub fn cb_download(filename: &str, ev: &DownloadEvent) {
    // do not print signature files progress bar
    if filename.ends_with(".sig") {
        return;
    }
    if let DownloadEvent::Init { .. } = ev {
        crate::pr!(" {} downloading...\n", clean_filename(filename));
    }
}

/// arg_to_string
fn arg_to_string(argv: &[String]) -> String {
    argv.join(" ")
}

struct HandlePtr(*const Handle);
// SAFETY: only dereferenced in the forked child, which has its own copy of the single-threaded process
unsafe impl Send for HandlePtr {}
// SAFETY: as above
unsafe impl Sync for HandlePtr {}
impl HandlePtr {
    fn get(&self) -> *const Handle {
        self.0
    }
}

/// systemvp: fork/exec `argv` with SIGINT/SIGQUIT ignored in the parent; the raw wait status, or None when
/// the fork/exec failed
fn systemvp(
    argv: &[String],
    sandboxuser: Option<&str>,
    handle: &std::rc::Rc<Handle>,
) -> Option<i32> {
    // SAFETY: signal state is saved and restored around the child
    let (mut oldint, mut oldquit, mut oldblock): (
        libc::sigaction,
        libc::sigaction,
        libc::sigset_t,
    ) = unsafe { std::mem::zeroed() };
    // SAFETY: as above
    unsafe {
        let mut sa_ign: libc::sigaction = std::mem::zeroed();
        sa_ign.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut sa_ign.sa_mask);
        libc::sigaction(libc::SIGINT, &sa_ign, &mut oldint);
        libc::sigaction(libc::SIGQUIT, &sa_ign, &mut oldquit);
        libc::sigaddset(&mut sa_ign.sa_mask, libc::SIGCHLD);
        libc::sigprocmask(libc::SIG_BLOCK, &sa_ign.sa_mask, &mut oldblock);
    }
    let user = sandboxuser.map(str::to_string);
    // the closure runs in the forked child of this single-threaded process
    let h = HandlePtr(std::rc::Rc::as_ptr(handle));
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    // SAFETY: runs in the forked child before exec; only signal/credential syscalls and an error message
    unsafe {
        cmd.pre_exec(move || {
            // restore signal handling for the child to inherit
            libc::sigaction(libc::SIGINT, &oldint, std::ptr::null_mut());
            libc::sigaction(libc::SIGQUIT, &oldquit, std::ptr::null_mut());
            libc::sigprocmask(libc::SIG_SETMASK, &oldblock, std::ptr::null_mut());
            if let Some(u) = &user {
                let ret = libalpm_rs::sandbox::sandbox_setup_child(&*h.get(), u, None, false);
                if ret != 0 {
                    pm_printf!(LOG_ERROR, "switching to sandbox user '{}' failed!\n", u);
                    libc::_exit(ret);
                }
            }
            Ok(())
        });
    }
    let ret = match cmd.spawn() {
        Ok(mut child) => loop {
            match child.wait() {
                Ok(st) => break Some(st.into_raw()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break None,
            }
        },
        Err(_) => None,
    };
    // SAFETY: restoring the saved state
    unsafe {
        libc::sigaction(libc::SIGINT, &oldint, std::ptr::null_mut());
        libc::sigaction(libc::SIGQUIT, &oldquit, std::ptr::null_mut());
        libc::sigprocmask(libc::SIG_SETMASK, &oldblock, std::ptr::null_mut());
    }
    ret
}

/// download_with_xfercommand: the external fetch callback. 0 on success, -1 on error.
pub fn download_with_xfercommand(
    xfercommand_argv: &[String],
    sandboxuser: Option<&str>,
    handle: &std::rc::Rc<Handle>,
    url: &str,
    localpath: &str,
    force: bool,
) -> i32 {
    if xfercommand_argv.is_empty() {
        return -1;
    }
    let Some(slash) = url.rfind('/') else {
        return -1;
    };
    let filename = &url[slash + 1..];
    let destfile = format!("{localpath}{filename}");
    let tempfile = format!("{localpath}{filename}.part");
    if force && std::fs::metadata(&tempfile).is_ok() {
        let _ = std::fs::remove_file(&tempfile);
    }
    if force && std::fs::metadata(&destfile).is_ok() {
        let _ = std::fs::remove_file(&destfile);
    }
    let mut usepart = false;
    let argv: Vec<String> = xfercommand_argv
        .iter()
        .map(|v| {
            if v == "%o" {
                usepart = true;
                tempfile.clone()
            } else if v == "%u" {
                url.to_string()
            } else {
                v.clone()
            }
        })
        .collect();

    // save the cwd so we can restore it later
    let cwd = std::env::current_dir().ok();
    if cwd.is_none() {
        pm_printf!(LOG_ERROR, "could not get current working directory\n");
    }
    let mut ret;
    // cwd to the download directory
    if std::env::set_current_dir(localpath).is_err() {
        pm_printf!(
            LOG_WARNING,
            "could not chdir to download directory {}\n",
            localpath
        );
        ret = -1;
    } else {
        if crate::util::LOGMASK.load(std::sync::atomic::Ordering::Relaxed) & LOG_DEBUG != 0 {
            pm_printf!(LOG_DEBUG, "running command: {}\n", arg_to_string(&argv));
        }
        match systemvp(&argv, sandboxuser, handle) {
            None => {
                pm_printf!(LOG_WARNING, "running XferCommand: fork failed!\n");
                ret = -1;
            }
            Some(st) if st != 0 => {
                // download failed
                pm_printf!(
                    LOG_DEBUG,
                    "XferCommand command returned non-zero status code ({})\n",
                    st
                );
                ret = -1;
            }
            Some(_) => {
                // download was successful
                ret = 0;
                if usepart && let Err(e) = std::fs::rename(&tempfile, &destfile) {
                    pm_printf!(
                        LOG_ERROR,
                        "could not rename {} to {} ({})\n",
                        tempfile,
                        destfile,
                        crate::util_common::strerror(&e)
                    );
                    ret = -1;
                }
            }
        }
    }
    // restore the old cwd if we have it
    if let Some(c) = cwd
        && let Err(e) = std::env::set_current_dir(c)
    {
        pm_printf!(
            LOG_ERROR,
            "could not restore working directory ({})\n",
            crate::util_common::strerror(&e)
        );
    }
    if ret == -1 {
        // hack to let an user the time to cancel a download
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    ret
}
