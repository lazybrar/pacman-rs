//! Port of lib/libalpm/sandbox.c: the download sandbox (user switch, Landlock, seccomp) and the pipe
//! protocol that carries log and download callbacks from the sandboxed child to the parent.
//! The wire layout is the one of the C structs on this platform (native endianness, enum = 4 bytes,
//! off_t/size_t = 8 bytes, structs padded as C does).
use crate::handle::{DownloadEvent, Handle};

/// _alpm_sandbox_callback_t
pub const SANDBOX_CB_LOG: i32 = 0;
pub const SANDBOX_CB_DOWNLOAD: i32 = 1;

/// _alpm_use_sandbox
pub use crate::util::use_sandbox;

/// alpm_sandbox_setup_child: restrict writes to `sandbox_path`, set no_new_privs, filter syscalls and drop to
/// `sandboxuser`. 0 on success, -1 on error.
pub fn sandbox_setup_child(
    handle: &Handle,
    sandboxuser: &str,
    sandbox_path: Option<&str>,
    restrict_syscalls: bool,
) -> i32 {
    // SAFETY: getuid cannot fail
    if unsafe { libc::getuid() } != 0 {
        return -1;
    }
    let Ok(c) = std::ffi::CString::new(sandboxuser) else {
        return -1;
    };
    // SAFETY: valid C string; the passwd fields are read immediately
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        return -1;
    }
    // SAFETY: pw is non-null
    let (uid, gid) = unsafe { ((*pw).pw_uid, (*pw).pw_gid) };
    let (fs_off, sys_off) = {
        let o = handle.opts.borrow();
        (o.disable_sandbox_filesystem, o.disable_sandbox_syscalls)
    };
    if let Some(p) = sandbox_path
        && !fs_off
        && !crate::sandbox_fs::restrict_writes_to(handle, p)
    {
        return -1;
    }
    // make sure that we cannot gain more privileges later, failure is fine
    // SAFETY: prctl with constant arguments
    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if restrict_syscalls && !sys_off && !crate::sandbox_syscalls::syscalls_filter(handle) {
        return -1;
    }
    // SAFETY: plain credential syscalls
    unsafe {
        if libc::setgid(gid) != 0 {
            return -1;
        }
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return -1;
        }
        if libc::setuid(uid) != 0 {
            return -1;
        }
    }
    0
}

/// read_from_pipe: 0 on success, -1 on error or unexpected EOF
fn read_from_pipe(fd: i32, buf: &mut [u8]) -> i32 {
    let mut n = 0;
    while n < buf.len() {
        // SAFETY: the pointer/length pair is inside buf
        let r = unsafe { libc::read(fd, buf[n..].as_mut_ptr().cast(), buf.len() - n) };
        if r < 0 {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return -1;
            }
            continue;
        }
        if r == 0 {
            // we hit EOF unexpectedly - bail
            return -1;
        }
        n += r as usize;
    }
    0
}

/// write_to_pipe
fn write_to_pipe(fd: i32, buf: &[u8]) {
    let mut n = 0;
    while n < buf.len() {
        // SAFETY: the pointer/length pair is inside buf
        let r = unsafe { libc::write(fd, buf[n..].as_ptr().cast(), buf.len() - n) };
        if r < 0 {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return;
            }
            continue;
        }
        n += r as usize;
    }
}

/// _alpm_sandbox_cb_log: the child's log callback
pub fn sandbox_cb_log(pipe: i32, level: u32, msg: &str) {
    if pipe == -1 || msg.is_empty() {
        return;
    }
    write_to_pipe(pipe, &SANDBOX_CB_LOG.to_ne_bytes());
    write_to_pipe(pipe, &level.to_ne_bytes());
    write_to_pipe(pipe, &(msg.len() as i32).to_ne_bytes());
    write_to_pipe(pipe, msg.as_bytes());
}

/// _alpm_sandbox_cb_dl: the child's download callback
pub fn sandbox_cb_dl(pipe: i32, filename: &str, ev: &DownloadEvent) {
    if pipe == -1 {
        return;
    }
    write_to_pipe(pipe, &SANDBOX_CB_DOWNLOAD.to_ne_bytes());
    match *ev {
        DownloadEvent::Init { optional } => {
            write_to_pipe(pipe, &0i32.to_ne_bytes());
            write_to_pipe(pipe, &(optional as i32).to_ne_bytes());
        }
        DownloadEvent::Progress { downloaded, total } => {
            write_to_pipe(pipe, &1i32.to_ne_bytes());
            write_to_pipe(pipe, &downloaded.to_ne_bytes());
            write_to_pipe(pipe, &total.to_ne_bytes());
        }
        DownloadEvent::Retry { resume } => {
            write_to_pipe(pipe, &2i32.to_ne_bytes());
            write_to_pipe(pipe, &(resume as i32).to_ne_bytes());
        }
        DownloadEvent::Completed { total, result } => {
            write_to_pipe(pipe, &3i32.to_ne_bytes());
            write_to_pipe(pipe, &total.to_ne_bytes());
            write_to_pipe(pipe, &result.to_ne_bytes());
            write_to_pipe(pipe, &[0u8; 4]); // struct padding
        }
    }
    write_to_pipe(pipe, &filename.len().to_ne_bytes());
    write_to_pipe(pipe, filename.as_bytes());
}

fn read_i32(fd: i32) -> Option<i32> {
    let mut b = [0u8; 4];
    (read_from_pipe(fd, &mut b) != -1).then(|| i32::from_ne_bytes(b))
}

fn read_i64(fd: i32) -> Option<i64> {
    let mut b = [0u8; 8];
    (read_from_pipe(fd, &mut b) != -1).then(|| i64::from_ne_bytes(b))
}

/// _alpm_sandbox_process_cb_log: false on a protocol error
pub fn sandbox_process_cb_log(handle: &Handle, fd: i32) -> bool {
    let Some(level) = read_i32(fd) else {
        return false;
    };
    let Some(size) = read_i32(fd) else {
        return false;
    };
    if size <= 0 {
        return false;
    }
    let mut buf = vec![0u8; size as usize];
    if read_from_pipe(fd, &mut buf) == -1 {
        return false;
    }
    handle.log(
        level as u32,
        format_args!("{}", String::from_utf8_lossy(&buf)),
    );
    true
}

/// _alpm_sandbox_process_cb_download: false on a protocol error
pub fn sandbox_process_cb_download(handle: &Handle, fd: i32) -> bool {
    let Some(ty) = read_i32(fd) else {
        return false;
    };
    let ev = match ty {
        0 => {
            let Some(o) = read_i32(fd) else { return false };
            DownloadEvent::Init { optional: o != 0 }
        }
        1 => {
            let (Some(d), Some(t)) = (read_i64(fd), read_i64(fd)) else {
                return false;
            };
            DownloadEvent::Progress {
                downloaded: d,
                total: t,
            }
        }
        2 => {
            let Some(r) = read_i32(fd) else { return false };
            DownloadEvent::Retry { resume: r != 0 }
        }
        3 => {
            let Some(t) = read_i64(fd) else { return false };
            let Some(r) = read_i32(fd) else { return false };
            if read_i32(fd).is_none() {
                return false;
            }
            DownloadEvent::Completed {
                total: t,
                result: r,
            }
        }
        _ => return false,
    };
    let Some(len) = read_i64(fd) else {
        return false;
    };
    if len < 0 || len as usize >= libc::PATH_MAX as usize {
        return false;
    }
    let mut name = vec![0u8; len as usize];
    if len > 0 && read_from_pipe(fd, &mut name) == -1 {
        return false;
    }
    if let Some(cb) = handle.dlcb.borrow().as_ref() {
        cb(&String::from_utf8_lossy(&name), &ev);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// every callback written by the child's side is read back by the parent's side, in order
    #[test]
    fn pipe_roundtrip() {
        let mut fds = [0i32; 2];
        // SAFETY: pipe fills the two descriptors
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let h = Handle::new("/nonexistent");
        let logs: Rc<RefCell<Vec<(u32, String)>>> = Rc::default();
        let l2 = logs.clone();
        *h.logcb.borrow_mut() = Some(Box::new(move |lvl, m| {
            l2.borrow_mut().push((lvl, m.to_string()))
        }));
        let evs: Rc<RefCell<Vec<(String, DownloadEvent)>>> = Rc::default();
        let e2 = evs.clone();
        *h.dlcb.borrow_mut() = Some(Box::new(move |n, e| {
            e2.borrow_mut().push((n.to_string(), *e))
        }));

        let sent = [
            DownloadEvent::Init { optional: true },
            DownloadEvent::Progress {
                downloaded: 12345678901,
                total: 99999999999,
            },
            DownloadEvent::Retry { resume: true },
            DownloadEvent::Completed {
                total: 42,
                result: -1,
            },
        ];
        sandbox_cb_log(fds[1], 2, "warning text\n");
        for e in &sent {
            sandbox_cb_dl(fds[1], "core.db", e);
        }
        sandbox_cb_log(fds[1], 1, "second\n");
        // SAFETY: closing our write end so that reads hit EOF at the end
        unsafe { libc::close(fds[1]) };
        let mut kinds = Vec::new();
        loop {
            let mut b = [0u8; 4];
            // SAFETY: reading into a local buffer
            if unsafe { libc::read(fds[0], b.as_mut_ptr().cast(), 4) } != 4 {
                break;
            }
            let t = i32::from_ne_bytes(b);
            kinds.push(t);
            let ok = if t == SANDBOX_CB_LOG {
                sandbox_process_cb_log(&h, fds[0])
            } else {
                sandbox_process_cb_download(&h, fds[0])
            };
            assert!(ok);
        }
        assert_eq!(kinds, [0, 1, 1, 1, 1, 0]);
        assert_eq!(
            *logs.borrow(),
            [
                (2, "warning text\n".to_string()),
                (1, "second\n".to_string())
            ]
        );
        let got: Vec<DownloadEvent> = evs.borrow().iter().map(|(_, e)| *e).collect();
        assert_eq!(got, sent);
        assert!(evs.borrow().iter().all(|(n, _)| n == "core.db"));
        // a truncated stream is a protocol error, not a hang
        // SAFETY: closing our read end
        unsafe { libc::close(fds[0]) };
    }

    /// an unknown event type or an empty log message is rejected
    #[test]
    fn protocol_errors() {
        let mut fds = [0i32; 2];
        // SAFETY: pipe fills the two descriptors
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let h = Handle::new("/nonexistent");
        write_to_pipe(fds[1], &7i32.to_ne_bytes());
        assert!(!sandbox_process_cb_download(&h, fds[0]));
        write_to_pipe(fds[1], &2i32.to_ne_bytes());
        write_to_pipe(fds[1], &0i32.to_ne_bytes());
        assert!(!sandbox_process_cb_log(&h, fds[0]));
        // SAFETY: closing both ends
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
