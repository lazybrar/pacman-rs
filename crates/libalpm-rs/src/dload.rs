//! Port of lib/libalpm/dload.c: downloads through libcurl's multi interface (parallel downloads, server
//! failover, resume, If-Modified-Since, signature payloads), the sandboxed variant (fork + Landlock/seccomp
//! with callbacks over a pipe), the external fetch callback path and `alpm_fetch_pkgurl`.
//! Payloads are `Rc<RefCell<Payload>>`: curl's callbacks and the driver loop share them.
use crate::alpm_log;
use crate::error::Error;
use crate::handle::{DownloadEvent, Event, Handle};
use crate::log::{LOG_DEBUG, LOG_ERROR, LOG_WARNING};
use crate::sandbox::*;
use crate::util::{
    download_dir_setup, filecache_find, filecache_setup, remove_temporary_download_dir, strerror,
    use_sandbox,
};
use curl::easy::{Easy2, Handler, NetRc, TimeCondition, WriteError};
use curl::multi::{Easy2Handle, Multi};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::rc::Rc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

/// number of "soft" errors required to blacklist a server, set to 0 to disable server blacklisting
const SERVER_ERROR_LIMIT: i32 = 3;
/// enum { ABORT_OVER_MAXFILESIZE = 1 }
const ABORT_OVER_MAXFILESIZE: i32 = 1;
/// static int dload_interrupted (never reset upstream either)
static DLOAD_INTERRUPTED: AtomicI32 = AtomicI32::new(0);

/// struct dload_payload
#[derive(Default)]
pub struct Payload {
    /// name of the remote file
    pub remote_name: String,
    /// temporary file name, to which the payload is downloaded
    pub tempfile_name: Option<String>,
    /// name to which the downloaded file will be renamed
    pub destfile_name: Option<String>,
    /// either `fileurl`, or (`servers`, `filepath`): then "$server/$filepath" is tried per server
    pub fileurl: Option<String>,
    pub filepath: Option<String>,
    pub cache_servers: Vec<String>,
    pub servers: Vec<String>,
    pub(crate) cache_pos: usize,
    pub(crate) server_pos: usize,
    pub(crate) respcode: i64,
    /// the mtime of the existing version of this file, if there is one
    pub mtime_existing_file: i64,
    pub(crate) initial_size: i64,
    pub max_size: i64,
    pub(crate) prevprogress: i64,
    pub force: bool,
    pub allow_resume: bool,
    pub errors_ok: bool,
    pub unlink_on_fail: bool,
    /// download the accompanying *.sig file
    pub download_signature: bool,
    pub signature_optional: bool,
    pub(crate) error_buffer: String,
    /// this payload is for a signature file
    pub(crate) signature: bool,
    pub(crate) request_errors_ok: bool,
    /// tempfile_openmode == "ab"
    pub(crate) append: bool,
    /// temp download file
    pub localf: Option<File>,
}

pub type PayloadRef = Rc<RefCell<Payload>>;

/// new payload holder
pub fn payload_ref(p: Payload) -> PayloadRef {
    Rc::new(RefCell::new(p))
}

/// get_filename
fn get_filename(url: &str) -> &str {
    url.rfind('/').map_or(url, |p| &url[p + 1..])
}

/// mbasename
fn mbasename(path: &str) -> &str {
    path.rfind('/').map_or(path, |p| &path[p + 1..])
}

/// _getumask
fn getumask() -> u32 {
    // SAFETY: umask cannot fail
    unsafe {
        let m = libc::umask(0);
        libc::umask(m);
        m as u32
    }
}

fn chmod(path: &str, mode: u32) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).is_ok()
}

/// finalize_download_file: -1 on error, 1 when the file is empty (and removed), 0 otherwise
fn finalize_download_file(filename: &str) -> i32 {
    let Ok(st) = std::fs::metadata(filename) else {
        return -1;
    };
    if st.len() == 0 {
        let _ = std::fs::remove_file(filename);
        return 1;
    }
    // SAFETY: getuid cannot fail
    if unsafe { libc::getuid() } == 0 {
        let Ok(c) = std::ffi::CString::new(filename) else {
            return -1;
        };
        // SAFETY: valid C string
        if unsafe { libc::chown(c.as_ptr(), 0, 0) } == -1 {
            return -1;
        }
    }
    if !chmod(filename, !getumask() & 0o666) {
        return -1;
    }
    0
}

/// create_tempfile: "<localpath>alpmtmp.XXXXXX", opened with O_EXCL; sets tempfile_name and remote_name
fn create_tempfile(handle: &Handle, payload: &mut Payload, localpath: &str) -> Option<File> {
    use std::os::fd::FromRawFd;
    let mut template = format!("{localpath}alpmtmp.XXXXXX").into_bytes();
    template.push(0);
    // SAFETY: template is a writable NUL-terminated buffer
    let fd = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
    template.pop();
    let randpath = String::from_utf8_lossy(&template).into_owned();
    // SAFETY: fchmod on the descriptor just created (fd == -1 fails harmlessly)
    if fd == -1 || unsafe { libc::fchmod(fd, !getumask() & 0o666) } != 0 {
        let _ = std::fs::remove_file(&randpath);
        if fd != -1 {
            // SAFETY: closing the descriptor we own
            unsafe { libc::close(fd) };
        }
        alpm_log!(
            handle,
            LOG_ERROR,
            "failed to create temporary file for download\n"
        );
        return None;
    }
    // SAFETY: fd is a valid open descriptor we own
    let f = unsafe { File::from_raw_fd(fd) };
    payload.remote_name = mbasename(&randpath).to_string();
    payload.tempfile_name = Some(randpath);
    Some(f)
}

/// curl_gethost: the host part of a URL (user:pass@ removed), "disk" for file://; None when too long or invalid
fn curl_gethost(url: &str) -> Option<String> {
    const HOSTNAME_SIZE: usize = 256;
    if url.starts_with("file://") {
        return Some("disk".to_string());
    }
    let start = url.find("//")? + 2;
    let rest = &url[start..];
    let mut hostlen = rest.find('/').unwrap_or(rest.len());
    let mut p = 0;
    // there might be a user:pass@ on the URL. hide it.
    let b = rest.as_bytes();
    let mut q = hostlen;
    while q > 1 {
        q -= 1;
        if b[q] == b'@' {
            break;
        }
    }
    if q < b.len() && b[q] == b'@' && q != 0 {
        hostlen -= q + 1;
        p = q + 1;
    }
    if hostlen > HOSTNAME_SIZE - 1 {
        // buffer overflow imminent
        return None;
    }
    Some(String::from_utf8_lossy(&b[p..p + hostlen]).into_owned())
}

/// find_server_errors: index of the host's error counter, created on demand
fn find_server_errors(handle: &Handle, server: &str) -> Option<usize> {
    let host = curl_gethost(server)?;
    let mut v = handle.server_errors.borrow_mut();
    if let Some(i) = v.iter().position(|(h, _)| *h == host) {
        return Some(i);
    }
    v.push((host, 0));
    Some(v.len() - 1)
}

/// skip for hard errors or too many soft errors
fn should_skip_server(handle: &Handle, server: &str) -> bool {
    if SERVER_ERROR_LIMIT != 0
        && let Some(i) = find_server_errors(handle, server)
    {
        let e = handle.server_errors.borrow()[i].1;
        return !(0..SERVER_ERROR_LIMIT).contains(&e);
    }
    false
}

/// only skip for hard errors
fn should_skip_cache_server(handle: &Handle, server: &str) -> bool {
    if SERVER_ERROR_LIMIT != 0
        && let Some(i) = find_server_errors(handle, server)
    {
        return handle.server_errors.borrow()[i].1 < 0;
    }
    false
}

/// block normal servers after too many errors
fn server_soft_error(handle: &Handle, server: &str) {
    if SERVER_ERROR_LIMIT != 0
        && let Some(i) = find_server_errors(handle, server)
        && !should_skip_server(handle, server)
    {
        handle.server_errors.borrow_mut()[i].1 += 1;
        if should_skip_server(handle, server) {
            let host = handle.server_errors.borrow()[i].0.clone();
            alpm_log!(
                handle,
                LOG_WARNING,
                "too many errors from {}, skipping for the remainder of this transaction\n",
                host
            );
        }
    }
}

/// immediate block for both servers and cache servers
fn server_hard_error(handle: &Handle, server: &str) {
    if SERVER_ERROR_LIMIT != 0
        && let Some(i) = find_server_errors(handle, server)
    {
        let host = {
            let mut v = handle.server_errors.borrow_mut();
            if v[i].1 == -1 {
                return;
            }
            // always set even if already skipped for soft errors to disable cache servers too
            v[i].1 = -1;
            v[i].0.clone()
        };
        alpm_log!(
            handle,
            LOG_WARNING,
            "fatal error from {}, skipping for the remainder of this transaction\n",
            host
        );
    }
}

/// payload_next_server
fn payload_next_server(handle: &Handle, payload: &mut Payload) -> Option<String> {
    while payload.cache_pos < payload.cache_servers.len()
        && should_skip_cache_server(handle, &payload.cache_servers[payload.cache_pos])
    {
        payload.cache_pos += 1;
    }
    if payload.cache_pos < payload.cache_servers.len() {
        let s = payload.cache_servers[payload.cache_pos].clone();
        payload.cache_pos += 1;
        payload.request_errors_ok = true;
        return Some(s);
    }
    while payload.server_pos < payload.servers.len()
        && should_skip_server(handle, &payload.servers[payload.server_pos])
    {
        payload.server_pos += 1;
    }
    if payload.server_pos < payload.servers.len() {
        let s = payload.servers[payload.server_pos].clone();
        payload.server_pos += 1;
        payload.request_errors_ok = payload.errors_ok;
        return Some(s);
    }
    None
}

/// the curl callbacks of one transfer (dload_parseheader_cb, dload_progress_cb, the FILE write)
struct Cb {
    p: PayloadRef,
    handle: Rc<Handle>,
}

impl Handler for Cb {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        let mut p = self.p.borrow_mut();
        match p.localf.as_mut().map(|f| f.write_all(data)) {
            Some(Ok(())) => Ok(data.len()),
            _ => Ok(0),
        }
    }

    /// dload_parseheader_cb: track the response code of the current response
    fn header(&mut self, data: &[u8]) -> bool {
        if data.starts_with(b"HTTP/") {
            let line = String::from_utf8_lossy(data);
            if let Some(code) = line
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse::<i64>().ok())
            {
                self.p.borrow_mut().respcode = code;
            }
        }
        true
    }

    /// dload_progress_cb: false aborts the transfer
    fn progress(&mut self, dltotal: f64, dlnow: f64, _ultotal: f64, _ulnow: f64) -> bool {
        let mut p = self.p.borrow_mut();
        let (dltotal, dlnow) = (dltotal as i64, dlnow as i64);
        // avoid displaying progress bar for redirects with a body
        if p.respcode >= 300 {
            return true;
        }
        // SIGINT sent, abort by alerting curl
        if DLOAD_INTERRUPTED.load(Ordering::Relaxed) != 0 {
            return false;
        }
        if dlnow < 0 || dltotal <= 0 || dlnow > dltotal {
            // bogus values : stop here
            return true;
        }
        let current_size = p.initial_size + dlnow;
        // is our filesize still under any set limit?
        if p.max_size != 0 && current_size > p.max_size {
            DLOAD_INTERRUPTED.store(ABORT_OVER_MAXFILESIZE, Ordering::Relaxed);
            return false;
        }
        // none of what follows matters if the front end has no callback
        if self.handle.dlcb.borrow().is_none() {
            return true;
        }
        let total_size = p.initial_size + dltotal;
        if p.prevprogress == total_size {
            return true;
        }
        // do NOT include initial_size since it wasn't part of the package's download_size
        let name = p.remote_name.clone();
        p.prevprogress = current_size;
        drop(p);
        if let Some(cb) = self.handle.dlcb.borrow().as_ref() {
            cb(
                &name,
                &DownloadEvent::Progress {
                    downloaded: dlnow,
                    total: dltotal,
                },
            );
        }
        true
    }
}

fn dlcb(handle: &Handle, name: &str, ev: DownloadEvent) {
    if let Some(cb) = handle.dlcb.borrow().as_ref() {
        cb(name, &ev);
    }
}

/// curl_set_handle_opts
fn curl_set_handle_opts(easy: &mut Easy2<Cb>, handle: &Handle, payload: &mut Payload) {
    let url = payload.fileurl.clone().unwrap_or_default();
    let _ = easy.url(&url);
    let _ = easy.connect_timeout(Duration::from_secs(10));
    let _ = easy.max_redirections(10);
    let _ = easy.fetch_filetime(true);
    let _ = easy.progress(true);
    let _ = easy.follow_location(true);
    if !handle.opts.borrow().disable_dl_timeout {
        let _ = easy.low_speed_limit(1);
        let _ = easy.low_speed_time(Duration::from_secs(10));
    }
    let _ = easy.netrc(NetRc::Optional);
    let _ = easy.tcp_keepalive(true);
    let _ = easy.tcp_keepidle(Duration::from_secs(60));
    let _ = easy.tcp_keepintvl(Duration::from_secs(60));
    let mut auth = curl::easy::Auth::new();
    auth.basic(true).digest(true).gssnegotiate(true).ntlm(true);
    let _ = easy.http_auth(&auth);

    alpm_log!(
        handle,
        LOG_DEBUG,
        "{}: url is {}\n",
        payload.remote_name,
        url
    );
    if payload.max_size != 0 {
        alpm_log!(
            handle,
            LOG_DEBUG,
            "{}: maxsize {}\n",
            payload.remote_name,
            payload.max_size
        );
        let _ = easy.max_filesize(payload.max_size as u64);
    }
    if let Ok(ua) = std::env::var("HTTP_USER_AGENT") {
        let _ = easy.useragent(&ua);
    }
    if !payload.force && payload.mtime_existing_file != 0 {
        // start from scratch, but only download if our local is out of date.
        let _ = easy.time_condition(TimeCondition::IfModifiedSince);
        let _ = easy.time_value(payload.mtime_existing_file);
        alpm_log!(
            handle,
            LOG_DEBUG,
            "{}: using time condition {}\n",
            payload.remote_name,
            payload.mtime_existing_file
        );
    } else if let Some(st) = payload
        .tempfile_name
        .as_ref()
        .and_then(|t| std::fs::metadata(t).ok())
        && payload.allow_resume
    {
        // a previous partial download exists, resume from end of file.
        payload.append = true;
        let _ = easy.resume_from(st.len());
        alpm_log!(
            handle,
            LOG_DEBUG,
            "{}: tempfile found, attempting continuation from {} bytes\n",
            payload.remote_name,
            st.len()
        );
        payload.initial_size = st.len() as i64;
    }
}

/// one running transfer
struct Active {
    handle: Easy2Handle<Cb>,
    p: PayloadRef,
}

struct Driver<'a> {
    handle: &'a Rc<Handle>,
    multi: Multi,
    active: HashMap<usize, Active>,
    next_token: usize,
}

impl Driver<'_> {
    fn attach(&mut self, easy: Easy2<Cb>, p: PayloadRef) -> bool {
        match self.multi.add2(easy) {
            Ok(mut h) => {
                let t = self.next_token;
                self.next_token += 1;
                let _ = h.set_token(t);
                self.active.insert(t, Active { handle: h, p });
                true
            }
            Err(_) => false,
        }
    }

    /// curl_add_payload: 0 when a new download was started (or the .part file is already complete), -1 on error
    fn add_payload(&mut self, pref: &PayloadRef) -> i32 {
        let handle = self.handle.clone();
        let mut easy = Easy2::new(Cb {
            p: pref.clone(),
            handle: handle.clone(),
        });
        let mut payload = pref.borrow_mut();
        if payload.fileurl.is_some() {
            if !payload.servers.is_empty() || payload.filepath.is_some() {
                handle.pm_errno.set(Some(Error::WrongArgs));
                return -1;
            }
            payload.request_errors_ok = payload.errors_ok;
        } else {
            let Some(server) = payload_next_server(&handle, &mut payload) else {
                handle.pm_errno.set(Some(Error::ServerNone));
                return -1;
            };
            let Some(filepath) = payload.filepath.clone() else {
                handle.pm_errno.set(Some(Error::WrongArgs));
                return -1;
            };
            payload.fileurl = Some(format!("{server}/{filepath}"));
        }
        payload.append = false;
        let url = payload.fileurl.clone().unwrap();
        if curl_gethost(&url).is_none() {
            alpm_log!(handle, LOG_ERROR, "url '{}' is invalid\n", url);
            handle.pm_errno.set(Some(Error::ServerBadUrl));
            return -1;
        }
        curl_set_handle_opts(&mut easy, &handle, &mut payload);
        if payload.max_size == payload.initial_size && payload.max_size != 0 {
            // .part file is complete
            return 0;
        }
        if payload.localf.is_none() {
            let tmp = payload.tempfile_name.clone().unwrap_or_default();
            let f = if payload.append {
                std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(&tmp)
            } else {
                File::create(&tmp)
            };
            match f {
                Ok(f) => payload.localf = Some(f),
                Err(e) => {
                    alpm_log!(
                        handle,
                        LOG_ERROR,
                        "could not open file {}: {}\n",
                        tmp,
                        strerror(&e)
                    );
                    handle.pm_errno.set(Some(Error::Retrieve));
                    return -1;
                }
            }
        }
        alpm_log!(
            handle,
            LOG_DEBUG,
            "{}: opened tempfile for download: {} ({})\n",
            payload.remote_name,
            payload.tempfile_name.as_deref().unwrap_or(""),
            if payload.append { "ab" } else { "wb" }
        );
        let (name, optional) = (payload.remote_name.clone(), payload.errors_ok);
        drop(payload);
        if !self.attach(easy, pref.clone()) {
            return -1;
        }
        dlcb(&handle, &name, DownloadEvent::Init { optional });
        0
    }

    /// curl_retry_next_server: 0 if the retry was started (the easy handle is re-attached), -1 otherwise
    fn retry_next_server(&mut self, easy: &mut Option<Easy2<Cb>>, pref: &PayloadRef) -> i32 {
        let handle = self.handle.clone();
        let mut p = pref.borrow_mut();
        let Some(server) = payload_next_server(&handle, &mut p) else {
            alpm_log!(
                handle,
                LOG_DEBUG,
                "{}: no more servers to retry\n",
                p.remote_name
            );
            return -1;
        };
        // regenerate a new fileurl
        let url = format!("{}/{}", server, p.filepath.clone().unwrap_or_default());
        p.fileurl = Some(url.clone());
        alpm_log!(
            handle,
            LOG_DEBUG,
            "{}: retrying from {}\n",
            p.remote_name,
            url
        );
        let e = easy.as_mut().unwrap();
        if let Some(f) = p.localf.as_mut() {
            let _ = f.flush();
        }
        let st = p
            .tempfile_name
            .as_ref()
            .and_then(|t| std::fs::metadata(t).ok());
        if let (true, Some(st)) = (p.allow_resume, st) {
            // a previous partial download exists, resume from end of file.
            p.append = true;
            let _ = e.resume_from(st.len());
            alpm_log!(
                handle,
                LOG_DEBUG,
                "{}: tempfile found, attempting continuation from {} bytes\n",
                p.remote_name,
                st.len()
            );
            p.initial_size = st.len() as i64;
        } else {
            // we keep the file for a new retry but remove its data if any
            if let Some(f) = p.localf.as_mut() {
                if f.set_len(0).is_err() {
                    handle.pm_errno.set(Some(Error::System));
                    return -1;
                }
                let _ = f.seek(SeekFrom::Start(0));
            }
        }
        let (name, resume) = (p.remote_name.clone(), p.allow_resume);
        drop(p);
        dlcb(&handle, &name, DownloadEvent::Retry { resume });
        // set curl with the new URL, restart the transfer
        let _ = e.url(&url);
        let easy = easy.take().unwrap();
        self.attach(easy, pref.clone());
        0
    }

    /// curl_check_finished_download. Returns 2 retry happened, 1 up-to-date, 0 completed, -1 error for a
    /// required file, -2 error for an optional file.
    fn check_finished(
        &mut self,
        token: usize,
        result: Result<(), curl::Error>,
        active_downloads: &mut usize,
    ) -> i32 {
        let handle = self.handle.clone();
        let Active {
            handle: eh,
            p: pref,
        } = self.active.remove(&token).unwrap();
        let mut easy = Some(self.multi.remove2(eh).unwrap());
        let (fileurl, remote_name) = {
            let p = pref.borrow();
            (p.fileurl.clone().unwrap_or_default(), p.remote_name.clone())
        };
        let hostname = curl_gethost(&fileurl).unwrap_or_default();
        alpm_log!(
            handle,
            LOG_DEBUG,
            "{}: {} returned result {} from transfer\n",
            remote_name,
            "curl",
            result.as_ref().err().map_or(0, |e| e.code())
        );
        let mut ret = -1;
        let (mut remote_time, mut bytes_dl) = (-1i64, 0i64);
        // `ok` is false when the error paths jump to cleanup
        let mut ok = false;
        match &result {
            Ok(()) => {
                let respcode = pref.borrow().respcode;
                // get http/ftp response code
                alpm_log!(
                    handle,
                    LOG_DEBUG,
                    "{}: response code {}\n",
                    remote_name,
                    respcode
                );
                if respcode >= 400 {
                    if !pref.borrow().request_errors_ok {
                        handle.pm_errno.set(Some(Error::Retrieve));
                        // non-translated message is same as libcurl
                        let msg = format!("The requested URL returned error: {respcode}");
                        pref.borrow_mut().error_buffer = msg.clone();
                        alpm_log!(
                            handle,
                            LOG_ERROR,
                            "failed retrieving file '{}' from {} : {}\n",
                            remote_name,
                            hostname,
                            msg
                        );
                        server_soft_error(&handle, &fileurl);
                    }
                    {
                        let mut p = pref.borrow_mut();
                        let initial = p.initial_size;
                        if let Some(f) = p.localf.as_mut() {
                            let _ = f.flush();
                            if f.metadata().is_ok_and(|m| m.len() as i64 != initial) {
                                // an html error page was written to the file, reset it
                                if f.set_len(initial as u64).is_err() {
                                    handle.pm_errno.set(Some(Error::System));
                                    return -1;
                                }
                                let _ = f.seek(SeekFrom::Start(initial as u64));
                            }
                        }
                    }
                    if self.retry_next_server(&mut easy, &pref) == 0 {
                        return 2;
                    }
                    pref.borrow_mut().unlink_on_fail = true;
                } else {
                    ok = true;
                }
            }
            Err(e) if e.is_aborted_by_callback() => {
                // handle the interrupt accordingly
                if DLOAD_INTERRUPTED.load(Ordering::Relaxed) == ABORT_OVER_MAXFILESIZE {
                    pref.borrow_mut().unlink_on_fail = true;
                    handle.pm_errno.set(Some(Error::Libcurl));
                    alpm_log!(
                        handle,
                        LOG_ERROR,
                        "failed retrieving file '{}' from {} : expected download size exceeded\n",
                        remote_name,
                        hostname
                    );
                    server_soft_error(&handle, &fileurl);
                }
            }
            Err(e) if e.is_couldnt_resolve_host() => {
                handle.pm_errno.set(Some(Error::ServerBadUrl));
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "failed retrieving file '{}' from {} : {}\n",
                    remote_name,
                    hostname,
                    e.extra_description().unwrap_or("")
                );
                server_hard_error(&handle, &fileurl);
                if self.retry_next_server(&mut easy, &pref) == 0 {
                    return 2;
                }
            }
            Err(e) => {
                let text = e.extra_description().unwrap_or("").to_string();
                pref.borrow_mut().error_buffer = text.clone();
                if !pref.borrow().request_errors_ok {
                    handle.pm_errno.set(Some(Error::Libcurl));
                    alpm_log!(
                        handle,
                        LOG_ERROR,
                        "failed retrieving file '{}' from {} : {}\n",
                        remote_name,
                        hostname,
                        text
                    );
                    server_soft_error(&handle, &fileurl);
                } else {
                    alpm_log!(
                        handle,
                        LOG_DEBUG,
                        "failed retrieving file '{}' from {} : {}\n",
                        remote_name,
                        hostname,
                        text
                    );
                }
                if self.retry_next_server(&mut easy, &pref) == 0 {
                    return 2;
                }
                // delete zero length downloads
                let mut p = pref.borrow_mut();
                if p.localf
                    .as_ref()
                    .and_then(|f| f.metadata().ok())
                    .is_some_and(|m| m.len() == 0)
                {
                    p.unlink_on_fail = true;
                }
            }
        }

        if ok {
            let easy_ref = easy.as_ref().unwrap();
            remote_time = easy_ref.filetime().ok().flatten().unwrap_or(-1);
            let remote_size = easy_ref.content_length_download().map_or(-1, |v| v as i64);
            bytes_dl = easy_ref.download_size().map_or(-1, |v| v as i64);
            let timecond = easy_ref.time_condition_unmet().unwrap_or(false);
            let effective_url = easy_ref
                .effective_url()
                .ok()
                .flatten()
                .unwrap_or("")
                .to_string();
            let (signature, download_signature, respcode) = {
                let p = pref.borrow();
                (p.signature, p.download_signature, p.respcode)
            };

            // Let's check if client requested downloading accompanion *.sig file
            if !signature && download_signature && respcode < 400 {
                let p = pref.borrow();
                let dbext = handle.dbext();
                let mut effective_filename = get_filename(&effective_url).to_string();
                if let Some(q) = effective_filename.rfind('?') {
                    effective_filename.truncate(q);
                }
                let realname = p
                    .destfile_name
                    .clone()
                    .or(p.tempfile_name.clone())
                    .unwrap_or_default();
                // only use the effective url for sig downloads if it contains .dbext or .pkg
                let url =
                    if effective_filename.contains(&dbext) || effective_filename.contains(".pkg") {
                        effective_url.clone()
                    } else {
                        p.fileurl.clone().unwrap_or_default()
                    };
                let sig = Payload {
                    fileurl: Some(format!("{url}.sig")),
                    remote_name: format!("{}.sig", p.remote_name),
                    destfile_name: Some(format!("{realname}.sig")),
                    tempfile_name: Some(format!("{realname}.sig.part")),
                    signature: true,
                    force: p.force,
                    unlink_on_fail: p.unlink_on_fail,
                    errors_ok: p.signature_optional,
                    // set hard upper limit of 16KiB
                    max_size: 16 * 1024,
                    ..Default::default()
                };
                drop(p);
                // sic: a failure to start is ignored upstream, the counter is bumped regardless
                self.add_payload(&payload_ref(sig));
                *active_downloads += 1;
            }

            // time condition was met and we didn't download anything. we need to clean up the 0 byte
            // .part file that's left behind.
            if timecond && bytes_dl == 0 {
                alpm_log!(
                    handle,
                    LOG_DEBUG,
                    "{}: file met time condition\n",
                    remote_name
                );
                ret = 1;
                if let Some(t) = pref.borrow().tempfile_name.as_ref() {
                    let _ = std::fs::remove_file(t);
                }
            } else if remote_size != -1 && bytes_dl != -1 && bytes_dl != remote_size {
                // remote_size isn't necessarily the full size of the file, just what the server reported as
                // remaining to download.
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "{} appears to be truncated: {}/{} bytes\n",
                    remote_name,
                    bytes_dl,
                    remote_size
                );
                handle.pm_errno.set(Some(Error::Retrieve));
            } else {
                ret = 0;
            }
        }

        // cleanup
        {
            let mut p = pref.borrow_mut();
            if p.localf.take().is_some()
                && remote_time != -1
                && let Some(t) = p.tempfile_name.as_ref()
            {
                let tv = libc::timeval {
                    tv_sec: remote_time,
                    tv_usec: 0,
                };
                if let Ok(c) = std::ffi::CString::new(t.as_str()) {
                    // SAFETY: valid C string and two timevals
                    unsafe { libc::utimes(c.as_ptr(), [tv, tv].as_ptr()) };
                }
            }
            if ret == 0
                && let (Some(d), Some(t)) = (p.destfile_name.clone(), p.tempfile_name.clone())
                && let Err(e) = std::fs::rename(&t, &d)
            {
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "could not rename {} to {} ({})\n",
                    t,
                    d,
                    strerror(&e)
                );
                ret = -1;
            }
            if (ret == -1 || DLOAD_INTERRUPTED.load(Ordering::Relaxed) != 0)
                && p.unlink_on_fail
                && let Some(t) = p.tempfile_name.as_ref()
            {
                let _ = std::fs::remove_file(t);
            }
            dlcb(
                &handle,
                &p.remote_name,
                DownloadEvent::Completed {
                    total: bytes_dl,
                    result: ret,
                },
            );
            p.fileurl = None;
            if ret == -1 && p.errors_ok {
                ret = -2;
            }
        }
        ret
    }
}

/// Use to sort payloads by max size in descending order. Same merge sort as alpm_list_msort with the
/// `int`-truncated comparison of the upstream comparator.
fn msort(v: Vec<PayloadRef>) -> Vec<PayloadRef> {
    fn cmp(l: &PayloadRef, r: &PayloadRef) -> i32 {
        (r.borrow().max_size.wrapping_sub(l.borrow().max_size)) as i32
    }
    if v.len() <= 1 {
        return v;
    }
    let half = v.len() / 2;
    let mut right = v;
    let left = right.drain(..half).collect::<Vec<_>>();
    let (left, right) = (msort(left), msort(right));
    let mut out = Vec::with_capacity(left.len() + right.len());
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        if cmp(&left[i], &right[j]) <= 0 {
            out.push(left[i].clone());
            i += 1;
        } else {
            out.push(right[j].clone());
            j += 1;
        }
    }
    out.extend_from_slice(&left[i..]);
    out.extend_from_slice(&right[j..]);
    out
}

/// curl_download_internal: -1 error for a required file, 0 a payload was downloaded, 1 nothing downloaded
/// and all errors were non-fatal
fn curl_download_internal(handle: &Rc<Handle>, payloads: &[PayloadRef]) -> i32 {
    let max_streams = handle.opts.borrow().parallel_downloads as usize;
    let mut err = 0;
    let mut updated = false;
    let mut d = Driver {
        handle,
        multi: Multi::new(),
        active: HashMap::new(),
        next_token: 0,
    };
    // Sort payloads by package size
    let payloads = msort(payloads.to_vec());
    let mut p = 0usize;
    let plen = payloads.len();
    let mut active_downloads = 0usize;
    while active_downloads > 0 || p < plen {
        while active_downloads < max_streams && p < plen {
            if d.add_payload(&payloads[p]) == 0 {
                p += 1;
            } else {
                // The payload failed to start. Do not start any new downloads.
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "failed to setup a download payload for {}\n",
                    payloads[p].borrow().remote_name
                );
                p = plen;
                err = -1;
            }
            active_downloads += 1;
        }
        let mc = d.multi.perform().and_then(|n| {
            active_downloads = n as usize;
            d.multi
                .wait(&mut [], Duration::from_millis(1000))
                .map(|_| ())
        });
        if let Err(e) = mc {
            alpm_log!(
                handle,
                LOG_ERROR,
                "curl returned error {} from transfer\n",
                e.code()
            );
            p = plen;
            err = -1;
        }
        // collect the finished transfers, then process them
        let mut done: Vec<(usize, Result<(), curl::Error>)> = Vec::new();
        d.multi.messages(|m| {
            if let Ok(t) = m.token()
                && let Some(a) = d.active.get(&t)
                && let Some(r) = m.result_for2(&a.handle)
            {
                done.push((t, r));
            }
        });
        for (t, r) in done {
            let ret = d.check_finished(t, r, &mut active_downloads);
            if ret == 2 {
                active_downloads += 1;
            } else if ret == -1 {
                // if current payload failed to download then stop adding new payloads but wait for the
                // current ones
                p = plen;
                err = -1;
            } else if ret == 0 {
                updated = true;
            }
        }
    }
    let ret = if err != 0 {
        -1
    } else if updated {
        0
    } else {
        1
    };
    alpm_log!(
        handle,
        LOG_DEBUG,
        "curl_download_internal return code is {}\n",
        ret
    );
    ret
}

/// curl_download_internal_sandboxed: run the download in a forked child inside the sandbox
fn curl_download_internal_sandboxed(
    handle: &Rc<Handle>,
    payloads: &[PayloadRef],
    localpath: &str,
    childsig: &mut i32,
) -> i32 {
    let mut fds = [0i32; 2];
    // SAFETY: pipe fills the two descriptors
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return -1;
    }
    // SAFETY: standard signal setup around fork, restored below
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
    let mut err = 0;
    // SAFETY: fork; the child only continues in this function until _exit
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    }
    if pid == 0 {
        // child
        let wfd = fds[1];
        // SAFETY: closing/flagging our own descriptors
        unsafe {
            libc::close(fds[0]);
            libc::fcntl(wfd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        *handle.logcb.borrow_mut() = Some(Box::new(move |lvl, msg| sandbox_cb_log(wfd, lvl, msg)));
        *handle.dlcb.borrow_mut() = Some(Box::new(move |name, ev| sandbox_cb_dl(wfd, name, ev)));
        *handle.fetchcb.borrow_mut() = None;
        *handle.eventcb.borrow_mut() = None;
        *handle.questioncb.borrow_mut() = None;
        // restore default signal handling in the child
        crate::util::reset_signals();
        // cwd to the download directory
        let mut ret;
        if std::env::set_current_dir(localpath).is_err() {
            handle.pm_errno.set(Some(Error::NotADir));
            alpm_log!(
                handle,
                LOG_ERROR,
                "could not chdir to download directory {}\n",
                localpath
            );
            ret = -1;
        } else {
            let user = handle.opts.borrow().sandboxuser.clone().unwrap_or_default();
            if sandbox_setup_child(handle, &user, Some(localpath), true) != 0 {
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "switching to sandbox user '{}' failed!\n",
                    user
                );
                // SAFETY: leaving the child
                unsafe { libc::_exit(2) };
            }
            ret = curl_download_internal(handle, payloads);
        }
        // pass the result back to the parent
        if ret != 0 && ret != 1 {
            ret = 2;
        }
        // SAFETY: leaving the child without running destructors
        unsafe { libc::_exit(ret) };
    }
    // parent
    // SAFETY: closing our copy of the write end
    unsafe { libc::close(fds[1]) };
    let mut ret = -1;
    if pid != -1 {
        let had_error;
        loop {
            let mut b = [0u8; 4];
            let mut got = 0;
            // SAFETY: reading into a local buffer
            let r = unsafe { libc::read(fds[0], b.as_mut_ptr().cast(), 4) };
            if r >= 0 {
                got = r as usize;
            }
            if r < 0 || got != 4 {
                had_error = true;
                break;
            }
            let t = i32::from_ne_bytes(b);
            if t == SANDBOX_CB_DOWNLOAD {
                if !sandbox_process_cb_download(handle, fds[0]) {
                    had_error = true;
                    break;
                }
            } else if t == SANDBOX_CB_LOG && !sandbox_process_cb_log(handle, fds[0]) {
                had_error = true;
                break;
            }
        }
        if had_error {
            // SAFETY: signalling our child
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        let mut status = 0;
        let mut wret;
        loop {
            // SAFETY: waiting for our child
            wret = unsafe { libc::waitpid(pid, &mut status, 0) };
            if !(wret == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR))
            {
                break;
            }
        }
        if wret > 0 {
            if libc::WIFSIGNALED(status) {
                *childsig = libc::WTERMSIG(status);
            }
            if !libc::WIFEXITED(status) {
                // the child did not terminate normally
                handle.pm_errno.set(Some(Error::Retrieve));
                ret = -1;
            } else {
                ret = libc::WEXITSTATUS(status);
                if ret != 0 {
                    if ret == 2 {
                        // an error happened for a required file, or unexpected exit status
                        handle.pm_errno.set(Some(Error::Retrieve));
                        ret = -1;
                    } else {
                        handle.pm_errno.set(Some(Error::Retrieve));
                        ret = 1;
                    }
                }
            }
        } else {
            // waitpid failed
            err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
    }
    // SAFETY: closing our descriptor and restoring the signal state
    unsafe {
        libc::close(fds[0]);
        libc::sigaction(libc::SIGINT, &oldint, std::ptr::null_mut());
        libc::sigaction(libc::SIGQUIT, &oldquit, std::ptr::null_mut());
        libc::sigprocmask(libc::SIG_SETMASK, &oldblock, std::ptr::null_mut());
    }
    if err != 0 {
        ret = -1;
    }
    ret
}

/// payload_download_fetchcb
fn payload_download_fetchcb(handle: &Handle, p: &Payload, server: &str, localpath: &str) -> i32 {
    let fileurl = format!("{server}/{}", p.filepath.as_deref().unwrap_or(""));
    match handle.fetchcb.borrow().as_ref() {
        Some(cb) => cb(&fileurl, localpath, p.force),
        None => -1,
    }
}

/// move_file: finalize `filepath` and rename it into `directory`
fn move_file(filepath: &str, directory: &str) -> i32 {
    let ret = finalize_download_file(filepath);
    if ret != 0 {
        return ret;
    }
    let dest = format!("{directory}{}", mbasename(filepath));
    if std::fs::rename(filepath, dest).is_err() {
        return -1;
    }
    0
}

/// finalize_download_locations
fn finalize_download_locations(payloads: &[PayloadRef], localpath: &str) -> i32 {
    let mut returnvalue = 0;
    for pref in payloads {
        let p = pref.borrow();
        let mut filename: Option<&str> = None;
        if p.destfile_name
            .as_ref()
            .is_some_and(|d| std::fs::metadata(d).is_ok())
        {
            filename = p.destfile_name.as_deref();
        } else if p
            .tempfile_name
            .as_ref()
            .is_some_and(|t| std::fs::metadata(t).is_ok())
        {
            filename = p.tempfile_name.as_deref();
        }
        if let Some(f) = filename
            && move_file(f, localpath) == -1
            && p.mtime_existing_file == 0
        {
            // handle is not reachable here: the error text goes through the payload owner
            returnvalue = -1;
        }
        if p.download_signature {
            let base = p
                .destfile_name
                .as_ref()
                .or(p.tempfile_name.as_ref())
                .cloned()
                .unwrap_or_default();
            if move_file(&format!("{base}.sig"), localpath) == -1 {
                move_file(&format!("{base}.sig.part"), localpath);
            }
        }
    }
    returnvalue
}

/// prepare_resumable_downloads
fn prepare_resumable_downloads(handle: &Handle, payloads: &[PayloadRef], localpath: &str) {
    let mut pw: Option<(u32, u32)> = None;
    if use_sandbox(handle) {
        let user = handle.opts.borrow().sandboxuser.clone().unwrap_or_default();
        let Ok(c) = std::ffi::CString::new(user) else {
            return;
        };
        // SAFETY: valid C string; fields are read immediately
        let r = unsafe { libc::getpwnam(c.as_ptr()) };
        if r.is_null() {
            return;
        }
        // SAFETY: r is non-null
        pw = Some(unsafe { ((*r).pw_uid, (*r).pw_gid) });
    }
    for pref in payloads {
        let mut p = pref.borrow_mut();
        if let Some(d) = p.destfile_name.clone() {
            let dest = format!("{localpath}{}", mbasename(&d));
            if let Ok(st) = std::fs::metadata(&dest)
                && st.len() != 0
            {
                p.mtime_existing_file = st.mtime();
            }
        }
        let Some(t) = p.tempfile_name.clone() else {
            continue;
        };
        if !use_sandbox(handle) {
            continue;
        }
        let src = format!("{localpath}{}", mbasename(&t));
        match std::fs::metadata(&src) {
            Ok(st) if st.len() != 0 => {}
            _ => continue,
        }
        if std::fs::rename(&src, &t).is_err() {
            continue;
        }
        if let Some((uid, gid)) = pw
            && let Ok(c) = std::ffi::CString::new(t.as_str())
        {
            // SAFETY: valid C string
            if unsafe { libc::chown(c.as_ptr(), uid, gid) } == 0 {
                // upstream asserts on the opposite value and returns; the effect is the same here
            }
        }
    }
}

/// _alpm_download: -1 error for a required file, 0 a payload was actually downloaded, 1 no files were
/// downloaded and all errors were non-fatal
pub fn download(
    handle: &Rc<Handle>,
    payloads: &[PayloadRef],
    localpath: &str,
    temporary_localpath: &str,
) -> i32 {
    let mut finalize_ret = 0;
    let mut childsig = 0;
    prepare_resumable_downloads(handle, payloads, localpath);

    #[allow(clippy::needless_late_init)]
    let ret;
    if handle.fetchcb.borrow().is_none() {
        ret = if use_sandbox(handle) {
            curl_download_internal_sandboxed(handle, payloads, temporary_localpath, &mut childsig)
        } else {
            curl_download_internal(handle, payloads)
        };
    } else {
        let mut updated = false;
        let mut r;
        for pref in payloads {
            let p = pref.borrow();
            r = -1;
            let fetch = |url: &str, force: bool| -> i32 {
                handle
                    .fetchcb
                    .borrow()
                    .as_ref()
                    .map_or(-1, |cb| cb(url, temporary_localpath, force))
            };
            if let Some(url) = &p.fileurl {
                r = fetch(url, p.force);
                if r != -1 && p.download_signature {
                    // Download signature if requested
                    let retsig = fetch(&format!("{url}.sig"), p.force);
                    if !p.signature_optional {
                        r = retsig;
                    }
                }
            } else {
                let mut used: Option<&String> = None;
                for s in p.cache_servers.iter().chain(p.servers.iter()) {
                    r = payload_download_fetchcb(handle, &p, s, temporary_localpath);
                    if r != -1 {
                        used = Some(s);
                        break;
                    }
                }
                if r != -1
                    && p.download_signature
                    && let Some(s) = used
                {
                    let retsig = fetch(
                        &format!("{s}/{}.sig", p.filepath.as_deref().unwrap_or("")),
                        p.force,
                    );
                    if !p.signature_optional {
                        r = retsig;
                    }
                }
            }
            if r == -1 && !p.errors_ok {
                handle.pm_errno.set(Some(Error::ExternalDownload));
                return -1;
            } else if r == 0 {
                updated = true;
            }
        }
        ret = if updated { 0 } else { 1 };
    }

    if use_sandbox(handle) {
        finalize_ret = finalize_download_locations(payloads, localpath);
        remove_temporary_download_dir(temporary_localpath);
    }
    // propagate after finalizing so .part files get copied over
    if childsig != 0 {
        // SAFETY: re-raising the child's fatal signal on ourselves
        unsafe { libc::kill(libc::getpid(), childsig) };
    }
    if finalize_ret != 0 && ret == 0 {
        handle.pm_errno.set(Some(Error::Retrieve));
        return -1;
    }
    ret
}

/// url_basename
fn url_basename(url: &str) -> Option<&str> {
    let base = &url[url.rfind('/')? + 1..];
    (!base.is_empty()).then_some(base)
}

/// alpm_fetch_pkgurl: download package URLs into the cache; returns the cached paths
pub fn fetch_pkgurl(handle: &Rc<Handle>, urls: &[String]) -> Result<Vec<String>, Error> {
    use crate::consts::{SIG_PACKAGE, SIG_PACKAGE_OPTIONAL};
    let siglevel = {
        let o = handle.opts.borrow();
        if o.remote_file_siglevel & crate::consts::SIG_USE_DEFAULT != 0 {
            o.siglevel
        } else {
            o.remote_file_siglevel
        }
    };
    let mut fetched: Vec<String> = Vec::new();
    // find a valid cache dir to download to
    let cachedir = filecache_setup(handle);
    let Some(temporary_cachedir) = download_dir_setup(handle, &cachedir) else {
        return Err(handle.errno().unwrap_or(Error::RetrievePrepare));
    };
    let mut payloads: Vec<PayloadRef> = Vec::new();
    for url in urls {
        let mut filepath = None;
        if let Some(urlbase) = url_basename(url) {
            // attempt to find the file in our pkgcache
            filepath = filecache_find(handle, urlbase);
            if filepath.is_some() && siglevel & SIG_PACKAGE != 0 {
                // if there's no .sig file then forget about the pkg file and go for download
                if !crate::util::filecache_exists(handle, &format!("{urlbase}.sig")) {
                    filepath = None;
                }
            }
        }
        if let Some(f) = filepath {
            // the file is locally cached so add it to the output right away
            fetched.push(f);
            continue;
        }
        let mut payload = Payload {
            fileurl: Some(url.clone()),
            remote_name: get_filename(url).to_string(),
            ..Default::default()
        };
        let c = url.rfind('/').map(|p| &url[p..]);
        if c.is_some_and(|c| c.contains(".pkg")) && !payload.remote_name.is_empty() {
            // we probably have a usable package filename to download to
            payload.destfile_name = Some(format!("{temporary_cachedir}{}", payload.remote_name));
            payload.tempfile_name =
                Some(format!("{temporary_cachedir}{}.part", payload.remote_name));
            payload.allow_resume = true;
        } else {
            // The URL does not contain a filename, so download to a temporary location. We can not support
            // resuming this kind of download; any partial transfers will be destroyed
            payload.unlink_on_fail = true;
            match create_tempfile(handle, &mut payload, &temporary_cachedir) {
                Some(f) => payload.localf = Some(f),
                None => return Err(handle.errno().unwrap_or(Error::Retrieve)),
            }
        }
        payload.download_signature = siglevel & SIG_PACKAGE != 0;
        payload.signature_optional = siglevel & SIG_PACKAGE_OPTIONAL != 0;
        payloads.push(payload_ref(payload));
    }
    if !payloads.is_empty() {
        handle.event(&Event::PkgRetrieveStart {
            num: payloads.len(),
            total_size: 0,
        });
        if download(handle, &payloads, &cachedir, &temporary_cachedir) == -1 {
            alpm_log!(handle, LOG_WARNING, "failed to retrieve some files\n");
            handle.event(&Event::PkgRetrieveFailed);
            handle.pm_errno.set(Some(Error::Retrieve));
            return Err(Error::Retrieve);
        }
        handle.event(&Event::PkgRetrieveDone);
        for pref in &payloads {
            let p = pref.borrow();
            let name = match &p.destfile_name {
                Some(d) => mbasename(d).to_string(),
                None => mbasename(p.tempfile_name.as_deref().unwrap_or("")).to_string(),
            };
            match filecache_find(handle, &name) {
                Some(f) => fetched.push(f),
                None => {
                    alpm_log!(
                        handle,
                        LOG_WARNING,
                        "download completed successfully but no file in the cache\n"
                    );
                    handle.pm_errno.set(Some(Error::Retrieve));
                    return Err(Error::Retrieve);
                }
            }
        }
    }
    Ok(fetched)
}
