//! Differential test of downloads (dload.c, alpm_db_update, -Sy/-Syy/-Fy/-Sw) against /usr/bin/pacman.
//! Both programs run under `fakeroot` (they refuse -Sy for a normal user) against throw-away dbpath, cachedir,
//! logfile, gpgdir and root, and a local HTTP server started by the test (one fresh instance per program run,
//! so the request logs can be compared too). Compared: exit status, stdout, stderr (paths and ports
//! normalised), the resulting files (bytes, plus mtime for databases and packages) and the HTTP requests
//! the server saw. No network beyond 127.0.0.1; never the real dbpath/cachedir; LC_ALL=C.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const SYS: &str = "/usr/bin/pacman";

// ---------------------------------------------------------------- HTTP server

#[derive(Clone)]
enum Behavior {
    Normal,
    /// answer with this status and a small body
    Status(u16),
    /// announce the whole body, then stall after a few bytes
    Stall,
    /// announce more than is sent, then close
    Truncated,
}

#[derive(Clone)]
struct Entry {
    body: Vec<u8>,
    mtime: i64,
    behavior: Behavior,
}

type Files = Vec<(String, Entry)>;

fn http_date(t: i64) -> String {
    // SAFETY: gmtime_r/strftime on local buffers
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::gmtime_r(&t, &mut tm);
        let mut buf = [0u8; 64];
        let n = libc::strftime(
            buf.as_mut_ptr().cast(),
            64,
            c"%a, %d %b %Y %H:%M:%S GMT".as_ptr(),
            &tm,
        );
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }
}

fn parse_http_date(s: &str) -> Option<i64> {
    let c = std::ffi::CString::new(s).ok()?;
    // SAFETY: strptime/timegm on local data
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        let r = libc::strptime(c.as_ptr(), c"%a, %d %b %Y %H:%M:%S GMT".as_ptr(), &mut tm);
        if r.is_null() {
            return None;
        }
        Some(libc::timegm(&mut tm))
    }
}

struct Server {
    port: u16,
    log: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Server {
    fn start(files: Files) -> Server {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        l.set_nonblocking(true).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let files = Arc::new(files);
        let (log2, stop2) = (log.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                match l.accept() {
                    Ok((s, _)) => {
                        let (files, log) = (files.clone(), log2.clone());
                        std::thread::spawn(move || {
                            let _ = handle(s, &files, &log);
                        });
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
                }
            }
        });
        Server { port, log, stop }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn handle(mut s: TcpStream, files: &Files, log: &Mutex<Vec<String>>) -> std::io::Result<()> {
    s.set_nonblocking(false)?;
    let mut buf = Vec::new();
    let mut b = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut b)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&b[..n]);
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = text.lines();
    let req = lines.next().unwrap_or("");
    let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
    let (mut range, mut ims) = (None, None);
    for l in lines {
        let low = l.to_ascii_lowercase();
        if let Some(v) = low.strip_prefix("range: bytes=") {
            range = v.trim_end_matches('-').parse::<usize>().ok();
        }
        if low.starts_with("if-modified-since:") {
            ims = Some(l["if-modified-since:".len()..].trim().to_string());
        }
    }
    log.lock().unwrap().push(format!(
        "{} range={:?} ims={}",
        req.split_whitespace().take(2).collect::<Vec<_>>().join(" "),
        range,
        ims.clone().unwrap_or_default()
    ));
    let send = |s: &mut TcpStream, head: &str, body: &[u8]| -> std::io::Result<()> {
        s.write_all(head.as_bytes())?;
        s.write_all(body)?;
        s.flush()
    };
    let Some((_, e)) = files.iter().find(|(p, _)| *p == path) else {
        return send(
            &mut s,
            "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found",
            b"",
        );
    };
    match &e.behavior {
        Behavior::Status(code) => {
            let body = "error page body";
            return send(
                &mut s,
                &format!(
                    "HTTP/1.1 {code} Err\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ),
                b"",
            );
        }
        Behavior::Stall => {
            s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nLast-Modified: {}\r\nConnection: close\r\n\r\n",
                    e.body.len().max(1000),
                    http_date(e.mtime)
                )
                .as_bytes(),
            )?;
            s.write_all(&e.body[..e.body.len().min(5)])?;
            s.flush()?;
            std::thread::sleep(std::time::Duration::from_secs(14));
            return Ok(());
        }
        Behavior::Truncated => {
            s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nLast-Modified: {}\r\nConnection: close\r\n\r\n",
                    e.body.len() + 100,
                    http_date(e.mtime)
                )
                .as_bytes(),
            )?;
            return s.write_all(&e.body);
        }
        Behavior::Normal => {}
    }
    if let Some(since) = ims.as_deref().and_then(parse_http_date)
        && e.mtime <= since
    {
        return send(
            &mut s,
            &format!(
                "HTTP/1.1 304 Not Modified\r\nLast-Modified: {}\r\nConnection: close\r\n\r\n",
                http_date(e.mtime)
            ),
            b"",
        );
    }
    match range {
        Some(n) if n < e.body.len() => send(
            &mut s,
            &format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nLast-Modified: {}\r\nConnection: close\r\n\r\n",
                e.body.len() - n,
                n,
                e.body.len() - 1,
                e.body.len(),
                http_date(e.mtime)
            ),
            &e.body[n..],
        ),
        Some(_) => send(
            &mut s,
            "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            b"",
        ),
        None => send(
            &mut s,
            &format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nLast-Modified: {}\r\nConnection: close\r\n\r\n",
                e.body.len(),
                http_date(e.mtime)
            ),
            &e.body,
        ),
    }
}

// ---------------------------------------------------------------- fixtures

const T0: i64 = 1_600_000_000;

fn tar_gz(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (p, d) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(d.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, p, &d[..]).unwrap();
    }
    let raw = b.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&raw).unwrap();
    gz.finish().unwrap()
}

struct Pkg {
    name: &'static str,
    ver: &'static str,
    deps: Vec<&'static str>,
    body: Vec<u8>,
}

impl Pkg {
    fn new(name: &'static str, deps: &[&'static str], size: usize) -> Pkg {
        let info = format!("pkgname = {name}\npkgver = 1-1\narch = any\n");
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(info.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, ".PKGINFO", info.as_bytes()).unwrap();
        let mut pad = tar::Header::new_gnu();
        let junk: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
        pad.set_size(junk.len() as u64);
        pad.set_mode(0o644);
        pad.set_cksum();
        b.append_data(&mut pad, "junk", &junk[..]).unwrap();
        let raw = b.into_inner().unwrap();
        Pkg {
            name,
            ver: "1-1",
            deps: deps.to_vec(),
            body: zstd::encode_all(&raw[..], 3).unwrap(),
        }
    }
    fn filename(&self) -> String {
        format!("{}-{}-any.pkg.tar.zst", self.name, self.ver)
    }
    fn desc(&self, csize_override: Option<usize>) -> Vec<u8> {
        let mut d = format!(
            "%FILENAME%\n{}\n\n%NAME%\n{}\n\n%VERSION%\n{}\n\n%CSIZE%\n{}\n\n%ISIZE%\n1\n\n%SHA256SUM%\n{:x}\n\n%ARCH%\nany\n\n",
            self.filename(),
            self.name,
            self.ver,
            csize_override.unwrap_or(self.body.len()),
            Sha256::digest(&self.body)
        );
        if !self.deps.is_empty() {
            d.push_str(&format!("%DEPENDS%\n{}\n\n", self.deps.join("\n")));
        }
        d.into_bytes()
    }
}

fn db_bytes(pkgs: &[&Pkg], csize_override: Option<usize>) -> Vec<u8> {
    let e: Vec<(String, Vec<u8>)> = pkgs
        .iter()
        .map(|p| (format!("{}-{}/desc", p.name, p.ver), p.desc(csize_override)))
        .collect();
    tar_gz(
        &e.iter()
            .map(|(n, d)| (n.as_str(), d.clone()))
            .collect::<Vec<_>>(),
    )
}

fn entry(body: Vec<u8>, i: i64) -> Entry {
    Entry {
        body,
        mtime: T0 + i * 1000,
        behavior: Behavior::Normal,
    }
}

fn with(mut e: Entry, b: Behavior) -> Entry {
    e.behavior = b;
    e
}

// ---------------------------------------------------------------- cases

struct Dirs {
    base: PathBuf,
    root: PathBuf,
    db: PathBuf,
    cache: PathBuf,
    gpg: PathBuf,
    log: PathBuf,
    conf: PathBuf,
}

type PreFn = Box<dyn Fn(&Dirs) + Send + Sync>;
type RepoFn = Box<dyn Fn(&[u16]) -> String + Send + Sync>;

struct Case {
    name: &'static str,
    /// one file set per HTTP server instance (a repo's Server lines point at instances)
    servers: Vec<Files>,
    /// pacman.conf below [options]: the repo sections, given the server ports
    repos: RepoFn,
    options: &'static str,
    runs: Vec<Vec<&'static str>>,
    /// create pre-existing files in the dirs
    pre: Option<PreFn>,
    /// sort output lines (parallel downloads finish in any order)
    sort: bool,
    /// copy the signing keyring into gpgdir
    keyring: bool,
}

/// -Sw prints the transaction summary and prompts of sync.c (T13): compare stdout only for -Sy/-Fy runs
fn compares_stdout(args: &[&str]) -> bool {
    !args.contains(&"-Sw")
}

fn simple_repo(names: &'static [&'static str]) -> RepoFn {
    Box::new(move |ports| {
        names
            .iter()
            .map(|n| format!("[{n}]\nServer = http://127.0.0.1:{}/repo\n", ports[0]))
            .collect()
    })
}

fn base_case(name: &'static str, files: Files, args: Vec<&'static str>) -> Case {
    Case {
        name,
        servers: vec![files],
        repos: simple_repo(&["foo"]),
        options: "",
        runs: vec![args],
        pre: None,
        sort: false,
        keyring: false,
    }
}

fn build_cases() -> Vec<Case> {
    let a = Pkg::new("liba", &[], 3000);
    let b = Pkg::new("appb", &["liba"], 5000);
    let big = Pkg::new("bigc", &[], 20000);
    let db = |pk: &[&Pkg]| db_bytes(pk, None);
    let good_files = |pk: &[&Pkg]| -> Files {
        let mut f: Files = vec![("/repo/foo.db".into(), entry(db(pk), 1))];
        for p in pk {
            f.push((format!("/repo/{}", p.filename()), entry(p.body.clone(), 2)));
        }
        f
    };
    let mut cases: Vec<Case> = Vec::new();

    // -Sy: 200, repeat (304), -Syy (forced), 404, 500, failover, truncated, stall
    cases.push(base_case("sy-200", good_files(&[&a]), vec!["-Sy"]));
    let mut c = base_case("sy-up-to-date", good_files(&[&a]), vec!["-Sy"]);
    c.runs = vec![vec!["-Sy"], vec!["-Sy"], vec!["-Syy"]];
    cases.push(c);
    cases.push(base_case("sy-404", vec![], vec!["-Sy"]));
    cases.push(base_case(
        "sy-500",
        vec![(
            "/repo/foo.db".into(),
            with(entry(db(&[&a]), 1), Behavior::Status(500)),
        )],
        vec!["-Sy"],
    ));
    cases.push(base_case(
        "sy-403",
        vec![(
            "/repo/foo.db".into(),
            with(entry(db(&[&a]), 1), Behavior::Status(403)),
        )],
        vec!["-Sy"],
    ));
    cases.push(base_case(
        "sy-truncated",
        vec![(
            "/repo/foo.db".into(),
            with(entry(db(&[&a]), 1), Behavior::Truncated),
        )],
        vec!["-Sy"],
    ));
    cases.push(base_case(
        "sy-stall-low-speed",
        vec![(
            "/repo/foo.db".into(),
            with(entry(db(&[&a]), 1), Behavior::Stall),
        )],
        vec!["-Sy"],
    ));
    let mut c = base_case("sy-failover", vec![], vec!["-Sy"]);
    c.servers = vec![
        vec![(
            "/repo/foo.db".into(),
            with(entry(db(&[&a]), 1), Behavior::Status(500)),
        )],
        good_files(&[&a]),
    ];
    c.repos = Box::new(|p| {
        format!(
            "[foo]\nServer = http://127.0.0.1:{}/repo\nServer = http://127.0.0.1:{}/repo\n",
            p[0], p[1]
        )
    });
    cases.push(c);
    let mut c = base_case("sy-failover-then-hard-fail", vec![], vec!["-Sy"]);
    c.servers = vec![vec![], vec![]];
    c.repos = Box::new(|p| {
        format!(
            "[foo]\nServer = http://127.0.0.1:{}/repo\nServer = http://127.0.0.1:{}/repo\n",
            p[0], p[1]
        )
    });
    cases.push(c);
    let mut c = base_case("sy-bad-host", vec![], vec!["-Sy"]);
    c.repos = Box::new(|_| "[foo]\nServer = http://nonexistent.invalid/repo\n".into());
    cases.push(c);
    let mut c = base_case("sy-bad-url", vec![], vec!["-Sy"]);
    c.repos = Box::new(|_| "[foo]\nServer = nourl\n".into());
    cases.push(c);
    // several repos, parallel downloads
    let mut c = base_case("sy-parallel", vec![], vec!["-Sy"]);
    let mut f = good_files(&[&a]);
    f.push(("/repo/bar.db".into(), entry(db(&[&b]), 3)));
    f.push(("/repo/baz.db".into(), entry(db(&[&big]), 4)));
    c.servers = vec![f];
    c.repos = simple_repo(&["foo", "bar", "baz"]);
    c.options = "ParallelDownloads = 3\n";
    c.sort = true;
    cases.push(c);
    // one repo missing among three: the others must still land in the sync dir? (upstream stops on error)
    let mut c = base_case("sy-parallel-one-missing", vec![], vec!["-Sy"]);
    let mut f = good_files(&[&a]);
    f.push(("/repo/baz.db".into(), entry(db(&[&big]), 4)));
    c.servers = vec![f];
    c.repos = simple_repo(&["foo", "bar", "baz"]);
    c.options = "ParallelDownloads = 2\n";
    c.sort = true;
    cases.push(c);
    // db with a stale local copy and a newer remote
    let mut c = base_case("sy-updates-stale", good_files(&[&a]), vec!["-Sy"]);
    c.pre = Some(Box::new(|d| {
        let p = d.db.join("sync/foo.db");
        std::fs::write(&p, b"old").unwrap();
        let t = libc::timeval {
            tv_sec: 1_500_000_000,
            tv_usec: 0,
        };
        let cp = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        // SAFETY: valid path and two timevals
        unsafe { libc::utimes(cp.as_ptr(), [t, t].as_ptr()) };
    }));
    cases.push(c);
    // signature at DatabaseOptional / DatabaseRequired without a .sig on the server
    let mut c = base_case("sy-dbsig-optional-missing", good_files(&[&a]), vec!["-Sy"]);
    c.options = "SigLevel = Optional TrustAll\n";
    cases.push(c);
    let mut c = base_case("sy-dbsig-required-missing", good_files(&[&a]), vec!["-Sy"]);
    c.options = "SigLevel = Required DatabaseRequired TrustedOnly\n";
    cases.push(c);
    // signature present and valid / tampered
    for (name, tamper) in [
        ("sy-dbsig-required-valid", false),
        ("sy-dbsig-required-tampered", true),
    ] {
        let mut c = base_case(name, vec![], vec!["-Sy"]);
        c.keyring = true;
        c.options = "SigLevel = Required DatabaseRequired TrustedOnly\n";
        let dbb = db(&[&a]);
        let sig = sign_bytes(&dbb, tamper);
        c.servers = vec![vec![
            ("/repo/foo.db".into(), entry(dbb, 1)),
            ("/repo/foo.db.sig".into(), entry(sig, 1)),
        ]];
        cases.push(c);
    }
    // XferCommand with curl
    let mut c = base_case("sy-xfercommand-curl", good_files(&[&a]), vec!["-Sy"]);
    c.options = "XferCommand = /usr/bin/curl -L -C - -f -o %o %u\n";
    cases.push(c);
    let mut c = base_case("sy-xfercommand-fail", vec![], vec!["-Sy"]);
    c.options = "XferCommand = /usr/bin/curl -L -C - -f -o %o %u\n";
    cases.push(c);
    // DownloadUser: under fakeroot the sandbox is selected but the user switch fails identically for both
    let mut c = base_case(
        "sy-sandbox-user-switch-fails",
        good_files(&[&a]),
        vec!["-Sy"],
    );
    c.options = "DownloadUser = nobody\n";
    cases.push(c);
    let mut c = base_case("sy-sandbox-no-such-user", good_files(&[&a]), vec!["-Sy"]);
    c.options = "DownloadUser = nosuchuser\n";
    cases.push(c);
    // -Fy
    let mut c = base_case("fy-files-db", vec![], vec!["-Fy"]);
    c.servers = vec![vec![("/repo/foo.files".into(), entry(db(&[&a]), 1))]];
    cases.push(c);

    // -Sw
    let mut c = base_case(
        "sw-pkg-with-dep",
        good_files(&[&a, &b]),
        vec!["-Sy", "-Sw", "appb"],
    );
    c.runs = vec![vec!["-Sy"], vec!["-Sw", "appb"]];
    cases.push(c);
    let mut c = base_case("sw-twice-cached", good_files(&[&a, &b]), vec![]);
    c.runs = vec![vec!["-Sy"], vec!["-Sw", "appb"], vec!["-Sw", "appb"]];
    cases.push(c);
    let mut c = base_case("sw-not-found", good_files(&[&a]), vec![]);
    c.runs = vec![vec!["-Sy"], vec!["-Sw", "nothere"]];
    cases.push(c);
    let mut c = base_case("sw-pkg-404", good_files(&[&a, &b]), vec![]);
    c.servers[0].retain(|(p, _)| !p.contains("liba"));
    c.runs = vec![vec!["-Sy"], vec!["-Sw", "appb"]];
    cases.push(c);
    let mut c = base_case("sw-resume-part", good_files(&[&a]), vec![]);
    c.runs = vec![vec!["-Sy"], vec!["-Sw", "liba"]];
    let body = a.body.clone();
    let fname = a.filename();
    c.pre = Some(Box::new(move |d| {
        std::fs::create_dir_all(&d.cache).unwrap();
        std::fs::write(
            d.cache.join(format!("{fname}.part")),
            &body[..body.len() / 2],
        )
        .unwrap();
    }));
    cases.push(c);
    let mut c = base_case("sw-size-exceeded", vec![], vec![]);
    c.servers = vec![{
        let mut f = vec![("/repo/foo.db".into(), entry(db_bytes(&[&a], Some(10)), 1))];
        f.push((format!("/repo/{}", a.filename()), entry(a.body.clone(), 2)));
        f
    }];
    c.runs = vec![vec!["-Sy"], vec!["-Sw", "liba"]];
    cases.push(c);
    let mut c = base_case("sw-xfercommand", good_files(&[&a, &b]), vec![]);
    c.options = "XferCommand = /usr/bin/curl -L -C - -f -o %o %u\n";
    c.runs = vec![vec!["-Sy"], vec!["-Sw", "appb"]];
    cases.push(c);
    let mut c = base_case("sw-parallel", good_files(&[&a, &b, &big]), vec![]);
    c.options = "ParallelDownloads = 3\n";
    c.runs = vec![vec!["-Sy"], vec!["-Sw", "appb", "bigc"]];
    c.sort = true;
    cases.push(c);
    let mut c = base_case("sw-pkgsig-optional-missing", good_files(&[&a]), vec![]);
    c.options = "SigLevel = Optional TrustAll\n";
    c.runs = vec![vec!["-Sy"], vec!["-Sw", "liba"]];
    cases.push(c);
    cases
}

// ---------------------------------------------------------------- signing helper

fn gpg(home: &Path, args: &[&str], stdin: Option<&str>) -> String {
    let mut c = Command::new("gpg");
    c.env("GNUPGHOME", home)
        .env("LC_ALL", "C")
        .args([
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
        ])
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    if let Some(s) = stdin {
        ch.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    let o = ch.wait_with_output().unwrap();
    assert!(
        o.status.success(),
        "gpg {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// the one signing home and the verification keyring built from it, created once
fn keyring() -> &'static (PathBuf, PathBuf) {
    static K: std::sync::OnceLock<(PathBuf, PathBuf)> = std::sync::OnceLock::new();
    K.get_or_init(|| {
        let base = std::env::temp_dir().join(format!("pacman-rs-dl-keys-{}", std::process::id()));
        let (s, v) = (base.join("S"), base.join("V"));
        for h in [&s, &v] {
            std::fs::create_dir_all(h).unwrap();
            std::fs::set_permissions(h, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .unwrap();
        }
        std::fs::write(s.join("pubring.gpg"), b"").unwrap();
        for f in ["pubring.gpg", "trustdb.gpg"] {
            std::fs::write(v.join(f), b"").unwrap();
        }
        let out = gpg(
            &s,
            &[
                "--status-fd",
                "1",
                "--quick-gen-key",
                "Dl Test <dl@sig.test>",
                "ed25519",
                "sign",
                "never",
            ],
            None,
        );
        let fpr = out
            .lines()
            .find_map(|l| {
                l.strip_prefix("[GNUPG:] KEY_CREATED ")
                    .map(|r| r[2..].to_string())
            })
            .unwrap();
        std::fs::write(base.join("fpr"), &fpr).unwrap();
        let o = Command::new("gpg")
            .env("GNUPGHOME", &s)
            .args(["--batch", "--export", &fpr])
            .output()
            .unwrap();
        std::fs::write(base.join("pub.gpg"), o.stdout).unwrap();
        gpg(
            &v,
            &["--import", base.join("pub.gpg").to_str().unwrap()],
            None,
        );
        gpg(&v, &["--import-ownertrust"], Some(&format!("{fpr}:6:\n")));
        gpg(&v, &["--check-trustdb"], None);
        let _ = Command::new("gpgconf")
            .args(["--kill", "all"])
            .env("GNUPGHOME", &s)
            .status();
        let _ = Command::new("gpgconf")
            .args(["--kill", "all"])
            .env("GNUPGHOME", &v)
            .status();
        (s, v)
    })
}

fn sign_bytes(data: &[u8], tamper: bool) -> Vec<u8> {
    let (s, _) = keyring();
    let dir = s.parent().unwrap().join(format!("sig-{}", data.len()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("payload");
    std::fs::write(&f, data).unwrap();
    let fpr = std::fs::read_to_string(s.parent().unwrap().join("fpr")).unwrap();
    let sig = dir.join("payload.sig");
    let _ = std::fs::remove_file(&sig);
    gpg(
        s,
        &[
            "--local-user",
            &fpr,
            "--detach-sign",
            "-o",
            sig.to_str().unwrap(),
            f.to_str().unwrap(),
        ],
        None,
    );
    let mut b = std::fs::read(&sig).unwrap();
    if tamper {
        let n = b.len();
        b[n - 3] ^= 0xff;
    }
    b
}

// ---------------------------------------------------------------- running

struct Outcome {
    runs: Vec<(i32, String, String)>,
    files: BTreeMap<String, String>,
    requests: Vec<String>,
}

fn normalize(s: &str, d: &Dirs, ports: &[u16], sort: bool) -> String {
    let mut s = s.replace(d.base.to_str().unwrap(), "$D");
    for (i, p) in ports.iter().enumerate() {
        s = s.replace(&format!("127.0.0.1:{p}"), &format!("127.0.0.1:$P{i}"));
    }
    // curl's progress meter (XferCommand without -s) differs in its speed numbers
    let s = s.replace('\r', "\n");
    let mut lines: Vec<&str> = s
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !(l.contains("Dload")
                || t.starts_with("% Total")
                || (t.starts_with(|c: char| c.is_ascii_digit()) && t.contains("   ")))
        })
        .collect();
    if sort {
        lines.sort();
    }
    lines.join("\n")
}

fn tree(root: &Path, dir: &Path, mtimes: bool, out: &mut BTreeMap<String, String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
        if p.is_dir() {
            out.insert(rel.clone(), "dir".into());
            tree(root, &p, mtimes, out);
        } else {
            use std::os::unix::fs::MetadataExt;
            let b = std::fs::read(&p).unwrap_or_default();
            let m = std::fs::metadata(&p).unwrap();
            out.insert(
                rel,
                format!(
                    "{} {:x} mtime={} mode={:o}",
                    b.len(),
                    Sha256::digest(&b),
                    // only the remote times the server sent are comparable; anything else is "now"
                    if mtimes && (T0..T0 + 10_000).contains(&m.mtime()) {
                        m.mtime()
                    } else {
                        0
                    },
                    m.mode() & 0o7777
                ),
            );
        }
    }
}

fn run_program(bin: &str, case: &Case, idx: &AtomicUsize) -> Outcome {
    let base = std::env::temp_dir().join(format!(
        "pacman-rs-dl-{}-{}-{}",
        std::process::id(),
        case.name,
        idx.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&base);
    let d = Dirs {
        root: base.join("root"),
        db: base.join("db"),
        cache: base.join("cache"),
        gpg: base.join("gpg"),
        log: base.join("log"),
        conf: base.join("pacman.conf"),
        base: base.clone(),
    };
    for p in [
        &d.root,
        &d.db.join("local"),
        &d.db.join("sync"),
        &d.cache,
        &d.gpg,
    ] {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(d.db.join("local/ALPM_DB_VERSION"), "9\n").unwrap();
    std::fs::set_permissions(&d.gpg, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    if case.keyring {
        let (_, v) = keyring();
        for f in ["pubring.gpg", "trustdb.gpg"] {
            std::fs::copy(v.join(f), d.gpg.join(f)).unwrap();
        }
    }
    let servers: Vec<Server> = case
        .servers
        .iter()
        .map(|f| Server::start(f.clone()))
        .collect();
    let ports: Vec<u16> = servers.iter().map(|s| s.port).collect();
    let conf = format!(
        "[options]\nRootDir = {}\nDBPath = {}\nCacheDir = {}/\nLogFile = {}\nGPGDir = {}\nHookDir = {}/hooks\nSigLevel = Never\nLocalFileSigLevel = Never\n{}{}",
        d.root.display(),
        d.db.display(),
        d.cache.display(),
        d.log.display(),
        d.gpg.display(),
        d.base.display(),
        case.options,
        (case.repos)(&ports)
    );
    std::fs::write(&d.conf, conf).unwrap();
    if let Some(pre) = &case.pre {
        pre(&d);
    }
    let mut runs = Vec::new();
    for args in &case.runs {
        let o = Command::new("fakeroot")
            .arg("--")
            .arg(bin)
            .args([
                "--config",
                d.conf.to_str().unwrap(),
                "--noprogressbar",
                "--noconfirm",
            ])
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .output()
            .unwrap();
        runs.push((
            o.status.code().unwrap_or(-1),
            normalize(&String::from_utf8_lossy(&o.stdout), &d, &ports, case.sort),
            normalize(&String::from_utf8_lossy(&o.stderr), &d, &ports, case.sort),
        ));
    }
    let mut files = BTreeMap::new();
    for sub in [&d.db, &d.cache] {
        tree(
            &d.base,
            sub,
            !case.options.contains("XferCommand"),
            &mut files,
        );
    }
    files.retain(|k, _| !k.ends_with("ALPM_DB_VERSION"));
    let mut requests: Vec<String> = servers
        .iter()
        .enumerate()
        .flat_map(|(i, s)| {
            s.log
                .lock()
                .unwrap()
                .iter()
                .map(move |l| format!("S{i} {l}"))
                .collect::<Vec<_>>()
        })
        .collect();
    requests.sort();
    let _ = Command::new("gpgconf")
        .args(["--kill", "all"])
        .env("GNUPGHOME", &d.gpg)
        .status();
    let _ = std::fs::remove_dir_all(&base);
    Outcome {
        runs,
        files,
        requests,
    }
}

fn diff_outcomes(case: &Case, a: &Outcome, b: &Outcome) -> Vec<String> {
    let mut v = Vec::new();
    for (i, (x, y)) in a.runs.iter().zip(&b.runs).enumerate() {
        if x.0 != y.0 {
            v.push(format!("run {i}: exit {} vs {}", x.0, y.0));
        }
        if x.1 != y.1 && compares_stdout(&case.runs[i]) {
            v.push(format!(
                "run {i}: stdout\n--- ours\n{}\n--- system\n{}",
                x.1, y.1
            ));
        }
        if x.2 != y.2 {
            v.push(format!(
                "run {i}: stderr\n--- ours\n{}\n--- system\n{}",
                x.2, y.2
            ));
        }
    }
    if a.files != b.files {
        v.push(format!(
            "files\n--- ours\n{:#?}\n--- system\n{:#?}",
            a.files, b.files
        ));
    }
    if a.requests != b.requests {
        v.push(format!(
            "requests\n--- ours\n{:#?}\n--- system\n{:#?}",
            a.requests, b.requests
        ));
    }
    v
}

#[test]
fn downloads_match_pacman() {
    if !Path::new(SYS).exists()
        || !Path::new("/usr/bin/fakeroot").exists()
        || !Path::new("/usr/bin/curl").exists()
    {
        eprintln!("skip: pacman, fakeroot or curl missing");
        return;
    }
    let ours = env!("CARGO_BIN_EXE_pacman-rs");
    let cases = build_cases();
    let only = std::env::var("DL_DIFF_ONLY").ok();
    let idx = AtomicUsize::new(0);
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(&'static str, Vec<String>)>> = Mutex::new(Vec::new());
    std::thread::scope(|sc| {
        for _ in 0..6 {
            sc.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(c) = cases.get(i) else { break };
                    if only.as_deref().is_some_and(|o| !c.name.contains(o)) {
                        continue;
                    }
                    let a = run_program(ours, c, &idx);
                    let b = run_program(SYS, c, &idx);
                    let d = diff_outcomes(c, &a, &b);
                    results.lock().unwrap().push((c.name, d));
                }
            });
        }
    });
    let mut r = results.into_inner().unwrap();
    r.sort_by_key(|x| x.0);
    let mut failed = 0;
    for (name, d) in &r {
        if d.is_empty() {
            eprintln!("ok   {name}");
        } else {
            failed += 1;
            eprintln!("FAIL {name}");
            for x in d.iter().take(4) {
                eprintln!("    {x}");
            }
        }
    }
    eprintln!("download cases: {} run, {} failed", r.len(), failed);
    assert_eq!(failed, 0);
    let _ = std::fs::remove_dir_all(keyring().0.parent().unwrap());
}
