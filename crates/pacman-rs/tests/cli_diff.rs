//! Differential test of the whole CLI against /usr/bin/pacman: read-only commands only (never -S -y, -D,
//! -R, -U, never a transaction), run under LC_ALL=C with several terminal widths and colour settings.
//! stdout, stderr and the exit status must be identical. Skips when /usr/bin/pacman is missing.
//! `CLI_DIFF_ONLY=<family>` restricts the run to one command family.
use libalpm_rs::alpm::alpm_initialize;
use libalpm_rs::package::{PkgFrom, PkgReason};
use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

const SYS: &str = "/usr/bin/pacman";

#[derive(Clone)]
struct Case {
    family: &'static str,
    cols: &'static str,
    args: Vec<String>,
}

fn run(bin: &str, c: &Case) -> (Vec<u8>, Vec<u8>, i32) {
    let o = Command::new(bin)
        .arg0("pacman")
        .args(&c.args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("COLUMNS", c.cols)
        .env("TZ", "UTC")
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .unwrap();
    (o.stdout, o.stderr, o.status.code().unwrap_or(-1))
}

/// first differing line, for the report
fn first_diff(a: &[u8], b: &[u8]) -> String {
    let (a, b) = (String::from_utf8_lossy(a), String::from_utf8_lossy(b));
    let (la, lb): (Vec<_>, Vec<_>) = (a.lines().collect(), b.lines().collect());
    for i in 0..la.len().max(lb.len()) {
        if la.get(i) != lb.get(i) {
            return format!(
                "line {}: ours {:?} | system {:?}",
                i + 1,
                la.get(i),
                lb.get(i)
            );
        }
    }
    "(no line differs: trailing newline?)".into()
}

fn out_lines(args: &[&str]) -> Vec<String> {
    let o = Command::new(SYS)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .map(String::from)
        .collect()
}

fn s(a: &[&str]) -> Vec<String> {
    a.iter().map(|x| x.to_string()).collect()
}

fn build_cases() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    let mut add = |family: &'static str, cols: &[&'static str], args: Vec<String>| {
        for c in cols {
            cases.push(Case {
                family,
                cols: c,
                args: args.clone(),
            });
        }
    };
    const W: &[&str] = &["80", "120", "200"];
    const W1: &[&str] = &["80"];

    let mut alpm = alpm_initialize("/", "/var/lib/pacman").expect("local db");
    let repos = Command::new("/usr/bin/pacman-conf")
        .arg("--repo-list")
        .output()
        .unwrap()
        .stdout;
    for r in String::from_utf8_lossy(&repos).lines() {
        alpm.register_syncdb(r, 0).unwrap();
    }
    let pkgs = alpm.localdb.get_pkgcache().unwrap();
    let by_key = |f: &dyn Fn(&libalpm_rs::package::Pkg) -> usize, n: usize| -> Vec<String> {
        let mut v: Vec<_> = pkgs.iter().map(|p| (f(p), p.name.clone())).collect();
        v.sort_by(|a, b| b.cmp(a));
        v.into_iter().take(n).map(|x| x.1).collect()
    };
    let mut edge: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    edge.insert(
        "epoch",
        pkgs.iter()
            .filter(|p| p.version.contains(':'))
            .take(4)
            .map(|p| p.name.clone())
            .collect(),
    );
    edge.insert(
        "longdesc",
        by_key(&|p| p.desc().desc.as_deref().map_or(0, str::len), 4),
    );
    edge.insert("manydeps", by_key(&|p| p.desc().depends.len(), 4));
    edge.insert("optdeps", by_key(&|p| p.desc().optdepends.len(), 4));
    edge.insert("provides", by_key(&|p| p.desc().provides.len(), 3));
    edge.insert(
        "conflicts",
        by_key(&|p| p.desc().conflicts.len() + p.desc().replaces.len(), 3),
    );
    edge.insert("licenses", by_key(&|p| p.desc().licenses.len(), 3));
    edge.insert(
        "scriptlet",
        pkgs.iter()
            .filter(|p| p.has_scriptlet())
            .take(4)
            .map(|p| p.name.clone())
            .collect(),
    );
    edge.insert(
        "backup",
        pkgs.iter()
            .filter(|p| p.backup().iter().any(|b| b.hash.is_some()))
            .take(4)
            .map(|p| p.name.clone())
            .collect(),
    );
    edge.insert(
        "groups",
        pkgs.iter()
            .filter(|p| !p.desc().groups.is_empty())
            .take(4)
            .map(|p| p.name.clone())
            .collect(),
    );
    edge.insert(
        "asdeps",
        pkgs.iter()
            .filter(|p| p.desc().reason == PkgReason::Depend)
            .take(3)
            .map(|p| p.name.clone())
            .collect(),
    );
    edge.insert("bigfiles", by_key(&|p| p.files().files.len(), 3));
    edge.insert(
        "nofiles",
        pkgs.iter()
            .filter(|p| p.files().files.is_empty())
            .take(2)
            .map(|p| p.name.clone())
            .collect(),
    );
    let foreign: Vec<String> = out_lines(&["-Qmq"]);
    edge.insert("foreign", foreign.iter().take(4).cloned().collect());
    let mut seed = 0x9E3779B97F4A7C15u64;
    let mut random = Vec::new();
    for _ in 0..30 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        random.push(pkgs[(seed % pkgs.len() as u64) as usize].name.clone());
    }
    edge.insert("random", random);
    let mut sample: Vec<String> = edge.values().flatten().cloned().collect();
    sample.sort();
    sample.dedup();
    let groups: Vec<String> = alpm
        .localdb
        .get_groupcache()
        .unwrap()
        .iter()
        .map(|g| g.name.clone())
        .take(3)
        .collect();
    let syncs: Vec<String> = alpm.syncdbs.iter().map(|d| d.name().to_string()).collect();
    let mut sync_sample: Vec<String> = Vec::new();
    for d in &alpm.syncdbs {
        let cache = d.get_pkgcache().unwrap();
        for p in cache.iter().step_by((cache.len() / 12).max(1)).take(12) {
            sync_sample.push(format!("{}/{}", d.name(), p.name));
        }
    }
    for n in sample.iter().take(20) {
        if let Some(sp) = alpm
            .syncdbs
            .iter()
            .find_map(|d| d.pkg_from_cache(n).map(|_| d.name()))
        {
            sync_sample.push(format!("{sp}/{n}"));
        }
    }
    sync_sample.sort();
    sync_sample.dedup();
    drop(alpm);

    // --- whole-database queries
    for a in [
        &["-Q"][..],
        &["-Qq"],
        &["-Qe"],
        &["-Qd"],
        &["-Qdq"],
        &["-Qt"],
        &["-Qtt"],
        &["-Qtq"],
        &["-Qm"],
        &["-Qn"],
        &["-Qmq"],
        &["-Qeq"],
        &["-Qdt"],
        &["-Qet"],
        &["-Qg"],
        &["-Qgq"],
        &["-Qu"],
        &["-Qua"],
        &["-Quq"],
        &["-Qdtt"],
        &["-Qmt"],
        &["-Qdm"],
    ] {
        add("q-list", W1, s(a));
    }
    for a in [
        &["-Qi"][..],
        &["-Qii"],
        &["-Ql"],
        &["-Qlq"],
        &["-Qs", ""],
        &["-Qsq", "lib"],
        &["-Qk"],
        &["-Qkq"],
        &["-Qc"],
    ] {
        add("q-all", W1, s(a));
    }
    add("q-all", &["120"], s(&["-Qi"]));
    add("q-all", &["200"], s(&["-Qii"]));
    // -Qkk reads every file: restrict to a sample below
    // --- per package
    for n in &sample {
        add("q-info", W, s(&["-Qi", n]));
        add("q-info", W1, s(&["-Qii", n]));
        add("q-list", W1, s(&["-Ql", n]));
        add("q-list", W1, s(&["-Qlq", n]));
        add("q-check", W1, s(&["-Qk", n]));
        add("q-check", W1, s(&["-Qkq", n]));
        add("q-misc", W1, s(&["-Q", n]));
        add("q-misc", W1, s(&["-Qq", n]));
        add("q-misc", W1, s(&["-Qc", n]));
    }
    for n in sample.iter().step_by(4) {
        add("q-check", W1, s(&["-Qkk", n]));
    }
    add(
        "q-info",
        &["80"],
        s(&["--color", "always", "-Qi", &sample[0]]),
    );
    add(
        "q-info",
        &["80"],
        s(&["--color", "always", "-Qii", &sample[sample.len() / 2]]),
    );
    add(
        "q-list",
        &["80"],
        s(&["--color", "always", "-Ql", &sample[1]]),
    );
    add("q-list", &["80"], s(&["--color", "always", "-Qu"]));
    add("q-list", &["80"], s(&["--color", "always", "-Q"]));
    add(
        "q-list",
        &["80"],
        s(&["--color", "never", "-Q", &sample[1], &sample[2]]),
    );
    add(
        "q-search",
        &["80", "120", "200"],
        s(&["--color", "always", "-Qs", "^lib.*[0-9]$"]),
    );
    add("q-search", &["80"], s(&["--color", "always", "-Qg"]));
    // several targets at once, with local/ prefix and satisfiers (provides)
    add(
        "q-info",
        W1,
        s(&["-Qi", &format!("local/{}", sample[0]), &sample[1]]),
    );
    add(
        "q-misc",
        W1,
        s(&["-Q", "sh", "libc.so=6-64", "nonexistent-pkg", "bash>=1"]),
    );
    add("q-misc", W1, s(&["-Qq", "-e", "-t", "-n"]));
    // --- search
    for rx in [
        "^zlib",
        "linux",
        "python|perl",
        "^[a-c].{2}$",
        "kernel module",
        "compress",
        "x",
        "\\.so",
        "(gcc|clang)",
        "zstd",
        "^$",
    ] {
        add("q-search", W, s(&["-Qs", rx]));
    }
    add("q-search", W1, s(&["-Qs", "gcc", "lib"]));
    add("q-search", W1, s(&["-Qsq", "gcc", "lib"]));
    add("q-search", W1, s(&["-Qs"]));
    for g in &groups {
        add("q-group", W1, s(&["-Qg", g]));
        add("q-group", W1, s(&["-Qgq", g]));
        add("q-group", W1, s(&["-Qge", g]));
    }
    // --- owners
    for f in [
        "/usr/bin/ls",
        "ls",
        "/usr/lib",
        "/usr/lib/",
        "/etc/pacman.conf",
        "/nonexistent/file",
        "/",
        "pacman",
        "/bin/sh",
        "/usr/bin/../bin/sh",
        "/tmp",
        "bash",
        "/etc/",
        "usr/bin/ls",
    ] {
        add("q-owns", W1, s(&["-Qo", f]));
        add("q-owns", W1, s(&["-Qoq", f]));
    }
    add(
        "q-owns",
        W1,
        s(&["-Qo", "/usr/bin/ls", "/etc/pacman.conf", "/zzz"]),
    );
    add("q-owns", W1, s(&["-Qo", ""]));
    add("q-owns", W1, s(&["-Qo"]));
    // --- package files (symlinked into a directory without .sig files)
    let cache = std::path::Path::new("/var/cache/pacman/pkg");
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cli-diff-pkgs");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let mut files: Vec<PathBuf> = std::fs::read_dir(cache)
        .map(|d| {
            d.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.to_string_lossy().contains(".pkg.tar")
                        && !p.to_string_lossy().ends_with(".sig")
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    let step = (files.len() / 10).max(1);
    for f in files.iter().step_by(step).take(10) {
        let link = tmp.join(f.file_name().unwrap());
        let _ = std::os::unix::fs::symlink(f, &link);
        let l = link.to_string_lossy().into_owned();
        add("q-file", W, s(&["-Qip", &l]));
        add("q-file", W1, s(&["-Qlp", &l]));
        add("q-file", W1, s(&["-Qlpq", &l]));
        add("q-file", W1, s(&["-Qp", &l]));
        add("q-file", W1, s(&["-Qpc", &l]));
        add("q-file", W1, s(&["-Qipii", &l]));
    }
    // --- sync database (read only)
    for a in [
        &["-Sl"][..],
        &["-Slq"],
        &["-Sg"],
        &["-Sgq"],
        &["-Sgg"],
        &["-Ss", ""],
        &["-Ssq", "^lib"],
        &["-Si"],
    ] {
        add("s-all", W1, s(a));
    }
    add("s-all", &["120"], s(&["-Si"]));
    for r in &syncs {
        add("s-list", W1, s(&["-Sl", r]));
        add("s-list", W1, s(&["-Slq", r]));
    }
    add("s-list", W1, s(&["-Sl", &syncs[0], "nonexistent-repo"]));
    add(
        "s-list",
        &["80"],
        s(&["--color", "always", "-Sl", &syncs[0]]),
    );
    for n in &sync_sample {
        add("s-info", W, s(&["-Si", n]));
        add("s-info", W1, s(&["-Sii", n]));
    }
    add(
        "s-info",
        W1,
        s(&["--color", "always", "-Si", &sync_sample[0]]),
    );
    for rx in [
        "^zlib",
        "linux",
        "python|perl",
        "kernel module",
        "x",
        "compress",
    ] {
        add("s-search", W, s(&["-Ss", rx]));
        add("s-search", W1, s(&["-Ssq", rx]));
        add("s-search", W1, s(&["--color", "always", "-Ss", rx]));
    }
    add("s-search", W1, s(&["-Ss", "gcc", "lib"]));
    for g in [
        "base-devel",
        "gnome",
        "kde-applications",
        "nonexistent-group",
        "xorg",
    ] {
        add("s-group", W1, s(&["-Sg", g]));
        add("s-group", W1, s(&["-Sgq", g]));
    }
    // --- dependency test
    for a in [
        &["-T"][..],
        &["-T", "bash"],
        &["-T", "bash>=1"],
        &["-T", "bash>=999"],
        &["-T", "nonexistent", "bash", "sh"],
        &["-T", "libc.so=6-64"],
        &["-T", "pacman<5", "glibc=1:2"],
        &["-T", "pacman: with desc"],
    ] {
        add("deptest", W1, s(a));
    }
    // --- bad input, usage, version, option errors
    let bad: &[&[&str]] = &[
        &["-Qi", "nonexistent-package"],
        &["-Qi", "nonexistent-1", "nonexistent-2"],
        &["-Qs", "["],
        &["-Qs", "("],
        &["-Qs", "*a"],
        &["-Ss", "["],
        &["-Ss", "+"],
        &["-Qg", "nonexistent-group"],
        &["-Sg", "nonexistent-group"],
        &["-Si", "nonexistent/pkg"],
        &["-Si", "core/nonexistent"],
        &["-Sl", "nonexistent"],
        &["-Qo", "/nonexistent"],
        &["-Ql", "nonexistent"],
        &["-Qk", "nonexistent"],
        &["-Qp"],
        &["-Qp", "/nonexistent.pkg.tar.zst"],
        &["-Qp", "/etc/pacman.conf"],
        &["-Qip", "/etc/hostname"],
        &["-Qo", "-p"],
        &["-Qs", "-g"],
        &["-Qs", "-o"],
        &["-Qg", "-i"],
        &["-Qs", "-i"],
        &["-Qo", "-l"],
        &["-Qs", "-e"],
        &["-Qo", "-u"],
        &["-Qd", "-e"],
        &["-Qn", "-m"],
        &["-Qgk"],
        &["-Qpg"],
        &["-Qps"],
        &["-QS"],
        &["-QR"],
        &["-SQ"],
        &["-Q", "-S"],
        &["--query", "--sync"],
        &["-Sc", "-g"],
        &["-Si", "-g"],
        &["-Ss", "-l"],
        &["-Sl", "-g"],
        &["-Sg", "-u"],
        &["-Ss", "x", "-u"],
        &["-Si", "-l"],
        &["-Sc", "-i"],
        &["-Sc", "-y"],
        &["--bogus"],
        &["-Q", "--bogus"],
        &["-Q", "-Z"],
        &["-Qx"],
        &["-Q", "--sysupgrade"],
        &["-T", "-q"],
        &["-Qi", "--cachedir"],
        &["--color", "bogus", "-Q"],
        &["--color"],
        &["-Q", "--debug=9"],
        &["-Q", "--ask=abc"],
        &["-Q", "--dbpath", "/nonexistent"],
        &["-Q", "--root", "/nonexistent"],
        &["-Q", "--config", "/nonexistent"],
        &["-Q", "--config"],
        &["-Q", "--logfile"],
        &["-Q", "--gpgdir", "/nonexistent"],
        &["-Q", "--hookdir", "/nonexistent"],
        &["-Q", "--cachedir", "/nonexistent"],
        &["-Q", "--sysroot", "/nonexistent"],
        &[],
        &["-h"],
        &["-V"],
        &["--help"],
        &["--version"],
        &["-Qh"],
        &["-Sh"],
        &["-Rh"],
        &["-Uh"],
        &["-Dh"],
        &["-Fh"],
        &["-Th"],
        &["-Sh", "-V"],
        &["-QQ"],
        &["--q"],
        &["--que"],
        &["--quer", "-i", "bash"],
        &["-Qq", "--info", "bash"],
        &["--que", "--in", "bash"],
        &["-S"],
        &["-S", "bash"],
        &["-R", "bash"],
        &["-U", "x"],
        &["-D", "x"],
        &["-Sy"],
        &["-Su"],
        &["-Sc"],
        &["-Rns", "bash"],
        &["-Q", "-"],
        &["-Q", "--noconfirm", "--confirm", "bash"],
        &["-Q", "--nodeps", "bash"],
        &["-Q", "--print", "bash"],
        &["-Qi", "--", "-bash"],
        &["-Qi", "bash", "--", "-x"],
        &["-V", "-Q"],
        &["-h", "-Q"],
        &["-Ql", "--root", "/", "bash"],
        &["-Qi", "-v", "bash"],
        &["-Qv", "bash"],
        &["-Qvv", "bash"],
        &["-Q", "-b", "/var/lib/pacman", "bash"],
        &["-Q", "-r", "/", "bash"],
        &["-Q", "--arch", "x86_64", "bash"],
        &["-Qq", "--noprogressbar", "bash"],
        &["-Q", "--disable-sandbox", "bash"],
        &["-Ql", "bash", "glibc", "nonexistent"],
        &["-Qo", "/usr/bin/bash", "-q"],
        &["-Qc", "bash"],
        &["-Qc", "nonexistent"],
    ];
    for a in bad {
        add("bad-input", W1, s(a));
    }
    add("bad-input", &["120"], s(&["-Qi"]));
    add("bad-input", &["0"], s(&["-Qi", &sample[0]]));
    add("bad-input", &["10"], s(&["-Qi", &sample[0]]));
    add("bad-input", &["abc"], s(&["-Qi", &sample[0]]));
    cases
}

#[test]
fn cli_matches_pacman() {
    if !std::path::Path::new(SYS).exists()
        || !std::path::Path::new("/var/lib/pacman/local/ALPM_DB_VERSION").exists()
    {
        eprintln!("skip: no system pacman or database");
        return;
    }
    let ours = env!("CARGO_BIN_EXE_pacman-rs").to_string();
    let mut cases = build_cases();
    if let Ok(only) = std::env::var("CLI_DIFF_ONLY") {
        cases.retain(|c| c.family == only);
    }
    let lock_before = std::path::Path::new("/var/lib/pacman/db.lck").exists();
    let results: Mutex<BTreeMap<&'static str, (usize, Vec<String>)>> = Mutex::new(BTreeMap::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|sc| {
        for _ in 0..8 {
            sc.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(c) = cases.get(i) else { break };
                    let a = run(&ours, c);
                    let b = run(SYS, c);
                    let mut r = results.lock().unwrap();
                    let e = r.entry(c.family).or_default();
                    if a == b {
                        e.0 += 1;
                    } else {
                        let what = if a.2 != b.2 {
                            format!("exit {} vs {}", a.2, b.2)
                        } else if a.0 != b.0 {
                            format!("stdout: {}", first_diff(&a.0, &b.0))
                        } else {
                            format!("stderr: {}", first_diff(&a.1, &b.1))
                        };
                        e.1.push(format!(
                            "COLUMNS={} {} -> {}",
                            c.cols,
                            c.args.join(" "),
                            what
                        ));
                    }
                }
            });
        }
    });
    assert_eq!(
        lock_before,
        std::path::Path::new("/var/lib/pacman/db.lck").exists(),
        "db.lck appeared or vanished"
    );
    let r = results.into_inner().unwrap();
    let mut failed = 0;
    for (fam, (pass, fails)) in &r {
        eprintln!("{fam}: {pass} passed, {} failed", fails.len());
        for f in fails.iter().take(15) {
            eprintln!("    MISMATCH {f}");
        }
        failed += fails.len();
    }
    assert_eq!(failed, 0, "{failed} mismatches");
}

#[test]
fn never_creates_db_lock() {
    if !std::path::Path::new("/var/lib/pacman/local/ALPM_DB_VERSION").exists() {
        return;
    }
    let before = std::path::Path::new("/var/lib/pacman/db.lck").exists();
    for a in [
        &["-Q"][..],
        &["-Qi", "pacman"],
        &["-Ss", "x"],
        &["-T", "bash"],
    ] {
        let _ = Command::new(env!("CARGO_BIN_EXE_pacman-rs"))
            .args(a)
            .output()
            .unwrap();
        assert_eq!(
            before,
            std::path::Path::new("/var/lib/pacman/db.lck").exists()
        );
    }
}

// PkgFrom is imported for future family filters
#[allow(dead_code)]
const _F: Option<PkgFrom> = None;

/// -Qip prints the signature results of a package file: run against a temp COPY of the system keyring
/// (--gpgdir), never the real one.
#[test]
fn qip_signature_display_matches_pacman() {
    let src = std::path::Path::new("/etc/pacman.d/gnupg");
    let cache = std::path::Path::new("/var/cache/pacman/pkg");
    if !std::path::Path::new(SYS).exists() || !src.join("pubring.gpg").exists() || !cache.exists() {
        eprintln!("skip: no system pacman, keyring or cache");
        return;
    }
    let home = std::env::temp_dir().join(format!("pacman-rs-qip-gnupg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    std::fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    for f in ["pubring.gpg", "trustdb.gpg", "gpg.conf"] {
        if src.join(f).exists() {
            std::fs::copy(src.join(f), home.join(f)).unwrap();
        }
    }
    let mut pkgs: Vec<PathBuf> = std::fs::read_dir(cache)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.to_string_lossy().ends_with(".pkg.tar.zst")
                && PathBuf::from(format!("{}.sig", p.display())).exists()
        })
        .collect();
    pkgs.sort();
    pkgs.truncate(30);
    // plus one without a signature file, if any
    if let Some(p) = std::fs::read_dir(cache)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.to_string_lossy().ends_with(".pkg.tar.zst")
                && !PathBuf::from(format!("{}.sig", p.display())).exists()
        })
    {
        pkgs.push(p);
    }
    let ours = env!("CARGO_BIN_EXE_pacman-rs");
    let mut bad = Vec::new();
    for p in &pkgs {
        for cols in ["200", "60"] {
            let c = Case {
                family: "qip-sig",
                cols: if cols == "200" { "200" } else { "60" },
                args: s(&[
                    "--gpgdir",
                    home.to_str().unwrap(),
                    "-Qip",
                    p.to_str().unwrap(),
                ]),
            };
            let (a, b) = (run(ours, &c), run(SYS, &c));
            if a != b {
                bad.push(format!(
                    "{} COLUMNS={cols}: {}",
                    p.display(),
                    first_diff(&a.0, &b.0)
                ));
            }
        }
    }
    eprintln!("qip-sig: {} cases, {} failed", pkgs.len() * 2, bad.len());
    let _ = Command::new("gpgconf")
        .args(["--kill", "all"])
        .env("GNUPGHOME", &home)
        .status();
    let _ = std::fs::remove_dir_all(&home);
    assert!(bad.is_empty(), "{bad:#?}");
}
