//! Differential test: our pacman-conf against /usr/bin/pacman-conf (stdout, stderr, exit code).
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const SYS: &str = "/usr/bin/pacman-conf";

fn run(bin: &str, args: &[&str]) -> (String, String, i32) {
    let o = Command::new(bin)
        .arg0("pacman-conf")
        .args(args)
        .output()
        .unwrap();
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
        o.status.code().unwrap_or(-1),
    )
}

fn check(args: &[&str]) {
    let ours = run(env!("CARGO_BIN_EXE_pacman-conf"), args);
    let sys = run(SYS, args);
    assert_eq!(ours, sys, "args {args:?}");
}

fn skip() -> bool {
    if !Path::new(SYS).exists() {
        eprintln!("skip: {SYS} missing");
    }
    !Path::new(SYS).exists()
}

fn root(n: &str) -> PathBuf {
    let r = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("pconf-{n}"));
    let _ = std::fs::remove_dir_all(&r);
    std::fs::create_dir_all(&r).unwrap();
    r
}

const ARGSETS: &[&[&str]] = &[
    &[],
    &["-v"],
    &["-l"],
    &["-l", "-r", "core"],
    &["-r", "core"],
    &["-r", "nonexistent"],
    &[
        "-r", "core", "Server", "usage", "SIGLEVEL", "Include", "bogus",
    ],
    &["Server"],
    &["RootDir"],
    &["rootdir", "DBPath", "bogus"],
    &["-v", "HoldPkg"],
    &["-l", "x"],
    &[
        "CacheDir",
        "HookDir",
        "GPGDir",
        "LogFile",
        "DownloadUser",
        "HoldPkg",
        "IgnorePkg",
        "IgnoreGroup",
        "NoUpgrade",
        "NoExtract",
    ],
    &[
        "Architecture",
        "XferCommand",
        "UseSyslog",
        "Color",
        "CheckSpace",
        "VerbosePkgLists",
        "DisableDownloadTimeout",
        "ILoveCandy",
        "NoProgressBar",
    ],
    &[
        "DisableSandbox",
        "DisableSandboxFilesystem",
        "DisableSandboxSyscalls",
        "ParallelDownloads",
        "CleanMethod",
        "SigLevel",
        "LocalFileSigLevel",
        "RemoteFileSigLevel",
        "Include",
    ],
    &["-R", "/tmp"],
    &["-R", "/tmp/", "DBPath", "LogFile"],
    &["-S", "/tmp", "RootDir", "DBPath"],
];

fn matrix(cfg: &Path) {
    let c = cfg.to_str().unwrap();
    for a in ARGSETS {
        let mut v = vec!["--config", c];
        v.extend_from_slice(a);
        check(&v);
    }
}

#[test]
fn live_config() {
    if skip() {
        return;
    }
    for a in ARGSETS {
        check(a);
    }
}

#[test]
fn options_and_usage() {
    if skip() {
        return;
    }
    let r = root("opts");
    let cfg = r.join("min.conf");
    std::fs::write(&cfg, "[options]\n[core]\nServer = http://x/$repo\n").unwrap();
    let c = cfg.to_str().unwrap();
    for a in [
        vec!["-h"],
        vec!["--help"],
        vec!["-V"],
        vec!["--version"],
        vec!["-x"],
        vec!["--bogus"],
        vec!["--bogus=1"],
        vec!["--conf", c],
        vec!["--config"],
        vec!["-c"],
        vec!["--r"],
        vec!["--re"],
        vec!["--rep"],
        vec!["--repo"],
        vec!["--repo-l"],
        vec!["--repo-list=3"],
        vec!["--verbose=x"],
        vec!["-vl", "--config", c],
        vec!["-lc", c],
        vec!["-c", c, "-vl"],
        vec!["Server", "-c", c],
        vec!["-c", c, "--", "-v"],
        vec!["-c", c, "--", "Server", "-r"],
        vec!["-"],
        vec!["-c", c, "-"],
        vec!["-cx"],
        vec!["-vx"],
        vec!["-c", "/nonexistent"],
        vec!["-c", "/tmp"],
        vec!["-h", "-c", "/nonexistent"],
        vec!["-c", c, "-r", "core", "-l"],
        vec!["--sysroot=/nonexistent", "-c", c],
        vec!["-S", "/nonexistent", "-c", c],
        vec!["-c", c, "-R", "/nonexistent", "RootDir", "DBPath"],
        vec!["-c", c, "--rootdir=/a//", "DBPath"],
        vec!["-c", c, "-R", "/", "DBPath", "LogFile"],
    ] {
        check(&a);
    }
}

#[test]
fn synthetic_configs() {
    if skip() {
        return;
    }
    let r = root("synth");
    let d = |n: &str| {
        let p = r.join(n);
        std::fs::create_dir_all(&p).unwrap();
        p.to_str().unwrap().to_string()
    };
    let (c1, c2, h1, g1) = (d("cache1"), d("cache2"), d("hooks"), d("gpg"));
    let (root_d, db_d) = (d("rootdir"), d("db"));
    let w = |n: &str, s: &str| {
        let p = r.join(n);
        std::fs::write(&p, s).unwrap();
        p
    };
    let full = format!(
        "# comment\n[options]\nRootDir = {root_d}\nDBPath = {db_d}\nCacheDir = {c1}\nCacheDir = {c2}\nHookDir = {h1}\nGPGDir = {g1}\n\
LogFile = /tmp/x.log\nDownloadUser = alpm\nHoldPkg = a b  c\nHoldPkg = d\nIgnorePkg = i1 i2\nIgnoreGroup = g1\nNoUpgrade = etc/foo etc/bar\n\
NoExtract = usr/share/doc/*\nArchitecture = x86_64 auto\nXferCommand = /usr/bin/curl -fC - --retry 3 %u -o '%o x'\nUseSyslog\nColor\nCheckSpace\n\
VerbosePkgLists\nDisableDownloadTimeout\nILoveCandy\nNoProgressBar\nDisableSandbox\nParallelDownloads = 3\nCleanMethod = KeepInstalled KeepCurrent\n\
SigLevel = Required DatabaseOptional\nLocalFileSigLevel = Optional\nRemoteFileSigLevel = Required\n\
[core]\nServer = http://mirror/$repo/os/$arch\nCacheServer = http://cache/$repo\nSigLevel = Never\nUsage = Sync Search\n\
[extra]\nServer = file:///srv/$repo\nSigLevel = PackageRequired DatabaseNever TrustAll\nUsage = All\n[custom]\nUsage = Install Upgrade\nSigLevel = PackageTrustedOnly\n"
    );
    let mut cfgs: Vec<(String, String)> = vec![("full".into(), full)];
    let bodies: &[(&str, &str)] = &[
        ("empty", ""),
        ("noprefix", "Foo = bar\n"),
        ("no_section_include", "[options]\nHoldPkg = x\n"),
        (
            "unknown_opts",
            "[options]\nBogus = 1\nBogusFlag\nUseSyslog = yes\nNoUpgrade\nParallelDownloads\nCheckSpace = 1\n",
        ),
        ("unknown_repo_dir", "[core]\nBogus = 1\nInclude\n"),
        ("repo_no_value", "[core]\nServer\n"),
        ("repo_no_value2", "[core]\nUsage\n"),
        ("repo_no_value3", "[core]\nSigLevel\n"),
        (
            "repo_empty_value",
            "[core]\nSigLevel =\nUsage =\nServer =\n",
        ),
        ("bad_siglevel", "[options]\nSigLevel = Bogus Required\n"),
        ("bad_siglevel2", "[core]\nSigLevel = Required Bogus\n"),
        ("bad_usage", "[core]\nUsage = Sync Bogus Search\n"),
        ("pd0", "[options]\nParallelDownloads = 0\n"),
        ("pdneg", "[options]\nParallelDownloads = -3\n"),
        ("pdabc", "[options]\nParallelDownloads = abc\n"),
        ("pdbig", "[options]\nParallelDownloads = 99999999999\n"),
        (
            "pdhuge",
            "[options]\nParallelDownloads = 99999999999999999999999\n",
        ),
        (
            "pdlong",
            "[options]\nParallelDownloads = 9223372036854775807\n",
        ),
        ("pdplus", "[options]\nParallelDownloads = +7\n"),
        ("pdspace", "[options]\nParallelDownloads = 5 6\n"),
        ("pdempty", "[options]\nParallelDownloads =\n"),
        ("pdmax", "[options]\nParallelDownloads = 2147483647\n"),
        ("clean_bad", "[options]\nCleanMethod = KeepCurrent Bogus\n"),
        ("clean_cur", "[options]\nCleanMethod = KeepCurrent\n"),
        ("xfer_bad", "[options]\nXferCommand = curl 'unbalanced\n"),
        ("arch_missing", "[core]\nServer = http://m/$arch/$repo\n"),
        (
            "arch_auto",
            "[options]\nArchitecture = auto\n[core]\nServer = http://m/$arch/$repo/$arch\nCacheServer = $repo$repo\n",
        ),
        (
            "arch_two",
            "[options]\nArchitecture = i686 x86_64\n[core]\nServer = http://m/$arch\n",
        ),
        ("empty_section", "[]\nServer = a\n[options]\n"),
        (
            "tabs_crlf",
            "[options]\r\n\tHoldPkg\t=\tfoo\tbar\r\n  \t# c\r\n[core]\r\nServer=http://x\r\n",
        ),
        ("equals_in_value", "[core]\nServer = http://x/?a=b=c\n"),
        ("key_spaces", "[core]\n  Server   =   spaced value  \n"),
        (
            "section_spaces",
            "  [ core ]  \nServer = a\n[core]\nServer=b\n",
        ),
        (
            "dup_repo",
            "[core]\nServer = a\n[core]\nServer = b\n[options]\nHoldPkg=x\n[core]\nUsage=Sync\n",
        ),
        (
            "sig_combos",
            "[options]\nSigLevel = Optional TrustAll\nLocalFileSigLevel = PackageNever\nRemoteFileSigLevel = DatabaseOptional\n[a]\n[b]\nSigLevel = PackageOptional\n[c]\nSigLevel = Never\n[d]\nSigLevel = DatabaseRequired PackageTrustAll\n",
        ),
        (
            "sig_global_never",
            "[options]\nSigLevel = Never\n[a]\nSigLevel = PackageRequired\n[b]\n",
        ),
        ("sig_empty_global", "[options]\nSigLevel =\n[a]\n"),
        (
            "only_flags",
            "[options]\nColor\nColor\nDisableSandboxSyscalls\n",
        ),
        ("nonexist_path", "[options]\nRootDir = /nonexistent/zzz\n"),
        ("nonexist_cache", "[options]\nCacheDir = /nonexistent/zzz\n"),
        ("nonexist_hook", "[options]\nHookDir = /nonexistent/zzz\n"),
        ("nonexist_gpg", "[options]\nGPGDir = /nonexistent/zzz\n"),
        ("nonexist_db", "[options]\nDBPath = /nonexistent/zzz\n"),
        ("include_empty", "[options]\nInclude\n"),
        ("include_missing", "[options]\nInclude = /nonexistent/zzz\n"),
        (
            "include_glob_nomatch",
            "[options]\nInclude = /nonexistent/*.conf\n",
        ),
        ("nul_and_long", ""),
        (
            "db_first_wins",
            "[options]\nDBPath = /tmp\nDBPath = /usr\nRootDir = /usr\nRootDir=/tmp\nLogFile = a\nLogFile = b\nDownloadUser = x\nDownloadUser = y\n",
        ),
        ("root_only", "[options]\nRootDir = /usr\n"),
        ("root_trailing", "[options]\nRootDir = /usr/lib/../\n"),
    ];
    for (n, b) in bodies {
        cfgs.push((n.to_string(), b.to_string()));
    }
    // includes
    let inc_dir = d("inc");
    std::fs::write(
        format!("{inc_dir}/a.conf"),
        "Server = http://a/$repo\nHoldPkg = fromA\n",
    )
    .unwrap();
    std::fs::write(
        format!("{inc_dir}/b.conf"),
        "[inc_repo]\nServer = http://b\n",
    )
    .unwrap();
    std::fs::write(
        format!("{inc_dir}/bad.conf"),
        "Bogus = 1\n[core]\nUsage = Nope\n",
    )
    .unwrap();
    std::fs::write(
        format!("{inc_dir}/chain1.conf"),
        format!("Include = {inc_dir}/chain2.conf\nHoldPkg = c1\n"),
    )
    .unwrap();
    std::fs::write(
        format!("{inc_dir}/chain2.conf"),
        "HoldPkg = c2\n[after]\nServer = s\n",
    )
    .unwrap();
    std::fs::write(
        format!("{inc_dir}/loop.conf"),
        format!("Include = {inc_dir}/loop.conf\n"),
    )
    .unwrap();
    std::fs::write(format!("{inc_dir}/nosec.conf"), "# nothing\n").unwrap();
    cfgs.push((
        "inc_basic".into(),
        format!("[core]\nInclude = {inc_dir}/a.conf\n[options]\nInclude = {inc_dir}/a.conf\n"),
    ));
    cfgs.push((
        "inc_glob".into(),
        format!("[x]\nInclude = {inc_dir}/[ab].conf\nInclude = {inc_dir}/*.nomatch\n"),
    ));
    cfgs.push((
        "inc_before_section".into(),
        format!("Include = {inc_dir}/b.conf\n[core]\nServer = z\n"),
    ));
    cfgs.push((
        "inc_chain".into(),
        format!("[options]\nInclude = {inc_dir}/chain1.conf\nHoldPkg = main\n"),
    ));
    cfgs.push((
        "inc_loop".into(),
        format!("[options]\nInclude = {inc_dir}/loop.conf\n"),
    ));
    cfgs.push((
        "inc_bad".into(),
        format!("[options]\nInclude = {inc_dir}/bad.conf\n"),
    ));
    cfgs.push((
        "inc_nosec_before".into(),
        format!("Include = {inc_dir}/a.conf\n"),
    ));
    cfgs.push((
        "inc_dir".into(),
        format!("[options]\nInclude = {inc_dir}\n"),
    ));
    cfgs.push((
        "inc_escape".into(),
        format!("[options]\nInclude = {inc_dir}/\\*.conf\n"),
    ));
    for (n, b) in cfgs {
        let p = w(&format!("{n}.conf"), &b);
        matrix(&p);
    }
    // long line (> PATH_MAX) is split into chunks, NUL cuts a chunk, invalid UTF-8
    let long = format!(
        "[options]\nHoldPkg = {}\n[core]\nServer = {}\n",
        "x".repeat(5000),
        "y".repeat(9000)
    );
    matrix(&w("long.conf", &long));
    let mut nul = b"[options]\nHoldPkg = a\0b\nHoldPkg = c\n".to_vec();
    nul.extend_from_slice(b"[core]\nServer = ok\n");
    std::fs::write(r.join("nul.conf"), nul).unwrap();
    matrix(&r.join("nul.conf"));
    // missing file and directory as config
    matrix(&r.join("does-not-exist.conf"));
    matrix(&r);
    // sysroot: config, includes, server file:// urls and paths all get the prefix
    let sr = d("sysroot");
    std::fs::create_dir_all(format!("{sr}/etc/pacman.d")).unwrap();
    std::fs::create_dir_all(format!("{sr}/var/lib/pacman")).unwrap();
    std::fs::write(
        format!("{sr}/etc/pacman.d/mirrorlist"),
        "Server = file:///srv/mirror/$repo\nServer = http://x/$repo\n",
    )
    .unwrap();
    std::fs::write(
        format!("{sr}/etc/pacman.conf"),
        "[options]\nDBPath = /var/lib/pacman\nLogFile = /var/log/p.log\n[core]\nInclude = /etc/pacman.d/mirrorlist\n[extra]\nInclude = /etc/pacman.d/mirror*\n",
    )
    .unwrap();
    for a in [
        vec!["-S", &sr, "-c", "/etc/pacman.conf"],
        vec![
            "-S",
            &sr,
            "-c",
            "/etc/pacman.conf",
            "-v",
            "DBPath",
            "Server",
        ],
        vec!["-S", &sr, "-c", "/etc/pacman.conf", "-r", "extra"],
        vec!["-S", &sr, "-R", "/mnt", "-c", "/etc/pacman.conf"],
        vec!["-S", &sr, "-c", "/etc/nonexistent"],
        vec!["--sysroot", &sr, "--rootdir=/foo", "-c", "/etc/pacman.conf"],
    ] {
        check(&a);
    }
}
