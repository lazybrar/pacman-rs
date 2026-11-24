//! Differential test of signing.c against the system libalpm. A C harness (tests/oracle/sigcheck.c, built
//! with `gcc -lalpm` at test time) and its Rust twin (examples/sigcheck.rs) print ret/errno, every signature
//! result (status, validity, fingerprint, uid) and the logged errors; the outputs must be identical.
//! Synthetic matrix: keys x signatures x levels in a temporary GNUPGHOME (never the real /etc/pacman.d/gnupg;
//! the live check uses a temp COPY of it). No network. Skips when gcc, alpm.h or gpg are missing.
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const P: i32 = 1;
const P_OPT: i32 = 1 << 1;
const P_MARG: i32 = 1 << 2;
const P_UNK: i32 = 1 << 3;
const D: i32 = 1 << 10;
const D_OPT: i32 = 1 << 11;
const D_MARG: i32 = 1 << 12;
const D_UNK: i32 = 1 << 13;

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

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
        "gpg {:?} failed: {}",
        args,
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn gen_key(home: &Path, name: &str, extra: &[&str], expire: &str) -> String {
    let uid = format!("{name} <{}@sig.test>", name.to_lowercase());
    let mut a: Vec<&str> = extra.to_vec();
    a.extend([
        "--status-fd",
        "1",
        "--quick-gen-key",
        &uid,
        "ed25519",
        "sign",
        expire,
    ]);
    let out = gpg(home, &a, None);
    out.lines()
        .find_map(|l| l.strip_prefix("[GNUPG:] KEY_CREATED ").map(|r| &r[2..]))
        .unwrap()
        .to_string()
}

fn sign(home: &Path, key: &str, file: &Path, sig: &Path, extra: &[&str]) {
    let mut a: Vec<&str> = extra.to_vec();
    a.extend([
        "--local-user",
        key,
        "--detach-sign",
        "-o",
        sig.to_str().unwrap(),
        file.to_str().unwrap(),
    ]);
    let _ = std::fs::remove_file(sig);
    gpg(home, &a, None);
}

fn tar_zst_pkg(path: &Path, desc: &str) {
    let info = format!(
        "pkgname = sigpkg\npkgbase = sigpkg\npkgver = 1-1\npkgdesc = {desc}\nurl = \nbuilddate = 1\npackager = t\nsize = 0\narch = any\n"
    );
    let info = info.as_bytes();
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(info.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, ".PKGINFO", info).unwrap();
    let raw = b.into_inner().unwrap();
    std::fs::write(path, zstd::encode_all(&raw[..], 3).unwrap()).unwrap();
}

#[derive(Clone)]
struct Case {
    label: String,
    args: Vec<String>,
    cwd: Option<PathBuf>,
}

fn run(bin: &Path, c: &Case) -> String {
    let mut cmd = Command::new(bin);
    cmd.args(&c.args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", std::env::var("PATH").unwrap_or_default());
    if let Some(d) = &c.cwd {
        cmd.current_dir(d);
    }
    let o = cmd.output().unwrap();
    format!(
        "{}exit={}",
        String::from_utf8_lossy(&o.stdout),
        o.status.code().unwrap_or(-1)
    )
}

fn rust_bin() -> PathBuf {
    // target/<profile>/deps/<test> -> target/<profile>/examples/sigcheck
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.join("examples").join("sigcheck")
}

/// run every case with both binaries on `threads` threads; returns (cases, failures)
fn compare(
    oracle: &Path,
    cases: &[Case],
) -> (usize, Vec<String>, std::collections::BTreeSet<String>) {
    let ours = rust_bin();
    assert!(ours.exists(), "build the example first: {}", ours.display());
    let fails = std::sync::Mutex::new(Vec::new());
    let seen = std::sync::Mutex::new(std::collections::BTreeSet::new());
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let Some(c) = cases.get(i) else { break };
                    let (a, b) = (run(&ours, c), run(oracle, c));
                    for l in b.lines().filter(|l| l.starts_with("result")) {
                        let f: Vec<&str> = l.split_whitespace().collect();
                        seen.lock().unwrap().insert(format!("{} {}", f[2], f[3]));
                    }
                    if a != b {
                        fails
                            .lock()
                            .unwrap()
                            .push(format!("{}\n--- ours\n{a}\n--- system\n{b}", c.label));
                    }
                }
            });
        }
    });
    (
        cases.len(),
        fails.into_inner().unwrap(),
        seen.into_inner().unwrap(),
    )
}

fn build_oracle(dir: &Path) -> Option<PathBuf> {
    if !have("gpg") || !Path::new("/usr/include/alpm.h").exists() {
        return None;
    }
    let out = dir.join("sigcheck-c");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/sigcheck.c");
    let ok = Command::new("gcc")
        .args([
            "-O0",
            "-o",
            out.to_str().unwrap(),
            src.to_str().unwrap(),
            "-lalpm",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    ok.then_some(out)
}

struct Scn {
    name: String,
    /// keys that sign the payload (concatenated signatures)
    signers: Vec<String>,
    tamper: bool,
    nosig: bool,
    garbage: bool,
}

#[test]
fn signing_matches_libalpm() {
    let base = std::env::temp_dir().join(format!("pacman-rs-sigtest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let Some(oracle) = build_oracle(&base) else {
        eprintln!("skipping: gcc/alpm.h/gpg missing");
        return;
    };
    let (s_home, v_home) = (base.join("S"), base.join("V"));
    for h in [&s_home, &v_home] {
        std::fs::create_dir_all(h).unwrap();
        std::fs::set_permissions(h, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    }
    // legacy keyring files, like pacman-key's
    for f in ["pubring.gpg", "trustdb.gpg"] {
        std::fs::write(v_home.join(f), b"").unwrap();
    }
    std::fs::write(s_home.join("pubring.gpg"), b"").unwrap();

    // ---- keys
    let m = gen_key(&s_home, "Master", &[], "never");
    let m2 = gen_key(&s_home, "Signer2", &[], "never");
    let mut keys: BTreeMap<&str, String> = BTreeMap::new();
    for n in [
        "Full", "Ultimate", "Marginal", "Unknown", "Never", "Disabled", "Missing", "Revoked",
    ] {
        keys.insert(n, gen_key(&s_home, n, &[], "never"));
    }
    keys.insert(
        "Expired",
        gen_key(
            &s_home,
            "Expired",
            &["--faked-system-time", "20230101T000000"],
            "1y",
        ),
    );
    gpg(
        &s_home,
        &["--local-user", &m, "--quick-sign-key", &m2],
        None,
    );
    gpg(
        &s_home,
        &["--local-user", &m, "--quick-sign-key", &keys["Full"]],
        None,
    );
    gpg(
        &s_home,
        &["--local-user", &m2, "--quick-sign-key", &keys["Marginal"]],
        None,
    );
    // ---- payloads and signatures
    let pkg = base.join("payload.pkg.tar.zst");
    tar_zst_pkg(&pkg, "t");
    // same shape, different content: a valid package whose bytes do not match the signature
    let pkg_tampered = base.join("tampered.pkg.tar.zst");
    tar_zst_pkg(&pkg_tampered, "tampered");
    let mut sigs: BTreeMap<String, PathBuf> = BTreeMap::new();
    let all: Vec<(&str, String)> = keys.iter().map(|(k, v)| (*k, v.clone())).collect();
    for (n, f) in &all {
        let sp = base.join(format!("{n}.sig"));
        if *n == "Expired" {
            sign(
                &s_home,
                f,
                &pkg,
                &sp,
                &["--faked-system-time", "20230102T000000"],
            );
        } else {
            sign(&s_home, f, &pkg, &sp, &[]);
        }
        sigs.insert((*n).into(), sp);
    }
    for n in ["Full", "Ultimate"] {
        let sp = base.join(format!("{n}.expsig"));
        sign(
            &s_home,
            &keys[n],
            &pkg,
            &sp,
            &["--default-sig-expire", "seconds=1"],
        );
        sigs.insert(format!("{n}.expsig"), sp);
    }
    std::thread::sleep(std::time::Duration::from_secs(3));

    // revoke a key (the revocation certificate gpg stored at generation time)
    let rev =
        std::fs::read_to_string(s_home.join(format!("openpgp-revocs.d/{}.rev", keys["Revoked"])))
            .unwrap();
    let rev = rev.replace(
        ":-----BEGIN PGP PUBLIC KEY BLOCK-----",
        "-----BEGIN PGP PUBLIC KEY BLOCK-----",
    );
    gpg(&s_home, &["--import"], Some(&rev));

    // ---- verification keyring: everything but Missing; ownertrust and disabled set here
    let mut export: Vec<&str> = vec![&m, &m2];
    export.extend(
        keys.iter()
            .filter(|(k, _)| **k != "Missing")
            .map(|(_, v)| v.as_str()),
    );
    let mut ea = vec!["--export"];
    ea.extend(&export);
    let blob = {
        let out = Command::new("gpg")
            .env("GNUPGHOME", &s_home)
            .args(["--batch"])
            .args(&ea)
            .output()
            .unwrap();
        out.stdout
    };
    std::fs::write(base.join("pub.gpg"), &blob).unwrap();
    gpg(
        &v_home,
        &["--import", base.join("pub.gpg").to_str().unwrap()],
        None,
    );
    let trust = format!(
        "{m}:6:\n{}:6:\n{m2}:4:\n{}:3:\n",
        keys["Ultimate"], keys["Never"]
    );
    gpg(&v_home, &["--import-ownertrust"], Some(&trust));
    gpg(
        &v_home,
        &["--command-fd", "0", "--edit-key", &keys["Disabled"]],
        Some("disable\nsave\n"),
    );
    // validity "never": a key with a bad TOFU policy
    std::fs::write(v_home.join("gpg.conf"), "trust-model tofu+pgp\n").unwrap();
    gpg(&v_home, &["--tofu-policy", "bad", &keys["Never"]], None);
    gpg(&v_home, &["--check-trustdb"], None);

    // ---- scenarios
    let mut scns: Vec<Scn> = Vec::new();
    for n in keys.keys() {
        scns.push(Scn {
            name: format!("good-{n}"),
            signers: vec![(*n).into()],
            tamper: false,
            nosig: false,
            garbage: false,
        });
        scns.push(Scn {
            name: format!("tamper-{n}"),
            signers: vec![(*n).into()],
            tamper: true,
            nosig: false,
            garbage: false,
        });
    }
    for n in ["Full", "Ultimate"] {
        scns.push(Scn {
            name: format!("sigexp-{n}"),
            signers: vec![format!("{n}.expsig")],
            tamper: false,
            nosig: false,
            garbage: false,
        });
    }
    scns.push(Scn {
        name: "nosig".into(),
        signers: vec![],
        tamper: false,
        nosig: true,
        garbage: false,
    });
    scns.push(Scn {
        name: "garbage".into(),
        signers: vec![],
        tamper: false,
        nosig: false,
        garbage: true,
    });
    for other in [
        "Missing", "Marginal", "Disabled", "Expired", "Unknown", "Full",
    ] {
        scns.push(Scn {
            name: format!("two-Full-{other}"),
            signers: vec!["Full".into(), other.into()],
            tamper: false,
            nosig: false,
            garbage: false,
        });
    }
    scns.push(Scn {
        name: "two-tampered".into(),
        signers: vec!["Full".into(), "Ultimate".into()],
        tamper: true,
        nosig: false,
        garbage: false,
    });

    let tmpl = base.join("scn");
    let mut cases: Vec<Case> = Vec::new();
    let mut axis: BTreeMap<&str, usize> = BTreeMap::new();
    let gd = v_home.to_str().unwrap().to_string();
    for s in &scns {
        let dir = tmpl.join(&s.name);
        let dbp = dir.join("dbp");
        std::fs::create_dir_all(dbp.join("local")).unwrap();
        std::fs::create_dir_all(dbp.join("sync")).unwrap();
        let payload = if s.tamper { &pkg_tampered } else { &pkg };
        let pfile = dir.join("pkg-1-1-any.pkg.tar.zst");
        let dbfile = dbp.join("sync/foo.db");
        std::fs::copy(payload, &pfile).unwrap();
        std::fs::copy(payload, &dbfile).unwrap();
        if !s.nosig {
            let sigbytes = if s.garbage {
                b"this is not a signature".to_vec()
            } else {
                let mut v = Vec::new();
                for k in &s.signers {
                    v.extend(std::fs::read(&sigs[k.as_str()]).unwrap());
                }
                v
            };
            std::fs::write(format!("{}.sig", pfile.display()), &sigbytes).unwrap();
            std::fs::write(format!("{}.sig", dbfile.display()), &sigbytes).unwrap();
        }
        let a = |mode: &str, level: i32, path: &Path| -> Vec<String> {
            vec![
                mode.into(),
                gd.clone(),
                dbp.to_str().unwrap().into(),
                level.to_string(),
                path.to_str().unwrap().into(),
            ]
        };
        for lv in [
            0,
            P,
            P | P_OPT,
            P | P_MARG,
            P | P_UNK,
            P | P_MARG | P_UNK,
            P | P_OPT | P_MARG | P_UNK,
        ] {
            cases.push(Case {
                label: format!("{} pkgload {lv}", s.name),
                args: a("pkgload", lv, &pfile),
                cwd: None,
            });
            *axis.entry("pkgload").or_default() += 1;
        }
        cases.push(Case {
            label: format!("{} pkgsig", s.name),
            args: a("pkgsig", 0, &pfile),
            cwd: None,
        });
        *axis.entry("pkgsig").or_default() += 1;
        for lv in [
            0,
            D,
            D | D_OPT,
            D | D_MARG,
            D | D_UNK,
            D | D_MARG | D_UNK,
            D | D_OPT | D_MARG | D_UNK,
        ] {
            cases.push(Case {
                label: format!("{} dbvalid {lv}", s.name),
                args: a("dbvalid", lv, &dbfile),
                cwd: None,
            });
            *axis.entry("dbvalid").or_default() += 1;
        }
        cases.push(Case {
            label: format!("{} dbsig", s.name),
            args: a("dbsig", 0, &dbfile),
            cwd: None,
        });
        *axis.entry("dbsig").or_default() += 1;
    }

    // ---- signature carried in a sync database (base64, %PGPSIG%)
    {
        use base64::Engine;
        let b64 =
            |p: &Path| base64::engine::general_purpose::STANDARD.encode(std::fs::read(p).unwrap());
        let variants: Vec<(&str, Option<String>, bool)> = vec![
            ("good-Full", Some(b64(&sigs["Full"])), false),
            ("good-Marginal", Some(b64(&sigs["Marginal"])), false),
            ("good-Missing", Some(b64(&sigs["Missing"])), false),
            ("good-Expired", Some(b64(&sigs["Expired"])), false),
            ("tampered", Some(b64(&sigs["Full"])), true),
            ("garbage-b64", Some("!!!not base64!!!".into()), false),
            (
                "garbage-sig",
                Some(base64::engine::general_purpose::STANDARD.encode(b"not a signature")),
                false,
            ),
            ("nosig", None, false),
        ];
        for (name, sig, tamper) in variants {
            let dir = base.join("sp").join(name);
            let dbp = dir.join("dbp");
            std::fs::create_dir_all(dbp.join("local")).unwrap();
            std::fs::create_dir_all(dbp.join("sync")).unwrap();
            std::fs::copy(
                if tamper { &pkg_tampered } else { &pkg },
                dir.join("sp-1-1-any.pkg.tar.zst"),
            )
            .unwrap();
            let mut desc = String::from(
                "%FILENAME%\nsp-1-1-any.pkg.tar.zst\n\n%NAME%\nsp\n\n%VERSION%\n1-1\n\n",
            );
            if let Some(s) = sig {
                desc.push_str(&format!("%PGPSIG%\n{s}\n\n"));
            }
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            h.set_size(desc.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "sp-1-1/desc", desc.as_bytes())
                .unwrap();
            let raw = b.into_inner().unwrap();
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            gz.write_all(&raw).unwrap();
            std::fs::write(dbp.join("sync/foo.db"), gz.finish().unwrap()).unwrap();
            cases.push(Case {
                label: format!("syncpkg {name}"),
                args: vec![
                    "syncpkg".into(),
                    gd.clone(),
                    dbp.to_str().unwrap().into(),
                    "0".into(),
                    "x".into(),
                ],
                cwd: Some(dir),
            });
            *axis.entry("syncpkg").or_default() += 1;
        }
    }

    // ---- not-writable keyring (key import refused), missing keyring (init warning)
    {
        let ro = base.join("RO");
        std::fs::create_dir_all(&ro).unwrap();
        std::fs::set_permissions(&ro, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        for f in ["pubring.gpg", "trustdb.gpg"] {
            std::fs::copy(v_home.join(f), ro.join(f)).unwrap();
            std::fs::set_permissions(
                ro.join(f),
                std::os::unix::fs::PermissionsExt::from_mode(0o444),
            )
            .unwrap();
        }
        let none = base.join("NONE");
        std::fs::create_dir_all(&none).unwrap();
        for (tag, home) in [("ro", &ro), ("nokeyring", &none)] {
            for sname in ["good-Missing", "good-Expired", "good-Full", "nosig"] {
                let dbp = tmpl.join(sname).join("dbp");
                for lv in [D, D | D_OPT] {
                    cases.push(Case {
                        label: format!("{tag} {sname} dbvalid {lv}"),
                        args: vec![
                            "dbvalid".into(),
                            home.to_str().unwrap().into(),
                            dbp.to_str().unwrap().into(),
                            lv.to_string(),
                            "x".into(),
                        ],
                        cwd: None,
                    });
                    *axis.entry("keyring-state").or_default() += 1;
                }
            }
        }
    }

    let (n, fails, seen) = compare(&oracle, &cases);
    eprintln!("status/validity pairs seen: {seen:?}");
    for (k, v) in &axis {
        eprintln!("axis {k}: {v} cases");
    }
    eprintln!(
        "synthetic matrix: {} scenarios, {} cases, {} failures",
        scns.len(),
        n,
        fails.len()
    );
    for f in fails.iter().take(5) {
        eprintln!("FAIL {f}");
    }
    let _ = Command::new("gpgconf")
        .args(["--kill", "all"])
        .env("GNUPGHOME", &s_home)
        .status();
    let _ = Command::new("gpgconf")
        .args(["--kill", "all"])
        .env("GNUPGHOME", &v_home)
        .status();
    assert!(fails.is_empty(), "{} differ", fails.len());
    let _ = std::fs::remove_dir_all(&base);
}

/// every cached package with a .sig, against a temp COPY of the system keyring (Required)
#[test]
fn live_cache_matches_libalpm() {
    let src = Path::new("/etc/pacman.d/gnupg");
    let cache = Path::new("/var/cache/pacman/pkg");
    if !src.join("pubring.gpg").exists() || !cache.exists() {
        eprintln!("skipping: no system keyring/cache");
        return;
    }
    let base = std::env::temp_dir().join(format!("pacman-rs-sigtest-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let Some(oracle) = build_oracle(&base) else {
        eprintln!("skipping: gcc/alpm.h/gpg missing");
        return;
    };
    let home = base.join("gnupg");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::set_permissions(&home, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    for f in ["pubring.gpg", "trustdb.gpg", "gpg.conf"] {
        if src.join(f).exists() {
            std::fs::copy(src.join(f), home.join(f)).unwrap();
        }
    }
    let dbp = base.join("dbp");
    std::fs::create_dir_all(dbp.join("local")).unwrap();
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
    let mut cases = Vec::new();
    let mut loads = 0;
    for p in &pkgs {
        let a = |mode: &str, level: i32| {
            vec![
                mode.to_string(),
                home.to_str().unwrap().into(),
                dbp.to_str().unwrap().into(),
                level.to_string(),
                p.to_str().unwrap().into(),
            ]
        };
        cases.push(Case {
            label: format!("pkgsig {}", p.display()),
            args: a("pkgsig", 0),
            cwd: None,
        });
        if loads < 40 {
            cases.push(Case {
                label: format!("pkgload {}", p.display()),
                args: a("pkgload", P),
                cwd: None,
            });
            loads += 1;
        }
    }
    let (n, fails, seen) = compare(&oracle, &cases);
    eprintln!("status/validity pairs seen: {seen:?}");
    eprintln!(
        "live cache: {} packages with .sig, {} cases ({} pkgload at Required), {} failures",
        pkgs.len(),
        n,
        loads,
        fails.len()
    );
    for f in fails.iter().take(5) {
        eprintln!("FAIL {f}");
    }
    let _ = Command::new("gpgconf")
        .args(["--kill", "all"])
        .env("GNUPGHOME", &home)
        .status();
    assert!(fails.is_empty(), "{} differ", fails.len());
    let _ = std::fs::remove_dir_all(&base);
}
