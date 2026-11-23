//! -F against /usr/bin/pacman on a throw-away dbpath whose `.files` databases are built from the live
//! local database (the system has none). Read-only: `local` is a symlink, nothing is written there.
use libalpm_rs::alpm::alpm_initialize;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const SYS: &str = "/usr/bin/pacman";

fn run(bin: &str, dbpath: &str, args: &[&str]) -> (Vec<u8>, Vec<u8>, i32) {
    let o = Command::new(bin)
        .arg0("pacman")
        .arg("--dbpath")
        .arg(dbpath)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("COLUMNS", "80")
        .env("TZ", "UTC")
        .output()
        .unwrap();
    (o.stdout, o.stderr, o.status.code().unwrap_or(-1))
}

#[test]
fn files_operation_matches_pacman() {
    if !std::path::Path::new(SYS).exists()
        || !std::path::Path::new("/var/lib/pacman/local/ALPM_DB_VERSION").exists()
    {
        eprintln!("skip: no system pacman or database");
        return;
    }
    let alpm = alpm_initialize("/", "/var/lib/pacman").unwrap();
    let pkgs = alpm.localdb.get_pkgcache().unwrap();
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("files-diff");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("sync")).unwrap();
    std::os::unix::fs::symlink("/var/lib/pacman/local", root.join("local")).unwrap();
    // every 3rd package goes into "core", every 3rd+1 into "extra", the rest nowhere
    let mut tars = [tar::Builder::new(Vec::new()), tar::Builder::new(Vec::new())];
    let mut names = Vec::new();
    for (i, p) in pkgs.iter().enumerate().take(400) {
        let t = match i % 3 {
            0 => 0,
            1 => 1,
            _ => continue,
        };
        let d = p.desc();
        let mut files = String::from("%FILES%\n");
        for f in &p.files().files {
            files.push_str(&f.name);
            files.push('\n');
        }
        files.push('\n');
        let desc = format!(
            "%NAME%\n{}\n\n%VERSION%\n{}\n\n%GROUPS%\n{}\n\n",
            p.name,
            p.version,
            d.groups.join("\n")
        );
        for (n, body) in [("desc", desc), ("files", files)] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tars[t]
                .append_data(
                    &mut h,
                    format!("{}-{}/{}", p.name, p.version, n),
                    body.as_bytes(),
                )
                .unwrap();
        }
        names.push(p.name.clone());
    }
    for (t, repo) in ["core", "extra"].iter().enumerate() {
        let raw = std::mem::replace(&mut tars[t], tar::Builder::new(Vec::new()))
            .into_inner()
            .unwrap();
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(&raw).unwrap();
        std::fs::write(root.join(format!("sync/{repo}.files")), e.finish().unwrap()).unwrap();
    }
    let db = root.to_str().unwrap().to_string();
    let ours = env!("CARGO_BIN_EXE_pacman-rs");
    let sample: Vec<&String> = names.iter().step_by(23).take(12).collect();
    let mut cmds: Vec<Vec<String>> = vec![];
    let mut add = |a: &[&str]| cmds.push(a.iter().map(|s| s.to_string()).collect());
    add(&["-Fl"]);
    add(&["-Flq"]);
    add(&["-Fl", "--machinereadable"]);
    add(&["-F"]);
    add(&["-Fy"]);
    add(&["-Fh"]);
    for n in &sample {
        add(&["-Fl", n]);
        add(&["-Flq", n]);
        add(&["-Fl", "--machinereadable", n]);
        add(&["-Fl", &format!("core/{n}")]);
        add(&["-Fl", &format!("extra/{n}")]);
    }
    for t in [
        "usr/bin/ls",
        "/usr/bin/ls",
        "ls",
        "bash",
        "usr/lib",
        "usr/share/doc",
        "etc/pacman.conf",
        "nonexistent",
        "usr/bin/",
        "//usr/bin/bash",
        "libc.so.6",
        "pacman.conf",
    ] {
        add(&["-F", t]);
        add(&["-Fq", t]);
        add(&["-F", "--machinereadable", t]);
        add(&["-F", t, "ls", "nonexistent"]);
    }
    for t in [
        "^ls$",
        "bin/ls",
        "\\.so\\.6$",
        "^lib.*\\.so",
        "[",
        "(",
        "man/man1/b",
        "KEY",
        "zsh|fish",
    ] {
        add(&["-Fx", t]);
        add(&["-Fxq", t]);
        add(&["-Fx", "--machinereadable", t]);
    }
    add(&["-Fl", "nonexistent"]);
    add(&["-Fl", "core/"]);
    add(&["-Fl", "nonrepo/bash"]);
    add(&["-Flx", "bash"]);
    add(&["-F", "--color", "always", "bin/ls"]);
    add(&["-F", "--color", "always", "ls"]);
    add(&["-Fx", "--color", "always", "^lib"]);
    let (mut pass, mut fails) = (0, Vec::new());
    for a in &cmds {
        let a: Vec<&str> = a.iter().map(String::as_str).collect();
        let (x, y) = (run(ours, &db, &a), run(SYS, &db, &a));
        if x == y {
            pass += 1;
        } else {
            fails.push(format!(
                "{:?}: exit {} vs {}; stdout equal: {}; stderr: ours {:?} | system {:?}",
                a,
                x.2,
                y.2,
                x.0 == y.0,
                String::from_utf8_lossy(&x.1).lines().next(),
                String::from_utf8_lossy(&y.1).lines().next()
            ));
        }
    }
    eprintln!("files: {pass} passed, {} failed", fails.len());
    for f in fails.iter().take(20) {
        eprintln!("    MISMATCH {f}");
    }
    assert!(fails.is_empty());
}
