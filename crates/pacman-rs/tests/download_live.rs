//! The single live smoke test of downloads: `-Sy` against the real mirrorlist into a temp dbpath, compared with
//! the system pacman's `-Sy` into another temp dbpath (same files, same sizes). Needs network; skipped when
//! the system pacman cannot reach a mirror. Never touches the real dbpath, logfile or keyring (temp copy).
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn run(bin: &str, base: &Path, name: &str) -> (i32, String, BTreeMap<String, u64>) {
    let d = base.join(name);
    std::fs::create_dir_all(d.join("db/local")).unwrap();
    std::fs::write(d.join("db/local/ALPM_DB_VERSION"), "9\n").unwrap();
    // the real config without DownloadUser (fakeroot would select the sandbox and the user switch fails)
    let conf: String = std::fs::read_to_string("/etc/pacman.conf")
        .unwrap()
        .lines()
        .filter(|l| !l.trim_start().starts_with("DownloadUser"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(d.join("pacman.conf"), conf).unwrap();
    let o = Command::new("fakeroot")
        .arg("--")
        .arg(bin)
        .args([
            "--config",
            d.join("pacman.conf").to_str().unwrap(),
            "--dbpath",
            d.join("db").to_str().unwrap(),
            "--logfile",
            d.join("log").to_str().unwrap(),
            "--gpgdir",
            base.join("gnupg").to_str().unwrap(),
            "--noprogressbar",
            "-Sy",
        ])
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .unwrap();
    let mut files = BTreeMap::new();
    for e in std::fs::read_dir(d.join("db/sync")).unwrap().flatten() {
        files.insert(
            e.file_name().to_string_lossy().into_owned(),
            e.metadata().unwrap().len(),
        );
    }
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stderr).into_owned(),
        files,
    )
}

#[test]
fn live_sy_matches_pacman() {
    let src = Path::new("/etc/pacman.d/gnupg");
    if !Path::new("/usr/bin/pacman").exists()
        || !Path::new("/usr/bin/fakeroot").exists()
        || !src.exists()
    {
        eprintln!("skip: no pacman, fakeroot or keyring");
        return;
    }
    let ours = env!("CARGO_BIN_EXE_pacman-rs");
    let base: PathBuf = std::env::temp_dir().join(format!("pacman-rs-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let g = base.join("gnupg");
    std::fs::create_dir_all(&g).unwrap();
    std::fs::set_permissions(&g, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    for f in ["pubring.gpg", "trustdb.gpg", "gpg.conf"] {
        if src.join(f).exists() {
            std::fs::copy(src.join(f), g.join(f)).unwrap();
        }
    }
    let sys = run("/usr/bin/pacman", &base, "sys");
    if sys.0 != 0 {
        eprintln!("skip: system pacman -Sy failed (no network?): {}", sys.1);
        let _ = std::fs::remove_dir_all(&base);
        return;
    }
    let us = run(ours, &base, "ours");
    eprintln!("live -Sy: system files {:?}\nours {:?}", sys.2, us.2);
    let _ = Command::new("gpgconf")
        .args(["--kill", "all"])
        .env("GNUPGHOME", &g)
        .status();
    let _ = std::fs::remove_dir_all(&base);
    assert_eq!(us.0, 0, "ours failed: {}", us.1);
    // mirrors can update between the two runs: names must match, sizes must match unless a db changed
    assert_eq!(
        us.2.keys().collect::<Vec<_>>(),
        sys.2.keys().collect::<Vec<_>>()
    );
    assert_eq!(us.2, sys.2);
}
