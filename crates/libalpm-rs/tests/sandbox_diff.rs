//! Differential test of the download sandbox (sandbox.c, sandbox_fs.c, sandbox_syscalls.c) against the system
//! libalpm's alpm_sandbox_setup_child, run as uid 0 inside a user namespace (`unshare -Ur`, no real root):
//! the filesystem (Landlock) and syscall (seccomp) restrictions get applied before the switch to the sandbox
//! user, which fails in a user namespace; probes then show what is restricted. The log lines include the
//! number of restricted syscalls, so the denied-syscall list is compared too. A full run as real root with
//! DownloadUser is a user test (not done here).
use std::path::{Path, PathBuf};
use std::process::Command;

fn unshare_ok() -> bool {
    Command::new("unshare")
        .args(["-Ur", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn ours() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.join("examples").join("sandboxcheck")
}

fn run(bin: &Path, args: &[&str]) -> String {
    let o = Command::new("unshare")
        .args(["-Ur", "--"])
        .arg(bin)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    format!(
        "{}{}exit={}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr),
        o.status.code().unwrap_or(-1)
    )
}

#[test]
fn sandbox_matches_libalpm() {
    if !unshare_ok() || !Path::new("/usr/include/alpm.h").exists() {
        eprintln!("skip: no user namespaces or alpm.h");
        return;
    }
    let base = std::env::temp_dir().join(format!("pacman-rs-sandbox-{}", std::process::id()));
    std::fs::create_dir_all(base.join("allowed")).unwrap();
    let oracle = base.join("sandboxcheck-c");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/sandboxcheck.c");
    assert!(
        Command::new("gcc")
            .args([
                "-O0",
                "-o",
                oracle.to_str().unwrap(),
                src.to_str().unwrap(),
                "-lalpm"
            ])
            .status()
            .unwrap()
            .success()
    );
    let ours = ours();
    assert!(
        ours.exists(),
        "build the example first (cargo build --workspace --examples)"
    );
    let allowed = base.join("allowed");
    let outside = base.join("outside");
    let mut n = 0;
    let mut bad = Vec::new();
    for mode in ["", "nofs", "nosys"] {
        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_file(allowed.join("inside"));
        let mut args = vec![allowed.to_str().unwrap(), outside.to_str().unwrap()];
        if !mode.is_empty() {
            args.push(mode);
        }
        let b = run(&oracle, &args);
        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_file(allowed.join("inside"));
        let a = run(&ours, &args);
        n += 1;
        eprintln!("--- mode {mode:?} (system)\n{b}");
        if a != b {
            bad.push(format!("mode {mode:?}\n--- ours\n{a}\n--- system\n{b}"));
        }
    }
    let _ = std::fs::remove_dir_all(&base);
    eprintln!("sandbox cases: {n}, {} failed", bad.len());
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
