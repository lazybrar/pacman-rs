//! Differential test of transactions (trans.c, sync.c prepare/load, conflict.c, CLI sync.c) against /usr/bin/pacman.
//! Synthetic repos are written straight into a throw-away dbpath (local db directories, sync db tarballs, cached
//! package files); both programs run under `fakeroot` with their own --config. Compared: exit status, stdout,
//! stderr (paths normalised) and the resulting cache/db files. Questions are answered through stdin so the
//! interactive code runs too. Nothing installs: every run ends in --print, -Sw, an error or an answered "no".
//! No network; never the real dbpath/cachedir; LC_ALL=C.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const SYS: &str = "/usr/bin/pacman";

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


// ---------------------------------------------------------------- package model

#[derive(Clone)]
struct P {
    name: &'static str,
    ver: &'static str,
    depends: Vec<&'static str>,
    provides: Vec<&'static str>,
    conflicts: Vec<&'static str>,
    replaces: Vec<&'static str>,
    groups: Vec<&'static str>,
    arch: &'static str,
    /// local packages: installed as a dependency
    dep_reason: bool,
}

fn p(name: &'static str, ver: &'static str) -> P {
    P {
        name,
        ver,
        depends: vec![],
        provides: vec![],
        conflicts: vec![],
        replaces: vec![],
        groups: vec![],
        arch: "any",
        dep_reason: false,
    }
}

impl P {
    fn d(mut self, x: &[&'static str]) -> P {
        self.depends = x.to_vec();
        self
    }
    fn pr(mut self, x: &[&'static str]) -> P {
        self.provides = x.to_vec();
        self
    }
    fn cf(mut self, x: &[&'static str]) -> P {
        self.conflicts = x.to_vec();
        self
    }
    fn rp(mut self, x: &[&'static str]) -> P {
        self.replaces = x.to_vec();
        self
    }
    fn g(mut self, x: &[&'static str]) -> P {
        self.groups = x.to_vec();
        self
    }
    fn arch(mut self, a: &'static str) -> P {
        self.arch = a;
        self
    }
    fn asdep(mut self) -> P {
        self.dep_reason = true;
        self
    }
    fn filename(&self) -> String {
        format!("{}-{}-{}.pkg.tar.zst", self.name, self.ver, self.arch)
    }
    fn lists(&self) -> String {
        let mut s = String::new();
        for (k, v) in [
            ("GROUPS", &self.groups),
            ("DEPENDS", &self.depends),
            ("CONFLICTS", &self.conflicts),
            ("PROVIDES", &self.provides),
            ("REPLACES", &self.replaces),
        ] {
            if !v.is_empty() {
                s.push_str(&format!("%{k}%\n{}\n\n", v.join("\n")));
            }
        }
        s
    }
    fn isize(&self) -> usize {
        1_000_000 + self.name.len() * 1000
    }
    /// the package file: a tar.zst with a .PKGINFO
    fn body(&self) -> Vec<u8> {
        let mut info = format!(
            "pkgname = {}\npkgver = {}\narch = {}\nsize = {}\n",
            self.name,
            self.ver,
            self.arch,
            self.isize()
        );
        for (k, v) in [
            ("group", &self.groups),
            ("depend", &self.depends),
            ("conflict", &self.conflicts),
            ("provides", &self.provides),
            ("replaces", &self.replaces),
        ] {
            for x in v {
                info.push_str(&format!("{k} = {x}\n"));
            }
        }
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(info.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, ".PKGINFO", info.as_bytes()).unwrap();
        zstd::encode_all(&b.into_inner().unwrap()[..], 3).unwrap()
    }
    fn sync_desc(&self) -> Vec<u8> {
        let body = self.body();
        format!(
            "%FILENAME%\n{}\n\n%NAME%\n{}\n\n%VERSION%\n{}\n\n%DESC%\ndesc of {}\n\n%CSIZE%\n{}\n\n%ISIZE%\n{}\n\n%SHA256SUM%\n{:x}\n\n%ARCH%\n{}\n\n{}",
            self.filename(),
            self.name,
            self.ver,
            self.name,
            body.len(),
            self.isize(),
            Sha256::digest(&body),
            self.arch,
            self.lists()
        )
        .into_bytes()
    }
    fn local_desc(&self) -> Vec<u8> {
        format!(
            "%NAME%\n{}\n\n%VERSION%\n{}\n\n%ARCH%\n{}\n\n%SIZE%\n{}\n\n{}{}",
            self.name,
            self.ver,
            self.arch,
            self.isize(),
            if self.dep_reason { "%REASON%\n1\n\n" } else { "" },
            self.lists()
        )
        .into_bytes()
    }
}

// ---------------------------------------------------------------- cases

struct Run {
    args: Vec<&'static str>,
    /// answers to the questions (stdin)
    stdin: &'static str,
    noconfirm: bool,
}

struct Case {
    name: &'static str,
    local: Vec<P>,
    repos: Vec<(&'static str, Vec<P>)>,
    /// extra [options] lines
    options: &'static str,
    runs: Vec<Run>,
    /// put the packages of the repos in the package cache
    cached: bool,
    /// names of cached packages to corrupt (a byte appended)
    corrupt: Vec<&'static str>,
    /// signature mode of the cached packages: None, Some(tamper)
    sigs: Option<bool>,
    keyring: bool,
}

fn run(args: &[&'static str]) -> Run {
    Run {
        args: args.to_vec(),
        stdin: "",
        noconfirm: true,
    }
}

/// interactive: no --noconfirm, answers come from stdin
fn ask(args: &[&'static str], stdin: &'static str) -> Run {
    Run {
        args: args.to_vec(),
        stdin,
        noconfirm: false,
    }
}

fn case(name: &'static str, local: Vec<P>, repo: Vec<P>, runs: Vec<Run>) -> Case {
    Case {
        name,
        local,
        repos: vec![("core", repo)],
        options: "",
        runs,
        cached: false,
        corrupt: vec![],
        sigs: None,
        keyring: false,
    }
}

fn build_cases() -> Vec<Case> {
    let mut v: Vec<Case> = Vec::new();
    let base = || vec![p("glibc", "2.0-1"), p("bash", "5.0-1").d(&["glibc"])];

    // ---- plain targets
    v.push(case(
        "plain-print",
        base(),
        vec![p("app", "1.0-1").d(&["glibc"])],
        vec![
            run(&["-Sp", "app"]),
            run(&["-Sp", "--print-format", "%n %v %r %s %f", "app"]),
            run(&["-Sp", "--print-format", "%a|%d|%e|%h|%m|%u|%p|%D|%G|%L|%H|%P|%R|%C|%M|%O", "app"]),
            run(&["-Sp", "core/app"]),
            run(&["-Sp", "nosuch/app"]),
            run(&["-Sp", "nothere"]),
            run(&["-Sp", "app", "nothere"]),
            run(&["-Sp", "app", "app"]),
        ],
    ));
    v.push(case(
        "plain-interactive",
        base(),
        vec![p("app", "1.0-1").d(&["glibc"])],
        vec![
            ask(&["-S", "app"], "n\n"),
            ask(&["-S", "app"], "maybe\n"),
            ask(&["-S", "--verbose", "app"], "n\n"),
            ask(&["-Sw", "app"], "n\n"),
            ask(&["-S", "--needed", "bash", "app"], "n\n"),
            ask(&["-S", "bash"], "n\n"),
        ],
    ));
    // ---- dependency chains, provides, versions
    v.push(case(
        "deps-chain",
        base(),
        vec![
            p("app", "1.0-1").d(&["libb"]),
            p("libb", "1.0-1").d(&["libc>=2", "glibc"]),
            p("libc", "2.0-1"),
            p("zlibc", "3.0-1"),
        ],
        vec![
            run(&["-Sp", "app"]),
            run(&["-Sp", "--print-format", "%n", "app", "zlibc"]),
            ask(&["-S", "app"], "n\n"),
            ask(&["-S", "--verbose", "app"], "n\n"),
        ],
    ));
    v.push(case(
        "deps-provides",
        base(),
        vec![
            p("app", "1.0-1").d(&["virt"]),
            p("impl-a", "1.0-1").pr(&["virt"]),
            p("impl-b", "1.0-1").pr(&["virt=2"]),
            p("needs2", "1.0-1").d(&["virt>=2"]),
        ],
        vec![
            run(&["-Sp", "app"]),
            run(&["-Sp", "virt"]),
            run(&["-Sp", "needs2"]),
            ask(&["-S", "app"], "2\nn\n"),
            ask(&["-S", "app"], "\nn\n"),
            ask(&["-S", "app"], "7\n1\nn\n"),
            ask(&["-S", "app"], "x\n"),
        ],
    ));
    v.push(case(
        "deps-missing",
        base(),
        vec![
            p("app", "1.0-1").d(&["nosuchlib"]),
            p("app2", "1.0-1").d(&["libv>=5"]),
            p("libv", "1.0-1"),
            p("ok", "1.0-1"),
        ],
        vec![
            run(&["-Sp", "app"]),
            run(&["-Sp", "app2"]),
            run(&["-Sp", "ok", "app"]),
            ask(&["-S", "ok", "app"], "y\nn\n"),
            ask(&["-S", "ok", "app"], "n\n"),
            ask(&["-S", "app"], "y\n"),
            run(&["-Sp", "-d", "app"]),
            run(&["-Sp", "-dd", "app2"]),
        ],
    ));
    v.push(case(
        "deps-cycle",
        base(),
        vec![
            p("a", "1.0-1").d(&["b"]),
            p("b", "1.0-1").d(&["c"]),
            p("c", "1.0-1").d(&["a"]),
        ],
        vec![
            run(&["-Sp", "a"]),
            run(&["-Sp", "--print-format", "%n", "a", "c"]),
            ask(&["-S", "a"], "n\n"),
        ],
    ));
    // a local package whose dependency an upgrade would break
    v.push(case(
        "deps-breaks-local",
        vec![p("lib", "1.0-1"), p("user", "1.0-1").d(&["lib<2"])],
        vec![p("lib", "2.0-1"), p("user", "1.0-1").d(&["lib<2"])],
        vec![
            run(&["-Sp", "lib"]),
            run(&["-Sup"]),
            ask(&["-S", "lib"], "n\n"),
        ],
    ));
    // ---- groups
    v.push(case(
        "groups",
        base(),
        vec![
            p("g1", "1.0-1").g(&["grp"]),
            p("g2", "1.0-1").g(&["grp"]).d(&["glibc"]),
            p("g3", "1.0-1").g(&["grp", "other"]),
            p("single", "1.0-1").g(&["solo"]),
        ],
        vec![
            run(&["-Sp", "grp"]),
            run(&["-Sp", "--print-format", "%n", "other", "solo"]),
            ask(&["-S", "grp"], "\nn\n"),
            ask(&["-S", "grp"], "1 3\nn\n"),
            ask(&["-S", "grp"], "^2\nn\n"),
            ask(&["-S", "grp"], "2-3\nn\n"),
            ask(&["-S", "grp"], "9\n1\nn\n"),
            ask(&["-S", "grp"], "a\n1\nn\n"),
            ask(&["-S", "solo"], "\nn\n"),
            run(&["-Sp", "nogroup"]),
            run(&["-Sp", "--needed", "grp"]),
        ],
    ));
    // ---- replaces
    v.push(case(
        "replaces",
        vec![p("old", "1.0-1"), p("keep", "1.0-1")],
        vec![p("new", "2.0-1").rp(&["old"]), p("keep", "1.0-1")],
        vec![
            run(&["-Sp", "new"]),
            run(&["-Sup"]),
            ask(&["-Su"], "y\nn\n"),
            ask(&["-Su"], "n\nn\n"),
            ask(&["-Su"], "\nn\n"),
            ask(&["-Su", "--ask", "2"], "n\n"),
            ask(&["-S", "new"], "n\n"),
        ],
    ));
    v.push(case(
        "replaces-ignored",
        vec![p("old", "1.0-1")],
        vec![p("new", "2.0-1").rp(&["old"])],
        {
            let mut r = vec![ask(&["-Su"], "n\n"), run(&["-Sup"])];
            r.push(ask(&["-Su", "--ignore", "new"], "n\n"));
            r.push(ask(&["-Su", "--ignore", "old"], "n\n"));
            r
        },
    ));
    // ---- conflicts
    v.push(case(
        "conflicts-inner",
        base(),
        vec![
            p("a", "1.0-1").cf(&["b"]),
            p("b", "1.0-1"),
            p("c", "1.0-1").pr(&["d"]).cf(&["d"]),
            p("d", "1.0-1"),
            p("e", "1.0-1").cf(&["f>=2"]),
            p("f", "2.0-1"),
        ],
        vec![
            ask(&["-S", "a", "b"], "n\n"),
            ask(&["-S", "c", "d"], "n\n"),
            ask(&["-S", "e", "f"], "n\n"),
            ask(&["-S", "d", "c"], "n\n"),
            run(&["-S", "a", "b"]),
            run(&["-Sw", "a", "b"]),
        ],
    ));
    v.push(case(
        "conflicts-local",
        vec![p("loc", "1.0-1"), p("tail", "1.0-1")],
        vec![
            p("rem", "1.0-1").cf(&["loc"]),
            p("rem2", "1.0-1").cf(&["tail<2"]),
            p("loc2", "1.0-1"),
        ],
        vec![
            run(&["-S", "rem"]),
            ask(&["-S", "rem"], "y\nn\n"),
            ask(&["-S", "rem"], "n\n"),
            ask(&["-S", "rem"], "\n"),
            ask(&["-S", "rem2"], "y\nn\n"),
            ask(&["-Sp", "rem"], ""),
            run(&["-Sw", "rem"]),
        ],
    ));
    v.push(case(
        "conflicts-local-reverse",
        vec![p("loc", "1.0-1").cf(&["newc"])],
        vec![p("newc", "1.0-1")],
        vec![run(&["-S", "newc"]), ask(&["-S", "newc"], "y\nn\n")],
    ));
    // ---- ignored packages
    v.push({
        let mut c = case(
            "ignored",
            vec![p("ign", "1.0-1"), p("normal", "1.0-1")],
            vec![
                p("ign", "2.0-1"),
                p("normal", "2.0-1"),
                p("fresh", "1.0-1").g(&["gg"]),
                p("needsign", "1.0-1").d(&["ign2"]),
                p("ign2", "1.0-1"),
            ],
            vec![
                run(&["-Sup"]),
                run(&["-Sp", "ign"]),
                run(&["-Sp", "fresh"]),
                run(&["-Sp", "gg"]),
                ask(&["-S", "ign"], "y\nn\n"),
                ask(&["-S", "ign"], "n\n"),
                ask(&["-S", "ign"], "\nn\n"),
                ask(&["-Sw", "ign"], "n\n"),
                ask(&["-S", "gg"], "\nn\n"),
                ask(&["-S", "needsign"], "n\n"),
                run(&["-Sp", "--ignore", "ign", "ign"]),
                run(&["-Sup", "--ignore", "normal"]),
                run(&["-Sup", "--ignoregroup", "gg"]),
            ],
        );
        c.options = "IgnorePkg = ign fresh\nIgnoreGroup = gg\n";
        c
    });
    // ---- --needed
    v.push(case(
        "needed",
        vec![p("same", "1.0-1"), p("older", "1.0-1"), p("newer", "2.0-1")],
        vec![
            p("same", "1.0-1"),
            p("older", "2.0-1"),
            p("newer", "1.0-1"),
            p("grp1", "1.0-1").g(&["gn"]),
            p("same2", "1.0-1").g(&["gn"]),
        ],
        vec![
            run(&["-Sp", "--needed", "same"]),
            run(&["-Sp", "same"]),
            run(&["-Sp", "--needed", "older"]),
            run(&["-Sp", "--needed", "newer"]),
            run(&["-Sp", "newer"]),
            run(&["-Sp", "--needed", "same", "older"]),
            run(&["-Sp", "--needed", "gn"]),
            ask(&["-S", "--needed", "same"], "n\n"),
            ask(&["-S", "same"], "n\n"),
            ask(&["-S", "newer"], "n\n"),
            run(&["-Sw", "same"]),
        ],
    ));
    // ---- -Su
    v.push({
        let mut c = case(
            "sysupgrade",
            vec![
                p("up", "1.0-1"),
                p("down", "2.0-1"),
                p("same", "1.0-1"),
                p("localonly", "1.0-1"),
                p("ignored", "1.0-1"),
                p("ldep", "1.0-1").asdep(),
            ],
            vec![
                p("up", "1.5-1").d(&["newdep"]),
                p("down", "1.0-1"),
                p("same", "1.0-1"),
                p("ignored", "9.0-1"),
                p("newdep", "1.0-1"),
                p("ldep", "1.0-2"),
            ],
            vec![
                run(&["-Sup"]),
                run(&["-Suup"]),
                run(&["-Sup", "--ignore", "up"]),
                run(&["-Suup", "--ignore", "down"]),
                run(&["-Su", "--print-format", "%n-%v", "-p"]),
                run(&["-Sup", "up"]),
                ask(&["-Su"], "n\n"),
                ask(&["-Suu"], "n\n"),
                ask(&["-Su", "--verbose"], "n\n"),
                ask(&["-Suw"], "n\n"),
                run(&["-Sw", "-u"]),
            ],
        );
        c.options = "IgnorePkg = ignored\n";
        c
    });
    v.push(case(
        "sysupgrade-nothing",
        vec![p("same", "1.0-1"), p("localonly", "1.0-1")],
        vec![p("same", "1.0-1")],
        vec![run(&["-Sup"]), run(&["-Su"]), run(&["-Suw"]), ask(&["-Su"], "n\n")],
    ));
    // repo priority and usage
    v.push({
        let mut c = case(
            "multi-repo",
            vec![p("both", "1.0-1")],
            vec![p("both", "2.0-1"), p("only-core", "1.0-1")],
            vec![
                run(&["-Sp", "both"]),
                run(&["-Sp", "extra/both"]),
                run(&["-Sp", "core/both"]),
                run(&["-Sp", "extra/only-core"]),
                run(&["-Sup"]),
                run(&["-Sp", "--print-format", "%n %r", "both", "only-core", "x-extra"]),
            ],
        );
        c.repos.push(("extra", vec![p("both", "3.0-1"), p("x-extra", "1.0-1")]));
        c
    });
    v.push({
        let mut c = case(
            "verbose-lists",
            vec![p("up", "1.0-1"), p("gone", "1.0-1").cf(&["rp"])],
            vec![p("up", "2.0-1"), p("rp", "1.0-1"), p("new", "1.0-1").rp(&["gone"])],
            vec![
                ask(&["-Su"], "n\n"),
                ask(&["-Su"], "\nn\n"),
                ask(&["-S", "rp"], "y\nn\n"),
                run(&["-Sp", "Cargo.toml"]),
                run(&["-S", "Cargo.toml"]),
            ],
        );
        c.options = "VerbosePkgLists\n";
        c
    });
    // architecture check
    v.push({
        let mut c = case(
            "arch",
            base(),
            vec![
                p("good", "1.0-1").arch("x86_64"),
                p("bad", "1.0-1").arch("armv7h"),
                p("any1", "1.0-1"),
            ],
            vec![
                run(&["-Sp", "good"]),
                run(&["-Sp", "bad"]),
                run(&["-Sp", "bad", "good", "any1"]),
                ask(&["-S", "bad"], "n\n"),
            ],
        );
        c.options = "Architecture = x86_64\n";
        c
    });
    // duplicate file names
    v.push(case(
        "dup-filename",
        base(),
        vec![p("a", "1.0-1"), p("a", "1.0-1")],
        vec![run(&["-Sp", "a"])],
    ));
    // missing sync db
    v.push({
        let mut c = case("missing-db", base(), vec![p("a", "1.0-1")], vec![run(&["-Sp", "a"]), run(&["-Sup"])]);
        c.repos.push(("ghost", vec![]));
        c
    });

    // ---- -Sw: validation of downloaded packages
    let apps = || vec![p("app", "1.0-1").d(&["lib1"]), p("lib1", "1.0-1")];
    v.push({
        let mut c = case(
            "sw-cached-ok",
            vec![],
            apps(),
            vec![run(&["-Sw", "app"]), run(&["-Sw", "app", "lib1"]), ask(&["-Sw", "app"], "y\n")],
        );
        c.cached = true;
        c
    });
    v.push({
        let mut c = case(
            "sw-corrupt",
            vec![],
            apps(),
            vec![run(&["-Sw", "app"]), run(&["-Sw", "app"])],
        );
        c.cached = true;
        c.corrupt = vec!["lib1"];
        c
    });
    v.push({
        let mut c = case(
            "sw-corrupt-ask",
            vec![],
            apps(),
            vec![ask(&["-Sw", "app"], "\n\n"), ask(&["-Sw", "app"], "y\nn\n")],
        );
        c.cached = true;
        c.corrupt = vec!["app", "lib1"];
        c
    });
    v.push({
        let mut c = case(
            "sw-corrupt-no",
            vec![],
            apps(),
            vec![ask(&["-Sw", "app"], "y\nn\n"), ask(&["-Sw", "app"], "y\ny\ny\n")],
        );
        c.cached = true;
        c.corrupt = vec!["app"];
        c
    });
    v.push({
        let mut c = case("sw-sig-valid", vec![], apps(), vec![run(&["-Sw", "app"])]);
        c.cached = true;
        c.options = "SigLevel = Required DatabaseOptional TrustedOnly\n";
        c.sigs = Some(false);
        c.keyring = true;
        c
    });
    v.push({
        let mut c = case(
            "sw-sig-bad",
            vec![],
            apps(),
            vec![run(&["-Sw", "app"]), run(&["-Sw", "app"])],
        );
        c.cached = true;
        c.options = "SigLevel = Required DatabaseOptional TrustedOnly\n";
        c.sigs = Some(true);
        c.keyring = true;
        c
    });
    v.push({
        let mut c = case("sw-sig-missing", vec![], apps(), vec![run(&["-Sw", "app"])]);
        c.cached = true;
        c.options = "SigLevel = Required DatabaseOptional TrustedOnly\n";
        c.keyring = true;
        c
    });
    v.push({
        let mut c = case("sw-sig-optional-missing", vec![], apps(), vec![run(&["-Sw", "app"])]);
        c.cached = true;
        c.options = "SigLevel = Optional TrustAll\n";
        c
    });
    v.push({
        let mut c = case(
            "sw-sysupgrade",
            vec![p("lib1", "0.5-1")],
            apps(),
            vec![run(&["-Suw"]), run(&["-Sw", "-u", "app"]), ask(&["-Suw"], "y\n")],
        );
        c.cached = true;
        c
    });
    v.push(case("sw-not-cached-no-server", vec![], apps(), vec![run(&["-Sw", "app"])]));
    v
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
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = s.parent().unwrap().join(format!("sig-{}", N.fetch_add(1, Ordering::SeqCst)));
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

struct Dirs {
    base: PathBuf,
    root: PathBuf,
    db: PathBuf,
    cache: PathBuf,
    gpg: PathBuf,
    log: PathBuf,
    conf: PathBuf,
}

struct Outcome {
    runs: Vec<(i32, String, String)>,
    files: BTreeMap<String, String>,
}

fn normalize(s: &str, d: &Dirs) -> String {
    s.replace(d.base.to_str().unwrap(), "$D")
}

fn tree(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
        if p.is_dir() {
            out.insert(rel.clone(), "dir".into());
            tree(root, &p, out);
        } else {
            let b = std::fs::read(&p).unwrap_or_default();
            out.insert(rel, format!("{} {:x}", b.len(), Sha256::digest(&b)));
        }
    }
}

fn write_tree(case: &Case, d: &Dirs) {
    for p in [&d.root, &d.db.join("local"), &d.db.join("sync"), &d.cache, &d.gpg, &d.base.join("srv")] {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(d.db.join("local/ALPM_DB_VERSION"), "9\n").unwrap();
    std::fs::set_permissions(&d.gpg, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    for lp in &case.local {
        let dir = d.db.join(format!("local/{}-{}", lp.name, lp.ver));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("desc"), lp.local_desc()).unwrap();
        std::fs::write(dir.join("files"), "%FILES%\n\n").unwrap();
    }
    for (repo, pkgs) in &case.repos {
        if pkgs.is_empty() {
            continue;
        }
        let e: Vec<(String, Vec<u8>)> = pkgs
            .iter()
            .map(|p| (format!("{}-{}/desc", p.name, p.ver), p.sync_desc()))
            .collect();
        let tgz = tar_gz(&e.iter().map(|(n, b)| (n.as_str(), b.clone())).collect::<Vec<_>>());
        std::fs::write(d.db.join(format!("sync/{repo}.db")), tgz).unwrap();
        if case.cached {
            for p in pkgs {
                let mut body = p.body();
                if case.corrupt.contains(&p.name) {
                    // sync desc keeps the checksum of the good file
                    body.push(0);
                }
                let f = d.cache.join(p.filename());
                std::fs::write(&f, &body).unwrap();
                if let Some(tamper) = case.sigs {
                    // sign the good bytes
                    let good = p.body();
                    std::fs::write(d.cache.join(format!("{}.sig", p.filename())), sign_bytes(&good, tamper))
                        .unwrap();
                }
            }
        }
    }
    if case.keyring {
        let (_, v) = keyring();
        for f in ["pubring.gpg", "trustdb.gpg"] {
            std::fs::copy(v.join(f), d.gpg.join(f)).unwrap();
        }
    }
}

fn run_program(bin: &str, case: &Case, idx: &AtomicUsize) -> Outcome {
    let base = std::env::temp_dir().join(format!(
        "pacman-rs-sync-{}-{}-{}",
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
    write_tree(case, &d);
    let mut conf = format!(
        "[options]\nRootDir = {}\nDBPath = {}\nCacheDir = {}/\nLogFile = {}\nGPGDir = {}\nHookDir = {}/hooks\nSigLevel = Never\nLocalFileSigLevel = Never\n{}",
        d.root.display(),
        d.db.display(),
        d.cache.display(),
        d.log.display(),
        d.gpg.display(),
        d.base.display(),
        case.options,
    );
    for (repo, _) in &case.repos {
        conf.push_str(&format!("[{repo}]\nServer = file://{}/srv\n", d.base.display()));
    }
    std::fs::write(&d.conf, conf).unwrap();
    let mut runs = Vec::new();
    for r in &case.runs {
        let mut cmd = Command::new("fakeroot");
        cmd.arg("--").arg(bin).args(["--config", d.conf.to_str().unwrap(), "--noprogressbar"]);
        if r.noconfirm {
            cmd.arg("--noconfirm");
        }
        let mut ch = cmd
            .args(&r.args)
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut si = ch.stdin.take().unwrap();
        let input = r.stdin.to_string();
        let w = std::thread::spawn(move || {
            let _ = si.write_all(input.as_bytes());
        });
        let o = ch.wait_with_output().unwrap();
        let _ = w.join();
        runs.push((
            o.status.code().unwrap_or(-1),
            normalize(&String::from_utf8_lossy(&o.stdout), &d),
            normalize(&String::from_utf8_lossy(&o.stderr), &d),
        ));
    }
    let mut files = BTreeMap::new();
    for sub in [&d.db, &d.cache] {
        tree(&d.base, sub, &mut files);
    }
    files.retain(|k, _| !k.ends_with("ALPM_DB_VERSION"));
    let _ = Command::new("gpgconf")
        .args(["--kill", "all"])
        .env("GNUPGHOME", &d.gpg)
        .status();
    let _ = std::fs::remove_dir_all(&base);
    Outcome { runs, files }
}

fn diff_outcomes(case: &Case, a: &Outcome, b: &Outcome) -> Vec<String> {
    let mut v = Vec::new();
    for (i, (x, y)) in a.runs.iter().zip(&b.runs).enumerate() {
        let args = case.runs[i].args.join(" ");
        if x.0 != y.0 {
            v.push(format!("run {i} ({args}): exit {} vs {}", x.0, y.0));
        }
        if x.1 != y.1 {
            v.push(format!("run {i} ({args}): stdout\n--- ours\n{}\n--- system\n{}", x.1, y.1));
        }
        if x.2 != y.2 {
            v.push(format!("run {i} ({args}): stderr\n--- ours\n{}\n--- system\n{}", x.2, y.2));
        }
    }
    if a.files != b.files {
        v.push(format!("files\n--- ours\n{:#?}\n--- system\n{:#?}", a.files, b.files));
    }
    v
}

#[test]
fn transactions_match_pacman() {
    if !Path::new(SYS).exists() || !Path::new("/usr/bin/fakeroot").exists() {
        eprintln!("skip: pacman or fakeroot missing");
        return;
    }
    let ours = env!("CARGO_BIN_EXE_pacman-rs");
    let cases = build_cases();
    let only = std::env::var("SYNC_DIFF_ONLY").ok();
    let idx = AtomicUsize::new(0);
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(&'static str, usize, Vec<String>)>> = Mutex::new(Vec::new());
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
                    results.lock().unwrap().push((c.name, c.runs.len(), d));
                }
            });
        }
    });
    let mut r = results.into_inner().unwrap();
    r.sort_by_key(|x| x.0);
    let (mut failed, mut runs) = (0, 0);
    for (name, n, d) in &r {
        runs += n;
        if d.is_empty() {
            eprintln!("ok   {name} ({n} runs)");
        } else {
            failed += 1;
            eprintln!("FAIL {name}");
            for x in d.iter().take(5) {
                eprintln!("    {x}");
            }
        }
    }
    eprintln!("transaction cases: {} run ({runs} commands), {} failed", r.len(), failed);
    assert_eq!(failed, 0);
    let _ = std::fs::remove_dir_all(keyring().0.parent().unwrap());
}

/// the live databases: a copy of /var/lib/pacman, read-only operations (--print) against the system pacman
#[test]
fn live_print_matches_pacman() {
    if !Path::new(SYS).exists() || !Path::new("/var/lib/pacman/local").exists() {
        eprintln!("skip: no pacman databases");
        return;
    }
    let base = std::env::temp_dir().join(format!("pacman-rs-sync-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let cp = Command::new("cp")
        .args(["-r", "/var/lib/pacman/local", "/var/lib/pacman/sync"])
        .arg(&base)
        .status()
        .unwrap();
    assert!(cp.success());
    let ours = env!("CARGO_BIN_EXE_pacman-rs");
    let sets: &[&[&str]] = &[
        &["-Sup"],
        &["-Suup"],
        &["-Sp", "base-devel", "linux"],
        &["-Sp", "--print-format", "%n %v %r %s %f", "extra/vim"],
        &["-Sp", "--needed", "base"],
        &["-Sp", "nonexistent-pkg-xyz"],
        &["-Sp", "base-devel", "--ignore", "gcc"],
        &["-Sp", "--print-format", "%n-%v", "gnome"],
        &["-Sup", "--ignore", "linux"],
        &["-Sp", "core/linux", "extra/vim", "extra/gvim"],
    ];
    let mut failed = 0;
    for a in sets {
        let go = |bin: &str| {
            let o = Command::new(bin)
                .arg("--dbpath")
                .arg(&base)
                .args(*a)
                .env_clear()
                .env("LC_ALL", "C")
                .output()
                .unwrap();
            (
                o.status.code(),
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            )
        };
        let (x, y) = (go(ours), go(SYS));
        if x != y {
            failed += 1;
            eprintln!("FAIL live {a:?}\n--- ours {x:?}\n--- system {y:?}");
        } else {
            eprintln!("ok   live {a:?}");
        }
    }
    let _ = std::fs::remove_dir_all(&base);
    assert_eq!(failed, 0);
}
