use libalpm_rs::be_local::db_register_local;
use libalpm_rs::db::Db;
use libalpm_rs::deps::dep_compute_string;
use libalpm_rs::error::Error;
use libalpm_rs::handle::Handle;
use libalpm_rs::log::*;
use libalpm_rs::package::*;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

type Logs = Rc<RefCell<Vec<(u32, String)>>>;

fn open(dbpath: &str) -> (Db, Logs) {
    let h = Handle::new(dbpath);
    let logs: Logs = Rc::new(RefCell::new(Vec::new()));
    let l2 = logs.clone();
    *h.logcb.borrow_mut() = Some(Box::new(move |lvl, m| {
        l2.borrow_mut().push((lvl, m.to_string()))
    }));
    (db_register_local(&h).expect("register"), logs)
}

fn errs(logs: &Logs) -> Vec<String> {
    logs.borrow()
        .iter()
        .filter(|(l, _)| *l & (LOG_ERROR | LOG_WARNING) != 0)
        .map(|(_, m)| m.clone())
        .collect()
}

fn fixture(name: &str) -> PathBuf {
    let r = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("localdb-{name}"));
    let _ = std::fs::remove_dir_all(&r);
    std::fs::create_dir_all(r.join("local")).unwrap();
    std::fs::write(r.join("local/ALPM_DB_VERSION"), "9\n").unwrap();
    r
}

fn put(root: &Path, dir: &str, file: &str, body: &str) {
    let d = root.join("local").join(dir);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join(file), body).unwrap();
}

const FULL_DESC: &str = "%NAME%\nfull\n\n%VERSION%\n1:2.0-3\n\n%BASE%\nfullbase\n\n%DESC%\nA full package\n\n%URL%\nhttps://example.org\n\n\
%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000000\n\n%INSTALLDATE%\n1700000100\n\n%PACKAGER%\nSomeone <a@b.c>\n\n%SIZE%\n12345\n\n\
%REASON%\n1\n\n%GROUPS%\ng1\ng2\n\n%LICENSE%\nGPL\nMIT\n\n%VALIDATION%\nmd5\nsha256\npgp\nbogus\n\n%REPLACES%\nold\nolder<2\n\n\
%DEPENDS%\nglibc>=2.30\nbash\n\n%OPTDEPENDS%\nfoo: for foo support\nbar\n\n%MAKEDEPENDS%\ngcc\n\n%CHECKDEPENDS%\ncheck\n\n\
%CONFLICTS%\nclash=1\n\n%PROVIDES%\nvirt=1.0\nlibx.so=1-64\n\n%XDATA%\npkgtype=pkg\nother=a=b\n\n";

#[test]
fn every_field() {
    let r = fixture("fields");
    put(&r, "full-1:2.0-3", "desc", FULL_DESC);
    put(
        &r,
        "full-1:2.0-3",
        "files",
        "%FILES%\nusr/\nusr/bin/\nusr/bin/full\netc/full.conf\n\n%BACKUP%\netc/full.conf\tabc123\nnohash\n\n",
    );
    put(&r, "full-1:2.0-3", "install", "post_install() { :; }\n");
    put(&r, "full-1:2.0-3", "changelog", "log\n");
    let (mut db, logs) = open(r.to_str().unwrap());
    let p = db.get_pkg("full").unwrap();
    assert_eq!((p.name.as_str(), p.version.as_str()), ("full", "1:2.0-3"));
    let d = p.desc();
    assert_eq!(d.base.as_deref(), Some("fullbase"));
    assert_eq!(d.desc.as_deref(), Some("A full package"));
    assert_eq!(d.url.as_deref(), Some("https://example.org"));
    assert_eq!(
        (d.arch.as_deref(), d.builddate, d.installdate, d.isize),
        (Some("x86_64"), 1700000000, 1700000100, 12345)
    );
    assert_eq!(d.packager.as_deref(), Some("Someone <a@b.c>"));
    assert_eq!(d.reason, PkgReason::Depend);
    assert_eq!(d.groups, ["g1", "g2"]);
    assert_eq!(d.licenses, ["GPL", "MIT"]);
    assert_eq!(
        d.validation,
        PKG_VALIDATION_MD5SUM | PKG_VALIDATION_SHA256SUM | PKG_VALIDATION_SIGNATURE
    );
    let s = |v: &Vec<libalpm_rs::deps::Dep>| v.iter().map(dep_compute_string).collect::<Vec<_>>();
    assert_eq!(s(&d.replaces), ["old", "older<2"]);
    assert_eq!(s(&d.depends), ["glibc>=2.30", "bash"]);
    assert_eq!(s(&d.optdepends), ["foo: for foo support", "bar"]);
    assert_eq!(s(&d.makedepends), ["gcc"]);
    assert_eq!(s(&d.checkdepends), ["check"]);
    assert_eq!(s(&d.conflicts), ["clash=1"]);
    assert_eq!(s(&d.provides), ["virt=1.0", "libx.so=1-64"]);
    assert_eq!(
        d.xdata,
        [
            Xdata {
                name: "pkgtype".into(),
                value: "pkg".into()
            },
            Xdata {
                name: "other".into(),
                value: "a=b".into()
            }
        ]
    );
    let names: Vec<_> = p.files().files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["etc/full.conf", "usr/", "usr/bin/", "usr/bin/full"]); // sorted on load
    assert_eq!(p.backup().len(), 2);
    assert_eq!(p.backup()[0].hash.as_deref(), Some("abc123"));
    assert_eq!(p.backup()[1].hash, None);
    assert!(p.has_scriptlet());
    assert!(p.changelog_open().is_some());
    assert!(p.files().contains("usr/bin/full").is_some());
    assert_eq!(
        errs(&logs),
        ["unknown validation type for package full: bogus\n"]
    );
}

#[test]
fn groups_and_lookup() {
    let r = fixture("groups");
    for (n, g) in [
        ("a", "grp1\ngrp2\n"),
        ("b", "grp1\n"),
        ("c", "grp1\ngrp1\n"),
    ] {
        put(
            &r,
            &format!("{n}-1-1"),
            "desc",
            &format!("%NAME%\n{n}\n\n%VERSION%\n1-1\n\n%GROUPS%\n{g}\n"),
        );
        put(&r, &format!("{n}-1-1"), "files", "%FILES%\n\n");
    }
    let (mut db, _) = open(r.to_str().unwrap());
    let names: Vec<_> = db
        .get_pkgcache()
        .unwrap()
        .iter()
        .map(|p| p.name.clone())
        .collect();
    assert_eq!(names, ["a", "b", "c"]);
    assert_eq!(db.get_pkg("zzz").err(), Some(Error::PkgNotFound));
    assert_eq!(db.get_pkg("").err(), Some(Error::WrongArgs));
    let gc: Vec<_> = db
        .get_groupcache()
        .unwrap()
        .iter()
        .map(|g| (g.name.clone(), g.packages.clone()))
        .collect();
    // a pkg listing a group twice creates a second group entry (upstream quirk)
    assert_eq!(
        gc,
        [
            ("grp1".into(), vec![0, 1, 2]),
            ("grp2".into(), vec![0]),
            ("grp1".into(), vec![2])
        ]
    );
    assert!(db.get_group("grp2").unwrap().is_some());
    assert!(db.get_group("nope").unwrap().is_none());
}

#[test]
fn malformed_entries() {
    let r = fixture("bad");
    // stale-line quirk: desc ends without blank line
    put(
        &r,
        "stale-1-1",
        "desc",
        "%NAME%\nstale\n\n%VERSION%\n1-1\n\n%DESC%\nhello\n",
    );
    put(&r, "stale-1-1", "files", "%FILES%\nf\n");
    // mismatches, bad reason, unknown key, junk numbers
    put(
        &r,
        "mism-1-1",
        "desc",
        "%NAME%\nother\n\n%VERSION%\n9-9\n\n%REASON%\n7\n\n%SIZE%\n12x\n\n%BUILDDATE%\nabc\n\n%WHAT%\nx\ny\n\n%ARCH%\nany\n",
    );
    // bad xdata: later loads give up silently
    put(
        &r,
        "xd-1-1",
        "desc",
        "%NAME%\nxd\n\n%VERSION%\n1-1\n\n%XDATA%\nnoequals\n\n%ARCH%\nany\n\n",
    );
    put(&r, "xd-1-1", "files", "%FILES%\nf\n\n");
    // no files file
    put(
        &r,
        "nofiles-1-1",
        "desc",
        "%NAME%\nnofiles\n\n%VERSION%\n1-1\n\n",
    );
    // long line is split at 1023 bytes
    let long = "x".repeat(1500);
    put(
        &r,
        "long-1-1",
        "desc",
        &format!("%NAME%\nlong\n\n%VERSION%\n1-1\n\n%DESC%\n{long}\n\n"),
    );
    // invalid dir name, plain file, bad metadata
    std::fs::create_dir_all(r.join("local/invalidname")).unwrap();
    std::fs::write(r.join("local/afile"), "x").unwrap();
    put(&r, "-lead-1-1", "desc", "");
    put(&r, "dupe-1-1", "desc", "");
    put(&r, "dupe-2-1", "desc", "");
    let (mut db, logs) = open(r.to_str().unwrap());
    let names: Vec<_> = db
        .get_pkgcache()
        .unwrap()
        .iter()
        .map(|p| p.name.clone())
        .collect();
    assert_eq!(names.iter().filter(|n| *n == "dupe").count(), 1);
    assert!(!names.iter().any(|n| n == "invalidname" || n == "afile"));
    let e = errs(&logs);
    assert!(
        e.contains(&"invalid name for database entry 'invalidname'\n".to_string()),
        "{e:?}"
    );
    assert!(
        e.iter()
            .any(|m| m.starts_with("duplicated database entry 'dupe'"))
    );
    assert!(
        e.contains(
            &"invalid metadata for package -lead-1-1 (package name cannot start with '.' or '-')\n"
                .to_string()
        ),
        "{e:?}"
    );
    logs.borrow_mut().clear();

    let p = db.get_pkg("stale").unwrap();
    assert_eq!(p.desc().desc.as_deref(), Some("hello"));
    assert_eq!(p.files().files.len(), 1);
    assert_eq!(
        errs(&logs),
        ["stale: unknown key 'hello' in local database\n"]
    );
    logs.borrow_mut().clear();

    let p = db.get_pkg("mism").unwrap();
    let d = p.desc();
    assert_eq!(
        (d.reason, d.isize, d.builddate, d.arch.as_deref()),
        (PkgReason::Unknown, -1, 0, Some("any"))
    );
    assert_eq!(
        errs(&logs),
        [
            "local database is inconsistent: name mismatch on package mism\n",
            "local database is inconsistent: version mismatch on package mism\n",
            "unknown install reason for package mism: 7\n",
            "mism: unknown key '%WHAT%' in local database\n",
            "mism: unknown key 'any' in local database\n" // stale-line quirk: desc ends without a blank line
        ]
    );
    logs.borrow_mut().clear();

    let p = db.get_pkg("xd").unwrap();
    assert_eq!(p.desc().arch, None); // parse stopped at the bad xdata
    assert!(p.files().files.is_empty()); // load refused after the error, silently
    assert_eq!(p.force_load(), -1);
    assert_eq!(errs(&logs).len(), 0);

    let p = db.get_pkg("nofiles").unwrap();
    assert_eq!(p.desc().base, None);
    assert!(p.files().files.is_empty());
    assert_eq!(errs(&logs).len(), 1);
    assert!(
        errs(&logs)[0].starts_with("could not open file "),
        "{:?}",
        errs(&logs)
    );
    assert!(!p.has_scriptlet());

    let p = db.get_pkg("long").unwrap();
    let d = p.desc().desc.clone().unwrap();
    assert_eq!(d.len(), 1023);
}

#[test]
fn validate_errors() {
    // wrong version
    let r = fixture("ver");
    std::fs::write(r.join("local/ALPM_DB_VERSION"), "8\n").unwrap();
    let h = Handle::new(r.to_str().unwrap());
    assert_eq!(db_register_local(&h).err(), Some(Error::DbVersion));
    // no version file, non-empty dir
    let r = fixture("nover");
    std::fs::remove_file(r.join("local/ALPM_DB_VERSION")).unwrap();
    put(&r, "x-1-1", "desc", "");
    let h = Handle::new(r.to_str().unwrap());
    assert_eq!(db_register_local(&h).err(), Some(Error::DbVersion));
    // empty dir: version file is created
    let r = fixture("empty");
    std::fs::remove_file(r.join("local/ALPM_DB_VERSION")).unwrap();
    let h = Handle::new(r.to_str().unwrap());
    assert!(db_register_local(&h).is_ok());
    assert_eq!(
        std::fs::read_to_string(r.join("local/ALPM_DB_VERSION")).unwrap(),
        "9\n"
    );
    // missing dir: created
    let r = fixture("missing");
    std::fs::remove_dir_all(r.join("local")).unwrap();
    let h = Handle::new(r.to_str().unwrap());
    assert!(db_register_local(&h).is_ok());
    assert!(r.join("local/ALPM_DB_VERSION").exists());
    // missing parent: cannot create
    let h = Handle::new("/nonexistent-parent/db");
    assert_eq!(db_register_local(&h).err(), Some(Error::DbCreate));
}

#[test]
fn live_database_matches_pacman() {
    let live = "/var/lib/pacman/";
    if !Path::new("/usr/bin/pacman").exists()
        || !Path::new(live).join("local/ALPM_DB_VERSION").exists()
    {
        eprintln!("skip: no live pacman database");
        return;
    }
    let (mut db, logs) = open(live);
    let out = Command::new("pacman")
        .arg("-Q")
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    let expect = String::from_utf8(out.stdout).unwrap();
    let got: String = db
        .get_pkgcache()
        .unwrap()
        .iter()
        .map(|p| format!("{} {}\n", p.name, p.version))
        .collect();
    assert_eq!(got, expect);
    let n = db.get_pkgcache().unwrap().len();
    assert!(n > 20);
    // 20 random packages: file lists must match -Ql exactly
    let mut seed = 0x9E3779B97F4A7C15u64;
    for _ in 0..20 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let name = db.get_pkgcache().unwrap()[(seed % n as u64) as usize]
            .name
            .clone();
        let out = Command::new("pacman")
            .args(["-Ql", &name])
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        let expect = String::from_utf8(out.stdout).unwrap();
        let p = db.get_pkg(&name).unwrap();
        let got: String = p
            .files()
            .files
            .iter()
            .map(|f| format!("{} {}\n", name, f.name))
            .collect::<String>();
        // -Ql prints "name /path"
        let got = got.replace(&format!("{name} "), &format!("{name} /"));
        assert_eq!(got, expect, "{name}");
    }
    // everything else loads without a single logged error/warning
    for p in db.get_pkgcache().unwrap() {
        assert_eq!(p.force_load(), 0);
    }
    assert!(errs(&logs).is_empty(), "{:?}", errs(&logs));
}
