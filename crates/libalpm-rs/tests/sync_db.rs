use libalpm_rs::be_sync::db_register_sync;
use libalpm_rs::db::*;
use libalpm_rs::deps::dep_compute_string;
use libalpm_rs::error::Error;
use libalpm_rs::handle::{Event, Handle};
use libalpm_rs::log::*;
use libalpm_rs::package::*;
use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

type Logs = Rc<RefCell<Vec<(u32, String)>>>;

fn handle(dbpath: &str, ext: &str) -> (Rc<Handle>, Logs, Rc<RefCell<Vec<Event>>>) {
    let h = Handle::with_dbext(dbpath, ext);
    let logs: Logs = Rc::new(RefCell::new(Vec::new()));
    let l2 = logs.clone();
    *h.logcb.borrow_mut() = Some(Box::new(move |lvl, m| {
        l2.borrow_mut().push((lvl, m.to_string()))
    }));
    let ev = Rc::new(RefCell::new(Vec::new()));
    let e2 = ev.clone();
    *h.eventcb.borrow_mut() = Some(Box::new(move |e| e2.borrow_mut().push(e.clone())));
    (h, logs, ev)
}

fn errs(logs: &Logs) -> Vec<String> {
    logs.borrow()
        .iter()
        .filter(|(l, _)| *l & (LOG_ERROR | LOG_WARNING) != 0)
        .map(|(_, m)| m.clone())
        .collect()
}

/// build a tar from (path, data) entries; a path ending in '/' is a directory
fn tar(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (p, d) in entries {
        let mut h = tar::Header::new_gnu();
        if p.ends_with('/') {
            h.set_entry_type(tar::EntryType::Directory);
            h.set_size(0);
            h.set_mode(0o755);
        } else {
            h.set_size(d.len() as u64);
            h.set_mode(0o644);
        }
        h.set_cksum();
        b.append_data(&mut h, p, d.as_bytes()).unwrap();
    }
    b.into_inner().unwrap()
}

fn compress(kind: &str, raw: &[u8]) -> Vec<u8> {
    match kind {
        "none" => raw.to_vec(),
        "gz" => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(raw).unwrap();
            e.finish().unwrap()
        }
        "zst" => zstd::encode_all(raw, 3).unwrap(),
        "xz" => {
            let mut e = liblzma::write::XzEncoder::new(Vec::new(), 6);
            e.write_all(raw).unwrap();
            e.finish().unwrap()
        }
        "bz2" => {
            let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            e.write_all(raw).unwrap();
            e.finish().unwrap()
        }
        "lz4" => {
            let mut e = lz4_flex::frame::FrameEncoder::new(Vec::new());
            e.write_all(raw).unwrap();
            e.finish().unwrap()
        }
        _ => unreachable!(),
    }
}

fn root(name: &str) -> PathBuf {
    let r = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("syncdb-{name}"));
    let _ = std::fs::remove_dir_all(&r);
    std::fs::create_dir_all(r.join("sync")).unwrap();
    r
}

const DESC: &str = "%FILENAME%\nfoo-1.0-1-x86_64.pkg.tar.zst\n\n%NAME%\nfoo\n\n%BASE%\nfoobase\n\n%VERSION%\n1.0-1\n\n%DESC%\nFoo thing\n\n%GROUPS%\ngrpA\n\n\
%CSIZE%\n1000\n\n%ISIZE%\n5000\n\n%MD5SUM%\nd41d8cd98f00b204e9800998ecf8427e\n\n%SHA256SUM%\ne3b0c44298fc1c149afbf4c8996fb924\n\n%PGPSIG%\nQUJD\n\n\
%URL%\nhttps://foo.example\n\n%LICENSE%\nMIT\nGPL\n\n%ARCH%\nx86_64\n\n%BUILDDATE%\n1700000000\n\n%PACKAGER%\nBuilder <b@x>\n\n%REPLACES%\nbar\n\n\
%CONFLICTS%\nbaz<2\n\n%PROVIDES%\nfoo-api=1\n\n%DATA%\npkgtype=pkg\n\n";
const DEPENDS: &str = "%DEPENDS%\nglibc>=2.30\nbash\n\n%OPTDEPENDS%\nfoo: thing\n\n%MAKEDEPENDS%\ngcc\n\n%CHECKDEPENDS%\ncheck\n\n";

fn good_entries() -> Vec<(&'static str, &'static str)> {
    vec![
        ("foo-1.0-1/", ""),
        ("foo-1.0-1/desc", DESC),
        ("foo-1.0-1/depends", DEPENDS),
        ("bar-2-1/desc", "%NAME%\nbar\n\n%VERSION%\n2-1\n"),
        ("bar-2-1/files", "%FILES%\nusr/\nusr/bin/bar\n\n"),
    ]
}

#[test]
fn all_filters_and_fields() {
    for kind in ["none", "gz", "zst", "xz", "bz2", "lz4"] {
        let r = root(kind);
        std::fs::write(
            r.join("sync/test.db"),
            compress(kind, &tar(&good_entries())),
        )
        .unwrap();
        let (h, logs, _) = handle(r.to_str().unwrap(), ".db");
        let mut db = db_register_sync(&h, "test", 0);
        assert_eq!(db.get_valid(), 0);
        let names: Vec<_> = db
            .get_pkgcache()
            .unwrap_or_else(|e| panic!("{kind}: {e}"))
            .iter()
            .map(|p| p.name.clone())
            .collect();
        assert_eq!(names, ["bar", "foo"], "{kind}");
        let p = db.get_pkg("foo").unwrap();
        assert_eq!(p.origin, PkgFrom::SyncDb);
        assert_eq!(p.version, "1.0-1");
        assert_eq!(p.filename.as_deref(), Some("foo-1.0-1-x86_64.pkg.tar.zst"));
        assert_eq!(p.size, 1000);
        assert_eq!(
            p.md5sum.as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
        assert_eq!(p.base64_sig.as_deref(), Some("QUJD"));
        let d = p.desc();
        assert_eq!((d.isize, d.builddate), (5000, 1700000000));
        assert_eq!(d.licenses, ["MIT", "GPL"]);
        assert_eq!(d.groups, ["grpA"]);
        assert_eq!(d.xdata[0].name, "pkgtype");
        let s =
            |v: &Vec<libalpm_rs::deps::Dep>| v.iter().map(dep_compute_string).collect::<Vec<_>>();
        assert_eq!(
            (
                s(&d.depends),
                s(&d.makedepends),
                s(&d.checkdepends),
                s(&d.optdepends)
            ),
            (
                vec!["glibc>=2.30".to_string(), "bash".into()],
                vec!["gcc".to_string()],
                vec!["check".to_string()],
                vec!["foo: thing".to_string()]
            )
        );
        assert_eq!(
            (s(&d.replaces), s(&d.conflicts), s(&d.provides)),
            (
                vec!["bar".to_string()],
                vec!["baz<2".to_string()],
                vec!["foo-api=1".to_string()]
            )
        );
        assert_eq!(
            d.validation,
            PKG_VALIDATION_MD5SUM | PKG_VALIDATION_SHA256SUM | PKG_VALIDATION_SIGNATURE
        );
        let bar = db.get_pkg("bar").unwrap();
        assert_eq!(bar.desc().validation, PKG_VALIDATION_NONE);
        assert_eq!(bar.files().files.len(), 2);
        // desc ending with "%VERSION%\n2-1\n" and no blank line is fine (upstream returns a trailing empty line)
        assert!(errs(&logs).is_empty(), "{kind}: {:?}", errs(&logs));
        let g: Vec<_> = db
            .get_groupcache()
            .unwrap()
            .iter()
            .map(|g| g.name.clone())
            .collect();
        assert_eq!(g, ["grpA"]);
    }
}

#[test]
fn files_db_extension() {
    let r = root("files");
    std::fs::write(
        r.join("sync/test.files"),
        compress("gz", &tar(&good_entries())),
    )
    .unwrap();
    let (h, _, _) = handle(r.to_str().unwrap(), ".files");
    let mut db = db_register_sync(&h, "test", 0);
    assert!(db.path().ends_with("sync/test.files"));
    let bar = db.get_pkg("bar").unwrap();
    assert_eq!(bar.files().files[1].name, "usr/bin/bar");
}

#[test]
fn missing_db_raises_event() {
    let r = root("missing");
    let (h, _, ev) = handle(r.to_str().unwrap(), ".db");
    let mut db = db_register_sync(&h, "nope", 0);
    assert_eq!(
        *ev.borrow(),
        [Event::DatabaseMissing {
            dbname: "nope".into()
        }]
    );
    assert_eq!(db.get_valid(), 0);
    assert!(db.get_pkgcache().is_err());
    assert_eq!(h.errno(), Some(Error::DbNotFound));
}

fn load(name: &str, entries: &[(&str, &str)]) -> (Result<Vec<String>, Error>, Vec<String>, Db) {
    let r = root(name);
    std::fs::write(r.join("sync/t.db"), compress("gz", &tar(entries))).unwrap();
    let (h, logs, _) = handle(r.to_str().unwrap(), ".db");
    let mut db = db_register_sync(&h, "t", 0);
    let res = db
        .get_pkgcache()
        .map(|v| v.iter().map(|p| p.name.clone()).collect());
    (res, errs(&logs), db)
}

#[test]
fn malformed() {
    // invalid entry name: db is invalid
    let (r, e, db) = load(
        "badname",
        &[
            ("garbage/desc", "%NAME%\ngarbage\n\n"),
            ("a-1-1/desc", "%NAME%\na\n\n%VERSION%\n1-1\n"),
        ],
    );
    assert_eq!(r.err(), Some(Error::DbInvalid));
    assert_eq!(
        e,
        [
            "invalid name for database entry 'garbage/desc'\n",
            "could not parse package description file 'garbage/desc' from db 't'\n"
        ]
    );
    assert_eq!(db.status.get() & DB_STATUS_INVALID, DB_STATUS_INVALID);
    // illegal filename
    let (r, e, _) = load(
        "badfn",
        &[("a-1-1/desc", "%NAME%\na\n\n%FILENAME%\n../x.pkg\n\n")],
    );
    assert_eq!(r.err(), Some(Error::DbInvalid));
    assert_eq!(
        e[0],
        "t database is inconsistent: filename of package a is illegal\n"
    );
    // name mismatch is only an error message
    let (r, e, _) = load("mism", &[("a-1-1/desc", "%NAME%\nb\n\n%VERSION%\n9-9\n\n")]);
    assert_eq!(r.unwrap(), ["a"]);
    assert_eq!(
        e,
        [
            "t database is inconsistent: name mismatch on package a\n",
            "t database is inconsistent: version mismatch on package a\n"
        ]
    );
    // unknown key, entry without directory, unknown file
    let (r, e, _) = load(
        "unk",
        &[
            ("a-1-1/desc", "%WHAT%\nx\n\n%NAME%\na\n\n"),
            ("b-1-1", "x"),
            ("a-1-1/other", "zzz"),
        ],
    );
    assert_eq!(r.unwrap(), ["a", "b"]);
    assert_eq!(
        e,
        [
            "a: unknown key '%WHAT%' in sync database\n",
            "unknown database file: b-1-1\n"
        ]
    );
    // %NAME% as last line: the trailing empty line is read as the value
    let (r, e, _) = load("trail", &[("a-1-1/desc", "%NAME%\n")]);
    assert_eq!(r.unwrap(), ["a"]);
    assert_eq!(
        e,
        ["t database is inconsistent: name mismatch on package a\n"]
    );
    // bad xdata
    let (r, _, _) = load("xd", &[("a-1-1/desc", "%DATA%\nnoequals\n\n")]);
    assert_eq!(r.err(), Some(Error::DbInvalid));
    // package metadata check
    let (r, e, _) = load("meta", &[("-x-1-1/desc", "%NAME%\n-x\n\n")]);
    assert_eq!(r.err(), Some(Error::DbInvalid));
    assert_eq!(
        e[0],
        "invalid metadata for package -x-1-1 (package name cannot start with '.' or '-')\n"
    );
    // not an archive
    let r = root("garbage");
    std::fs::write(r.join("sync/t.db"), vec![0x41u8; 2048]).unwrap();
    let (h, logs, _) = handle(r.to_str().unwrap(), ".db");
    let mut db = db_register_sync(&h, "t", 0);
    assert_eq!(db.get_pkgcache().err(), Some(Error::Libarchive));
    assert!(errs(&logs)[0].starts_with("could not read db 't' ("));
    // empty file: no packages
    let r = root("empty");
    std::fs::write(r.join("sync/t.db"), b"").unwrap();
    let (h, _, _) = handle(r.to_str().unwrap(), ".db");
    let mut db = db_register_sync(&h, "t", 0);
    assert_eq!(db.get_pkgcache().unwrap().len(), 0);
}

fn sl(repo: &str) -> Vec<String> {
    let out = Command::new("pacman")
        .args(["-Sl", repo])
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| l.split(' ').take(3).collect::<Vec<_>>().join(" "))
        .collect()
}

/// field value(s) of a `pacman -Si` block
fn si_field(block: &str, key: &str) -> Option<String> {
    block.lines().find_map(|l| {
        let (k, v) = l.split_once(" : ")?;
        (k.trim_end() == key).then(|| v.to_string())
    })
}

#[test]
fn live_sync_dbs_match_pacman() {
    let live = Path::new("/var/lib/pacman/sync");
    if !Path::new("/usr/bin/pacman").exists() || !live.exists() {
        eprintln!("skip: no live sync databases");
        return;
    }
    let mut repos: Vec<String> = std::fs::read_dir(live)
        .unwrap()
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_string_lossy()
                .strip_suffix(".db")
                .map(String::from)
        })
        .collect();
    repos.sort();
    assert!(!repos.is_empty());
    let (h, logs, _) = handle("/var/lib/pacman/", ".db");
    let mut seed = 0x9E3779B97F4A7C15u64;
    for repo in repos {
        let mut db = db_register_sync(&h, &repo, 0);
        assert_eq!(db.get_valid(), 0);
        let got: Vec<String> = db
            .get_pkgcache()
            .unwrap()
            .iter()
            .map(|p| format!("{repo} {} {}", p.name, p.version))
            .collect();
        assert_eq!(got, sl(&repo), "{repo}");
        let n = got.len();
        for _ in 0..10.min(n) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let name = db.get_pkgcache().unwrap()[(seed % n as u64) as usize]
                .name
                .clone();
            let out = Command::new("pacman")
                .args(["-Si", &format!("{repo}/{name}")])
                .env("LC_ALL", "C")
                .output()
                .unwrap();
            let block = String::from_utf8(out.stdout).unwrap();
            let p = db.get_pkg(&name).unwrap();
            let d = p.desc();
            let list = |v: &Vec<libalpm_rs::deps::Dep>| {
                if v.is_empty() {
                    "None".to_string()
                } else {
                    v.iter()
                        .map(dep_compute_string)
                        .collect::<Vec<_>>()
                        .join("  ")
                }
            };
            let strs = |v: &Vec<String>| {
                if v.is_empty() {
                    "None".to_string()
                } else {
                    v.join("  ")
                }
            };
            assert_eq!(si_field(&block, "Name").as_deref(), Some(name.as_str()));
            assert_eq!(
                si_field(&block, "Version").as_deref(),
                Some(p.version.as_str()),
                "{name}"
            );
            assert_eq!(
                si_field(&block, "Description").as_deref(),
                d.desc.as_deref(),
                "{name}"
            );
            assert_eq!(
                si_field(&block, "Architecture").as_deref(),
                d.arch.as_deref(),
                "{name}"
            );
            assert_eq!(
                si_field(&block, "URL").unwrap_or_default(),
                d.url.clone().unwrap_or_else(|| "None".into()),
                "{name}"
            );
            assert_eq!(
                si_field(&block, "Licenses").unwrap(),
                strs(&d.licenses),
                "{name}"
            );
            assert_eq!(
                si_field(&block, "Groups").unwrap(),
                strs(&d.groups),
                "{name}"
            );
            assert_eq!(
                si_field(&block, "Depends On").unwrap(),
                list(&d.depends),
                "{name}"
            );
            assert_eq!(
                si_field(&block, "Provides").unwrap(),
                list(&d.provides),
                "{name}"
            );
            assert_eq!(
                si_field(&block, "Conflicts With").unwrap(),
                list(&d.conflicts),
                "{name}"
            );
            assert_eq!(
                si_field(&block, "Replaces").unwrap(),
                list(&d.replaces),
                "{name}"
            );
            assert_eq!(
                si_field(&block, "Packager").as_deref(),
                d.packager.as_deref(),
                "{name}"
            );
            assert!(
                p.filename.is_some() && p.size > 0 && p.md5sum.is_some() || p.sha256sum.is_some(),
                "{name}"
            );
        }
    }
    assert!(errs(&logs).is_empty(), "{:?}", errs(&logs));
}
