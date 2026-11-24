//! Rust twin of tests/oracle/sigcheck.c (same arguments, same output); used by tests/signing_diff.rs.
use libalpm_rs::alpm::alpm_initialize;
use libalpm_rs::be_package::pkg_load;
use libalpm_rs::signing::{SigList, db_check_pgp_signature, pkg_check_pgp_signature};

fn show_list(l: &SigList) {
    for (i, r) in l.iter().enumerate() {
        println!(
            "result {i}: status={} validity={} fpr={} uid={}",
            r.status as i32,
            r.validity as i32,
            r.key.fingerprint,
            r.key.uid.as_deref().unwrap_or("(null)")
        );
    }
}

fn errno(h: &libalpm_rs::handle::Handle) -> i32 {
    h.errno().map_or(0, |e| e as i32)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (mode, gpgdir, dbpath, level, path) =
        (&a[1], &a[2], &a[3], a[4].parse::<i32>().unwrap(), &a[5]);
    let mut alpm = alpm_initialize("/", dbpath).expect("init");
    let h = alpm.handle.clone();
    *h.logcb.borrow_mut() = Some(Box::new(|lvl, msg| {
        if lvl & (libalpm_rs::log::LOG_ERROR | libalpm_rs::log::LOG_WARNING) != 0
            || std::env::var("SIGCHECK_DEBUG").is_ok()
        {
            print!(
                "log {}: {}",
                if lvl & libalpm_rs::log::LOG_ERROR != 0 {
                    'E'
                } else {
                    'W'
                },
                msg
            );
        }
    }));
    h.set_gpgdir(gpgdir);
    match mode.as_str() {
        "pkgload" => match pkg_load(&h, path, false, level) {
            Ok(p) => {
                println!("ret=0 errno={}", errno(&h));
                println!("validation={}", p.desc().validation);
            }
            Err(_) => println!("ret=-1 errno={}", errno(&h)),
        },
        "pkgsig" => {
            let pkg = pkg_load(&h, path, false, 0).expect("load");
            let r = pkg_check_pgp_signature(&pkg);
            println!("ret={} errno={}", if r.is_ok() { 0 } else { -1 }, errno(&h));
            if let Ok(l) = &r {
                show_list(l);
            }
        }
        "dbvalid" | "dbsig" => {
            alpm.register_syncdb("foo", level).expect("register");
            let db = &alpm.syncdbs[0];
            if mode == "dbvalid" {
                let ret = db.get_valid();
                println!("ret={} errno={}", ret, errno(&h));
            } else {
                let r = db_check_pgp_signature(db);
                println!("ret={} errno={}", if r.is_ok() { 0 } else { -1 }, errno(&h));
                if let Ok(l) = &r {
                    show_list(l);
                }
            }
        }
        "syncpkg" => {
            alpm.register_syncdb("foo", 0).expect("register");
            let pkg = alpm.syncdbs[0].get_pkg("sp").expect("pkg");
            let r = pkg_check_pgp_signature(pkg);
            println!("ret={} errno={}", if r.is_ok() { 0 } else { -1 }, errno(&h));
            if let Ok(l) = &r {
                show_list(l);
            }
        }
        _ => std::process::exit(2),
    }
}
