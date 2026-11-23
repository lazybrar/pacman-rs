//! Port of src/pacman/deptest.c: -T
use crate::conf::Config;
use crate::pr;
use libalpm_rs::deps::find_satisfier;

/// pacman_deptest
pub fn pacman_deptest(cfg: &Config, targets: &[String]) -> i32 {
    let localdb = &cfg.alpm.as_ref().unwrap().localdb;
    let pkgcache = localdb.get_pkgcache().unwrap_or(&[]);
    let deps: Vec<&String> = targets
        .iter()
        .filter(|t| localdb.get_pkg(t).is_err() && find_satisfier(pkgcache, t).is_none())
        .collect();
    if deps.is_empty() {
        return 0;
    }
    for dep in deps {
        pr!("{}\n", dep);
    }
    127
}
