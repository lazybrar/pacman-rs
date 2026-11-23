//! Port of lib/libalpm/sync.c (so far: alpm_sync_get_new_version).
use crate::db::Db;
use crate::package::{Pkg, pkg_compare_versions};

/// alpm_sync_get_new_version: the first sync database's package when it is newer than `pkg`
pub fn sync_get_new_version<'a>(pkg: &Pkg, dbs_sync: &'a [Db]) -> Option<(&'a Db, &'a Pkg)> {
    pkg.handle.pm_errno.set(None);
    let found = dbs_sync
        .iter()
        .find_map(|db| db.pkg_from_cache(&pkg.name).map(|p| (db, p)));
    let Some((db, spkg)) = found else {
        crate::alpm_log!(
            pkg.handle,
            crate::log::LOG_DEBUG,
            "'{}' not found in sync db => no upgrade\n",
            pkg.name
        );
        return None;
    };
    // compare versions and see if spkg is an upgrade
    if pkg_compare_versions(spkg, pkg) > 0 {
        crate::alpm_log!(
            pkg.handle,
            crate::log::LOG_DEBUG,
            "new version of '{}' found ({} => {})\n",
            pkg.name,
            pkg.version,
            spkg.version
        );
        return Some((db, spkg));
    }
    // spkg is not an upgrade
    None
}
