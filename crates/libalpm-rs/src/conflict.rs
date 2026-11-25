//! Port of lib/libalpm/conflict.c: conflicts between packages (inner and outer). File conflicts arrive with T14.
//! Packages are borrowed from the databases instead of being `_alpm_pkg_dup`ed.
use crate::alpm_log;
use crate::db::Db;
use crate::deps::{Dep, dep_compute_string, depcmp};
use crate::handle::Handle;
use crate::log::LOG_DEBUG;
use crate::package::Pkg;

/// alpm_conflict_t
#[derive(Clone)]
pub struct Conflict<'a> {
    pub package1: &'a Pkg,
    pub package2: &'a Pkg,
    pub reason: Dep,
}

/// conflict_isin
fn conflict_isin(needle: &Conflict, haystack: &[Conflict]) -> bool {
    haystack.iter().any(|c| {
        needle.package1.name_hash == c.package1.name_hash
            && needle.package2.name_hash == c.package2.name_hash
            && needle.package1.name == c.package1.name
            && needle.package2.name == c.package2.name
    })
}

/// add_conflict
fn add_conflict<'a>(
    handle: &Handle,
    baddeps: &mut Vec<Conflict<'a>>,
    pkg1: &'a Pkg,
    pkg2: &'a Pkg,
    reason: &Dep,
) {
    let conflict = Conflict {
        package1: pkg1,
        package2: pkg2,
        reason: reason.clone(),
    };
    if !conflict_isin(&conflict, baddeps) {
        alpm_log!(
            handle,
            LOG_DEBUG,
            "package {} conflicts with {} (by {})\n",
            pkg1.name,
            pkg2.name,
            dep_compute_string(reason)
        );
        baddeps.push(conflict);
    }
}

/// check_conflict: packages of list1 whose conflicts match packages of list2; stored as (pkg1, pkg2) when
/// order >= 0, reversed otherwise
fn check_conflict<'a>(
    handle: &Handle,
    list1: &[&'a Pkg],
    list2: &[&'a Pkg],
    baddeps: &mut Vec<Conflict<'a>>,
    order: i32,
) {
    for &pkg1 in list1 {
        for conflict in &pkg1.desc().conflicts {
            for &pkg2 in list2 {
                if pkg1.name_hash == pkg2.name_hash && pkg1.name == pkg2.name {
                    // skip the package we're currently processing
                    continue;
                }
                if depcmp(pkg2, conflict) {
                    if order >= 0 {
                        add_conflict(handle, baddeps, pkg1, pkg2, conflict);
                    } else {
                        add_conflict(handle, baddeps, pkg2, pkg1, conflict);
                    }
                }
            }
        }
    }
}

/// _alpm_innerconflicts: conflicts inside a list of packages
pub fn innerconflicts<'a>(handle: &Handle, packages: &[&'a Pkg]) -> Vec<Conflict<'a>> {
    let mut baddeps = Vec::new();
    alpm_log!(handle, LOG_DEBUG, "check targets vs targets\n");
    check_conflict(handle, packages, packages, &mut baddeps, 0);
    baddeps
}

/// _alpm_outerconflicts: conflicts between a database and a list of packages
pub fn outerconflicts<'a>(db: &'a Db, packages: &[&'a Pkg]) -> Vec<Conflict<'a>> {
    let mut baddeps = Vec::new();
    let all: Vec<&Pkg> = db.get_pkgcache().unwrap_or(&[]).iter().collect();
    let dblist = crate::deps::pkg_list_diff(&all, packages);
    // two checks to be done here for conflicts
    alpm_log!(db.handle, LOG_DEBUG, "check targets vs db\n");
    check_conflict(&db.handle, packages, &dblist, &mut baddeps, 1);
    alpm_log!(db.handle, LOG_DEBUG, "check db vs targets\n");
    check_conflict(&db.handle, &dblist, packages, &mut baddeps, -1);
    baddeps
}

/// alpm_checkconflicts
pub fn checkconflicts<'a>(handle: &Handle, pkglist: &[&'a Pkg]) -> Vec<Conflict<'a>> {
    innerconflicts(handle, pkglist)
}

