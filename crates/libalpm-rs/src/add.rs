//! Port of lib/libalpm/add.c: `alpm_add_pkg` (adding a target to a transaction). Upgrading from a file is P2.
use crate::alpm::Alpm;
use crate::alpm_log;
use crate::error::Error;
use crate::handle::TransState;
use crate::log::{LOG_DEBUG, LOG_WARNING};
use crate::package::{Pkg, PkgFrom, PkgReason, pkg_compare_versions};
use crate::trans::{Trans, TRANS_FLAG_DOWNLOADONLY, TRANS_FLAG_NEEDED};

/// alpm_add_pkg: 0 on success, -1 on error (pm_errno is set)
pub fn add_pkg<'a>(alpm: &'a Alpm, trans: &mut Trans<'a>, pkg: &'a Pkg) -> i32 {
    let handle = &alpm.handle;
    if pkg.origin == PkgFrom::LocalDb || !std::rc::Rc::ptr_eq(handle, &pkg.handle) {
        handle.pm_errno.set(Some(Error::WrongArgs));
        return -1;
    }
    let Some(hdr) = handle.trans.get() else {
        handle.pm_errno.set(Some(Error::TransNull));
        return -1;
    };
    if hdr.state != TransState::Initialized {
        handle.pm_errno.set(Some(Error::TransNotInitialized));
        return -1;
    }
    let (pkgname, pkgver) = (&pkg.name, &pkg.version);
    alpm_log!(handle, LOG_DEBUG, "adding package '{}'\n", pkgname);
    if let Some(dup) = trans.find_add(pkgname) {
        if std::ptr::eq(dup, pkg) {
            alpm_log!(handle, LOG_DEBUG, "skipping duplicate target: {}\n", pkgname);
            return 0;
        }
        // error for separate packages with the same name
        handle.pm_errno.set(Some(Error::TransDupTarget));
        return -1;
    }
    if let Some(local) = alpm.localdb.pkg_from_cache(pkgname) {
        let cmp = pkg_compare_versions(pkg, local);
        if cmp == 0 {
            if hdr.flags & TRANS_FLAG_NEEDED != 0 {
                // with the NEEDED flag, packages up to date are not reinstalled
                alpm_log!(
                    handle,
                    LOG_WARNING,
                    "{}-{} is up to date -- skipping\n",
                    local.name,
                    local.version
                );
                return 0;
            } else if hdr.flags & TRANS_FLAG_DOWNLOADONLY == 0 {
                alpm_log!(
                    handle,
                    LOG_WARNING,
                    "{}-{} is up to date -- reinstalling\n",
                    local.name,
                    local.version
                );
            }
        } else if cmp < 0 && hdr.flags & TRANS_FLAG_DOWNLOADONLY == 0 {
            // local version is newer
            alpm_log!(
                handle,
                LOG_WARNING,
                "downgrading package {} ({} => {})\n",
                local.name,
                local.version,
                pkgver
            );
        }
    }
    // add the package to the transaction
    trans.reasons.insert(pkg.name.clone(), PkgReason::Explicit);
    alpm_log!(
        handle,
        LOG_DEBUG,
        "adding package {}-{} to the transaction add list\n",
        pkgname,
        pkgver
    );
    trans.add.push(pkg);
    0
}
