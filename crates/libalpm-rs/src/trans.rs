//! Port of lib/libalpm/trans.c: transaction init, prepare, commit (download-only so far) and release.
//! Upstream's `handle->trans` is split in two: the flags and state live on the handle (`Handle::trans`, read by
//! deps/sync code), the package lists in the `Trans` value the caller owns. Per-package transaction fields
//! (`removes`, `reason`) are kept here by package name instead of on the shared package objects.
use crate::alpm::Alpm;
use crate::alpm_log;
use crate::conflict::Conflict;
use crate::deps::{DepMissing, sortbydeps};
use crate::error::Error;
use crate::handle::{TransHdr, TransState};
use crate::log::LOG_DEBUG;
use crate::package::{Pkg, PkgReason};
use std::collections::HashMap;

pub const TRANS_FLAG_NODEPS: i32 = 1;
pub const TRANS_FLAG_NOSAVE: i32 = 1 << 2;
pub const TRANS_FLAG_NODEPVERSION: i32 = 1 << 3;
pub const TRANS_FLAG_CASCADE: i32 = 1 << 4;
pub const TRANS_FLAG_RECURSE: i32 = 1 << 5;
pub const TRANS_FLAG_DBONLY: i32 = 1 << 6;
pub const TRANS_FLAG_NOHOOKS: i32 = 1 << 7;
pub const TRANS_FLAG_ALLDEPS: i32 = 1 << 8;
pub const TRANS_FLAG_DOWNLOADONLY: i32 = 1 << 9;
pub const TRANS_FLAG_NOSCRIPTLET: i32 = 1 << 10;
pub const TRANS_FLAG_NOCONFLICTS: i32 = 1 << 11;
pub const TRANS_FLAG_NEEDED: i32 = 1 << 13;
pub const TRANS_FLAG_ALLEXPLICIT: i32 = 1 << 14;
pub const TRANS_FLAG_UNNEEDED: i32 = 1 << 15;
pub const TRANS_FLAG_RECURSEALL: i32 = 1 << 16;
pub const TRANS_FLAG_NOLOCK: i32 = 1 << 17;

/// alpm_trans_t (package lists)
#[derive(Default)]
pub struct Trans<'a> {
    pub add: Vec<&'a Pkg>,
    pub remove: Vec<&'a Pkg>,
    pub unresolvable: Vec<&'a Pkg>,
    /// pkg->removes of the packages in `add`, by package name
    pub removes: Vec<(String, Vec<&'a Pkg>)>,
    /// pkg->reason of the packages in `add` (and replacers), by package name
    pub reasons: HashMap<String, PkgReason>,
}

/// the `data` out-parameter of prepare/commit: which list is filled depends on the error
#[derive(Default)]
pub struct TransData<'a> {
    /// "name-version-arch" of packages with an invalid architecture
    pub invalid_arch: Vec<String>,
    pub missing: Vec<DepMissing>,
    pub conflicts: Vec<Conflict<'a>>,
    /// file names of invalid or corrupted packages
    pub invalid_files: Vec<String>,
}

impl<'a> Trans<'a> {
    /// pkg->removes
    pub fn removes_of(&self, name: &str) -> &[&'a Pkg] {
        self.removes
            .iter()
            .find(|(n, _)| n == name)
            .map_or(&[], |(_, v)| v.as_slice())
    }

    /// `pkg->removes = alpm_list_add(pkg->removes, local)`
    pub fn add_removes(&mut self, name: &str, local: &'a Pkg) {
        match self.removes.iter_mut().find(|(n, _)| n == name) {
            Some((_, v)) => v.push(local),
            None => self.removes.push((name.to_string(), vec![local])),
        }
    }

    /// `spkg->removes = alpm_list_add(NULL, lpkg)` (a fresh list)
    pub fn set_removes(&mut self, name: &str, local: &'a Pkg) {
        self.removes.retain(|(n, _)| n != name);
        self.removes.push((name.to_string(), vec![local]));
    }

    /// alpm_pkg_find on the add list
    pub fn find_add(&self, name: &str) -> Option<&'a Pkg> {
        let h = crate::util::hash_sdbm(name);
        self.add
            .iter()
            .copied()
            .find(|p| p.name_hash == h && p.name == name)
    }

    /// the install reason of a target (explicit when never set, like a zero-initialised package)
    pub fn reason_of(&self, name: &str) -> PkgReason {
        self.reasons.get(name).copied().unwrap_or_default()
    }
}

/// alpm_trans_init: 0 on success, -1 on error
pub fn trans_init<'a>(alpm: &'a Alpm, flags: i32) -> Result<Trans<'a>, Error> {
    let handle = &alpm.handle;
    if handle.trans.get().is_some() {
        return handle.err(Error::TransNotNull);
    }
    // lock db
    if flags & TRANS_FLAG_NOLOCK == 0 && handle.lock() != 0 {
        return handle.err(Error::HandleLock);
    }
    handle.trans.set(Some(TransHdr {
        flags,
        state: TransState::Initialized,
    }));
    handle.no_dep_version.set(flags & TRANS_FLAG_NODEPVERSION != 0);
    Ok(Trans::default())
}

/// check_arch: "name-version-arch" of the packages whose architecture is not accepted
fn check_arch(alpm: &Alpm, pkgs: &[&Pkg]) -> Vec<String> {
    let handle = &alpm.handle;
    let archs = handle.opts.borrow().architectures.clone();
    if archs.is_empty() {
        alpm_log!(handle, LOG_DEBUG, "skipping architecture checks\n");
        return Vec::new();
    }
    let mut invalid = Vec::new();
    for pkg in pkgs {
        let pkgarch = pkg.desc().arch.as_deref();
        // always allow non-architecture packages and those marked "any"
        let Some(pkgarch) = pkgarch else { continue };
        if pkgarch == "any" {
            continue;
        }
        if !archs.iter().any(|a| a == pkgarch) {
            invalid.push(format!("{}-{}-{}", pkg.name, pkg.version, pkgarch));
        }
    }
    invalid
}

impl<'a> Trans<'a> {
    /// alpm_trans_prepare: 0 on success, -1 on error (pm_errno is set)
    pub fn prepare(&mut self, alpm: &'a Alpm, data: &mut TransData<'a>) -> i32 {
        let handle = &alpm.handle;
        let Some(hdr) = handle.trans.get() else {
            handle.pm_errno.set(Some(Error::TransNull));
            return -1;
        };
        if hdr.state != TransState::Initialized {
            handle.pm_errno.set(Some(Error::TransNotInitialized));
            return -1;
        }
        // If there's nothing to do, return without complaining
        if self.add.is_empty() && self.remove.is_empty() {
            return 0;
        }
        let invalid = check_arch(alpm, &self.add);
        if !invalid.is_empty() {
            data.invalid_arch = invalid;
            handle.pm_errno.set(Some(Error::PkgInvalidArch));
            return -1;
        }
        // add.is_empty() would be _alpm_remove_prepare: -R is not ported and nothing fills `remove` without it
        if self.add.is_empty() {
            alpm_log!(handle, LOG_DEBUG, "remove transactions are not implemented\n");
            handle.pm_errno.set(Some(Error::TransType));
            return -1;
        }
        if crate::sync::sync_prepare(alpm, self, data) == -1 {
            // pm_errno is set by sync_prepare()
            return -1;
        }
        if hdr.flags & TRANS_FLAG_NODEPS == 0 {
            alpm_log!(handle, LOG_DEBUG, "sorting by dependencies\n");
            if !self.add.is_empty() {
                self.add = sortbydeps(alpm, &self.add, &self.remove, false);
            }
            if !self.remove.is_empty() {
                self.remove = sortbydeps(alpm, &self.remove, &[], true);
            }
        }
        handle.trans.set(Some(TransHdr {
            state: TransState::Prepared,
            ..hdr
        }));
        0
    }

    /// alpm_trans_commit, as far as downloads go: a DOWNLOADONLY transaction is complete after the validity
    /// check. Everything after that (file conflicts, hooks, installing, removing) is P2 and left to the caller
    /// to refuse; calling this for a transaction that would install is an error.
    pub fn commit(&mut self, alpm: &'a Alpm, data: &mut TransData<'a>) -> i32 {
        let handle = &alpm.handle;
        let Some(hdr) = handle.trans.get() else {
            handle.pm_errno.set(Some(Error::TransNull));
            return -1;
        };
        if hdr.state != TransState::Prepared {
            handle.pm_errno.set(Some(Error::TransNotPrepared));
            return -1;
        }
        if hdr.flags & TRANS_FLAG_NOLOCK != 0 {
            handle.pm_errno.set(Some(Error::TransNotLocked));
            return -1;
        }
        // If there's nothing to do, return without complaining
        if self.add.is_empty() && self.remove.is_empty() {
            return 0;
        }
        if !self.add.is_empty() {
            if crate::sync::sync_load(alpm, self, data) != 0 {
                // pm_errno is set by sync_load()
                return -1;
            }
            if hdr.flags & TRANS_FLAG_DOWNLOADONLY != 0 {
                return 0;
            }
        }
        alpm_log!(handle, LOG_DEBUG, "installing and removing packages is not implemented\n");
        handle.pm_errno.set(Some(Error::TransType));
        -1
    }

    /// alpm_trans_release: 0 on success, -1 on error
    pub fn release(self, alpm: &Alpm) -> i32 {
        let handle = &alpm.handle;
        let Some(hdr) = handle.trans.get() else {
            handle.pm_errno.set(Some(Error::TransNull));
            return -1;
        };
        handle.trans.set(None);
        handle.no_dep_version.set(false);
        // unlock db
        if hdr.flags & TRANS_FLAG_NOLOCK == 0 {
            handle.unlock();
        }
        0
    }
}
