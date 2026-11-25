//! Port of lib/libalpm/sync.c: sysupgrade, replacers, group lookup, `_alpm_sync_prepare`, the package download
//! and the keyring/validity/load checks of `_alpm_sync_load`. File conflicts and disk space checks
//! (`_alpm_sync_check`) and `_alpm_sync_commit` are P2/T14.
use crate::alpm::Alpm;
use crate::alpm_log;
use crate::conflict::{innerconflicts, outerconflicts};
use crate::consts::*;
use crate::db::{DB_STATUS_INVALID, DB_STATUS_MISSING, Db};
use crate::deps::{Dep, checkdeps, dep_from_string, depcmp, depcmp_literal, pkg_list_diff, resolvedeps};
use crate::dload::{Payload, PayloadRef, download, payload_ref};
use crate::error::Error;
use crate::handle::{Event, Progress, Question, TransHdr, TransState};
use crate::log::{LOG_DEBUG, LOG_ERROR, LOG_WARNING};
use crate::package::{Pkg, PkgFrom, PkgReason, pkg_compare_versions, pkg_should_ignore};
use crate::trans::*;
use crate::util::{download_dir_setup, filecache_exists, filecache_find, filecache_setup};

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

/// compute_download_size: what is left to download for `newpkg`, stored in its `dsize`. 0 on success, 1 when
/// a partial file exists, -1 on error.
fn compute_download_size(newpkg: &Pkg) -> i32 {
    let handle = &newpkg.handle;
    if newpkg.origin != PkgFrom::SyncDb {
        newpkg.dsize.set(Some(0));
        return 0;
    }
    let Some(fname) = newpkg.filename.as_deref() else {
        handle.pm_errno.set(Some(Error::PkgInvalidName));
        return -1;
    };
    let mut ret = 0;
    // downloaded file exists, so there's nothing to grab
    let size = if filecache_find(handle, fname).is_some() {
        0
    } else if let Some(fpath) = filecache_find(handle, &format!("{fname}.part")) {
        let mut size = 0;
        if let Ok(st) = std::fs::metadata(fpath) {
            // subtract the size of the .part file
            alpm_log!(handle, LOG_DEBUG, "using (package - .part) size\n");
            size = (newpkg.size - st.len() as i64).max(0);
        }
        // tell the caller that we have a partial
        ret = 1;
        size
    } else {
        newpkg.size
    };
    alpm_log!(
        handle,
        LOG_DEBUG,
        "setting download size {} for pkg {}\n",
        size,
        newpkg.name
    );
    newpkg.dsize.set(Some(size));
    ret
}

/// alpm_pkg_download_size
pub fn pkg_download_size(newpkg: &Pkg) -> i64 {
    if newpkg.dsize.get().is_none() {
        compute_download_size(newpkg);
    }
    newpkg.dsize.get().unwrap_or(0)
}

/// find_dl_candidates: the packages of the list that are not in the cache (with their signature when needed)
fn find_dl_candidates<'a>(alpm: &'a Alpm, add: &[&'a Pkg]) -> Result<Vec<&'a Pkg>, ()> {
    let handle = &alpm.handle;
    let mut files = Vec::new();
    for &spkg in add {
        if spkg.origin == PkgFrom::File {
            continue;
        }
        let Some(repo) = spkg
            .dbname
            .as_deref()
            .and_then(|n| alpm.syncdbs.iter().find(|d| d.treename == n))
        else {
            return Err(());
        };
        let siglevel = repo.get_siglevel();
        if repo.servers.borrow().is_empty() {
            handle.pm_errno.set(Some(Error::ServerNone));
            crate::alpm_log!(
                handle,
                LOG_ERROR,
                "{}: {}\n",
                Error::ServerNone.strerror(),
                repo.treename
            );
            return Err(());
        }
        let Some(filename) = spkg.filename.as_deref() else {
            handle.pm_errno.set(Some(Error::PkgInvalidName));
            return Err(());
        };
        let mut need_download = spkg.dsize.get().unwrap_or(0) != 0 || !filecache_exists(handle, filename);
        // even if the package file in the cache we need to check for accompanion *.sig file as well.
        if !need_download && siglevel & SIG_PACKAGE != 0 {
            need_download = !filecache_exists(handle, &format!("{filename}.sig"));
        }
        if need_download {
            files.push(spkg);
        }
    }
    Err(()).or(Ok(files))
}

/// download_files: fetch the packages of a transaction's add list into the cache.
/// 0 on success, -1 on error.
/// shortcut: the checkspace disk space check (diskspace.c) is not ported (CheckSpace is ignored).
pub fn download_files(alpm: &Alpm, add: &[&Pkg]) -> i32 {
    let handle = &alpm.handle;
    let cachedir = filecache_setup(handle);
    let Some(temporary_cachedir) = download_dir_setup(handle, &cachedir) else {
        add.iter().for_each(|p| p.dsize.set(None));
        return -1;
    };
    if let Some(h) = handle.trans.get() {
        handle.trans.set(Some(TransHdr {
            state: TransState::Downloading,
            ..h
        }));
    }
    let ret = download_files_inner(alpm, add, &cachedir, &temporary_cachedir);
    for pkg in add {
        pkg.dsize.set(None);
    }
    ret
}

fn download_files_inner(alpm: &Alpm, add: &[&Pkg], cachedir: &str, temporary_cachedir: &str) -> i32 {
    let handle = &alpm.handle;
    let Ok(files) = find_dl_candidates(alpm, add) else {
        return -1;
    };
    let mut ret = 0;
    if !files.is_empty() {
        let total_size: i64 = files.iter().map(|p| p.dsize.get().unwrap_or(0)).sum();
        handle.event(&Event::PkgRetrieveStart {
            num: files.len(),
            total_size,
        });
        let mut payloads: Vec<PayloadRef> = Vec::new();
        for pkg in &files {
            let repo = alpm
                .syncdbs
                .iter()
                .find(|d| Some(&d.treename) == pkg.dbname.as_ref())
                .unwrap();
            let siglevel = repo.get_siglevel();
            let filename = pkg.filename.clone().unwrap_or_default();
            payloads.push(payload_ref(Payload {
                remote_name: filename.clone(),
                destfile_name: Some(format!("{temporary_cachedir}{filename}")),
                tempfile_name: Some(format!("{temporary_cachedir}{filename}.part")),
                filepath: Some(filename),
                max_size: pkg.size,
                cache_servers: repo.cache_servers.borrow().clone(),
                servers: repo.servers.borrow().clone(),
                allow_resume: true,
                download_signature: siglevel & SIG_PACKAGE != 0,
                signature_optional: siglevel & SIG_PACKAGE_OPTIONAL != 0,
                ..Default::default()
            }));
        }
        ret = download(handle, &payloads, cachedir, temporary_cachedir);
        if ret == -1 {
            handle.event(&Event::PkgRetrieveFailed);
            crate::alpm_log!(handle, LOG_WARNING, "failed to retrieve some files\n");
        } else {
            handle.event(&Event::PkgRetrieveDone);
            ret = 0;
        }
    }
    ret
}

/// check_literal: 1 when `spkg` should replace `lpkg` in the transaction
fn check_literal(alpm: &Alpm, lpkg: &Pkg, spkg: &Pkg, enable_downgrade: bool) -> bool {
    let handle = &alpm.handle;
    // 1. literal was found in sdb
    let cmp = pkg_compare_versions(spkg, lpkg);
    if cmp > 0 {
        alpm_log!(
            handle,
            LOG_DEBUG,
            "new version of '{}' found ({} => {})\n",
            lpkg.name,
            lpkg.version,
            spkg.version
        );
        // check IgnorePkg/IgnoreGroup
        if pkg_should_ignore(handle, spkg) || pkg_should_ignore(handle, lpkg) {
            alpm_log!(
                handle,
                LOG_WARNING,
                "{}: ignoring package upgrade ({} => {})\n",
                lpkg.name,
                lpkg.version,
                spkg.version
            );
        } else {
            alpm_log!(
                handle,
                LOG_DEBUG,
                "adding package {}-{} to the transaction targets\n",
                spkg.name,
                spkg.version
            );
            return true;
        }
    } else if cmp < 0 {
        if enable_downgrade {
            // check IgnorePkg/IgnoreGroup
            if pkg_should_ignore(handle, spkg) || pkg_should_ignore(handle, lpkg) {
                alpm_log!(
                    handle,
                    LOG_WARNING,
                    "{}: ignoring package downgrade ({} => {})\n",
                    lpkg.name,
                    lpkg.version,
                    spkg.version
                );
            } else {
                alpm_log!(
                    handle,
                    LOG_WARNING,
                    "{}: downgrading from version {} to version {}\n",
                    lpkg.name,
                    lpkg.version,
                    spkg.version
                );
                return true;
            }
        } else {
            let sdb = alpm.pkg_db(spkg).map_or("", |d| d.treename.as_str());
            alpm_log!(
                handle,
                LOG_WARNING,
                "{}: local ({}) is newer than {} ({})\n",
                lpkg.name,
                lpkg.version,
                sdb,
                spkg.version
            );
        }
    }
    false
}

/// check_replacers: the packages of `sdb` that replace `lpkg` (and the user agreed to)
fn check_replacers<'a>(
    alpm: &'a Alpm,
    trans: &mut Trans<'a>,
    lpkg: &'a Pkg,
    sdb: &'a Db,
) -> Vec<&'a Pkg> {
    let handle = &alpm.handle;
    // 2. search for replacers in sdb
    let mut replacers = Vec::new();
    alpm_log!(
        handle,
        LOG_DEBUG,
        "searching for replacements for {} in {}\n",
        lpkg.name,
        sdb.treename
    );
    for spkg in sdb.get_pkgcache().unwrap_or(&[]) {
        // we only want to consider literal matches at this point.
        let found = spkg
            .desc()
            .replaces
            .iter()
            .any(|replace| depcmp_literal(lpkg, replace));
        if !found {
            continue;
        }
        // check IgnorePkg/IgnoreGroup
        if pkg_should_ignore(handle, spkg) || pkg_should_ignore(handle, lpkg) {
            alpm_log!(
                handle,
                LOG_WARNING,
                "ignoring package replacement ({}-{} => {}-{})\n",
                lpkg.name,
                lpkg.version,
                spkg.name,
                spkg.version
            );
            continue;
        }
        let mut q = Question::Replace {
            replace: false,
            oldpkg: lpkg,
            newpkg: spkg,
            newdb: sdb,
        };
        handle.question(&mut q);
        if !matches!(q, Question::Replace { replace: true, .. }) {
            continue;
        }
        // If spkg is already in the target list, we append lpkg to spkg's removes list
        if let Some(tpkg) = trans.find_add(&spkg.name) {
            // sanity check, multiple repos can contain spkg->name
            if tpkg.dbname.as_deref() != Some(sdb.treename.as_str()) {
                alpm_log!(
                    handle,
                    LOG_WARNING,
                    "cannot replace {} by {}\n",
                    lpkg.name,
                    spkg.name
                );
                continue;
            }
            alpm_log!(
                handle,
                LOG_DEBUG,
                "appending {} to the removes list of {}\n",
                lpkg.name,
                tpkg.name
            );
            trans.add_removes(&tpkg.name, lpkg);
            // check the to-be-replaced package's reason field
            if lpkg.desc().reason == PkgReason::Explicit {
                trans.reasons.insert(tpkg.name.clone(), PkgReason::Explicit);
            }
        } else {
            // add spkg to the target list; copy over reason
            trans.reasons.insert(spkg.name.clone(), lpkg.desc().reason);
            trans.set_removes(&spkg.name, lpkg);
            alpm_log!(
                handle,
                LOG_DEBUG,
                "adding package {}-{} to the transaction targets\n",
                spkg.name,
                spkg.version
            );
            replacers.push(spkg);
        }
    }
    replacers
}

/// alpm_sync_sysupgrade: 0 on success, -1 on error
pub fn sync_sysupgrade<'a>(alpm: &'a Alpm, trans: &mut Trans<'a>, enable_downgrade: bool) -> i32 {
    let handle = &alpm.handle;
    let Some(hdr) = handle.trans.get() else {
        handle.pm_errno.set(Some(Error::TransNull));
        return -1;
    };
    if hdr.state != TransState::Initialized {
        handle.pm_errno.set(Some(Error::TransNotInitialized));
        return -1;
    }
    alpm_log!(handle, LOG_DEBUG, "checking for package upgrades\n");
    for lpkg in alpm.localdb.get_pkgcache().unwrap_or(&[]) {
        if crate::package::pkg_find_ref(&trans.remove, &lpkg.name).is_some() {
            alpm_log!(
                handle,
                LOG_DEBUG,
                "{} is marked for removal -- skipping\n",
                lpkg.name
            );
            continue;
        }
        if trans.find_add(&lpkg.name).is_some() {
            alpm_log!(
                handle,
                LOG_DEBUG,
                "{} is already in the target list -- skipping\n",
                lpkg.name
            );
            continue;
        }
        // Search for replacers then literal (if no replacer) in each sync database.
        for sdb in &alpm.syncdbs {
            if sdb.usage.get() & DB_USAGE_UPGRADE == 0 {
                continue;
            }
            // Check sdb
            let replacers = check_replacers(alpm, trans, lpkg, sdb);
            if !replacers.is_empty() {
                trans.add.extend(replacers);
                // jump to next local package
                break;
            } else if let Some(spkg) = sdb.pkg_from_cache(&lpkg.name) {
                if check_literal(alpm, lpkg, spkg, enable_downgrade) {
                    trans.add.push(spkg);
                }
                // jump to next local package
                break;
            }
        }
    }
    0
}

/// alpm_find_group_pkgs
pub fn find_group_pkgs<'a>(alpm: &Alpm, dbs: &[&'a Db], name: &str) -> Vec<&'a Pkg> {
    let mut pkgs: Vec<&Pkg> = Vec::new();
    let mut ignorelist: Vec<&Pkg> = Vec::new();
    for db in dbs {
        let handle = &db.handle;
        let Ok(Some(grp)) = db.get_group(name) else {
            continue;
        };
        for pkg in db.group_packages(grp) {
            if crate::package::pkg_find_ref(&ignorelist, &pkg.name).is_some() {
                continue;
            }
            if handle.trans.get().is_some() && handle.trans_flags() & TRANS_FLAG_NEEDED != 0 {
                let local = alpm.localdb.pkg_from_cache(&pkg.name);
                if let Some(local) = local
                    && pkg_compare_versions(pkg, local) == 0
                {
                    // with the NEEDED flag, packages up to date are not reinstalled
                    alpm_log!(
                        handle,
                        LOG_WARNING,
                        "{}-{} is up to date -- skipping\n",
                        local.name,
                        local.version
                    );
                    ignorelist.push(pkg);
                    continue;
                }
            }
            if pkg_should_ignore(handle, pkg) {
                let mut q = Question::InstallIgnorepkg {
                    install: false,
                    pkg,
                };
                ignorelist.push(pkg);
                handle.question(&mut q);
                if !matches!(q, Question::InstallIgnorepkg { install: true, .. }) {
                    continue;
                }
            }
            if crate::package::pkg_find_ref(&pkgs, &pkg.name).is_none() {
                pkgs.push(pkg);
            }
        }
    }
    pkgs
}

/// _alpm_sync_prepare: 0 on success, -1 on error (pm_errno is set)
pub fn sync_prepare<'a>(alpm: &'a Alpm, trans: &mut Trans<'a>, data: &mut TransData<'a>) -> i32 {
    let handle = &alpm.handle;
    let flags = handle.trans_flags();
    let from_sync = trans.add.iter().any(|p| p.origin == PkgFrom::SyncDb);

    // ensure all sync database are valid if we will be using them
    for db in &alpm.syncdbs {
        if db.status.get() & DB_STATUS_INVALID != 0 {
            handle.pm_errno.set(Some(Error::DbInvalid));
            return -1;
        }
        // missing databases are not allowed if we have sync targets
        if from_sync && db.status.get() & DB_STATUS_MISSING != 0 {
            handle.pm_errno.set(Some(Error::DbNotFound));
            return -1;
        }
    }

    if flags & TRANS_FLAG_NODEPS == 0 {
        // Build up list by repeatedly resolving each transaction package
        // Resolve targets dependencies
        handle.event(&Event::ResolveDepsStart);
        alpm_log!(handle, LOG_DEBUG, "resolving target's dependencies\n");

        // build remove list for resolvedeps
        let mut remove: Vec<&Pkg> = trans.remove.clone();
        for spkg in &trans.add {
            remove.extend(trans.removes_of(&spkg.name));
        }
        // Compute the fake local database for resolvedeps (partial fix for the phonon/qt issue)
        let all_local: Vec<&Pkg> = alpm.localdb.get_pkgcache().unwrap_or(&[]).iter().collect();
        let localpkgs = pkg_list_diff(&all_local, &trans.add);

        // Resolve packages in the transaction one at a time, in addition building up a list of packages
        // which could not be resolved.
        let add = trans.add.clone();
        let mut resolved: Vec<&'a Pkg> = Vec::new();
        let mut unresolvable: Vec<&'a Pkg> = Vec::new();
        for &pkg in &add {
            if resolvedeps(
                alpm,
                &localpkgs,
                pkg,
                &add,
                &mut resolved,
                &remove,
                Some(&mut data.missing),
            ) == -1
            {
                unresolvable.push(pkg);
            }
            // Else, [resolved] now additionally contains [pkg] and all of its dependencies not already on the list
        }

        // If there were unresolvable top-level packages, prompt the user to see if they'd like to ignore them
        // rather than failing the sync
        if !unresolvable.is_empty() {
            let mut q = Question::RemovePkgs {
                skip: false,
                packages: unresolvable.clone(),
            };
            handle.question(&mut q);
            if matches!(q, Question::RemovePkgs { skip: true, .. }) {
                // User wants to remove the unresolvable packages from the transaction. The packages will be
                // removed from the actual transaction when the transaction packages are replaced with a
                // dependency-reordered list below
                handle.pm_errno.set(None);
                data.missing.clear();
            } else {
                // pm_errno was set by resolvedeps, callback may have overwrote it
                handle.pm_errno.set(Some(Error::UnsatisfiedDeps));
                return -1;
            }
        }

        // Ensure two packages don't have the same filename
        let mut ret = 0;
        for (i, pkg1) in resolved.iter().enumerate() {
            for pkg2 in &resolved[i + 1..] {
                if pkg1.filename.as_deref().unwrap_or("") == pkg2.filename.as_deref().unwrap_or("") {
                    ret = -1;
                    handle.pm_errno.set(Some(Error::TransDupFilename));
                    alpm_log!(
                        handle,
                        LOG_ERROR,
                        "packages {} and {} have the same filename: {}\n",
                        pkg1.name,
                        pkg2.name,
                        pkg1.filename.as_deref().unwrap_or("")
                    );
                }
            }
        }
        if ret != 0 {
            return ret;
        }

        // Set DEPEND reason for pulled packages
        for pkg in &resolved {
            if trans.find_add(&pkg.name).is_none() {
                trans.reasons.insert(pkg.name.clone(), PkgReason::Depend);
            }
        }

        // Unresolvable packages will be removed from the target list; set these aside in the transaction as a
        // list we won't operate on.
        trans.unresolvable = unresolvable;
        trans.add = resolved;
        handle.event(&Event::ResolveDepsDone);
    }

    if flags & TRANS_FLAG_NOCONFLICTS == 0 {
        // check for inter-conflicts and whatnot
        handle.event(&Event::InterConflictsStart);
        alpm_log!(handle, LOG_DEBUG, "looking for conflicts\n");

        // 1. check for conflicts in the target list
        alpm_log!(handle, LOG_DEBUG, "check targets vs targets\n");
        let deps = innerconflicts(handle, &trans.add);
        for conflict in &deps {
            let (name1, name2) = (&conflict.package1.name, &conflict.package2.name);
            // have we already removed one of the conflicting targets?
            let (Some(sync1), Some(sync2)) = (trans.find_add(name1), trans.find_add(name2)) else {
                continue;
            };
            alpm_log!(
                handle,
                LOG_DEBUG,
                "conflicting packages in the sync list: '{}' <-> '{}'\n",
                name1,
                name2
            );
            // if sync1 provides sync2, we remove sync2 from the targets, and vice versa
            let dep1 = dep_from_string(name1);
            let dep2 = dep_from_string(name2);
            let (rsync, sync) = if depcmp(sync1, &dep2) {
                (sync2, sync1)
            } else if depcmp(sync2, &dep1) {
                (sync1, sync2)
            } else {
                alpm_log!(handle, LOG_ERROR, "unresolvable package conflicts detected\n");
                handle.pm_errno.set(Some(Error::ConflictingDeps));
                data.conflicts.push(conflict.clone());
                return -1;
            };
            // Prints warning
            alpm_log!(
                handle,
                LOG_WARNING,
                "removing '{}-{}' from target list because it conflicts with '{}-{}'\n",
                rsync.name,
                rsync.version,
                sync.name,
                sync.version
            );
            if let Some(p) = trans
                .add
                .iter()
                .position(|p| crate::package::pkg_cmp(p, rsync).is_eq())
            {
                trans.add.remove(p);
            }
            // rsync is not a transaction target anymore
            trans.unresolvable.push(rsync);
        }

        // 2. we check for target vs db conflicts (and resolve)
        alpm_log!(handle, LOG_DEBUG, "check targets vs db and db vs targets\n");
        let deps = outerconflicts(&alpm.localdb, &trans.add);
        for conflict in &deps {
            let (name1, name2) = (&conflict.package1.name, &conflict.package2.name);
            // if name2 (the local package) is not elected for removal, we ask the user
            let found = crate::package::pkg_find_ref(&trans.remove, name2).is_some()
                || trans
                    .add
                    .iter()
                    .any(|spkg| crate::package::pkg_find_ref(trans.removes_of(&spkg.name), name2).is_some());
            if found {
                continue;
            }
            alpm_log!(
                handle,
                LOG_DEBUG,
                "package '{}-{}' conflicts with '{}-{}'\n",
                name1,
                conflict.package1.version,
                name2,
                conflict.package2.version
            );
            let mut q = Question::Conflict {
                remove: false,
                conflict,
            };
            handle.question(&mut q);
            if matches!(q, Question::Conflict { remove: true, .. }) {
                // append to the removes list
                let sync = trans.find_add(name1);
                let local = alpm.localdb.pkg_from_cache(name2);
                alpm_log!(handle, LOG_DEBUG, "electing '{}' for removal\n", name2);
                if let (Some(sync), Some(local)) = (sync, local) {
                    trans.add_removes(&sync.name, local);
                }
            } else {
                // abort
                alpm_log!(handle, LOG_ERROR, "unresolvable package conflicts detected\n");
                handle.pm_errno.set(Some(Error::ConflictingDeps));
                data.conflicts.push(conflict.clone());
                return -1;
            }
        }
        handle.event(&Event::InterConflictsDone);
    }

    // Build trans->remove list
    for spkg in trans.add.clone() {
        for &rpkg in trans.removes_of(&spkg.name).to_vec().iter() {
            if crate::package::pkg_find_ref(&trans.remove, &rpkg.name).is_none() {
                alpm_log!(handle, LOG_DEBUG, "adding '{}' to remove list\n", rpkg.name);
                trans.remove.push(rpkg);
            }
        }
    }

    if flags & TRANS_FLAG_NODEPS == 0 {
        alpm_log!(handle, LOG_DEBUG, "checking dependencies\n");
        let local: Vec<&Pkg> = alpm.localdb.get_pkgcache().unwrap_or(&[]).iter().collect();
        let deps = checkdeps(handle, &local, &trans.remove, &trans.add, true);
        if !deps.is_empty() {
            handle.pm_errno.set(Some(Error::UnsatisfiedDeps));
            data.missing = deps;
            return -1;
        }
    }
    for spkg in &trans.add {
        // update download size field
        // (alpm_db_get_pkg sets pm_errno when the package is not installed)
        let _ = alpm.localdb.get_pkg(&spkg.name);
        if compute_download_size(spkg) < 0 {
            return -1;
        }
        // shortcut: spkg->oldpkg (a dup of the installed package) is only used by the install code (P2)
    }
    0
}

/// prompt_to_delete: ask whether to delete a file now known to be invalid; true when it was removed
fn prompt_to_delete(handle: &crate::handle::Handle, filepath: &str, reason: Error) -> bool {
    let mut q = Question::Corrupted {
        remove: false,
        filepath,
        reason,
    };
    handle.question(&mut q);
    let remove = matches!(q, Question::Corrupted { remove: true, .. });
    if remove {
        let _ = std::fs::remove_file(filepath);
        let _ = std::fs::remove_file(crate::signing::sigpath(filepath));
    }
    remove
}

/// check_keyring: make sure the keys signing the packages are in the keyring (importing missing ones)
fn check_keyring(alpm: &Alpm, trans: &Trans) -> i32 {
    let handle = &alpm.handle;
    struct KeyInfo {
        uid: Option<String>,
        keyid: String,
    }
    let mut errors: Vec<KeyInfo> = Vec::new();
    handle.event(&Event::KeyringStart);
    let numtargs = trans.add.len();
    let mut current = 0;
    for pkg in &trans.add {
        let percent = (current * 100 / numtargs) as i32;
        handle.progress(Progress::KeyringStart, "", percent, numtargs, current);
        current += 1;
        if pkg.origin == PkgFrom::File {
            continue; // pkg_load() has been already called, this package is valid
        }
        let level = alpm.pkg_db(pkg).map_or(0, |d| d.get_siglevel());
        if level & SIG_PACKAGE != 0
            && let Ok(sig) = crate::signing::pkg_get_sig(pkg)
        {
            let mut keys = Vec::new();
            if crate::signing::extract_keyid(handle, &pkg.name, &sig, &mut keys).is_ok() {
                for key in keys {
                    alpm_log!(handle, LOG_DEBUG, "found signature key: {}\n", key);
                    if !errors.iter().any(|k| k.keyid == key)
                        && crate::signing::key_in_keychain(handle, &key) == 0
                    {
                        errors.push(KeyInfo {
                            uid: pkg.desc().packager.clone(),
                            keyid: key,
                        });
                    }
                }
            }
        }
    }
    handle.progress(Progress::KeyringStart, "", 100, numtargs, current);
    handle.event(&Event::KeyringDone);

    if !errors.is_empty() {
        handle.event(&Event::KeyDownloadStart);
        let mut fail = false;
        for k in &errors {
            if crate::signing::key_import(handle, k.uid.as_deref(), &k.keyid) == -1 {
                fail = true;
            }
        }
        handle.event(&Event::KeyDownloadDone);
        if fail {
            alpm_log!(handle, LOG_ERROR, "required key missing from keyring\n");
            return -1;
        }
    }
    0
}

/// check_validity: checksums and signatures of the downloaded packages; 0 when all are valid
fn check_validity(alpm: &Alpm, trans: &Trans, total: usize, total_bytes: u64) -> i32 {
    struct Validity {
        pkg_name: String,
        path: String,
        siglist: Option<crate::signing::SigList>,
        siglevel: i32,
        error: Error,
    }
    let handle = &alpm.handle;
    let mut current_bytes: u64 = 0;
    let mut errors: Vec<Validity> = Vec::new();

    // Check integrity of packages
    handle.event(&Event::IntegrityStart);
    let mut current = 0;
    for &pkg in &trans.add {
        let percent = ((current_bytes as f64 / total_bytes as f64) * 100.0) as i32;
        handle.progress(Progress::IntegrityStart, "", percent, total, current);
        current += 1;
        if pkg.origin == PkgFrom::File {
            continue; // pkg_load() has been already called, this package is valid
        }
        current_bytes += pkg.size as u64;
        let Some(path) = filecache_find(handle, pkg.filename.as_deref().unwrap_or("")) else {
            alpm_log!(
                handle,
                LOG_ERROR,
                "{}: could not find package in cache\n",
                pkg.name
            );
            handle.pm_errno.set(Some(Error::PkgNotFound));
            return -1;
        };
        let siglevel = alpm.pkg_db(pkg).map_or(0, |d| d.get_siglevel());
        let mut siglist = None;
        if let Err(e) =
            crate::be_package::pkg_validate_full(handle, &path, Some(pkg), siglevel, &mut siglist)
        {
            errors.push(Validity {
                pkg_name: pkg.name.clone(),
                path,
                siglist,
                siglevel,
                error: handle.errno().unwrap_or(e),
            });
        }
        // shortcut: v.pkg->validation is only used when installing (P2) and is not stored
    }
    handle.progress(Progress::IntegrityStart, "", 100, total, current);
    handle.event(&Event::IntegrityDone);

    if !errors.is_empty() {
        for v in &errors {
            match v.error {
                Error::PkgMissingSig => {
                    alpm_log!(
                        handle,
                        LOG_ERROR,
                        "{}: missing required signature\n",
                        v.pkg_name
                    );
                }
                Error::PkgInvalidSig | Error::PkgInvalidChecksum => {
                    if v.error == Error::PkgInvalidSig {
                        crate::signing::process_siglist(
                            handle,
                            &v.pkg_name,
                            v.siglist.as_ref().unwrap_or(&Vec::new()),
                            v.siglevel & SIG_PACKAGE_OPTIONAL != 0,
                            v.siglevel & SIG_PACKAGE_MARGINAL_OK != 0,
                            v.siglevel & SIG_PACKAGE_UNKNOWN_OK != 0,
                        );
                    }
                    prompt_to_delete(handle, &v.path, v.error);
                }
                Error::PkgNotFound | Error::Badperms | Error::PkgOpen => {
                    alpm_log!(
                        handle,
                        LOG_ERROR,
                        "failed to read file {}: {}\n",
                        v.path,
                        v.error.strerror()
                    );
                }
                _ => {} // ignore
            }
        }
        if handle.errno().is_none() {
            handle.pm_errno.set(Some(Error::PkgInvalid));
        }
        return -1;
    }
    0
}

/// dep_not_equal
fn dep_not_equal(l: &Dep, r: &Dep) -> bool {
    l.name_hash != r.name_hash || l.name != r.name || l.depmod != r.depmod || l.version != r.version
}

/// alpm_list_cmp_unsorted: true when both lists hold the same elements (`ne` is the C compare function that
/// returns non-zero for different elements). The quirks of the original are kept: after the in-order prefix the
/// rest of `left` is matched against all of `right`.
fn list_equal_unsorted<T>(left: &[T], right: &[T], ne: impl Fn(&T, &T) -> bool) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut start = 0;
    while start < left.len() && !ne(&left[start], &right[start]) {
        start += 1;
    }
    if start == left.len() {
        return true;
    }
    let mut matched = vec![false; right.len()];
    for l in &left[start..] {
        let mut found = false;
        for (n, r) in right.iter().enumerate() {
            // make sure we don't match the same value twice
            if matched[n] {
                continue;
            }
            if !ne(l, r) {
                found = true;
                matched[n] = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    true
}

/// check_pkg_matches_db: true when the package file differs from its database entry
fn check_pkg_matches_db(spkg: &Pkg, pkgfile: &Pkg) -> bool {
    let handle = &spkg.handle;
    let mut error = false;
    if spkg.name != pkgfile.name {
        alpm_log!(
            handle,
            LOG_DEBUG,
            "internal package name mismatch, expected: '{}', actual: '{}'\n",
            spkg.name,
            pkgfile.name
        );
        error = true;
    }
    if spkg.version != pkgfile.version {
        alpm_log!(
            handle,
            LOG_DEBUG,
            "internal package version mismatch, expected: '{}', actual: '{}'\n",
            spkg.version,
            pkgfile.version
        );
        error = true;
    }
    let (sd, fd) = (spkg.desc(), pkgfile.desc());
    if sd.isize != fd.isize {
        alpm_log!(
            handle,
            LOG_DEBUG,
            "internal package install size mismatch, expected: '{}', actual: '{}'\n",
            sd.isize,
            fd.isize
        );
        error = true;
    }
    let mut field = |name: &str, equal: bool| {
        if !equal {
            alpm_log!(handle, LOG_DEBUG, "internal package {} mismatch\n", name);
            error = true;
        }
    };
    field("depends", list_equal_unsorted(&sd.depends, &fd.depends, dep_not_equal));
    field("conflicts", list_equal_unsorted(&sd.conflicts, &fd.conflicts, dep_not_equal));
    field("replaces", list_equal_unsorted(&sd.replaces, &fd.replaces, dep_not_equal));
    field("provides", list_equal_unsorted(&sd.provides, &fd.provides, dep_not_equal));
    field("groups", list_equal_unsorted(&sd.groups, &fd.groups, |a, b| a != b));
    error
}

/// load_packages: load the downloaded package files and check them against the database entries.
/// Deviation: upstream replaces the targets with the loaded package files; that is only needed to install (P2),
/// so the loaded packages are dropped after the check.
fn load_packages<'a>(
    alpm: &Alpm,
    trans: &Trans<'a>,
    data: &mut TransData<'a>,
    total: usize,
    total_bytes: u64,
) -> i32 {
    let handle = &alpm.handle;
    let mut current_bytes: u64 = 0;
    let mut errors = 0;
    let mut delete: Vec<String> = Vec::new();

    // load packages from disk now that they are known-valid
    handle.event(&Event::LoadStart);
    let mut current = 0;
    for &spkg in &trans.add {
        let percent = ((current_bytes as f64 / total_bytes as f64) * 100.0) as i32;
        handle.progress(Progress::LoadStart, "", percent, total, current);
        current += 1;
        if spkg.origin == PkgFrom::File {
            continue; // pkg_load() has been already called, this package is valid
        }
        current_bytes += spkg.size as u64;
        let Some(filepath) = filecache_find(handle, spkg.filename.as_deref().unwrap_or("")) else {
            alpm_log!(
                handle,
                LOG_ERROR,
                "{}: could not find package in cache\n",
                spkg.name
            );
            handle.pm_errno.set(Some(Error::PkgNotFound));
            return -1;
        };
        // load the package file and replace pkgcache entry with it in the target list
        alpm_log!(
            handle,
            LOG_DEBUG,
            "replacing pkgcache entry with package file for target {}\n",
            spkg.name
        );
        let error = match crate::be_package::pkg_load_internal(handle, &filepath, true) {
            Err(_) => {
                alpm_log!(handle, LOG_DEBUG, "failed to load pkgfile internal\n");
                true
            }
            Ok(pkgfile) => check_pkg_matches_db(spkg, &pkgfile),
        };
        if error {
            errors += 1;
            data.invalid_files
                .push(spkg.filename.clone().unwrap_or_default());
            delete.push(filepath);
        }
    }
    handle.progress(Progress::LoadStart, "", 100, total, current);
    handle.event(&Event::LoadDone);

    if errors > 0 {
        for f in &delete {
            prompt_to_delete(handle, f, Error::PkgInvalid);
        }
        if handle.errno().is_none() {
            handle.pm_errno.set(Some(Error::PkgInvalid));
        }
        return -1;
    }
    0
}

/// _alpm_sync_load: download the packages and check them; 0 on success, -1 on error
pub fn sync_load<'a>(alpm: &Alpm, trans: &Trans<'a>, data: &mut TransData<'a>) -> i32 {
    let handle = &alpm.handle;
    if download_files(alpm, &trans.add) == -1 {
        return -1;
    }
    // make sure all required signatures are in keyring
    if check_keyring(alpm, trans) != 0 {
        return -1;
    }
    // get the total size of all packages so we can adjust the progress bar more realistically if there are
    // small and huge packages involved
    let mut total = 0;
    let mut total_bytes: u64 = 0;
    for spkg in &trans.add {
        if spkg.origin != PkgFrom::File {
            total_bytes += spkg.size as u64;
        }
        total += 1;
    }
    // this can only happen maliciously
    let total_bytes = total_bytes.max(1);
    if check_validity(alpm, trans, total, total_bytes) != 0 {
        return -1;
    }
    if handle.trans_flags() & TRANS_FLAG_DOWNLOADONLY != 0 {
        return 0;
    }
    if load_packages(alpm, trans, data, total, total_bytes) != 0 {
        return -1;
    }
    0
}
