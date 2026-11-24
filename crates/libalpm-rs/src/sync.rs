//! Port of lib/libalpm/sync.c (so far: alpm_sync_get_new_version and the package download of a transaction,
//! `download_files`).
use crate::alpm::Alpm;
use crate::consts::{SIG_PACKAGE, SIG_PACKAGE_OPTIONAL};
use crate::db::Db;
use crate::dload::{Payload, PayloadRef, download, payload_ref};
use crate::error::Error;
use crate::handle::Event;
use crate::log::{LOG_DEBUG, LOG_ERROR, LOG_WARNING};
use crate::package::{Pkg, PkgFrom, pkg_compare_versions};
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

/// compute_download_size (alpm_pkg_download_size): what is left to download for `newpkg`
pub fn download_size(newpkg: &Pkg) -> i64 {
    let handle = &newpkg.handle;
    if newpkg.origin != PkgFrom::SyncDb {
        return 0;
    }
    let fname = newpkg.filename.as_deref().unwrap_or("");
    // downloaded file exists, so there's nothing to grab
    let size = if filecache_find(handle, fname).is_some() {
        0
    } else if let Some(fpath) = filecache_find(handle, &format!("{fname}.part")) {
        let mut size = 0;
        if let Ok(st) = std::fs::metadata(fpath) {
            // subtract the size of the .part file
            crate::alpm_log!(handle, LOG_DEBUG, "using (package - .part) size\n");
            size = (newpkg.size - st.len() as i64).max(0);
        }
        size
    } else {
        newpkg.size
    };
    crate::alpm_log!(
        handle,
        LOG_DEBUG,
        "setting download size {} for pkg {}\n",
        size,
        newpkg.name
    );
    size
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
        let mut need_download = download_size(spkg) != 0 || !filecache_exists(handle, filename);
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
/// shortcut: the checkspace disk space check (diskspace.c) is not ported; the transaction state is not tracked.
pub fn download_files(alpm: &Alpm, add: &[&Pkg]) -> i32 {
    let handle = &alpm.handle;
    let cachedir = filecache_setup(handle);
    let Some(temporary_cachedir) = download_dir_setup(handle, &cachedir) else {
        return -1;
    };
    let Ok(files) = find_dl_candidates(alpm, add) else {
        return -1;
    };
    let mut ret = 0;
    if !files.is_empty() {
        let total_size: i64 = files.iter().map(|p| download_size(p)).sum();
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
        ret = download(handle, &payloads, &cachedir, &temporary_cachedir);
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
