//! Port of lib/libalpm/be_package.c: loading a package file (`.PKGINFO`, `.MTREE`, file list).
//! `alpm_pkg_load`'s signature handling and `_alpm_pkg_validate_internal` come with signing.c.
use crate::alpm_log;
use crate::archive::{
    AE_IFDIR, AE_IFREG, ArchiveLines, Fgets, decompress_bytes, open_archive, read_mtree,
};
use crate::backup::Backup;
use crate::deps::dep_from_string;
use crate::error::Error;
use crate::filelist::{File, FileList};
use crate::handle::Handle;
use crate::log::*;
use crate::package::*;
use crate::util::*;
use std::io::Read;
use std::rc::Rc;

/// handle_simple_path: true when the entry is metadata and not a payload file.
fn handle_simple_path(scriptlet: &mut bool, path: &str) -> bool {
    if path == ".INSTALL" {
        *scriptlet = true;
        true
    } else {
        path.starts_with('.')
    }
}

/// Everything parse_descfile fills in.
#[derive(Default)]
struct Parsed {
    name: Option<String>,
    name_hash: u64,
    version: Option<String>,
    desc: Desc,
    backup: Vec<Backup>,
}

/// parse_descfile: 0 on success, -1 on error
fn parse_descfile(handle: &Handle, data: Vec<u8>, p: &mut Parsed) -> i32 {
    let mut lines = ArchiveLines::new(data);
    let mut linenum = 0;
    loop {
        let raw = match lines.fgets() {
            Fgets::Line(l) => l.to_vec(),
            Fgets::Eof => return 0,
            Fgets::Err => {
                alpm_log!(handle, LOG_DEBUG, "error parsing package descfile\n");
                return -1;
            }
        };
        let mut key = raw;
        let len = strip_newline(&mut key);
        linenum += 1;
        if len == 0 || key[0] == b'#' {
            continue;
        }
        // line is always in this format: "key = value"
        let ptr = key.iter().position(|&c| c == b' ');
        let ok = ptr.is_some_and(|p| key.get(p..p + 3) == Some(b" = ".as_slice()));
        let pkgname = p.name.clone().unwrap_or_else(|| "error".to_string());
        if !ok {
            alpm_log!(
                handle,
                LOG_DEBUG,
                "{}: syntax error in description file line {}\n",
                pkgname,
                linenum
            );
            continue;
        }
        let ptr = ptr.unwrap();
        let k = &key[..ptr];
        let v = &key[ptr + 3..];
        let vs = lossy(v);
        let d = &mut p.desc;
        match k {
            b"pkgname" => {
                p.name_hash = hash_sdbm(&vs);
                p.name = Some(vs);
            }
            b"pkgbase" => d.base = Some(vs),
            b"pkgver" => p.version = Some(vs),
            b"basever" => {} // not used atm
            b"pkgdesc" => d.desc = Some(vs),
            b"group" => d.groups.push(vs),
            b"url" => d.url = Some(vs),
            b"license" => d.licenses.push(vs),
            b"builddate" => d.builddate = parsedate(v),
            b"packager" => d.packager = Some(vs),
            b"arch" => d.arch = Some(vs),
            // size in the raw package is uncompressed (installed) size
            b"size" => d.isize = strtoofft(v),
            b"depend" => d.depends.push(dep_from_string(&vs)),
            b"optdepend" => d.optdepends.push(dep_from_string(&vs)),
            b"makedepend" => d.makedepends.push(dep_from_string(&vs)),
            b"checkdepend" => d.checkdepends.push(dep_from_string(&vs)),
            b"conflict" => d.conflicts.push(dep_from_string(&vs)),
            b"replaces" => d.replaces.push(dep_from_string(&vs)),
            b"provides" => d.provides.push(dep_from_string(&vs)),
            b"backup" => p.backup.push(Backup {
                name: vs,
                hash: None,
            }),
            b"xdata" => match pkg_parse_xdata(&vs) {
                Some(x) => d.xdata.push(x),
                None => return -1,
            },
            _ => {
                alpm_log!(
                    handle,
                    LOG_WARNING,
                    "{}: unknown key '{}' in package description\n",
                    pkgname,
                    lossy(k)
                );
                alpm_log!(
                    handle,
                    LOG_DEBUG,
                    "{}: unknown key '{}' in description file line {}\n",
                    pkgname,
                    lossy(k),
                    linenum
                );
            }
        }
    }
}

/// libarchive entry file type of a tar entry
fn filetype(t: tar::EntryType) -> u32 {
    use tar::EntryType as E;
    match t {
        E::Directory => AE_IFDIR,
        E::Symlink => 0o120000,
        E::Block => 0o060000,
        E::Char => 0o020000,
        E::Fifo => 0o010000,
        _ => AE_IFREG,
    }
}

/// add_entry_to_files_list: directories get a trailing slash
fn add_entry(files: &mut Vec<File>, ftype: u32, path: &str, size: i64, mode: u32) {
    let name = if ftype == AE_IFDIR && !path.ends_with('/') {
        format!("{path}/")
    } else {
        path.to_string()
    };
    files.push(File { name, size, mode });
}

/// build_filelist_from_mtree: the file list, or None on error
fn build_filelist_from_mtree(
    handle: &Handle,
    filename: &str,
    scriptlet: &mut bool,
    data: Vec<u8>,
) -> Option<Vec<File>> {
    alpm_log!(
        handle,
        LOG_DEBUG,
        "found mtree for package {}, getting file list\n",
        filename
    );
    let bad = |what: &str| {
        alpm_log!(
            handle,
            LOG_DEBUG,
            "error while reading mtree of package {}: {}\n",
            filename,
            what
        );
        handle.pm_errno.set(Some(Error::Libarchive));
        None
    };
    let data = match decompress_bytes(data) {
        Ok(d) => d,
        Err(e) => return bad(&strerror(&e)),
    };
    let entries = match read_mtree(&data) {
        Ok(e) => e,
        Err(m) => return bad(&m),
    };
    let mut files = Vec::new();
    for e in entries {
        // strip leading "./" from path entries
        let path = e.path.strip_prefix("./").unwrap_or(&e.path);
        if handle_simple_path(scriptlet, path) {
            continue;
        }
        add_entry(&mut files, e.filetype, path, e.size, e.mode);
    }
    alpm_log!(
        handle,
        LOG_DEBUG,
        "finished mtree reading for {}\n",
        filename
    );
    Some(files)
}

/// _alpm_pkg_load_internal: `full` also builds the file list.
pub fn pkg_load_internal(handle: &Rc<Handle>, pkgfile: &str, full: bool) -> Result<Pkg, Error> {
    if pkgfile.is_empty() {
        return handle.err(Error::WrongArgs);
    }
    let mut archive = match open_archive(handle, pkgfile, Error::PkgOpen) {
        Ok(a) => a,
        Err(e) => {
            return handle.err(match e.errno {
                Some(libc::ENOENT) => Error::PkgNotFound,
                Some(libc::EACCES) => Error::Badperms,
                _ => Error::PkgOpen,
            });
        }
    };
    let size = archive.size as i64;
    alpm_log!(handle, LOG_DEBUG, "starting package load for {}\n", pkgfile);
    let mut parsed = Parsed::default();
    let (mut config, mut hit_mtree, mut scriptlet) = (false, false, false);
    let mut files: Vec<File> = Vec::new();
    let invalid = |h: &Handle| -> Result<Pkg, Error> { h.err(Error::PkgInvalid) };
    let read_failed = |e: &std::io::Error| {
        alpm_log!(
            handle,
            LOG_ERROR,
            "error while reading package {}: {}\n",
            pkgfile,
            strerror(e)
        );
        handle.err::<Pkg>(Error::Libarchive)
    };
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(e) => return read_failed(&e),
    };
    for ent in entries {
        let mut ent = match ent {
            Ok(e) => e,
            Err(e) => return read_failed(&e),
        };
        let entry_name = lossy(&ent.path_bytes());
        if entry_name == ".PKGINFO" {
            // parse the info file
            let mut data = Vec::new();
            if let Err(e) = ent.read_to_end(&mut data) {
                return read_failed(&e);
            }
            if parse_descfile(handle, data, &mut parsed) != 0 {
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "could not parse package description file in {}\n",
                    pkgfile
                );
                return invalid(handle);
            }
            if parsed.name.as_deref().is_none_or(str::is_empty) {
                alpm_log!(handle, LOG_ERROR, "missing package name in {}\n", pkgfile);
                return invalid(handle);
            }
            match parsed.version.as_deref() {
                None | Some("") => {
                    alpm_log!(
                        handle,
                        LOG_ERROR,
                        "missing package version in {}\n",
                        pkgfile
                    );
                    return invalid(handle);
                }
                Some(v) if !v.contains('-') => {
                    alpm_log!(
                        handle,
                        LOG_ERROR,
                        "invalid package version in {}\n",
                        pkgfile
                    );
                    return invalid(handle);
                }
                _ => {}
            }
            config = true;
            continue;
        } else if full && entry_name == ".MTREE" {
            // building the file list: cheap way
            let mut data = Vec::new();
            if let Err(e) = ent.read_to_end(&mut data) {
                return read_failed(&e);
            }
            match build_filelist_from_mtree(handle, pkgfile, &mut scriptlet, data) {
                Some(f) => {
                    files = f;
                    hit_mtree = true;
                }
                None => hit_mtree = false,
            }
            continue;
        } else if handle_simple_path(&mut scriptlet, &entry_name) {
            continue;
        } else if full && !hit_mtree {
            // building the file list: expensive way
            let h = ent.header();
            let ft = filetype(h.entry_type());
            let (sz, mode) = (h.size().unwrap_or(0) as i64, h.mode().unwrap_or(0) & 0o7777);
            add_entry(&mut files, ft, &entry_name, sz, ft | mode);
        }
        // if we are not doing a full read, see if we have all we need
        if (!full || hit_mtree) && config {
            break;
        }
    }
    if !config {
        alpm_log!(
            handle,
            LOG_ERROR,
            "missing package metadata in {}\n",
            pkgfile
        );
        return invalid(handle);
    }
    let mut pkg = Pkg::new(
        Rc::clone(handle),
        parsed.name.unwrap_or_default(),
        parsed.version.unwrap_or_default(),
        parsed.name_hash,
        PkgFrom::File,
    );
    pkg.filename = Some(pkgfile.to_string());
    pkg.file = Some(pkgfile.to_string());
    pkg.size = size;
    parsed.desc.validation = PKG_VALIDATION_NONE;
    pkg.set_desc(parsed.desc);
    let mut fl = FileList { files };
    if full {
        // "checking for conflicts" requires a sorted list, ensure that here
        alpm_log!(
            handle,
            LOG_DEBUG,
            "sorting package filelist for {}\n",
            pkgfile
        );
        fl.sort();
    }
    pkg.set_files(FilesData {
        files: fl,
        backup: parsed.backup,
    });
    pkg.set_scriptlet(scriptlet);
    if pkg_check_meta(&pkg) != 0 {
        return invalid(handle);
    }
    Ok(pkg)
}

/// _package_changelog_open/_read: the whole `.CHANGELOG` of a package file, None when it has none.
pub fn pkg_changelog_read_all(pkg: &Pkg) -> Option<Vec<u8>> {
    let file = pkg.file.as_deref()?;
    let mut archive = open_archive(&pkg.handle, file, Error::PkgOpen).ok()?;
    for ent in archive.entries().ok()? {
        let mut ent = ent.ok()?;
        if ent.path_bytes().as_ref() == b".CHANGELOG" {
            let mut v = Vec::new();
            ent.read_to_end(&mut v).ok()?;
            return Some(v);
        }
    }
    None
}

/// _alpm_pkg_validate_internal for a level without package signature requirements.
fn pkg_validate_unsigned(handle: &Handle, pkgfile: &str, level: i32) -> Result<i32, Error> {
    handle.pm_errno.set(None);
    if pkgfile.is_empty() {
        return handle.err(Error::WrongArgs);
    }
    // attempt to access the package file, ensure it exists
    let c = std::ffi::CString::new(pkgfile).map_err(|_| Error::WrongArgs)?;
    // SAFETY: valid C string
    if unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            c.as_ptr(),
            libc::R_OK,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let e = std::io::Error::last_os_error();
        alpm_log!(
            handle,
            LOG_DEBUG,
            "\"{}\" is not readable: {}\n",
            pkgfile,
            strerror(&e)
        );
        return handle.err(match e.raw_os_error() {
            Some(libc::ENOENT) => Error::PkgNotFound,
            Some(libc::EACCES) => Error::Badperms,
            _ => Error::PkgOpen,
        });
    }
    if level & crate::consts::SIG_PACKAGE != 0 {
        // shortcut: signing.c is not ported, so a package that must be signature-checked cannot be loaded
        alpm_log!(
            handle,
            LOG_ERROR,
            "package signature verification is not implemented yet\n"
        );
        return handle.err(Error::PkgInvalidSig);
    }
    Ok(PKG_VALIDATION_NONE)
}

/// alpm_pkg_load (for levels that do not need signature verification)
pub fn pkg_load(handle: &Rc<Handle>, filename: &str, full: bool, level: i32) -> Result<Pkg, Error> {
    let validation = pkg_validate_unsigned(handle, filename, level)?;
    let mut pkg = pkg_load_internal(handle, filename, full)?;
    if let Some(d) = pkg.desc.get_mut() {
        d.validation = validation;
    }
    Ok(pkg)
}
