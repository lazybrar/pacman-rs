//! Port of src/pacman/conf.c: config model + parsing (no libalpm setup, callbacks or xfercommand download).
use crate::ini::{Event, parse_ini};
use crate::pm_printf;
use crate::util::{LOG_DEBUG, LOG_ERROR, LOG_WARNING, resolve_path};
use crate::util_common::{strerror, wordsplit};
use std::io::IsTerminal;
use std::sync::atomic::Ordering;

pub const CONFFILE: &str = "/etc/pacman.conf";
pub const ROOTDIR: &str = "/";
pub const DBPATH: &str = "/var/lib/pacman/";
pub const GPGDIR: &str = "/etc/pacman.d/gnupg/";
pub const LOGFILE: &str = "/var/log/pacman.log";
pub const CACHEDIR: &str = "/var/cache/pacman/pkg/";
pub const HOOKDIR: &str = "/etc/pacman.d/hooks/";

pub const SIG_PACKAGE: i32 = 1;
pub const SIG_PACKAGE_OPTIONAL: i32 = 1 << 1;
pub const SIG_PACKAGE_MARGINAL_OK: i32 = 1 << 2;
pub const SIG_PACKAGE_UNKNOWN_OK: i32 = 1 << 3;
pub const SIG_DATABASE: i32 = 1 << 10;
pub const SIG_DATABASE_OPTIONAL: i32 = 1 << 11;
pub const SIG_DATABASE_MARGINAL_OK: i32 = 1 << 12;
pub const SIG_DATABASE_UNKNOWN_OK: i32 = 1 << 13;
pub const SIG_USE_DEFAULT: i32 = 1 << 30;

pub const DB_USAGE_SYNC: i32 = 1;
pub const DB_USAGE_SEARCH: i32 = 1 << 1;
pub const DB_USAGE_INSTALL: i32 = 1 << 2;
pub const DB_USAGE_UPGRADE: i32 = 1 << 3;
pub const DB_USAGE_ALL: i32 = (1 << 4) - 1;

pub const CLEAN_KEEPINST: u32 = 1;
pub const CLEAN_KEEPCUR: u32 = 1 << 1;

pub const COLOR_UNSET: u8 = 0;
pub const COLOR_OFF: u8 = 1;
pub const COLOR_ON: u8 = 2;

/// alpm_capabilities() & ALPM_CAPABILITY_SIGNATURES (we build with signature support).
const HAVE_SIGNATURES: bool = true;

#[derive(Default, Debug, Clone)]
pub struct ConfigRepo {
    pub name: String,
    pub cache_servers: Vec<String>,
    pub servers: Vec<String>,
    pub usage: i32,
    pub siglevel: i32,
    pub siglevel_mask: i32,
}

/// The parsed-from-config-file part of upstream's config_t.
#[derive(Default, Debug)]
pub struct Config {
    pub noprogressbar: bool,
    pub checkspace: bool,
    pub usesyslog: bool,
    pub color: u8,
    pub disable_dl_timeout: bool,
    pub disable_sandbox_filesystem: bool,
    pub disable_sandbox_syscalls: bool,
    pub rootdir: Option<String>,
    pub dbpath: Option<String>,
    pub logfile: Option<String>,
    pub gpgdir: Option<String>,
    pub sysroot: Option<String>,
    pub sandboxuser: Option<String>,
    pub hookdirs: Vec<String>,
    pub cachedirs: Vec<String>,
    pub architectures: Vec<String>,
    pub siglevel: i32,
    pub localfilesiglevel: i32,
    pub remotefilesiglevel: i32,
    pub siglevel_mask: i32,
    pub localfilesiglevel_mask: i32,
    pub remotefilesiglevel_mask: i32,
    pub chomp: bool,
    pub verbosepkglists: bool,
    pub parallel_downloads: u32,
    pub cleanmethod: u32,
    pub holdpkg: Vec<String>,
    pub ignorepkg: Vec<String>,
    pub ignoregrp: Vec<String>,
    pub noupgrade: Vec<String>,
    pub noextract: Vec<String>,
    pub xfercommand: Option<String>,
    pub xfercommand_argv: Vec<String>,
    pub repos: Vec<ConfigRepo>,
}

/// enable_colors (only the err/warn/nocolor strings matter so far: see util::COLORS).
pub fn enable_colors(on: bool) {
    crate::util::COLORS.store(on, Ordering::Relaxed);
}

/// config_new
pub fn config_new() -> Config {
    let mut c = Config::default();
    if HAVE_SIGNATURES {
        c.siglevel = SIG_PACKAGE | SIG_DATABASE;
        c.localfilesiglevel = SIG_USE_DEFAULT;
        c.remotefilesiglevel = SIG_USE_DEFAULT;
    }
    c.parallel_downloads = 1;
    c
}

/// config_add_architecture
fn config_add_architecture(c: &mut Config, arch: &str) {
    let arch = if arch == "auto" {
        // SAFETY: uname fills the zeroed struct.
        let mut un: libc::utsname = unsafe { std::mem::zeroed() };
        unsafe { libc::uname(&mut un) };
        let m = unsafe { std::ffi::CStr::from_ptr(un.machine.as_ptr()) };
        m.to_string_lossy().into_owned()
    } else {
        arch.to_string()
    };
    pm_printf!(LOG_DEBUG, "config: arch: {}\n", arch);
    c.architectures.push(arch);
}

/// parse_number: strtol(base 10) that must consume the whole non-empty string.
fn parse_number(value: &str) -> Option<i64> {
    let b = value.as_bytes();
    let mut i = 0;
    while i < b.len() && crate::util_common::c_isspace(b[i] as char) {
        i += 1;
    }
    let neg = b.get(i) == Some(&b'-');
    if matches!(b.get(i), Some(b'-' | b'+')) {
        i += 1;
    }
    let ds = i;
    let mut v: i128 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = (v * 10 + (b[i] - b'0') as i128).min(i128::from(u64::MAX));
        i += 1;
    }
    if i == ds || i != b.len() {
        return None;
    }
    let v = if neg { -v } else { v };
    i64::try_from(v).ok()
}

/// process_siglevel
fn process_siglevel(
    values: &[String],
    storage: &mut i32,
    storage_mask: &mut i32,
    file: &str,
    linenum: usize,
) -> i32 {
    let (mut level, mut mask) = (*storage, *storage_mask);
    let mut ret = 0;
    macro_rules! slset {
        ($sl:expr) => {{
            level |= $sl;
            mask |= $sl;
        }};
    }
    macro_rules! slunset {
        ($sl:expr) => {{
            level &= !($sl);
            mask |= $sl;
        }};
    }
    for original in values {
        let (value, package, database) = if let Some(v) = original.strip_prefix("Package") {
            (v, true, false)
        } else if let Some(v) = original.strip_prefix("Database") {
            (v, false, true)
        } else {
            (original.as_str(), true, true)
        };
        match value {
            "Never" => {
                if package {
                    slunset!(SIG_PACKAGE);
                }
                if database {
                    slunset!(SIG_DATABASE);
                }
            }
            "Optional" => {
                if package {
                    slset!(SIG_PACKAGE | SIG_PACKAGE_OPTIONAL);
                }
                if database {
                    slset!(SIG_DATABASE | SIG_DATABASE_OPTIONAL);
                }
            }
            "Required" => {
                if package {
                    slset!(SIG_PACKAGE);
                    slunset!(SIG_PACKAGE_OPTIONAL);
                }
                if database {
                    slset!(SIG_DATABASE);
                    slunset!(SIG_DATABASE_OPTIONAL);
                }
            }
            "TrustedOnly" => {
                if package {
                    slunset!(SIG_PACKAGE_MARGINAL_OK | SIG_PACKAGE_UNKNOWN_OK);
                }
                if database {
                    slunset!(SIG_DATABASE_MARGINAL_OK | SIG_DATABASE_UNKNOWN_OK);
                }
            }
            "TrustAll" => {
                if package {
                    slset!(SIG_PACKAGE_MARGINAL_OK | SIG_PACKAGE_UNKNOWN_OK);
                }
                if database {
                    slset!(SIG_DATABASE_MARGINAL_OK | SIG_DATABASE_UNKNOWN_OK);
                }
            }
            _ => {
                pm_printf!(
                    LOG_ERROR,
                    "config file {}, line {}: invalid value for '{}' : '{}'\n",
                    file,
                    linenum,
                    "SigLevel",
                    original
                );
                ret = 1;
            }
        }
        level &= !SIG_USE_DEFAULT;
    }
    if !HAVE_SIGNATURES && level & (SIG_PACKAGE | SIG_DATABASE) != 0 {
        pm_printf!(
            LOG_ERROR,
            "config file {}, line {}: '{}' option invalid, no signature support\n",
            file,
            linenum,
            "SigLevel"
        );
        ret = 1;
    }
    if ret == 0 {
        *storage = level;
        *storage_mask = mask;
    }
    ret
}

/// merge_siglevel
fn merge_siglevel(base: i32, over: i32, mask: i32) -> i32 {
    if mask != 0 {
        (over & mask) | (base & !mask)
    } else {
        over
    }
}

/// process_cleanmethods
fn process_cleanmethods(c: &mut Config, values: &[String], file: &str, linenum: usize) -> i32 {
    for value in values {
        match value.as_str() {
            "KeepInstalled" => c.cleanmethod |= CLEAN_KEEPINST,
            "KeepCurrent" => c.cleanmethod |= CLEAN_KEEPCUR,
            _ => {
                pm_printf!(
                    LOG_ERROR,
                    "config file {}, line {}: invalid value for '{}' : '{}'\n",
                    file,
                    linenum,
                    "CleanMethod",
                    value
                );
                return 1;
            }
        }
    }
    0
}

/// setrepeatingoption: strtok_r on spaces; returns the tokens.
fn setrepeatingoption(ptr: &str, option: &str) -> Vec<String> {
    let v: Vec<String> = ptr
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    for val in &v {
        pm_printf!(LOG_DEBUG, "config: {}: {}\n", option, val);
    }
    v
}

fn invalid_value(file: &str, linenum: usize, key: &str, value: &str) -> i32 {
    pm_printf!(
        LOG_ERROR,
        "config file {}, line {}: invalid value for '{}' : '{}'\n",
        file,
        linenum,
        key,
        value
    );
    1
}

fn not_recognized(file: &str, linenum: usize, key: &str, section: &str) {
    pm_printf!(
        LOG_WARNING,
        "config file {}, line {}: directive '{}' in section '{}' not recognized.\n",
        file,
        linenum,
        key,
        section
    );
}

/// _parse_options
fn parse_options(
    c: &mut Config,
    key: &str,
    value: Option<&str>,
    file: &str,
    linenum: usize,
) -> i32 {
    let Some(value) = value else {
        match key {
            "UseSyslog" => {
                c.usesyslog = true;
                pm_printf!(LOG_DEBUG, "config: usesyslog\n");
            }
            "ILoveCandy" => {
                c.chomp = true;
                pm_printf!(LOG_DEBUG, "config: chomp\n");
            }
            "VerbosePkgLists" => {
                c.verbosepkglists = true;
                pm_printf!(LOG_DEBUG, "config: verbosepkglists\n");
            }
            "CheckSpace" => c.checkspace = true,
            "Color" => {
                if c.color == COLOR_UNSET {
                    let tty = std::io::stdout().is_terminal();
                    c.color = if tty { COLOR_ON } else { COLOR_OFF };
                    enable_colors(tty);
                }
            }
            "NoProgressBar" => c.noprogressbar = true,
            "DisableDownloadTimeout" => c.disable_dl_timeout = true,
            "DisableSandbox" => {
                c.disable_sandbox_filesystem = true;
                c.disable_sandbox_syscalls = true;
            }
            "DisableSandboxFilesystem" => c.disable_sandbox_filesystem = true,
            "DisableSandboxSyscalls" => c.disable_sandbox_syscalls = true,
            _ => not_recognized(file, linenum, key, "options"),
        }
        return 0;
    };
    match key {
        "NoUpgrade" => c.noupgrade.extend(setrepeatingoption(value, "NoUpgrade")),
        "NoExtract" => c.noextract.extend(setrepeatingoption(value, "NoExtract")),
        "IgnorePkg" => c.ignorepkg.extend(setrepeatingoption(value, "IgnorePkg")),
        "IgnoreGroup" => c.ignoregrp.extend(setrepeatingoption(value, "IgnoreGroup")),
        "HoldPkg" => c.holdpkg.extend(setrepeatingoption(value, "HoldPkg")),
        // upstream b9f7d4a5 ("Partially revert resolving paths"): CacheDir/HookDir are not resolve_path'd
        "CacheDir" => c.cachedirs.extend(setrepeatingoption(value, "CacheDir")),
        "HookDir" => c.hookdirs.extend(setrepeatingoption(value, "HookDir")),
        "Architecture" => {
            for a in setrepeatingoption(value, "Architecture") {
                config_add_architecture(c, &a);
            }
        }
        "DBPath" | "RootDir" | "GPGDir" => {
            // don't overwrite a path specified on the command line
            let slot = match key {
                "DBPath" => &mut c.dbpath,
                "RootDir" => &mut c.rootdir,
                _ => &mut c.gpgdir,
            };
            if slot.is_none() {
                match resolve_path(value, key) {
                    Some(p) => {
                        pm_printf!(LOG_DEBUG, "config: {}: {}\n", key.to_lowercase(), p);
                        *slot = Some(p);
                    }
                    None => return 1,
                }
            }
        }
        "LogFile" => {
            if c.logfile.is_none() {
                c.logfile = Some(value.to_string());
                pm_printf!(LOG_DEBUG, "config: logfile: {}\n", value);
            }
        }
        "DownloadUser" => {
            if c.sandboxuser.is_none() {
                c.sandboxuser = Some(value.to_string());
                pm_printf!(LOG_DEBUG, "config: sandboxuser: {}\n", value);
            }
        }
        "XferCommand" => {
            match wordsplit(value) {
                Some(v) => c.xfercommand_argv = v,
                None => return invalid_value(file, linenum, "XferCommand", value),
            }
            c.xfercommand = Some(value.to_string());
            pm_printf!(LOG_DEBUG, "config: xfercommand: {}\n", value);
        }
        "CleanMethod" => {
            let methods = setrepeatingoption(value, "CleanMethod");
            if process_cleanmethods(c, &methods, file, linenum) != 0 {
                return 1;
            }
        }
        "SigLevel" | "LocalFileSigLevel" | "RemoteFileSigLevel" => {
            let values = setrepeatingoption(value, key);
            let (s, m) = match key {
                "SigLevel" => (&mut c.siglevel, &mut c.siglevel_mask),
                "LocalFileSigLevel" => (&mut c.localfilesiglevel, &mut c.localfilesiglevel_mask),
                _ => (&mut c.remotefilesiglevel, &mut c.remotefilesiglevel_mask),
            };
            if process_siglevel(&values, s, m, file, linenum) != 0 {
                return 1;
            }
        }
        "ParallelDownloads" => {
            let Some(number) = parse_number(value) else {
                return invalid_value(file, linenum, "ParallelDownloads", value);
            };
            if number < 1 {
                pm_printf!(
                    LOG_ERROR,
                    "config file {}, line {}: value for '{}' has to be positive : '{}'\n",
                    file,
                    linenum,
                    "ParallelDownloads",
                    value
                );
                return 1;
            }
            if number > i32::MAX as i64 {
                pm_printf!(
                    LOG_ERROR,
                    "config file {}, line {}: value for '{}' is too large : '{}'\n",
                    file,
                    linenum,
                    "ParallelDownloads",
                    value
                );
                return 1;
            }
            c.parallel_downloads = number as u32;
        }
        _ => not_recognized(file, linenum, key, "options"),
    }
    0
}

/// replace_server_vars; None when $arch is used without an Architecture.
fn replace_server_vars(arches: &[String], repo_name: &str, s: &str) -> Option<String> {
    if arches.is_empty() && s.contains("$arch") {
        pm_printf!(
            LOG_ERROR,
            "mirror '{}' contains the '{}' variable, but no '{}' is defined.\n",
            s,
            "$arch",
            "Architecture"
        );
        return None;
    }
    let mut r = s.to_string();
    if let Some(a) = arches.first() {
        r = r.replace("$arch", a);
    }
    Some(r.replace("$repo", repo_name))
}

/// process_usage
fn process_usage(values: &[String], usage: &mut i32, file: &str, linenum: usize) -> i32 {
    let mut level = *usage;
    let mut ret = 0;
    for key in values {
        match key.as_str() {
            "Sync" => level |= DB_USAGE_SYNC,
            "Search" => level |= DB_USAGE_SEARCH,
            "Install" => level |= DB_USAGE_INSTALL,
            "Upgrade" => level |= DB_USAGE_UPGRADE,
            "All" => level |= DB_USAGE_ALL,
            _ => {
                pm_printf!(
                    LOG_ERROR,
                    "config file {}, line {}: '{}' option '{}' not recognized\n",
                    file,
                    linenum,
                    "Usage",
                    key
                );
                ret = 1;
            }
        }
    }
    *usage = level;
    ret
}

/// _parse_repo
fn parse_repo(
    repo: &mut ConfigRepo,
    key: &str,
    value: Option<&str>,
    file: &str,
    line: usize,
) -> i32 {
    let mut ret = 0;
    macro_rules! check_value {
        () => {
            match value {
                Some(v) => v,
                None => {
                    pm_printf!(
                        LOG_ERROR,
                        "config file {}, line {}: directive '{}' needs a value\n",
                        file,
                        line,
                        key
                    );
                    return 1;
                }
            }
        };
    }
    match key {
        "CacheServer" => repo.cache_servers.push(check_value!().to_string()),
        "Server" => repo.servers.push(check_value!().to_string()),
        "SigLevel" => {
            let values = setrepeatingoption(check_value!(), "SigLevel");
            if !values.is_empty() {
                ret = process_siglevel(
                    &values,
                    &mut repo.siglevel,
                    &mut repo.siglevel_mask,
                    file,
                    line,
                );
            }
        }
        "Usage" => {
            let values = setrepeatingoption(check_value!(), "Usage");
            if !values.is_empty() && process_usage(&values, &mut repo.usage, file, line) != 0 {
                return 1;
            }
        }
        _ => not_recognized(file, line, key, &repo.name),
    }
    ret
}

/// escape_chars
fn escape_chars(pattern: &str, escape: &str) -> String {
    let mut out = String::new();
    for c in pattern.chars() {
        if escape.contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// prepend_dir
fn prepend_dir(dir: Option<&str>, path: &str) -> String {
    match dir {
        None => path.to_string(),
        Some(d) => {
            let sep = if d.ends_with('/') && !d.is_empty() {
                ""
            } else {
                "/"
            };
            format!("{}{}{}", d, sep, path.trim_start_matches('/'))
        }
    }
}

/// globdir with flags = GLOB_NOCHECK: Err(code) is the glob() return code.
fn globdir(dir: Option<&str>, pattern: &str) -> Result<Vec<String>, i32> {
    let full = match dir {
        None => pattern.to_string(),
        Some(d) => prepend_dir(Some(&escape_chars(d, "\\*?[")), pattern),
    };
    let Ok(cpat) = std::ffi::CString::new(full) else {
        return Err(libc::GLOB_NOMATCH);
    };
    // SAFETY: glob_t is plain data; glob initialises it and globfree releases it.
    let mut g: libc::glob_t = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::glob(cpat.as_ptr(), libc::GLOB_NOCHECK, None, &mut g) };
    let mut out = Vec::new();
    if r == 0 {
        for i in 0..g.gl_pathc {
            let p = unsafe { std::ffi::CStr::from_ptr(*g.gl_pathv.add(i)) };
            out.push(p.to_string_lossy().into_owned());
        }
    }
    unsafe { libc::globfree(&mut g) };
    if r == 0 { Ok(out) } else { Err(r) }
}

#[derive(Default)]
struct Section {
    name: Option<String>,
    repo: Option<usize>,
    depth: i32,
}

/// process_include
fn process_include(
    c: &mut Config,
    s: &mut Section,
    value: Option<&str>,
    file: &str,
    linenum: usize,
) -> i32 {
    const CONFIG_MAX_RECURSION: i32 = 10;
    let Some(value) = value else {
        pm_printf!(
            LOG_ERROR,
            "config file {}, line {}: directive '{}' needs a value\n",
            file,
            linenum,
            "Include"
        );
        return 1;
    };
    if s.depth >= CONFIG_MAX_RECURSION {
        pm_printf!(
            LOG_ERROR,
            "config parsing exceeded max recursion depth of {}.\n",
            CONFIG_MAX_RECURSION
        );
        return 1;
    }
    s.depth += 1;
    let mut ret = 0;
    // Ignore include failures... assume non-critical
    match globdir(c.sysroot.clone().as_deref(), value) {
        Err(libc::GLOB_NOSPACE) => pm_printf!(
            LOG_DEBUG,
            "config file {}, line {}: include globbing out of space\n",
            file,
            linenum
        ),
        Err(libc::GLOB_ABORTED) => {
            pm_printf!(
                LOG_DEBUG,
                "config file {}, line {}: include globbing read error for {}\n",
                file,
                linenum,
                value
            )
        }
        Err(_) => pm_printf!(
            LOG_DEBUG,
            "config file {}, line {}: no include found for {}\n",
            file,
            linenum,
            value
        ),
        Ok(paths) => {
            for p in paths {
                pm_printf!(
                    LOG_DEBUG,
                    "config file {}, line {}: including {}\n",
                    file,
                    linenum,
                    p
                );
                ret = parse_ini(&p, &mut |f, l, ev| parse_directive(c, s, f, l, ev));
                if ret != 0 {
                    break;
                }
            }
        }
    }
    s.depth -= 1;
    ret
}

/// _parse_directive
fn parse_directive(c: &mut Config, s: &mut Section, file: &str, linenum: usize, ev: Event) -> i32 {
    let (key, value) = match ev {
        Event::OpenFailed(e) => {
            pm_printf!(
                LOG_ERROR,
                "config file {} could not be read: {}\n",
                file,
                strerror(&e)
            );
            return 1;
        }
        Event::Section(name) => {
            s.name = Some(name.to_string());
            pm_printf!(LOG_DEBUG, "config: new section '{}'\n", name);
            if name == "options" {
                s.repo = None;
            } else {
                c.repos.push(ConfigRepo {
                    name: name.to_string(),
                    siglevel: SIG_USE_DEFAULT,
                    ..Default::default()
                });
                s.repo = Some(c.repos.len() - 1);
            }
            return 0;
        }
        Event::Directive { key, value, .. } => (key, value),
    };
    if key == "Include" {
        return process_include(c, s, value, file, linenum);
    }
    if s.name.is_none() {
        pm_printf!(
            LOG_ERROR,
            "config file {}, line {}: All directives must belong to a section.\n",
            file,
            linenum
        );
        return 1;
    }
    match s.repo {
        None => parse_options(c, key, value, file, linenum),
        Some(i) => parse_repo(&mut c.repos[i], key, value, file, linenum),
    }
}

/// prepend_sysroot
fn prepend_sysroot(c: &mut Config) {
    let Some(sr) = c.sysroot.clone() else { return };
    let sr = Some(sr.as_str());
    for v in [&mut c.rootdir, &mut c.dbpath, &mut c.logfile, &mut c.gpgdir]
        .into_iter()
        .flatten()
    {
        *v = prepend_dir(sr, v);
    }
    for d in c.cachedirs.iter_mut().chain(c.hookdirs.iter_mut()) {
        *d = prepend_dir(sr, d);
    }
    for r in &mut c.repos {
        for u in &mut r.servers {
            if let Some(old) = u.strip_prefix("file://") {
                *u = format!("file://{}", prepend_dir(sr, old));
            }
        }
    }
}

/// setdefaults: 0, or -1 on error.
pub fn setdefaults(c: &mut Config) -> i32 {
    if let Some(root) = &c.rootdir {
        let root = root.strip_suffix('/').unwrap_or(root).to_string();
        if c.dbpath.is_none() {
            c.dbpath = Some(format!("{}/{}", root, &DBPATH[1..]));
        }
        if c.logfile.is_none() {
            c.logfile = Some(format!("{}/{}", root, &LOGFILE[1..]));
        }
    } else {
        c.rootdir = Some(ROOTDIR.to_string());
        c.dbpath.get_or_insert_with(|| DBPATH.to_string());
    }
    c.logfile.get_or_insert_with(|| LOGFILE.to_string());
    c.gpgdir.get_or_insert_with(|| GPGDIR.to_string());
    if c.cachedirs.is_empty() {
        c.cachedirs.push(CACHEDIR.to_string());
    }
    if c.hookdirs.is_empty() {
        c.hookdirs.push(HOOKDIR.to_string());
    }
    if c.cleanmethod == 0 {
        c.cleanmethod = CLEAN_KEEPINST;
    }
    c.localfilesiglevel = merge_siglevel(c.siglevel, c.localfilesiglevel, c.localfilesiglevel_mask);
    c.remotefilesiglevel =
        merge_siglevel(c.siglevel, c.remotefilesiglevel, c.remotefilesiglevel_mask);
    let (siglevel, arches) = (c.siglevel, c.architectures.clone());
    for r in &mut c.repos {
        if r.usage == 0 {
            r.usage = DB_USAGE_ALL;
        }
        r.siglevel = merge_siglevel(siglevel, r.siglevel, r.siglevel_mask);
        for list in [&mut r.cache_servers, &mut r.servers] {
            for u in list.iter_mut() {
                match replace_server_vars(&arches, &r.name, u) {
                    Some(n) => *u = n,
                    None => return -1,
                }
            }
        }
    }
    prepend_sysroot(c);
    0
}

/// parseconfigfile
pub fn parseconfigfile(c: &mut Config, file: &str) -> i32 {
    let mut section = Section::default();
    let realfile = prepend_dir(c.sysroot.as_deref(), file);
    parse_ini(&realfile, &mut |f, l, ev| {
        parse_directive(c, &mut section, f, l, ev)
    })
}
