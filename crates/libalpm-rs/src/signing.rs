//! Port of lib/libalpm/signing.c: signature decoding, issuer key id extraction and verification through
//! gpgme (the same engine, keyring and trustdb as upstream, so the same keys are trusted).
//! Deviation: gpgme_set_locale is not called (the gpgme crate has no binding); it only affects gpg's own messages.
use crate::alpm_log;
use crate::base64::base64_decode;
use crate::db::Db;
use crate::error::Error;
use crate::handle::{Handle, Question};
use crate::log::*;
use crate::package::Pkg;
use gpgme::{Context, Key, KeyListMode, Protocol, Validity};
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};

/// alpm_decode_signature
pub fn decode_signature(base64_data: &str) -> Option<Vec<u8>> {
    base64_decode(base64_data.as_bytes())
}

/// length_check: true (an error) when reading `a` bytes at `position` would run past the data
fn length_check(
    handle: &Handle,
    length: usize,
    position: usize,
    a: usize,
    identifier: &str,
) -> bool {
    if a == 0 || position > length || length - position <= a {
        alpm_log!(
            handle,
            LOG_ERROR,
            "{}: signature format error\n",
            identifier
        );
        true
    } else {
        false
    }
}

fn at(sig: &[u8], i: usize) -> usize {
    sig.get(i).copied().unwrap_or(0) as usize
}

/// signed 32-bit big endian composed like the C expression (then sign-extended to size_t)
fn be32(sig: &[u8], p: usize) -> usize {
    let v = ((at(sig, p) as u32) << 24)
        | ((at(sig, p + 1) as u32) << 16)
        | ((at(sig, p + 2) as u32) << 8)
        | at(sig, p + 3) as u32;
    v as i32 as isize as usize
}

/// parse_subpacket
fn parse_subpacket(
    handle: &Handle,
    identifier: &str,
    sig: &[u8],
    pos: usize,
    plen: usize,
    keys: &mut Vec<String>,
) -> Result<(), ()> {
    let len = sig.len();
    let mut spos = pos;
    while spos < pos.wrapping_add(plen) {
        let slen;
        if at(sig, spos) < 192 {
            slen = at(sig, spos);
            spos += 1;
        } else if at(sig, spos) < 255 {
            if length_check(handle, len, spos, 2, identifier) {
                return Err(());
            }
            slen = ((at(sig, spos) - 192) << 8) + at(sig, spos + 1) + 192;
            spos += 2;
        } else {
            if length_check(handle, len, spos, 5, identifier) {
                return Err(());
            }
            slen = be32(sig, spos + 1);
            spos += 5;
        }
        if at(sig, spos) == 16 {
            // issuer key ID
            if length_check(handle, len, spos, 8, identifier) {
                return Err(());
            }
            keys.push(
                (0..8)
                    .map(|i| format!("{:02X}", at(sig, spos + i + 1)))
                    .collect(),
            );
            break;
        }
        if length_check(handle, len, spos, slen, identifier) {
            return Err(());
        }
        spos = spos.wrapping_add(slen);
    }
    Ok(())
}

#[allow(clippy::result_unit_err)]
/// alpm_extract_keyid: the issuer key ids of an OpenPGP signature (0, or -1 as Err on a format error)
pub fn extract_keyid(
    handle: &Handle,
    identifier: &str,
    sig: &[u8],
    keys: &mut Vec<String>,
) -> Result<(), ()> {
    let len = sig.len();
    let mut pos = 0usize;
    while pos < len {
        let blen;
        if sig[pos] & 0x80 == 0 {
            alpm_log!(
                handle,
                LOG_ERROR,
                "{}: signature format error\n",
                identifier
            );
            return Err(());
        }
        if sig[pos] & 0x40 != 0 {
            // new packet format
            if length_check(handle, len, pos, 1, identifier) {
                return Err(());
            }
            pos += 1;
            if at(sig, pos) < 192 {
                if length_check(handle, len, pos, 1, identifier) {
                    return Err(());
                }
                blen = at(sig, pos);
                pos += 1;
            } else if at(sig, pos) < 224 {
                if length_check(handle, len, pos, 2, identifier) {
                    return Err(());
                }
                blen = ((at(sig, pos) - 192) << 8) + at(sig, pos + 1) + 192;
                pos += 2;
            } else if at(sig, pos) == 255 {
                if length_check(handle, len, pos, 5, identifier) {
                    return Err(());
                }
                blen = be32(sig, pos + 1);
                pos += 5;
            } else {
                // partial body length not supported
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "{}: unsupported signature format\n",
                    identifier
                );
                return Err(());
            }
        } else {
            // old package format
            match sig[pos] & 0x03 {
                0 => {
                    if length_check(handle, len, pos, 2, identifier) {
                        return Err(());
                    }
                    blen = at(sig, pos + 1);
                    pos += 2;
                }
                1 => {
                    if length_check(handle, len, pos, 3, identifier) {
                        return Err(());
                    }
                    blen = (at(sig, pos + 1) << 8) | at(sig, pos + 2);
                    pos += 3;
                }
                2 => {
                    if length_check(handle, len, pos, 5, identifier) {
                        return Err(());
                    }
                    blen = be32(sig, pos + 1);
                    pos += 5;
                }
                _ => {
                    // partial body length not supported
                    alpm_log!(
                        handle,
                        LOG_ERROR,
                        "{}: unsupported signature format\n",
                        identifier
                    );
                    return Err(());
                }
            }
        }
        if length_check(handle, len, pos, 2, identifier) {
            return Err(());
        }
        if at(sig, pos) != 4 {
            // only support version 4 signature packet format
            alpm_log!(
                handle,
                LOG_ERROR,
                "{}: unsupported signature format\n",
                identifier
            );
            return Err(());
        }
        if at(sig, pos + 1) != 0x00 {
            // not a signature of a binary document
            alpm_log!(
                handle,
                LOG_ERROR,
                "{}: signature format error\n",
                identifier
            );
            return Err(());
        }
        pos += 4;
        // pos got changed above, so an explicit check is necessary
        if length_check(handle, len, pos, 2, identifier) {
            return Err(());
        }
        let hlen = (at(sig, pos) << 8) | at(sig, pos + 1);
        if length_check(handle, len, pos, hlen + 2, identifier) {
            return Err(());
        }
        pos += 2;
        parse_subpacket(handle, identifier, sig, pos, hlen, keys)?;
        pos += hlen;
        let ulen = (at(sig, pos) << 8) | at(sig, pos + 1);
        if length_check(handle, len, pos, ulen + 2, identifier) {
            return Err(());
        }
        pos += 2;
        parse_subpacket(handle, identifier, sig, pos, ulen, keys)?;
        pos = pos.wrapping_add(blen.wrapping_sub(hlen).wrapping_sub(8));
    }
    Ok(())
}

/// alpm_sigstatus_t
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigStatus {
    Valid,
    KeyExpired,
    SigExpired,
    KeyUnknown,
    KeyDisabled,
    Invalid,
}

/// alpm_sigvalidity_t
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigValidity {
    Full,
    Marginal,
    Never,
    Unknown,
}

/// alpm_pgpkey_t (strings are copied out; `data` is only kept for the import path)
#[derive(Default)]
pub struct PgpKey {
    pub data: Option<Key>,
    pub fingerprint: String,
    pub uid: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub created: i64,
    pub expires: i64,
}

/// alpm_sigresult_t
pub struct SigResult {
    pub key: PgpKey,
    pub status: SigStatus,
    pub validity: SigValidity,
}

/// alpm_siglist_t (alpm_siglist_cleanup is Drop)
pub type SigList = Vec<SigResult>;

/// string_validity
fn string_validity(v: Validity) -> &'static str {
    match v {
        Validity::Unknown => "unknown",
        Validity::Undefined => "undefined",
        Validity::Never => "never",
        Validity::Marginal => "marginal",
        Validity::Full => "full",
        Validity::Ultimate => "ultimate",
    }
}

/// list_sigsum
fn list_sigsum(sigsum: gpgme::SignatureSummary) -> Vec<&'static str> {
    use gpgme::SignatureSummary as S;
    let mut v = Vec::new();
    for (bit, name) in [
        (S::VALID, "valid"),
        (S::GREEN, "green"),
        (S::RED, "red"),
        (S::KEY_REVOKED, "key revoked"),
        (S::KEY_EXPIRED, "key expired"),
        (S::SIG_EXPIRED, "sig expired"),
        (S::KEY_MISSING, "key missing"),
        (S::CRL_MISSING, "crl missing"),
        (S::CRL_TOO_OLD, "crl too old"),
        (S::BAD_POLICY, "bad policy"),
        (S::SYS_ERROR, "sys error"),
    ] {
        if sigsum.contains(bit) {
            v.push(name);
        }
    }
    if sigsum.is_empty() {
        v.push("(empty)");
    }
    v
}

/// strerror text of a gpgme error (gpgme_strerror)
fn gerr(e: &gpgme::Error) -> String {
    e.description().into_owned()
}

/// the CHECK_ERR/gpg_error exit: log and set ALPM_ERR_GPGME
fn gpg_fail(handle: &Handle, e: &gpgme::Error) -> i32 {
    alpm_log!(handle, LOG_ERROR, "GPGME error: {}\n", gerr(e));
    handle.pm_errno.set(Some(Error::Gpgme));
    -1
}

static GPGME_INIT: AtomicBool = AtomicBool::new(false);

/// init_gpgme: process-global, like the C `static int init` (a second handle reuses the first engine home).
/// 0 on success, -1 on error (pm_errno set).
fn init_gpgme(handle: &Handle) -> i32 {
    if GPGME_INIT.load(Ordering::Relaxed) {
        return 0;
    }
    let gpgdir = handle.gpgdir();
    let sigdir = gpgdir.as_deref();
    if crate::util::access(handle, sigdir, "pubring.gpg", libc::R_OK).is_err()
        || crate::util::access(handle, sigdir, "trustdb.gpg", libc::R_OK).is_err()
    {
        handle.pm_errno.set(Some(Error::NotAFile));
        alpm_log!(handle, LOG_DEBUG, "Signature verification will fail!\n");
        alpm_log!(
            handle,
            LOG_WARNING,
            "Public keyring not found; have you run 'pacman-key --init'?\n"
        );
    }
    let gpg = gpgme::init();
    alpm_log!(handle, LOG_DEBUG, "GPGME version: {}\n", gpg.version());
    // check for OpenPGP support (should be a no-brainer, but be safe)
    if let Err(e) = gpg.check_engine_version(Protocol::OpenPgp) {
        return gpg_fail(handle, &e);
    }
    // set and check engine information
    if let Err(e) = gpg.set_engine_info(Protocol::OpenPgp, None::<&str>, sigdir) {
        return gpg_fail(handle, &e);
    }
    match gpg.engine_info() {
        Ok(info) => {
            if let Some(ei) = info.get(Protocol::OpenPgp) {
                alpm_log!(
                    handle,
                    LOG_DEBUG,
                    "GPGME engine info: file={}, home={}\n",
                    ei.path().unwrap_or(""),
                    ei.home_dir().unwrap_or("")
                );
            }
        }
        Err(e) => return gpg_fail(handle, &e),
    }
    GPGME_INIT.store(true, Ordering::Relaxed);
    0
}

/// _alpm_key_in_keychain: 1 if the key is known, 0 if unknown, -1 on error
pub fn key_in_keychain(handle: &Handle, fpr: &str) -> i32 {
    if handle.known_keys.borrow().iter().any(|k| k == fpr) {
        alpm_log!(handle, LOG_DEBUG, "key {} found in cache\n", fpr);
        return 1;
    }
    if init_gpgme(handle) != 0 {
        // pm_errno was set in init_gpgme
        return -1;
    }
    let Ok(mut ctx) = Context::from_protocol(Protocol::OpenPgp) else {
        return -1;
    };
    alpm_log!(handle, LOG_DEBUG, "looking up key {} locally\n", fpr);
    match ctx.get_key(fpr) {
        Err(e) if e.code() == gpgme::Error::EOF.code() => {
            alpm_log!(handle, LOG_DEBUG, "key lookup failed, unknown key\n");
            0
        }
        Ok(key) => {
            if key.is_expired() {
                alpm_log!(
                    handle,
                    LOG_DEBUG,
                    "key lookup success, but key is expired\n"
                );
                0
            } else {
                alpm_log!(handle, LOG_DEBUG, "key lookup success, key exists\n");
                handle.known_keys.borrow_mut().push(fpr.to_string());
                1
            }
        }
        Err(e) => {
            alpm_log!(handle, LOG_DEBUG, "gpg error: {}\n", gerr(&e));
            -1
        }
    }
}

/// key_import_wkd: 0 on success, -1 on error
fn key_import_wkd(handle: &Handle, email: &str, fpr: &str) -> i32 {
    let Ok(mut ctx) = Context::from_protocol(Protocol::OpenPgp) else {
        return -1;
    };
    let mode = ctx.key_list_mode() | KeyListMode::LOCATE_EXTERNAL;
    if let Err(e) = ctx.set_key_list_mode(mode) {
        alpm_log!(handle, LOG_DEBUG, "gpg error: {}\n", gerr(&e));
        return -1;
    }
    alpm_log!(handle, LOG_DEBUG, "looking up key {} using WKD\n", email);
    match ctx.get_key(email) {
        Ok(_) => {
            // check if correct key was imported via WKD
            if key_in_keychain(handle, fpr) != 0 {
                return 0;
            }
            alpm_log!(
                handle,
                LOG_DEBUG,
                "key lookup failed: WKD imported wrong fingerprint or key expired\n"
            );
            alpm_log!(
                handle,
                LOG_DEBUG,
                "gpg error: {}\n",
                gerr(&gpgme::Error::NO_ERROR)
            );
            -1
        }
        Err(e) => {
            alpm_log!(handle, LOG_DEBUG, "gpg error: {}\n", gerr(&e));
            -1
        }
    }
}

/// key_search_keyserver: Some(key) when found
fn key_search_keyserver(handle: &Handle, fpr: &str) -> Option<PgpKey> {
    // gpg2 needs the 0x prefix for key searches only
    let full_fpr = format!("0x{fpr}");
    let mut ctx = Context::from_protocol(Protocol::OpenPgp).ok()?;
    // using LOCAL and EXTERN together doesn't work for GPG 1.X
    let mode = (ctx.key_list_mode() - KeyListMode::LOCAL) | KeyListMode::EXTERN;
    if let Err(e) = ctx.set_key_list_mode(mode) {
        alpm_log!(handle, LOG_DEBUG, "gpg error: {}\n", gerr(&e));
        return None;
    }
    alpm_log!(handle, LOG_DEBUG, "looking up key {} remotely\n", fpr);
    let eof = |e: &gpgme::Error| e.code() == gpgme::Error::EOF.code();
    let mut res = ctx.get_key(&full_fpr);
    if let Err(e) = &res
        && eof(e)
    {
        alpm_log!(handle, LOG_DEBUG, "key lookup failed, unknown key\n");
        // alternate lookup using the 8 character fingerprint, for keyservers that cannot do subkeys
        if fpr.len() > 8 {
            let short_fpr = format!("0x{}", &fpr[fpr.len() - 8..]);
            alpm_log!(handle, LOG_DEBUG, "looking up key {} remotely\n", short_fpr);
            res = ctx.get_key(&short_fpr);
            if let Err(e) = &res
                && eof(e)
            {
                alpm_log!(handle, LOG_DEBUG, "key lookup failed, unknown key\n");
            }
        }
    }
    let key = match res {
        Ok(k) => k,
        Err(e) => {
            alpm_log!(handle, LOG_DEBUG, "gpg error: {}\n", gerr(&e));
            return None;
        }
    };
    let mut pk = PgpKey::default();
    if let Some(sk) = key.subkeys().next() {
        pk.fingerprint = sk
            .fingerprint()
            .or_else(|_| sk.id())
            .unwrap_or("")
            .to_string();
        pk.created = secs(sk.creation_time());
        pk.expires = secs(sk.expiration_time());
    }
    // we are probably going to fail importing, but continue anyway
    if let Some(u) = key.user_ids().next() {
        pk.uid = u.id().ok().map(str::to_string);
        pk.name = u.name().ok().map(str::to_string);
        pk.email = u.email().ok().map(str::to_string);
    }
    pk.data = Some(key);
    Some(pk)
}

fn secs(t: Option<std::time::SystemTime>) -> i64 {
    t.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64)
}

/// key_import_keyserver: 0 on success, -1 on error
fn key_import_keyserver(handle: &Handle, key: &PgpKey) -> i32 {
    let gpgdir = handle.gpgdir();
    if crate::util::access(handle, gpgdir.as_deref(), "pubring.gpg", libc::W_OK).is_err() {
        // no chance of import succeeding if pubring isn't writable
        alpm_log!(handle, LOG_ERROR, "keyring is not writable\n");
        return -1;
    }
    let Ok(mut ctx) = Context::from_protocol(Protocol::OpenPgp) else {
        return -1;
    };
    alpm_log!(handle, LOG_DEBUG, "importing key\n");
    let Some(k) = key.data.as_ref() else {
        return -1;
    };
    match ctx.import_keys([k]) {
        Err(_) => -1,
        Ok(result) => {
            // we know we tried to import exactly one key, so check for this
            let first = result.imports().next();
            match first {
                Some(imp) if result.considered() == 1 => {
                    if imp.result().is_err() {
                        alpm_log!(
                            handle,
                            LOG_DEBUG,
                            "gpg error: {}\n",
                            gerr(&gpgme::Error::NO_ERROR)
                        );
                        -1
                    } else {
                        0
                    }
                }
                _ => {
                    alpm_log!(handle, LOG_DEBUG, "could not import key, 0 results\n");
                    -1
                }
            }
        }
    }
}

/// email_from_uid
fn email_from_uid(uid: Option<&str>) -> Option<&str> {
    let uid = uid?;
    let start = uid.rfind('<')?;
    let end = start + uid[start..].rfind('>')?;
    Some(&uid[start + 1..end])
}

/// _alpm_key_import: import a key defined by a fingerprint into the local keyring. 0 on success, -1 on error.
pub fn key_import(handle: &Handle, uid: Option<&str>, fpr: &str) -> i32 {
    let mut ret = -1;
    let gpgdir = handle.gpgdir();
    if crate::util::access(handle, gpgdir.as_deref(), "pubring.gpg", libc::W_OK).is_err() {
        // no chance of import succeeding if pubring isn't writable
        alpm_log!(handle, LOG_ERROR, "keyring is not writable\n");
        return -1;
    }
    let mut q = Question::ImportKey {
        import: false,
        uid,
        fingerprint: fpr,
    };
    handle.question(&mut q);
    if matches!(q, Question::ImportKey { import: true, .. }) {
        // Try to import the key from a WKD first
        if let Some(email) = email_from_uid(uid) {
            ret = key_import_wkd(handle, email, fpr);
        }
        // If importing from the WKD fails, fall back to keyserver lookup
        if ret != 0 {
            if let Some(fetch) = key_search_keyserver(handle, fpr) {
                alpm_log!(
                    handle,
                    LOG_DEBUG,
                    "key \"{}\" on keyserver\n",
                    fetch.uid.as_deref().unwrap_or("(null)")
                );
                if key_import_keyserver(handle, &fetch) == 0 {
                    ret = 0;
                } else {
                    alpm_log!(handle, LOG_ERROR, "key \"{}\" could not be imported\n", fpr);
                }
            } else {
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "key \"{}\" could not be looked up remotely\n",
                    fpr
                );
            }
        }
    }
    ret
}

/// _alpm_sigpath
pub fn sigpath(path: &str) -> String {
    format!("{path}.sig")
}

/// _alpm_gpgme_checksig: check the detached signature of `path` (from `base64_sig`, else `path.sig`).
/// 0 in normal cases (a bad signature is reported in `siglist`), -1 with pm_errno set when the check failed.
pub fn gpgme_checksig(
    handle: &Handle,
    path: &str,
    base64_sig: Option<&str>,
    siglist: &mut SigList,
) -> i32 {
    macro_rules! err {
        ($e:expr) => {{
            handle.pm_errno.set(Some($e));
            return -1;
        }};
    }
    if crate::util::access(handle, None, path, libc::R_OK).is_err() {
        err!(Error::NotAFile);
    }
    siglist.clear();
    let mut sigfile = None;
    if base64_sig.is_none() {
        let sp = sigpath(path);
        match crate::util::access(handle, None, &sp, libc::R_OK)
            .ok()
            .and_then(|_| File::open(&sp).ok())
        {
            Some(f) => sigfile = Some(f),
            None => {
                alpm_log!(handle, LOG_DEBUG, "sig path {} could not be opened\n", sp);
                err!(Error::SigMissing);
            }
        }
    }
    // does the file we are verifying exist?
    let Ok(file) = File::open(path) else {
        err!(Error::NotAFile);
    };
    if init_gpgme(handle) != 0 {
        // pm_errno was set in init_gpgme
        return -1;
    }
    alpm_log!(handle, LOG_DEBUG, "checking signature for {}\n", path);
    let mut ctx = match Context::from_protocol(Protocol::OpenPgp) {
        Ok(c) => c,
        Err(e) => return gpg_fail(handle, &e),
    };
    // data object for the signature
    let sigdata: Vec<u8>;
    let verify = match (base64_sig, sigfile) {
        (Some(b64), _) => {
            // memory-based, we loaded it from a sync DB
            match decode_signature(b64) {
                Some(d) => sigdata = d,
                None => err!(Error::SigInvalid),
            }
            ctx.verify_detached(&sigdata, &file)
        }
        // file-based, it is on disk
        (None, Some(sf)) => ctx.verify_detached(&sf, &file),
        (None, None) => unreachable!(),
    };
    // here's where the magic happens
    let result = match verify {
        Ok(r) => r,
        Err(e) => return gpg_fail(handle, &e),
    };
    let sigs: Vec<_> = result.signatures().collect();
    if sigs.is_empty() {
        alpm_log!(handle, LOG_DEBUG, "no signatures returned\n");
        err!(Error::SigMissing);
    }
    alpm_log!(handle, LOG_DEBUG, "{} signatures returned\n", sigs.len());
    for gpgsig in &sigs {
        let fpr = gpgsig.fingerprint().unwrap_or("").to_string();
        alpm_log!(handle, LOG_DEBUG, "fingerprint: {}\n", fpr);
        for s in list_sigsum(gpgsig.summary()) {
            alpm_log!(handle, LOG_DEBUG, "summary: {}\n", s);
        }
        let st = gpgsig.status();
        let st_desc = match &st {
            Ok(()) => gerr(&gpgme::Error::NO_ERROR),
            Err(e) => gerr(e),
        };
        alpm_log!(handle, LOG_DEBUG, "status: {}\n", st_desc);
        let ts = secs(gpgsig.creation_time());
        alpm_log!(handle, LOG_DEBUG, "timestamp: {}\n", ts);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        if ts > now {
            alpm_log!(
                handle,
                LOG_DEBUG,
                "signature timestamp is greater than system time.\n"
            );
        }
        alpm_log!(
            handle,
            LOG_DEBUG,
            "exp_timestamp: {}\n",
            secs(gpgsig.expiration_time())
        );
        alpm_log!(
            handle,
            LOG_DEBUG,
            "validity: {}; reason: {}\n",
            string_validity(gpgsig.validity()),
            gerr(
                &gpgsig
                    .nonvalidity_reason()
                    .unwrap_or(gpgme::Error::NO_ERROR)
            )
        );

        let mut key = PgpKey::default();
        let mut disabled = false;
        match ctx.get_key(fpr.as_str()) {
            Err(e) if e.code() == gpgme::Error::EOF.code() => {
                alpm_log!(handle, LOG_DEBUG, "key lookup failed, unknown key\n");
                // we have no key to point at, keep the fingerprint
                key.fingerprint = fpr.clone();
            }
            Err(e) => return gpg_fail(handle, &e),
            Ok(k) => {
                if let Some(u) = k.user_ids().next() {
                    let sk = k.subkeys().next();
                    key.fingerprint = sk
                        .as_ref()
                        .and_then(|s| s.fingerprint().ok())
                        .unwrap_or("")
                        .to_string();
                    key.uid = u.id().ok().map(str::to_string);
                    key.name = u.name().ok().map(str::to_string);
                    key.email = u.email().ok().map(str::to_string);
                    key.created = sk.as_ref().map_or(0, |s| secs(s.creation_time()));
                    key.expires = sk.as_ref().map_or(0, |s| secs(s.expiration_time()));
                    alpm_log!(
                        handle,
                        LOG_DEBUG,
                        "key: {}, {}, owner_trust {}, disabled {}\n",
                        key.fingerprint,
                        key.uid.as_deref().unwrap_or(""),
                        string_validity(k.owner_trust()),
                        k.is_disabled() as i32
                    );
                    disabled = k.is_disabled();
                    key.data = Some(k);
                } else {
                    key.fingerprint = fpr.clone();
                }
            }
        }
        let mut status = match st {
            Ok(()) => SigStatus::Valid,
            Err(e) if e.code() == gpgme::Error::KEY_EXPIRED.code() => SigStatus::KeyExpired,
            Err(e) if e.code() == gpgme::Error::SIG_EXPIRED.code() => SigStatus::SigExpired,
            Err(e) if e.code() == gpgme::Error::NO_PUBKEY.code() => SigStatus::KeyUnknown,
            Err(_) => SigStatus::Invalid,
        };
        // special case: key disabled is not returned in above status code
        if key.data.is_some() && disabled {
            status = SigStatus::KeyDisabled;
        }
        let validity = match gpgsig.validity() {
            Validity::Ultimate | Validity::Full => SigValidity::Full,
            Validity::Marginal => SigValidity::Marginal,
            Validity::Never => SigValidity::Never,
            _ => SigValidity::Unknown,
        };
        siglist.push(SigResult {
            key,
            status,
            validity,
        });
    }
    0
}

/// _alpm_check_pgp_helper: check the signature and apply the optional/marginal/unknown policy.
/// Returns 0 on success, -1 on error (consult pm_errno or the returned list).
pub fn check_pgp_helper(
    handle: &Handle,
    path: &str,
    base64_sig: Option<&str>,
    optional: bool,
    marginal: bool,
    unknown: bool,
) -> (i32, SigList) {
    let mut siglist = SigList::new();
    let mut ret = gpgme_checksig(handle, path, base64_sig, &mut siglist);
    if ret != 0 && handle.errno() == Some(Error::SigMissing) {
        if optional {
            alpm_log!(handle, LOG_DEBUG, "missing optional signature\n");
            handle.pm_errno.set(None);
            ret = 0;
        } else {
            alpm_log!(handle, LOG_DEBUG, "missing required signature\n");
        }
    } else if ret != 0 {
        alpm_log!(handle, LOG_DEBUG, "signature check failed\n");
    } else {
        for r in &siglist {
            if ret != 0 {
                break;
            }
            match r.status {
                SigStatus::Valid | SigStatus::KeyExpired => {
                    alpm_log!(handle, LOG_DEBUG, "signature is valid\n");
                    match r.validity {
                        SigValidity::Full => {
                            alpm_log!(handle, LOG_DEBUG, "signature is fully trusted\n")
                        }
                        SigValidity::Marginal => {
                            alpm_log!(handle, LOG_DEBUG, "signature is marginal trust\n");
                            if !marginal {
                                ret = -1;
                            }
                        }
                        SigValidity::Unknown => {
                            alpm_log!(handle, LOG_DEBUG, "signature is unknown trust\n");
                            if !unknown {
                                ret = -1;
                            }
                        }
                        SigValidity::Never => {
                            alpm_log!(handle, LOG_DEBUG, "signature should never be trusted\n");
                            ret = -1;
                        }
                    }
                }
                SigStatus::SigExpired
                | SigStatus::KeyUnknown
                | SigStatus::KeyDisabled
                | SigStatus::Invalid => {
                    alpm_log!(handle, LOG_DEBUG, "signature is not valid\n");
                    ret = -1;
                }
            }
        }
    }
    (ret, siglist)
}

/// _alpm_process_siglist: log what is wrong with each result and try to import missing keys.
/// Returns true when a key was imported and the validation should be retried.
pub fn process_siglist(
    handle: &Handle,
    identifier: &str,
    siglist: &SigList,
    optional: bool,
    marginal: bool,
    unknown: bool,
) -> bool {
    let mut retry = false;
    if !optional && siglist.is_empty() {
        alpm_log!(
            handle,
            LOG_ERROR,
            "{}: missing required signature\n",
            identifier
        );
    }
    for result in siglist {
        let name = result.key.uid.as_deref().unwrap_or(&result.key.fingerprint);
        match result.status {
            SigStatus::Valid => match result.validity {
                SigValidity::Full => {}
                SigValidity::Marginal => {
                    if !marginal {
                        alpm_log!(
                            handle,
                            LOG_ERROR,
                            "{}: signature from \"{}\" is marginal trust\n",
                            identifier,
                            name
                        );
                    }
                }
                SigValidity::Unknown => {
                    if !unknown {
                        alpm_log!(
                            handle,
                            LOG_ERROR,
                            "{}: signature from \"{}\" is unknown trust\n",
                            identifier,
                            name
                        );
                    }
                }
                SigValidity::Never => {
                    alpm_log!(
                        handle,
                        LOG_ERROR,
                        "{}: signature from \"{}\" should never be trusted\n",
                        identifier,
                        name
                    );
                }
            },
            SigStatus::KeyExpired => {
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "{}: signature from \"{}\" is expired\n",
                    identifier,
                    name
                );
                if key_import(handle, result.key.uid.as_deref(), &result.key.fingerprint) == 0 {
                    retry = true;
                }
            }
            SigStatus::KeyUnknown => {
                // ensure this key is still actually unknown; we may have imported it on an earlier call
                if key_in_keychain(handle, &result.key.fingerprint) == 1 {
                    continue;
                }
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "{}: key \"{}\" is unknown\n",
                    identifier,
                    name
                );
                if key_import(handle, result.key.uid.as_deref(), &result.key.fingerprint) == 0 {
                    retry = true;
                }
            }
            SigStatus::KeyDisabled => {
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "{}: key \"{}\" is disabled\n",
                    identifier,
                    name
                );
            }
            SigStatus::SigExpired => {
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "{}: signature from \"{}\" is expired\n",
                    identifier,
                    name
                );
            }
            SigStatus::Invalid => {
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "{}: signature from \"{}\" is invalid\n",
                    identifier,
                    name
                );
            }
        }
    }
    retry
}

/// alpm_pkg_check_pgp_signature: Err carries pm_errno
pub fn pkg_check_pgp_signature(pkg: &Pkg) -> Result<SigList, Error> {
    pkg.handle.pm_errno.set(None);
    let mut siglist = SigList::new();
    let path = pkg.filename.as_deref().unwrap_or("");
    sig_result(
        &pkg.handle,
        gpgme_checksig(&pkg.handle, path, pkg.base64_sig.as_deref(), &mut siglist),
        siglist,
    )
}

/// alpm_db_check_pgp_signature
pub fn db_check_pgp_signature(db: &Db) -> Result<SigList, Error> {
    db.handle.pm_errno.set(None);
    let mut siglist = SigList::new();
    sig_result(
        &db.handle,
        gpgme_checksig(&db.handle, db.path(), None, &mut siglist),
        siglist,
    )
}

fn sig_result(handle: &Handle, ret: i32, siglist: SigList) -> Result<SigList, Error> {
    if ret == 0 {
        Ok(siglist)
    } else {
        Err(handle.errno().unwrap_or(Error::Gpgme))
    }
}

/// alpm_pkg_get_sig: the raw signature of a package (from the database entry or the cached `.sig` file)
pub fn pkg_get_sig(pkg: &Pkg) -> Result<Vec<u8>, Error> {
    let handle = &pkg.handle;
    if let Some(b64) = &pkg.base64_sig {
        return match decode_signature(b64) {
            Some(s) => Ok(s),
            None => handle.err(Error::SigInvalid),
        };
    }
    let Some(pkgpath) = crate::util::filecache_find(handle, pkg.filename.as_deref().unwrap_or("")) else {
        return handle.err(Error::PkgNotFound);
    };
    let sp = sigpath(&pkgpath);
    if crate::util::access(handle, None, &sp, libc::R_OK).is_err() {
        return handle.err(Error::SigMissing);
    }
    match std::fs::read(&sp) {
        Ok(d) => {
            alpm_log!(
                handle,
                LOG_DEBUG,
                "found detached signature {} with size {}\n",
                sp,
                d.len()
            );
            Ok(d)
        }
        Err(e) => handle.err(match e.raw_os_error() {
            Some(libc::EACCES) => Error::Badperms,
            Some(libc::ENOENT) => Error::NotAFile,
            _ => Error::System,
        }),
    }
}
