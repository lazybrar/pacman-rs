//! Port of the parts of lib/libalpm/signing.c that do not need gpgme: signature decoding and issuer key id
//! extraction. Verification (`_alpm_gpgme_checksig`) is not ported: `pkg_check_pgp_signature` reports a
//! missing signature file like upstream and refuses to verify one that exists.
use crate::alpm_log;
use crate::base64::base64_decode;
use crate::error::Error;
use crate::handle::Handle;
use crate::log::*;
use crate::package::Pkg;

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

/// alpm_pkg_check_pgp_signature for a package file: Err(SigMissing) without a detached signature.
/// shortcut: verification needs gpgme (signing.c); an existing signature is reported as a gpgme error.
pub fn pkg_check_pgp_signature(pkg: &Pkg) -> Result<(), Error> {
    pkg.handle.pm_errno.set(None);
    let path = pkg.filename.as_deref().unwrap_or("");
    if pkg.base64_sig.is_none() {
        let sigpath = format!("{path}.sig");
        if std::fs::File::open(&sigpath).is_err() {
            alpm_log!(
                pkg.handle,
                LOG_DEBUG,
                "sig path {} could not be opened\n",
                sigpath
            );
            return pkg.handle.err(Error::SigMissing);
        }
    }
    alpm_log!(
        pkg.handle,
        LOG_ERROR,
        "signature verification is not implemented yet\n"
    );
    pkg.handle.err(Error::Gpgme)
}
