//! The libarchive-facing parts of lib/libalpm/util.c: `_alpm_open_archive` (filters picked by magic bytes
//! like libarchive's `read_support_filter_all`) and `_alpm_archive_fgets`. Tar is the only format
//! (everything pacman packages and databases use); other formats read as "Unrecognized archive format".
//! Supported filters: none, gzip, bzip2, xz, zstd, lz4. Others (lzma-alone, lzip, lrzip, compress, uu) are
//! not detected and so surface as an unrecognized format.
use crate::alpm_log;
use crate::error::Error;
use crate::handle::Handle;
use crate::log::LOG_ERROR;
use crate::util::strerror;
use std::io::{BufRead, BufReader, Read};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    None,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Lz4,
}

/// Failure of `open_archive`: the pm_errno value and the underlying errno (ENOENT, EACCES, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenError {
    pub err: Error,
    pub errno: Option<i32>,
}

pub struct Archive {
    pub filter: Filter,
    /// st_size of the file
    pub size: u64,
    inner: tar::Archive<Box<dyn Read>>,
}

impl Archive {
    /// archive_read_next_header loop
    pub fn entries(&mut self) -> std::io::Result<tar::Entries<'_, Box<dyn Read>>> {
        self.inner.entries()
    }
}

/// Detect the compression filter from the leading bytes (libarchive's bidders).
fn detect(b: &[u8]) -> Filter {
    if b.starts_with(&[0x1f, 0x8b, 0x08]) {
        Filter::Gzip
    } else if b.len() >= 4 && &b[..3] == b"BZh" && (b'1'..=b'9').contains(&b[3]) {
        Filter::Bzip2
    } else if b.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Filter::Xz
    } else if b.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])
        || (b.len() >= 4 && b[0] & 0xf0 == 0x50 && b[1..4] == [0x2a, 0x4d, 0x18])
    {
        Filter::Zstd
    } else if b.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        Filter::Lz4
    } else {
        Filter::None
    }
}

fn wrap_filter<R: BufRead + 'static>(filter: Filter, br: R) -> std::io::Result<Box<dyn Read>> {
    Ok(match filter {
        Filter::None => Box::new(br),
        Filter::Gzip => Box::new(flate2::bufread::MultiGzDecoder::new(br)),
        Filter::Bzip2 => Box::new(bzip2::bufread::MultiBzDecoder::new(br)),
        Filter::Xz => Box::new(liblzma::bufread::XzDecoder::new_multi_decoder(br)),
        Filter::Zstd => Box::new(zstd::stream::read::Decoder::with_buffer(br)?),
        Filter::Lz4 => Box::new(lz4_flex::frame::FrameDecoder::new(br)),
    })
}

/// archive_read_support_filter_all on an in-memory buffer: decompress by magic bytes.
pub fn decompress_bytes(data: Vec<u8>) -> std::io::Result<Vec<u8>> {
    let filter = detect(&data);
    let mut out = Vec::new();
    wrap_filter(filter, std::io::Cursor::new(data))?.read_to_end(&mut out)?;
    Ok(out)
}

/// _alpm_open_archive: on failure logs like upstream and records `error` in pm_errno.
pub fn open_archive(handle: &Handle, path: &str, error: Error) -> Result<Archive, OpenError> {
    alpm_log!(handle, crate::log::LOG_DEBUG, "opening archive {}\n", path);
    let fail = |what: &str, e: &std::io::Error| -> Result<Archive, OpenError> {
        alpm_log!(
            handle,
            LOG_ERROR,
            "could not {} file {}: {}\n",
            what,
            path,
            strerror(e)
        );
        let _ = handle.err::<()>(error);
        Err(OpenError {
            err: error,
            errno: e.raw_os_error(),
        })
    };
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return fail("open", &e),
    };
    let size = match f.metadata() {
        Ok(m) => m.len(),
        Err(e) => return fail("stat", &e),
    };
    let mut br = BufReader::with_capacity(128 * 1024, f);
    let head = match br.fill_buf() {
        Ok(h) => h,
        Err(e) => return fail("open", &e),
    };
    let filter = detect(head);
    let r = match wrap_filter(filter, br) {
        Ok(r) => r,
        Err(e) => return fail("open", &e),
    };
    Ok(Archive {
        filter,
        size,
        inner: tar::Archive::new(r),
    })
}

/// struct archive_read_buffer + _alpm_archive_fgets over one entry's data.
pub struct ArchiveLines {
    data: Vec<u8>,
    pos: usize,
    max_line_size: usize,
    /// the end-of-data empty line (or an unterminated last line) has been returned
    tail_done: bool,
}

/// Result of one `_alpm_archive_fgets` call.
pub enum Fgets<'a> {
    /// ARCHIVE_OK with the line (cut at a NUL like a C string)
    Line(&'a [u8]),
    /// ARCHIVE_EOF
    Eof,
    /// any other return (line longer than max_line_size)
    Err,
}

impl ArchiveLines {
    pub fn new(data: Vec<u8>) -> Self {
        // 512K for a line length seems reasonable
        ArchiveLines {
            data,
            pos: 0,
            max_line_size: 512 * 1024,
            tail_done: false,
        }
    }

    /// _alpm_archive_fgets: lines end at '\n', or at NUL when no newline remains.
    pub fn fgets(&mut self) -> Fgets<'_> {
        if self.pos >= self.data.len() {
            // upstream returns one more (empty) line when the data ended with a terminator or was empty
            if self.tail_done {
                return Fgets::Eof;
            }
            self.tail_done = true;
            return Fgets::Line(b"");
        }
        let rest = &self.data[self.pos..];
        let (len, adv) = match rest.iter().position(|&c| c == b'\n') {
            Some(p) => (p, p + 1),
            None => match rest.iter().position(|&c| c == 0) {
                Some(p) => (p, p + 1),
                None => {
                    self.tail_done = true; // unterminated last line, then EOF
                    (rest.len(), rest.len())
                }
            },
        };
        if len + 1 > self.max_line_size {
            return Fgets::Err;
        }
        let line = &rest[..len];
        self.pos += adv;
        let cut = line.iter().position(|&c| c == 0).unwrap_or(line.len());
        Fgets::Line(&line[..cut])
    }
}

/// A parsed mtree entry (what libarchive's mtree reader exposes to build_filelist_from_mtree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtreeEntry {
    pub path: String,
    /// file type bits of st_mode (S_IFDIR, S_IFREG, ...)
    pub filetype: u32,
    pub size: i64,
    /// full mode: type bits | permission bits
    pub mode: u32,
}

pub const AE_IFDIR: u32 = 0o040000;
pub const AE_IFREG: u32 = 0o100000;

/// Decode mtree `\ooo` and C-style escapes in a path (libarchive parse_escapes).
fn mtree_unescape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'\\' && i + 1 < s.len() {
            let c = s[i + 1];
            let simple = match c {
                b'a' => Some(7),
                b'b' => Some(8),
                b'f' => Some(12),
                b'n' => Some(b'\n'),
                b'r' => Some(b'\r'),
                b't' => Some(b'\t'),
                b'v' => Some(11),
                b'\\' => Some(b'\\'),
                _ => None,
            };
            if let Some(v) = simple {
                out.push(v);
                i += 2;
                continue;
            }
            if (b'0'..=b'3').contains(&c)
                && i + 3 < s.len()
                && (b'0'..=b'7').contains(&s[i + 2])
                && (b'0'..=b'7').contains(&s[i + 3])
            {
                out.push(((c - b'0') << 6) | ((s[i + 2] - b'0') << 3) | (s[i + 3] - b'0'));
                i += 4;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// Read an mtree specification (full-path form, as written by bsdtar/makepkg): `#` comments, `/set`
/// and `/unset`, then `path keyword=value...` lines.
/// shortcut: the relative form (`..`, directory-relative names) is not supported.
pub fn read_mtree(data: &[u8]) -> Result<Vec<MtreeEntry>, String> {
    use std::collections::BTreeMap;
    let text = String::from_utf8_lossy(data);
    let mut set: BTreeMap<String, String> = BTreeMap::new();
    let mut out = Vec::new();
    let mut seen_any = false;
    for raw in text.lines() {
        let line = raw.trim_start_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            seen_any |= line.starts_with("#mtree");
            continue;
        }
        let mut words = line.split([' ', '\t']).filter(|w| !w.is_empty());
        let first = words.next().unwrap();
        if first == "/set" {
            for w in words {
                if let Some((k, v)) = w.split_once('=') {
                    set.insert(k.to_string(), v.to_string());
                }
            }
            seen_any = true;
            continue;
        }
        if first == "/unset" {
            for w in words {
                if w == "all" {
                    set.clear();
                } else {
                    set.remove(w);
                }
            }
            seen_any = true;
            continue;
        }
        let mut kw = set.clone();
        for w in words {
            match w.split_once('=') {
                Some((k, v)) => {
                    kw.insert(k.to_string(), v.to_string());
                }
                None => {
                    kw.insert(w.to_string(), String::new());
                }
            }
        }
        if !seen_any && !line.contains('=') {
            return Err("Unrecognized archive format".into());
        }
        seen_any = true;
        let filetype = match kw.get("type").map(String::as_str) {
            Some("dir") => AE_IFDIR,
            Some("link") => 0o120000,
            Some("block") => 0o060000,
            Some("char") => 0o020000,
            Some("fifo") => 0o010000,
            Some("socket") => 0o140000,
            _ => AE_IFREG,
        };
        let perm = kw
            .get("mode")
            .and_then(|m| u32::from_str_radix(m.trim_start_matches("0o"), 8).ok())
            .unwrap_or(0);
        let size = kw
            .get("size")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        out.push(MtreeEntry {
            path: String::from_utf8_lossy(&mtree_unescape(first.as_bytes())).into_owned(),
            filetype,
            size,
            mode: filetype | (perm & 0o7777),
        });
    }
    Ok(out)
}
