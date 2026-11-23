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

/// _alpm_open_archive: on failure logs like upstream and records `error` in pm_errno.
pub fn open_archive(handle: &Handle, path: &str, error: Error) -> Result<Archive, Error> {
    alpm_log!(handle, crate::log::LOG_DEBUG, "opening archive {}\n", path);
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            alpm_log!(
                handle,
                LOG_ERROR,
                "could not open file {}: {}\n",
                path,
                strerror(&e)
            );
            return handle.err(error);
        }
    };
    let size = match f.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            alpm_log!(
                handle,
                LOG_ERROR,
                "could not stat file {}: {}\n",
                path,
                strerror(&e)
            );
            return handle.err(error);
        }
    };
    let mut br = BufReader::with_capacity(128 * 1024, f);
    let head = match br.fill_buf() {
        Ok(h) => h,
        Err(e) => {
            alpm_log!(
                handle,
                LOG_ERROR,
                "could not open file {}: {}\n",
                path,
                strerror(&e)
            );
            return handle.err(error);
        }
    };
    let filter = detect(head);
    let r: Box<dyn Read> = match filter {
        Filter::None => Box::new(br),
        Filter::Gzip => Box::new(flate2::bufread::MultiGzDecoder::new(br)),
        Filter::Bzip2 => Box::new(bzip2::bufread::MultiBzDecoder::new(br)),
        Filter::Xz => Box::new(liblzma::bufread::XzDecoder::new_multi_decoder(br)),
        Filter::Zstd => match zstd::stream::read::Decoder::with_buffer(br) {
            Ok(d) => Box::new(d),
            Err(e) => {
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "could not open file {}: {}\n",
                    path,
                    strerror(&e)
                );
                return handle.err(error);
            }
        },
        Filter::Lz4 => Box::new(lz4_flex::frame::FrameDecoder::new(br)),
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
