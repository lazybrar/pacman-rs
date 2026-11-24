//! Port of the helpers from lib/libalpm/util.c used so far. Strings from DB files are converted lossily
//! to UTF-8 (shortcut: names/descriptions with invalid UTF-8 are not preserved).

/// Emulation of a C `FILE*` read with safe_fgets()/feof(): the whole file is read up front.
pub struct CFile {
    data: Vec<u8>,
    pos: usize,
    pub eof: bool,
    /// the "file" opened but reading fails (a directory)
    read_error: bool,
}

impl CFile {
    /// fopen(path, "r")
    pub fn open(path: &str) -> std::io::Result<CFile> {
        match std::fs::read(path) {
            Ok(data) => Ok(CFile {
                data,
                pos: 0,
                eof: false,
                read_error: false,
            }),
            Err(e) if e.raw_os_error() == Some(libc::EISDIR) => Ok(CFile {
                data: Vec::new(),
                pos: 0,
                eof: false,
                read_error: true,
            }),
            Err(e) => Err(e),
        }
    }

    /// safe_fgets(line, size, fp): on NULL the buffer `line` is left untouched (like C).
    pub fn fgets(&mut self, line: &mut Vec<u8>, size: usize) -> bool {
        if self.read_error {
            return false;
        }
        if self.pos >= self.data.len() {
            self.eof = true;
            return false;
        }
        let lim = (self.pos + size - 1).min(self.data.len());
        let mut end = lim;
        let mut hit_nl = false;
        if let Some(p) = self.data[self.pos..lim].iter().position(|&c| c == b'\n') {
            end = self.pos + p + 1;
            hit_nl = true;
        }
        if !hit_nl && end == self.data.len() && end - self.pos < size - 1 {
            self.eof = true;
        }
        let mut chunk = &self.data[self.pos..end];
        self.pos = end;
        if let Some(n) = chunk.iter().position(|&c| c == 0) {
            chunk = &chunk[..n];
        }
        line.clear();
        line.extend_from_slice(chunk);
        true
    }
}

/// _alpm_strip_newline: returns the new length.
pub fn strip_newline(s: &mut Vec<u8>) -> usize {
    while s.last() == Some(&b'\n') {
        s.pop();
    }
    s.len()
}

pub fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// _alpm_hash_sdbm (chars are signed like on x86 glibc)
pub fn hash_sdbm(s: &str) -> u64 {
    s.bytes().fold(0u64, |h, c| {
        (c as i8 as i64 as u64).wrapping_add(h.wrapping_mul(65599))
    })
}

/// _alpm_splitname: "name-ver-rel[/...]" -> (name, version, name_hash)
pub fn splitname(target: &str) -> Option<(String, String, u64)> {
    let end = target.find('/').unwrap_or(target.len());
    let t = &target.as_bytes()[..end];
    let p1 = t.iter().rposition(|&c| c == b'-')?;
    let p2 = t[..p1].iter().rposition(|&c| c == b'-')?;
    if p2 == 0 {
        return None;
    }
    let name = lossy(&t[..p2]);
    let h = hash_sdbm(&name);
    Some((name, lossy(&t[p2 + 1..]), h))
}

/// C strtoll(base 10) on bytes: (value, bytes consumed, ERANGE).
fn strtoll(b: &[u8]) -> (i64, usize, bool) {
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let neg = b.get(i) == Some(&b'-');
    if matches!(b.get(i), Some(b'-' | b'+')) {
        i += 1;
    }
    let ds = i;
    let mut v: i128 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = (v * 10 + (b[i] - b'0') as i128).min(1 << 70);
        i += 1;
    }
    if i == ds {
        return (0, 0, false);
    }
    let v = if neg { -v } else { v };
    match i64::try_from(v) {
        Ok(x) => (x, i, false),
        Err(_) => (if neg { i64::MIN } else { i64::MAX }, i, true),
    }
}

/// _alpm_parsedate: 0 on error.
pub fn parsedate(line: &[u8]) -> i64 {
    let (v, used, erange) = strtoll(line);
    if v == 0 && used == 0 || erange || used != line.len() {
        return 0;
    }
    v
}

/// _alpm_strtoofft: -1 on error.
pub fn strtoofft(line: &[u8]) -> i64 {
    if !line.first().is_some_and(u8::is_ascii_digit) {
        return -1;
    }
    let n = line.iter().take_while(|c| c.is_ascii_digit()).count();
    if n != line.len() {
        return -1;
    }
    let mut v: u128 = 0;
    for &c in line {
        v = (v * 10 + (c - b'0') as u128).min(1 << 70);
    }
    if v >= u64::MAX as u128 {
        return -1;
    }
    v as u64 as i64
}

/// _alpm_fnmatch(pattern, string): fnmatch(…, 0)
pub fn fnmatch(pattern: &str, string: &str) -> i32 {
    let (Ok(p), Ok(s)) = (
        std::ffi::CString::new(pattern),
        std::ffi::CString::new(string),
    ) else {
        return 1;
    };
    // SAFETY: both are valid NUL-terminated strings.
    unsafe { libc::fnmatch(p.as_ptr(), s.as_ptr(), 0) }
}

/// strerror text of an io::Error (without Rust's " (os error N)" suffix).
pub fn strerror(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.find(" (os error ") {
        Some(p) => s[..p].to_string(),
        None => s,
    }
}

/// _alpm_fnmatch_patterns: last matching pattern wins; 0 match, 1 inverted match, -1 no match
pub fn fnmatch_patterns(patterns: &[String], string: &str) -> i32 {
    for p in patterns.iter().rev() {
        let inverted = p.starts_with('!');
        let pat = if inverted || p.starts_with('\\') {
            &p[1..]
        } else {
            p.as_str()
        };
        if fnmatch(pat, string) == 0 {
            return inverted as i32;
        }
    }
    -1
}

/// hex_representation
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest_file<D: sha2::Digest>(path: &str) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut d = D::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        d.update(&buf[..n]);
    }
    Some(hex(&d.finalize()))
}

/// alpm_compute_md5sum
pub fn compute_md5sum(path: &str) -> Option<String> {
    digest_file::<md5::Md5>(path)
}

/// alpm_compute_sha256sum
pub fn compute_sha256sum(path: &str) -> Option<String> {
    digest_file::<sha2::Sha256>(path)
}

/// _alpm_access: faccessat(AT_SYMLINK_NOFOLLOW) on `dir`+`file`, logging like upstream; Err(errno)
pub fn access(
    handle: &crate::handle::Handle,
    dir: Option<&str>,
    file: &str,
    amode: i32,
) -> Result<(), i32> {
    let path = format!("{}{}", dir.unwrap_or(""), file);
    let Ok(c) = std::ffi::CString::new(path.as_str()) else {
        return Err(libc::ENOENT);
    };
    // SAFETY: valid C string
    let r =
        unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), amode, libc::AT_SYMLINK_NOFOLLOW) };
    if r == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    let s = strerror(&e);
    let what = [
        (libc::R_OK, "is not readable"),
        (libc::W_OK, "is not writable"),
        (libc::X_OK, "is not executable"),
    ];
    for (bit, msg) in what {
        if amode & bit != 0 {
            crate::alpm_log!(
                handle,
                crate::log::LOG_DEBUG,
                "\"{}\" {}: {}\n",
                path,
                msg,
                s
            );
        }
    }
    if amode == libc::F_OK {
        crate::alpm_log!(
            handle,
            crate::log::LOG_DEBUG,
            "\"{}\" does not exist: {}\n",
            path,
            s
        );
    }
    Err(e.raw_os_error().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits() {
        assert_eq!(splitname("pacman-6.0.1-2/desc").unwrap().0, "pacman");
        assert_eq!(splitname("lib-foo-1:2.0-3").unwrap().1, "1:2.0-3");
        assert!(splitname("foo-1").is_none());
        assert!(splitname("-1-2").is_none());
        assert!(splitname("foo").is_none());
    }

    #[test]
    fn numbers() {
        assert_eq!(strtoofft(b"123"), 123);
        assert_eq!(strtoofft(b"-1"), -1);
        assert_eq!(strtoofft(b"12a"), -1);
        assert_eq!(strtoofft(b"18446744073709551615"), -1);
        assert_eq!(parsedate(b"1700000000"), 1700000000);
        assert_eq!(parsedate(b"x"), 0);
        assert_eq!(parsedate(b"12x"), 0);
        assert_eq!(parsedate(b"-5"), -5);
        assert_eq!(parsedate(b"99999999999999999999"), 0);
    }

    #[test]
    fn fgets_semantics() {
        let dir = std::env::temp_dir().join(format!("alpm-cfile-{}", std::process::id()));
        std::fs::write(&dir, "ab\ncd").unwrap();
        let mut f = CFile::open(dir.to_str().unwrap()).unwrap();
        let mut l = Vec::new();
        assert!(f.fgets(&mut l, 1024) && l == b"ab\n" && !f.eof);
        assert!(f.fgets(&mut l, 1024) && l == b"cd" && f.eof);
        assert!(!f.fgets(&mut l, 1024) && l == b"cd");
        let mut f = CFile::open(dir.to_str().unwrap()).unwrap();
        assert!(f.fgets(&mut l, 3) && l == b"ab" && !f.eof);
        assert!(f.fgets(&mut l, 3) && l == b"\n");
        let _ = std::fs::remove_file(dir);
    }
}
