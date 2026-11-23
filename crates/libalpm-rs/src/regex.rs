//! POSIX regcomp/regexec through glibc (the Rust regex crate has different semantics).
//! The `regex_t` layout is glibc x86_64's (64 bytes, 8-byte aligned).
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

#[repr(C, align(8))]
struct RegexT([u8; 64]);

const REG_EXTENDED: c_int = 1;
const REG_ICASE: c_int = 2;
const REG_NEWLINE: c_int = 4;
const REG_NOSUB: c_int = 8;

unsafe extern "C" {
    fn regcomp(preg: *mut RegexT, pattern: *const c_char, cflags: c_int) -> c_int;
    fn regexec(
        preg: *const RegexT,
        string: *const c_char,
        nmatch: usize,
        pmatch: *mut u8,
        eflags: c_int,
    ) -> c_int;
    fn regfree(preg: *mut RegexT);
}

pub struct Regex {
    re: Box<RegexT>,
}

impl Regex {
    /// regcomp(REG_EXTENDED | REG_NOSUB | REG_ICASE | REG_NEWLINE): the flags alpm_db_search uses.
    pub fn new_ere_icase(pattern: &str) -> Option<Regex> {
        Self::new(pattern, REG_EXTENDED | REG_NOSUB | REG_ICASE | REG_NEWLINE)
    }

    /// regcomp(REG_EXTENDED | REG_NOSUB | REG_NEWLINE): the flags the files database search uses.
    pub fn new_ere(pattern: &str) -> Option<Regex> {
        Self::new(pattern, REG_EXTENDED | REG_NOSUB | REG_NEWLINE)
    }

    fn new(pattern: &str, flags: c_int) -> Option<Regex> {
        let c = CString::new(pattern).ok()?;
        let mut re = Box::new(RegexT([0; 64]));
        // SAFETY: re points to a writable regex_t-sized buffer; c is NUL-terminated.
        let r = unsafe { regcomp(&mut *re, c.as_ptr(), flags) };
        if r != 0 {
            return None;
        }
        Some(Regex { re })
    }

    /// regexec(&reg, s, 0, 0, 0) == 0
    pub fn is_match(&self, s: &str) -> bool {
        let Ok(c) = CString::new(s) else { return false };
        // SAFETY: valid compiled regex and C string.
        unsafe { regexec(&*self.re, c.as_ptr(), 0, std::ptr::null_mut(), 0) == 0 }
    }
}

impl Drop for Regex {
    fn drop(&mut self) {
        // SAFETY: compiled by regcomp
        unsafe { regfree(&mut *self.re) }
    }
}
