//! Thin glibc wrappers for locale-dependent text handling (mbrtowc/wcwidth/strftime) so that output
//! widths and dates match the C implementation exactly.
use std::os::raw::{c_char, c_int, c_long};

unsafe extern "C" {
    fn mbrtowc(pwc: *mut u32, s: *const c_char, n: usize, ps: *mut [u8; 8]) -> usize;
    fn wcwidth(c: u32) -> c_int;
    fn strftime(s: *mut c_char, max: usize, format: *const c_char, tm: *const libc::tm) -> usize;
    fn localtime_r(t: *const c_long, tm: *mut libc::tm) -> *mut libc::tm;
}

/// setlocale(LC_ALL, "")
pub fn init_locale() {
    // SAFETY: valid NUL-terminated empty string
    unsafe { libc::setlocale(libc::LC_ALL, c"".as_ptr()) };
}

/// One wide character of a multibyte string: the code point and the bytes it came from.
pub struct Wc<'a> {
    pub wc: u32,
    pub bytes: &'a str,
}

/// mbstowcs: convert up to the first invalid sequence (what the C code ends up using on failure).
pub fn mb_chars(s: &str) -> Vec<Wc<'_>> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut state = [0u8; 8];
    while i < b.len() {
        let mut wc = 0u32;
        // SAFETY: pointers are valid for the given length
        let n = unsafe {
            mbrtowc(
                &mut wc,
                b[i..].as_ptr() as *const c_char,
                b.len() - i,
                &mut state,
            )
        };
        if n == usize::MAX || n == usize::MAX - 1 || n == 0 {
            break;
        }
        // slices of a &str may split inside a char only if the locale disagrees with UTF-8; fall back
        // to lossy handling by stopping there
        let Some(sl) = s.get(i..i + n) else { break };
        out.push(Wc { wc, bytes: sl });
        i += n;
    }
    out
}

/// wcwidth
pub fn wc_width(c: u32) -> i32 {
    // SAFETY: plain function of its argument
    unsafe { wcwidth(c) }
}

/// wcswidth over a whole converted string: -1 when a character is not printable
pub fn wcs_width(chars: &[Wc]) -> i32 {
    let mut w = 0;
    for c in chars {
        let cw = wc_width(c.wc);
        if cw < 0 {
            return -1;
        }
        w += cw;
    }
    w
}

/// strftime("%c", localtime(&t)) into a buffer of 50 bytes
pub fn strftime_c(t: i64) -> String {
    // SAFETY: zeroed tm is a valid argument for localtime_r to fill
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let tt = t as c_long;
    unsafe { localtime_r(&tt, &mut tm) };
    let mut buf = [0 as c_char; 50];
    // SAFETY: buffer and format are valid
    let n = unsafe { strftime(buf.as_mut_ptr(), 50, c"%c".as_ptr(), &tm) };
    let bytes: Vec<u8> = buf[..n].iter().map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
