//! Port of lib/libalpm/base64.c (PolarSSL's decoder, including its leniency about newlines and padding).

const DEC_MAP: [u8; 128] = {
    let mut m = [127u8; 128];
    let mut i = 0;
    while i < 26 {
        m[(b'A' + i) as usize] = i;
        m[(b'a' + i) as usize] = 26 + i;
        i += 1;
    }
    let mut d = 0;
    while d < 10 {
        m[(b'0' + d) as usize] = 52 + d;
        d += 1;
    }
    m[b'+' as usize] = 62;
    m[b'/' as usize] = 63;
    m[b'=' as usize] = 64;
    m
};

/// base64_decode: None on an invalid character
pub fn base64_decode(src: &[u8]) -> Option<Vec<u8>> {
    let slen = src.len();
    let (mut j, mut n) = (0u32, 0usize);
    let mut i = 0;
    while i < slen {
        if slen - i >= 2 && src[i] == b'\r' && src[i + 1] == b'\n' {
            i += 1;
            continue;
        }
        if src[i] == b'\n' {
            i += 1;
            continue;
        }
        if src[i] == b'=' {
            j += 1;
            if j > 2 {
                return None;
            }
        }
        if src[i] > 127 || DEC_MAP[src[i] as usize] == 127 {
            return None;
        }
        if DEC_MAP[src[i] as usize] < 64 && j != 0 {
            return None;
        }
        n += 1;
        i += 1;
    }
    if n == 0 {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity((n * 6 + 7) >> 3);
    let (mut j, mut n, mut x) = (3u32, 0u32, 0u32);
    for &c in src {
        if c == b'\r' || c == b'\n' {
            continue;
        }
        if DEC_MAP[c as usize] == 64 {
            j = j.wrapping_sub(1);
        }
        x = (x << 6) | (DEC_MAP[c as usize] & 0x3f) as u32;
        n += 1;
        if n == 4 {
            n = 0;
            if j > 0 {
                out.push((x >> 16) as u8);
            }
            if j > 1 {
                out.push((x >> 8) as u8);
            }
            if j > 2 {
                out.push(x as u8);
            }
        }
    }
    Some(out)
}
