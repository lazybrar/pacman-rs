//! Port of lib/libalpm/version.c. Works on bytes like the C code (C locale ctype).

/// parseEVR: split `[epoch:]version[-release]`.
fn parse_evr(evr: &[u8]) -> (&[u8], &[u8], Option<&[u8]>) {
    let s = evr.iter().take_while(|c| c.is_ascii_digit()).count();
    let se = evr[s..].iter().rposition(|&c| c == b'-').map(|p| p + s);
    let (epoch, vstart): (&[u8], usize) = if evr.get(s) == Some(&b':') {
        (if s == 0 { b"0" } else { &evr[..s] }, s + 1)
    } else {
        (b"0", 0) // different from RPM: always assume 0 epoch
    };
    let version = &evr[vstart..se.unwrap_or(evr.len())];
    (epoch, version, se.map(|p| &evr[p + 1..]))
}

/// rpmvercmp: compare alpha and numeric segments of two versions.
fn rpmvercmp(a: &[u8], b: &[u8]) -> i32 {
    if a == b {
        return 0;
    }
    let (mut one, mut two, mut p1, mut p2) = (0, 0, 0, 0);
    while one < a.len() && two < b.len() {
        while one < a.len() && !a[one].is_ascii_alphanumeric() {
            one += 1;
        }
        while two < b.len() && !b[two].is_ascii_alphanumeric() {
            two += 1;
        }
        if one >= a.len() || two >= b.len() {
            break;
        }
        if one - p1 != two - p2 {
            return if one - p1 < two - p2 { -1 } else { 1 };
        }
        p1 = one;
        p2 = two;
        let isnum = a[p1].is_ascii_digit();
        let kind: fn(&u8) -> bool = if isnum {
            u8::is_ascii_digit
        } else {
            u8::is_ascii_alphabetic
        };
        while p1 < a.len() && kind(&a[p1]) {
            p1 += 1;
        }
        while p2 < b.len() && kind(&b[p2]) {
            p2 += 1;
        }
        let (mut s1, mut s2) = (&a[one..p1], &b[two..p2]);
        if s2.is_empty() {
            return if isnum { 1 } else { -1 };
        }
        if isnum {
            while s1.first() == Some(&b'0') {
                s1 = &s1[1..];
            }
            while s2.first() == Some(&b'0') {
                s2 = &s2[1..];
            }
            if s1.len() != s2.len() {
                return if s1.len() > s2.len() { 1 } else { -1 };
            }
        }
        match s1.cmp(s2) {
            std::cmp::Ordering::Less => return -1,
            std::cmp::Ordering::Greater => return 1,
            _ => {}
        }
        one = p1;
        two = p2;
    }
    if one >= a.len() && two >= b.len() {
        return 0;
    }
    let alpha = |s: &[u8], i: usize| s.get(i).is_some_and(u8::is_ascii_alphabetic);
    if (one >= a.len() && !alpha(b, two)) || alpha(a, one) {
        -1
    } else {
        1
    }
}

/// alpm_pkg_vercmp (NULL handling is expressed by Option).
pub fn pkg_vercmp(a: Option<&[u8]>, b: Option<&[u8]>) -> i32 {
    let (a, b) = match (a, b) {
        (None, None) => return 0,
        (None, _) => return -1,
        (_, None) => return 1,
        (Some(a), Some(b)) => (a, b),
    };
    if a == b {
        return 0;
    }
    let (e1, v1, r1) = parse_evr(a);
    let (e2, v2, r2) = parse_evr(b);
    let mut ret = rpmvercmp(e1, e2);
    if ret == 0 {
        ret = rpmvercmp(v1, v2);
        if ret == 0
            && let (Some(r1), Some(r2)) = (r1, r2)
        {
            ret = rpmvercmp(r1, r2);
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(a: &str, b: &str) -> i32 {
        pkg_vercmp(Some(a.as_bytes()), Some(b.as_bytes()))
    }

    // expectations taken from the system vercmp 7.1.0
    #[test]
    fn upstream_cases() {
        for (a, b, r) in [
            ("1.5.0", "1.5.0", 0),
            ("1.5.1", "1.5.0", 1),
            ("1.5.1", "1.5", 1),
            ("1.5.0-1", "1.5.0-1", 0),
            ("1.5.0-1", "1.5.0-2", -1),
            ("1.5.0-1", "1.5.1-1", -1),
            ("1.5.0-2", "1.5.1-1", -1),
            ("1.5-1", "1.5.b-2", -1),
            ("1.5-1", "1.5.b-1", -1),
            ("1.5.b-1", "1.5.b", 0),
            ("1.5.b-2", "1.5.b-1", 1),
            ("1.5.b-1", "1.5.b-2", -1),
            ("1.5.b", "1.5.b", 0),
            ("1.5.b", "1.5", 1),
            ("1.5", "1.5.b", -1),
            ("1.5.1", "1.5.b", 1),
            ("1.5.b", "1.5.1", -1),
            ("0:1.0", "1.0", 0),
            ("1:1.0", "2.0", 1),
            ("1.0", "1:0.1", -1),
            ("1.0", "0:1.0-1", 0),
            ("1.0a", "1.0alpha", -1),
            ("1.0alpha", "1.0b", -1),
            ("1.0b", "1.0beta", -1),
            ("1.0beta", "1.0rc", -1),
            ("1.0rc", "1.0", -1),
            ("1.0", "1.0.a", -1),
            ("1.0.a", "1.0.1", -1),
            ("1.0.1", "1.0.a", 1),
            ("1.0", "1.0_a", -1),
            ("1..0", "1.0", 1),
            ("1.0", "1..0", -1),
            ("1.0", "1.0.", -1),
            ("1.0.", "1.0", 1),
            ("1..0", "1.0.", 1),
            ("1.0", "1.00", 0),
            ("1.0", "1.01", -1),
        ] {
            assert_eq!(c(a, b), r, "{a} {b}");
        }
        assert_eq!(pkg_vercmp(None, Some(b"1")), -1);
        assert_eq!(pkg_vercmp(Some(b"1"), None), 1);
        assert_eq!(pkg_vercmp(None, None), 0);
    }
}
