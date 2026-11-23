//! Port of src/util/util-common.c (the pieces ported so far). Strings are `String`; invalid UTF-8 in
//! config files is converted lossily (shortcut: paths with non-UTF-8 bytes are not preserved).

/// C-locale isspace.
pub fn c_isspace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
}

/// strtrim: trim whitespace and newlines.
pub fn strtrim(s: &str) -> &str {
    s.trim_matches(c_isspace)
}

/// strerror text of an io::Error (without Rust's " (os error N)" suffix).
pub fn strerror(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.find(" (os error ") {
        Some(p) => s[..p].to_string(),
        None => s,
    }
}

/// wordsplit: split on whitespace honouring quotes; None on unbalanced quotes.
pub fn wordsplit(s: &str) -> Option<Vec<String>> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut c = 0;
    while c < b.len() && c_isspace(b[c] as char) {
        c += 1;
    }
    while c < b.len() {
        let mut word = Vec::new();
        let mut end = c;
        while end < b.len() && !c_isspace(b[end] as char) {
            if b[end] == b'\'' || b[end] == b'"' {
                let quote = b[end];
                end += 1;
                while end < b.len() && b[end] != quote {
                    if b[end] == b'\\' && b.get(end + 1) == Some(&quote) {
                        end += 1;
                    }
                    word.push(b[end]);
                    end += 1;
                }
                if end >= b.len() {
                    return None;
                }
            } else {
                if b[end] == b'\\' && matches!(b.get(end + 1), Some(b'\'' | b'"')) {
                    end += 1;
                }
                word.push(b[end]);
            }
            end += 1;
        }
        out.push(String::from_utf8_lossy(&word).into_owned());
        if end >= b.len() {
            break;
        }
        c = end + 1;
        while c < b.len() && c_isspace(b[c] as char) {
            c += 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_and_split() {
        assert_eq!(strtrim(" \t a b \n\x0b"), "a b");
        assert_eq!(
            wordsplit(" a 'b c' d\\\"e \"f\\\"g\" ").unwrap(),
            ["a", "b c", "d\"e", "f\"g"]
        );
        assert!(wordsplit("a 'b").is_none());
        assert_eq!(wordsplit("").unwrap().len(), 0);
    }
}
