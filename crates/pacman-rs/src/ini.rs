//! Port of src/common/ini.c.
use crate::util_common::strtrim;

pub enum Event<'a> {
    /// cb(file, 0, NULL, NULL, NULL): fopen failed
    OpenFailed(std::io::Error),
    /// cb(file, linenum, name, NULL, NULL)
    Section(&'a str),
    /// cb(file, linenum, section_name, key, value); value None when there is no '='
    Directive {
        section: Option<&'a str>,
        key: &'a str,
        value: Option<&'a str>,
    },
}

const PATH_MAX: usize = 4096;

/// parse_ini: returns the callback's value (0 if it never stopped the parse).
pub fn parse_ini(file: &str, cb: &mut dyn FnMut(&str, usize, Event) -> i32) -> i32 {
    let data = match std::fs::read(file) {
        Ok(d) => d,
        // fopen works on a directory, fgets then fails: an empty parse
        Err(e) if e.raw_os_error() == Some(libc::EISDIR) => return 0,
        Err(e) => return cb(file, 0, Event::OpenFailed(e)),
    };
    let mut section_name: Option<String> = None;
    let mut pos = 0;
    let mut linenum = 0;
    while pos < data.len() {
        // fgets(line, PATH_MAX): at most PATH_MAX-1 bytes, up to and including '\n'
        let lim = (pos + PATH_MAX - 1).min(data.len());
        let end = data[pos..lim]
            .iter()
            .position(|&c| c == b'\n')
            .map_or(lim, |p| pos + p + 1);
        let mut chunk = &data[pos..end];
        pos = end;
        if let Some(n) = chunk.iter().position(|&c| c == 0) {
            chunk = &chunk[..n];
        }
        linenum += 1;
        let text = String::from_utf8_lossy(chunk);
        let line = strtrim(&text);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].to_string();
            let ret = cb(file, linenum, Event::Section(&name));
            section_name = Some(name);
            if ret != 0 {
                return ret;
            }
            continue;
        }
        let (key, value) = match line.find('=') {
            Some(p) => (strtrim(&line[..p]), Some(strtrim(&line[p + 1..]))),
            None => (strtrim(line), None),
        };
        let ret = cb(
            file,
            linenum,
            Event::Directive {
                section: section_name.as_deref(),
                key,
                value,
            },
        );
        if ret != 0 {
            return ret;
        }
    }
    0
}
