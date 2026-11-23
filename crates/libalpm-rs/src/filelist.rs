//! Port of lib/libalpm/filelist.c.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub size: i64,
    pub mode: u32,
}

#[derive(Debug, Clone, Default)]
pub struct FileList {
    pub files: Vec<File>,
}

impl FileList {
    /// _alpm_filelist_sort: sort by strcmp, only when not already sorted.
    pub fn sort(&mut self) {
        if self
            .files
            .windows(2)
            .any(|w| w[0].name.as_bytes() > w[1].name.as_bytes())
        {
            self.files
                .sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        }
    }

    /// alpm_filelist_contains (bsearch)
    pub fn contains(&self, path: &str) -> Option<&File> {
        self.files
            .binary_search_by(|f| f.name.as_bytes().cmp(path.as_bytes()))
            .ok()
            .map(|i| &self.files[i])
    }
}

/// _alpm_filelist_difference: names only in `a`; both lists must be sorted.
pub fn filelist_difference<'a>(a: &'a FileList, b: &FileList) -> Vec<&'a str> {
    let (mut i, mut j) = (0, 0);
    let mut ret = Vec::new();
    while i < a.files.len() && j < b.files.len() {
        match a.files[i].name.as_bytes().cmp(b.files[j].name.as_bytes()) {
            std::cmp::Ordering::Less => {
                ret.push(a.files[i].name.as_str());
                i += 1;
            }
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
        }
    }
    ret.extend(a.files[i..].iter().map(|f| f.name.as_str()));
    ret
}

/// _alpm_filelist_pathcmp: strcmp ignoring one trailing '/'.
fn pathcmp(p1: &str, p2: &str) -> i32 {
    let (mut a, mut b) = (p1.as_bytes(), p2.as_bytes());
    while let (Some(x), Some(y)) = (a.first(), b.first()) {
        if x != y {
            break;
        }
        a = &a[1..];
        b = &b[1..];
    }
    if a.is_empty() && b.first() == Some(&b'/') {
        b = &b[1..];
    } else if b.is_empty() && a.first() == Some(&b'/') {
        a = &a[1..];
    }
    *a.first().unwrap_or(&0) as i32 - *b.first().unwrap_or(&0) as i32
}

/// _alpm_filelist_intersection: names in both (not both directories); both lists must be sorted.
pub fn filelist_intersection<'a>(a: &'a FileList, b: &FileList) -> Vec<&'a str> {
    let (mut i, mut j) = (0, 0);
    let mut ret = Vec::new();
    while i < a.files.len() && j < b.files.len() {
        let (sa, sb) = (a.files[i].name.as_str(), b.files[j].name.as_str());
        let cmp = pathcmp(sa, sb);
        if cmp < 0 {
            i += 1;
        } else if cmp > 0 {
            j += 1;
        } else {
            if !sa.ends_with('/') || !sb.ends_with('/') {
                ret.push(sa);
            }
            i += 1;
            j += 1;
        }
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fl(v: &[&str]) -> FileList {
        let mut l = FileList {
            files: v
                .iter()
                .map(|n| File {
                    name: n.to_string(),
                    ..Default::default()
                })
                .collect(),
        };
        l.sort();
        l
    }

    #[test]
    fn ops() {
        let a = fl(&["usr/", "usr/bin/", "usr/bin/x", "z"]);
        let b = fl(&["usr", "usr/bin/x", "q"]);
        assert_eq!(filelist_difference(&a, &b), ["usr/", "usr/bin/", "z"]);
        assert_eq!(
            filelist_intersection(&a, &fl(&["usr/", "usr/bin/x"])),
            ["usr/bin/x"]
        );
        assert!(a.contains("z").is_some() && a.contains("w").is_none());
        let mut u = FileList {
            files: vec![
                File {
                    name: "b".into(),
                    ..Default::default()
                },
                File {
                    name: "a".into(),
                    ..Default::default()
                },
            ],
        };
        u.sort();
        assert_eq!(u.files[0].name, "a");
    }
}
